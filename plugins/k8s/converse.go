package k8s

// converse.go generalizes investigate.go's "one finding, one shot" pattern
// into "one conversation, many turns" — still exactly ONE redacted LLM call
// per turn, never an agentic tool-use loop. Each turn:
//  1. resolves which resource the conversation is focused on,
//  2. classifies intent deterministically (keyword/regex, not an LLM call),
//  3. gathers evidence deterministically for that intent, reusing the same
//     snapshot/log/changestore/metrics machinery investigate.go uses, plus
//     the on-demand collectors in configmaps.go/secrets.go/nodedetail.go,
//  4. makes one llm.Complete() call over redacted evidence + conversation
//     history, and
//  5. persists both turns (redacted) via the injected convo.Store.
//
// No step opens a network connection outside the already-injected
// kubernetes.Interface, metrics.Provider, or LLMClient.

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/internal/convo"
	"github.com/exalm-ai/exalm/internal/metrics"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

var convoIDCounter int64

// newConvoID returns a process-unique conversation id. Not cryptographically
// random — conversation ids aren't a security boundary, just a lookup key.
func newConvoID() string {
	convoIDCounter++
	return fmt.Sprintf("c%d%06d", time.Now().UTC().Unix(), convoIDCounter)
}

// Converse runs one turn of a multi-turn investigation conversation and
// returns the updated Conversation (full transcript, so the caller never has
// to merge partial state). llm/red/mp may be nil — the engine degrades
// gracefully (deterministic-only reply, no metrics evidence) exactly like
// Investigate() does.
func (p *Plugin) Converse(ctx context.Context, convoID, findingID, namespace, message string,
	llm plugin.LLMClient, red plugin.Redactor, store convo.Store, mp metrics.Provider,
) (*plugin.Conversation, error) {
	p.mu.Lock()
	snap := p.lastSnapshot
	cs := p.lastCS
	newLF := p.newLogFetcher
	p.mu.Unlock()

	now := time.Now().UTC()
	message = strings.TrimSpace(message)
	if message == "" {
		return nil, fmt.Errorf("message is required")
	}

	conv := loadOrCreateConversation(ctx, store, convoID, findingID, namespace, now)
	conv.Messages = append(conv.Messages, plugin.ConversationMessage{Role: "user", Content: message, At: now})

	conv.Focus = resolveFocus(conv.Focus, findingID, message, snap)
	ns, name := splitFocus(conv.Focus)
	pod := findPod(snap, ns, name)
	intents := classifyIntent(message)

	// Baseline: pod status + snapshot evidence come free — always first.
	var steps []plugin.InvestigationStep
	var evidence []plugin.EvidenceItem
	if pod != nil {
		steps = append(steps, investigationSteps(syntheticFinding(*pod, ns, name), snap)...)
		evidence = append(evidence, podEvidence(*pod, ns, name, now)...)
	} else if ns != "" || name != "" {
		steps = append(steps, step("Pod status inspected", "unavailable", "no pod "+conv.Focus+" in the current snapshot", ""))
	}

	// Deterministic investigation plan: symptom catalog + question intents
	// decide which collectors run this turn. Still exactly one LLM call.
	p.evidCache.purge(now)
	plan := buildPlan(planInput{
		Message: message, Intents: intents, Focus: conv.Focus,
		Pod: pod, Snap: snap,
		Cached: func(collector string) bool {
			return p.evidCache.has(conv.ID, collector, conv.Focus, now)
		},
		Refresh: hasIntent(intents, "refresh"),
	})
	if conv.Fingerprint == "" {
		conv.Fingerprint = fingerprintFor(pod, snap, conv.Focus)
	}
	executedPlan, planSteps, planEvidence := executePlan(ctx, plan, execDeps{
		cs: cs, red: red, newLF: newLF, mp: mp, snap: snap, ns: ns, name: name, now: now,
		cache: p.evidCache, convoID: conv.ID,
	})
	steps = append(steps, planSteps...)
	evidence = labelEvidence(append(evidence, planEvidence...))

	timeline := buildTimeline(snap, ns, name, now)
	var fixes []plugin.RemediationAction
	if findingID != "" {
		fixes = fixesForFinding(snap, findingID)
	}
	suggestions := suggestFollowUps(intents, pod, steps)

	llmMessages := buildLLMMessages(conv, conv.Focus, steps, evidence, fixes)
	content := synthesizeConversationReply(ctx, llmMessages, llm, red)

	conv.Messages = append(conv.Messages, plugin.ConversationMessage{
		Role: "assistant", Content: content, At: time.Now().UTC(),
		Confidence:  deriveConvConfidence(evidence, steps),
		Steps:       steps,
		Evidence:    evidence,
		Fixes:       fixes,
		Timeline:    timeline,
		Suggestions: suggestions,
		Plan:        executedPlan,
	})
	conv.UpdatedAt = time.Now().UTC()

	if err := store.Update(ctx, conv); err != nil {
		return nil, fmt.Errorf("persist conversation: %w", err)
	}
	return &conv, nil
}

// loadOrCreateConversation fetches convoID from store, or starts a fresh one
// when it's empty/unknown (e.g. the client generated a new id, or this is the
// first turn after "Investigate" seeded findingID/namespace but no id yet).
func loadOrCreateConversation(ctx context.Context, store convo.Store, convoID, findingID, namespace string, now time.Time) plugin.Conversation {
	if convoID != "" {
		if existing, err := store.Get(ctx, convoID); err == nil {
			return existing
		}
	}
	id := convoID
	if id == "" {
		id = newConvoID()
	}
	return plugin.Conversation{ID: id, FindingID: findingID, Namespace: namespace, CreatedAt: now}
}

// syntheticFinding adapts a focus pod into the minimal plugin.Finding shape
// investigationSteps() needs, so the conversation engine and the per-finding
// Investigate() share one implementation of "what to check for this pod"
// instead of two.
func syntheticFinding(pod PodSummary, ns, name string) plugin.Finding {
	return plugin.Finding{
		Category: "Pods",
		Title:    fmt.Sprintf("%s: %s", pod.Reason, joinNsName(ns, name)),
	}
}

// splitFocus splits a "namespace/name" focus string. A bare name with no
// namespace returns ns="".
func splitFocus(focus string) (ns, name string) {
	if i := strings.Index(focus, "/"); i >= 0 {
		return focus[:i], focus[i+1:]
	}
	return "", focus
}

// resolveFocus decides which resource this turn is about: an explicit mention
// in the message wins; otherwise the conversation keeps its prior focus
// (this is what makes "show me the previous logs" resolve to the same pod
// without the user repeating its name). The very first turn of a
// finding-anchored conversation (opened via "Investigate") seeds focus from
// the finding when the message itself names nothing.
func resolveFocus(prevFocus, findingID, message string, snap Snapshot) string {
	if m := titleNsNameRe.FindString(message); m != "" {
		return m
	}
	lower := strings.ToLower(message)
	for _, pod := range snap.UnhealthyPods {
		if pod.Name != "" && strings.Contains(lower, strings.ToLower(pod.Name)) {
			return joinNsName(pod.Namespace, pod.Name)
		}
	}
	for _, dep := range snap.Deployments {
		if dep.Name != "" && strings.Contains(lower, strings.ToLower(dep.Name)) {
			return joinNsName(dep.Namespace, dep.Name)
		}
	}
	if prevFocus == "" && findingID != "" {
		for _, f := range BuildAndEnrichFindings(snap) {
			if f.ID() == findingID {
				if ns, name := findingTarget(f); name != "" {
					return joinNsName(ns, name)
				}
			}
		}
	}
	return prevFocus
}

// fixesForFinding returns the classified Fixes of the finding identified by
// id, re-deriving findings from the current snapshot exactly like Investigate().
func fixesForFinding(snap Snapshot, id string) []plugin.RemediationAction {
	for _, f := range BuildAndEnrichFindings(snap) {
		if f.ID() == id {
			return f.Fixes
		}
	}
	return nil
}

// podEvidence builds the same kind of EvidenceItem the per-finding evidence
// chain carries (log/event excerpts with kubectl anchors) for a focus pod.
func podEvidence(pod PodSummary, ns, name string, now time.Time) []plugin.EvidenceItem {
	var out []plugin.EvidenceItem
	for _, lt := range pod.LogTails {
		if lt.Lines == "" {
			continue
		}
		out = append(out, plugin.EvidenceItem{
			Kind: "log", Source: lt.Container, Excerpt: truncateString(lt.Lines, 600), At: now,
			Anchor: "kubectl logs " + name + " -n " + ns + " -c " + lt.Container,
		})
	}
	return out
}

// ── intent classification (deterministic, not an LLM call) ──

var intentPatterns = []struct {
	intent string
	re     *regexp.Regexp
}{
	{"previous-logs", regexp.MustCompile(`(?i)previous log|logs? before|prior log|last run|logs before it crashed`)},
	{"deploy-correlation", regexp.MustCompile(`(?i)deploy(ment)?|rollout|release|recent change|last (change|update)|replicaset`)},
	{"comparison", regexp.MustCompile(`(?i)compare|yesterday|did this happen before|previously|history|happened before`)},
	{"db-connectivity", regexp.MustCompile(`(?i)database|\bdb\b|postgres|mysql|redis|connection (pool|refused)`)},
	{"resource-usage", regexp.MustCompile(`(?i)memory|\bcpu\b|resource usage|\boom\b|out of memory`)},
	{"node-pressure", regexp.MustCompile(`(?i)\bnode\b|disk pressure|node pressure|scheduling`)},
	{"configmap", regexp.MustCompile(`(?i)config\s?map|configuration\b`)},
	{"secret", regexp.MustCompile(`(?i)\bsecrets?\b|credential`)},
	{"dns", regexp.MustCompile(`(?i)\bdns\b|resolve|resolution|no such host`)},
	{"timeline", regexp.MustCompile(`(?i)timeline|sequence of events|what happened|order of events`)},
	{"rca", regexp.MustCompile(`(?i)\brca\b|postmortem|incident report|root cause analysis`)},
	{"related-services", regexp.MustCompile(`(?i)related (service|pod)|depends on|dependency|dependent service|which service`)},
	{"ingress", regexp.MustCompile(`(?i)ingress|external traffic|\b503\b|\b502\b|gateway`)},
	{"storage", regexp.MustCompile(`(?i)\bpvc\b|\bpv\b|volume|storage ?class|disk (full|space)|persistent`)},
	{"rbac-question", regexp.MustCompile(`(?i)\brbac\b|permission|forbidden|service ?account|role ?binding`)},
	{"quota", regexp.MustCompile(`(?i)quota|limit ?range|namespace limit`)},
	{"scaling", regexp.MustCompile(`(?i)\bhpa\b|autoscal|scale|replicas|disruption budget|\bpdb\b`)},
	{"history", regexp.MustCompile(`(?i)happened before|recurr|similar (incident|issue)|last time|how often|more frequent`)},
	{"refresh", regexp.MustCompile(`(?i)\brefresh\b|re-?check|fetch again|latest (data|state)|re-?collect`)},
	{"vpa", regexp.MustCompile(`(?i)\bvpa\b|vertical pod autoscal`)},
}

// classifyIntent maps free-text to zero or more intent tags via keyword/regex
// matching — never via an LLM call. Returns ["general"] when nothing matches,
// so the engine still gathers the baseline pod/event/log evidence.
func classifyIntent(message string) []string {
	var out []string
	for _, p := range intentPatterns {
		if p.re.MatchString(message) {
			out = append(out, p.intent)
		}
	}
	if len(out) == 0 {
		out = append(out, "general")
	}
	return out
}

// hasIntent reports whether the classified intents include the given tag.
func hasIntent(intents []string, tag string) bool {
	for _, i := range intents {
		if i == tag {
			return true
		}
	}
	return false
}

func gatherPreviousLogs(ctx context.Context, cs kubernetes.Interface, newLF func(kubernetes.Interface) logFetcher, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || newLF == nil || name == "" {
		return []plugin.InvestigationStep{step("Previous container logs inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	lines, err := newLF(cs).Tail(ctx, ns, name, "", 200, true)
	if err != nil || lines == "" {
		return []plugin.InvestigationStep{step("Previous container logs inspected", "unavailable", "no previous-container log available", "kubectl logs "+name+" -n "+ns+" --previous")}, nil
	}
	return []plugin.InvestigationStep{step("Previous container logs inspected", "done", "", "kubectl logs "+name+" -n "+ns+" --previous")},
		[]plugin.EvidenceItem{{Kind: "log", Source: name + " (previous)", Excerpt: truncateString(lines, 600), At: time.Now().UTC(), Anchor: "kubectl logs " + name + " -n " + ns + " --previous"}}
}

func gatherChangeHistory(snap Snapshot, ns, name string, now time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	store := defaultStore()
	if store == nil || name == "" {
		return []plugin.InvestigationStep{step("Recent changes correlated", "unavailable", "changestore unavailable", "")}, nil
	}
	// Widen the window beyond the 30m correlation default — "compare with
	// yesterday" needs days, not minutes.
	changes, err := store.RecentForResource(ns, name, correlationKinds, 7*24*time.Hour, now)
	if err != nil || len(changes) == 0 {
		return []plugin.InvestigationStep{step("Recent changes correlated", "done", "no changes recorded for this resource in the last 7 days", "")}, nil
	}
	var evid []plugin.EvidenceItem
	for i, c := range changes {
		if i >= 5 {
			break
		}
		evid = append(evid, plugin.EvidenceItem{
			Kind: "change", Source: c.Kind + "/" + c.Name,
			Excerpt: fmt.Sprintf("%s by %s, %s ago", c.Action, c.Actor, humanizeAge(c.Timestamp, now)),
			At:      c.Timestamp,
		})
	}
	return []plugin.InvestigationStep{step("Recent changes correlated", "done", fmt.Sprintf("%d change(s) in the last 7 days", len(changes)), "")}, evid
}

func gatherConfigMaps(ctx context.Context, cs kubernetes.Interface, red plugin.Redactor, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || name == "" {
		return []plugin.InvestigationStep{step("ConfigMaps inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	cms, err := configMapsFor(ctx, cs, red, ns, name)
	if err != nil || len(cms) == 0 {
		return []plugin.InvestigationStep{step("ConfigMaps inspected", "done", "no ConfigMaps referenced by this pod", "")}, nil
	}
	var evid []plugin.EvidenceItem
	for _, cm := range cms {
		evid = append(evid, plugin.EvidenceItem{
			Kind: "change", Source: "configmap/" + cm.Name,
			Excerpt: fmt.Sprintf("keys: %s", strings.Join(cm.Keys, ", ")),
			Anchor:  "kubectl get configmap " + cm.Name + " -n " + ns + " -o yaml",
		})
	}
	return []plugin.InvestigationStep{step("ConfigMaps inspected", "done", fmt.Sprintf("%d configmap(s) referenced", len(cms)), "")}, evid
}

func gatherSecrets(ctx context.Context, cs kubernetes.Interface, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || name == "" {
		return []plugin.InvestigationStep{step("Secrets inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	secs, err := secretsFor(ctx, cs, ns, name)
	if err != nil || len(secs) == 0 {
		return []plugin.InvestigationStep{step("Secrets inspected", "done", "no Secrets referenced by this pod", "")}, nil
	}
	var evid []plugin.EvidenceItem
	for _, sec := range secs {
		// Existence/type/age only — never a value. See secrets.go.
		evid = append(evid, plugin.EvidenceItem{
			Kind: "change", Source: "secret/" + sec.Name,
			Excerpt: fmt.Sprintf("type=%s age=%s", sec.Type, sec.Age),
			Anchor:  "kubectl get secret " + sec.Name + " -n " + ns,
		})
	}
	return []plugin.InvestigationStep{step("Secrets inspected (existence/type only — values never read)", "done", fmt.Sprintf("%d secret(s) referenced", len(secs)), "")}, evid
}

func gatherNodePressure(ctx context.Context, cs kubernetes.Interface, snap Snapshot, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || name == "" {
		return []plugin.InvestigationStep{step("Node conditions inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	nodeName, err := nodeNameForPod(ctx, cs, ns, name)
	if err != nil || nodeName == "" {
		return []plugin.InvestigationStep{step("Node conditions inspected", "unavailable", "could not resolve the pod's node", "")}, nil
	}
	detail, err := nodeDetail(ctx, cs, nodeName)
	if err != nil {
		return []plugin.InvestigationStep{step("Node conditions inspected", "unavailable", "node detail fetch failed", "")}, nil
	}
	evid := []plugin.EvidenceItem{{
		Kind: "metric", Source: "node/" + nodeName,
		Excerpt: fmt.Sprintf("capacity=%v allocatable=%v conditions=%v taints=%v", detail.Capacity, detail.Allocatable, detail.Conditions, detail.Taints),
		Anchor:  "kubectl describe node " + nodeName,
	}}
	for _, ni := range snap.NodeIssues {
		if ni.Name == nodeName {
			evid = append(evid, plugin.EvidenceItem{Kind: "event", Source: nodeName, Excerpt: strings.Join(ni.Conditions, ", ")})
		}
	}
	return []plugin.InvestigationStep{step("Node conditions & capacity inspected", "done", nodeName, "kubectl describe node "+nodeName)}, evid
}

func gatherMetrics(ctx context.Context, mp metrics.Provider, ns, name string, now time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if mp == nil {
		return []plugin.InvestigationStep{step("Metrics inspected", "unavailable", "no metrics provider configured", "")}, nil
	}
	series, err := mp.Series(ctx, metrics.Query{Namespace: ns, Name: name, Window: 24 * time.Hour, Now: now, Magnitude: 1})
	if err != nil || len(series) == 0 {
		return []plugin.InvestigationStep{step("Metrics inspected", "unavailable", "no series returned", "")}, nil
	}
	s0 := series[0]
	var last float64
	if len(s0.Points) > 0 {
		last = s0.Points[len(s0.Points)-1].V
	}
	kind := "measured"
	if s0.Modeled {
		kind = "modeled — no real metrics backend wired"
	}
	evid := []plugin.EvidenceItem{{
		Kind: "metric", Source: s0.Name,
		Excerpt: fmt.Sprintf("latest=%.1f threshold=%.1f (%s)", last, s0.Threshold, kind),
		At:      now,
	}}
	return []plugin.InvestigationStep{step("Metrics inspected", "done", s0.Name+" ("+kind+")", "")}, evid
}

// gatherDNSHeuristic approximates a DNS diagnosis from signals Exalm already
// has, since Exalm runs outside the cluster and has no real DNS resolver to
// query: CoreDNS pod health, Service/Endpoints presence, and a substring scan
// of already-collected log tails for classic resolution-failure messages.
// This is explicitly a heuristic, not real DNS diagnostics — surfaced as such
// in the step detail so the UI/LLM never overstate the confidence.
func gatherDNSHeuristic(snap Snapshot, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	var evid []plugin.EvidenceItem
	for _, pod := range snap.UnhealthyPods {
		if pod.Namespace == "kube-system" && strings.HasPrefix(strings.ToLower(pod.Name), "coredns") {
			evid = append(evid, plugin.EvidenceItem{Kind: "event", Source: pod.Name, Excerpt: "CoreDNS pod unhealthy: " + pod.Reason})
		}
	}
	for _, si := range snap.ServiceIssues {
		if ns == "" || si.Namespace == ns {
			evid = append(evid, plugin.EvidenceItem{Kind: "event", Source: "service/" + si.Name, Excerpt: si.Issue})
		}
	}
	dnsErrRe := regexp.MustCompile(`(?i)no such host|i/o timeout|could not resolve|name or service not known|lookup .* failed`)
	for _, pod := range snap.UnhealthyPods {
		if name != "" && pod.Name != name {
			continue
		}
		for _, lt := range pod.LogTails {
			if loc := dnsErrRe.FindString(lt.Lines); loc != "" {
				evid = append(evid, plugin.EvidenceItem{Kind: "log", Source: pod.Name + "/" + lt.Container, Excerpt: loc})
			}
		}
	}
	return []plugin.InvestigationStep{step("DNS heuristic checked (approximation — Exalm runs outside the cluster, no real resolver query)", "done", fmt.Sprintf("%d signal(s) found", len(evid)), "")}, evid
}

func gatherRelatedResources(snap Snapshot, ns string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	var evid []plugin.EvidenceItem
	for _, si := range snap.ServiceIssues {
		if ns == "" || si.Namespace == ns {
			evid = append(evid, plugin.EvidenceItem{Kind: "event", Source: "service/" + si.Name, Excerpt: si.Issue})
		}
	}
	for _, sm := range snap.SelectorMismatches {
		if ns == "" || sm.Namespace == ns {
			evid = append(evid, plugin.EvidenceItem{Kind: "event", Source: "service/" + sm.ServiceName, Excerpt: "selector mismatch — matches " + sm.MatchingLabel})
		}
	}
	return []plugin.InvestigationStep{step("Related services inspected", "done", fmt.Sprintf("%d related signal(s)", len(evid)), "")}, evid
}

// ── timeline ──

// buildTimeline assembles a chronological view of what happened to the focus
// resource: real-timestamped changestore events, real-timestamped warning
// events (EventSummary.LastSeenAt), and a final "current state" entry from
// the live snapshot. Sorted ascending (oldest first) to match the user-facing
// "A → B → C" reading order.
func buildTimeline(snap Snapshot, ns, name string, now time.Time) []plugin.TimelineEvent {
	var out []plugin.TimelineEvent

	if cstore := defaultStore(); cstore != nil && name != "" {
		if changes, err := cstore.RecentForResource(ns, name, correlationKinds, 7*24*time.Hour, now); err == nil {
			for _, c := range changes {
				out = append(out, plugin.TimelineEvent{
					At: c.Timestamp, Label: fmt.Sprintf("%s %s", c.Kind, c.Action), Source: "change", Detail: c.Name,
				})
			}
		}
	}
	for _, e := range snap.Events {
		if name != "" && e.PodName != name {
			continue
		}
		if ns != "" && e.Namespace != ns {
			continue
		}
		sev := "info"
		if e.Density > 1 {
			sev = "high"
		}
		out = append(out, plugin.TimelineEvent{At: e.LastSeenAt, Label: e.Reason, Severity: sev, Source: "event", Detail: e.Message})
	}
	if pod := findPod(snap, ns, name); pod != nil {
		out = append(out, plugin.TimelineEvent{At: now, Label: pod.Phase, Severity: severityForReason(pod.Reason), Source: "pod", Detail: pod.Reason})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

func severityForReason(reason string) string {
	switch reason {
	case "CrashLoopBackOff", "OOMKilled", "Evicted":
		return "critical"
	case "":
		return "info"
	default:
		return "high"
	}
}

// ── follow-up suggestions (deterministic — no second LLM call) ──

// suggestFollowUps proposes what to investigate next, based on which gather
// steps this turn did NOT yet run for the current focus. Purely rule-based.
func suggestFollowUps(intents []string, pod *PodSummary, steps []plugin.InvestigationStep) []string {
	done := map[string]bool{}
	for _, s := range steps {
		done[s.Label] = s.Status == "done"
	}
	has := func(intent string) bool {
		for _, i := range intents {
			if i == intent {
				return true
			}
		}
		return false
	}

	var out []string
	add := func(s string) {
		if len(out) < 5 {
			out = append(out, s)
		}
	}
	if pod != nil && pod.HasNoLimits && !has("resource-usage") {
		add("Investigate memory usage")
	}
	if !has("deploy-correlation") && !has("comparison") {
		add("Check recent deployments")
	}
	if !has("previous-logs") {
		add("Show previous logs")
	}
	if !has("db-connectivity") {
		add("Check database connectivity")
	}
	if !has("node-pressure") {
		add("Check node resource pressure")
	}
	if !has("rca") {
		add("Generate an RCA")
	}
	return out
}

// ── LLM assembly + synthesis (exactly one call per turn) ──

// buildLLMMessages converts the conversation's existing turns into the
// provider-agnostic Message history, then appends THIS turn's question
// enriched with the freshly gathered steps/evidence/fixes. Earlier turns keep
// their original (already-redacted) content — only the newest user message
// carries new evidence, so context doesn't balloon turn over turn.
func buildLLMMessages(conv plugin.Conversation, focus string, steps []plugin.InvestigationStep, evidence []plugin.EvidenceItem, fixes []plugin.RemediationAction) []plugin.Message {
	msgs := make([]plugin.Message, 0, len(conv.Messages))
	for i, m := range conv.Messages {
		if i == len(conv.Messages)-1 {
			break // last message is this turn's user question; build it enriched below
		}
		msgs = append(msgs, plugin.Message{Role: m.Role, Content: m.Content})
	}
	last := conv.Messages[len(conv.Messages)-1]
	msgs = append(msgs, plugin.Message{Role: "user", Content: buildEnrichedTurn(last.Content, focus, steps, evidence, fixes)})
	return msgs
}

func buildEnrichedTurn(question, focus string, steps []plugin.InvestigationStep, evidence []plugin.EvidenceItem, fixes []plugin.RemediationAction) string {
	var b strings.Builder
	fmt.Fprintf(&b, "QUESTION: %s\n", question)
	if focus != "" {
		fmt.Fprintf(&b, "FOCUS RESOURCE: %s\n", focus)
	}
	if len(steps) > 0 {
		b.WriteString("\nCHECKS PERFORMED THIS TURN:\n")
		for _, s := range steps {
			fmt.Fprintf(&b, "- [%s] %s — %s\n", s.Status, s.Label, s.Detail)
		}
	}
	if len(evidence) > 0 {
		b.WriteString("\nEVIDENCE:\n")
		for _, e := range evidence {
			fmt.Fprintf(&b, "- (%s/%s) %s\n", e.Kind, e.Source, e.Excerpt)
		}
	}
	if len(fixes) > 0 {
		b.WriteString("\nKNOWN FIXES FOR THIS RESOURCE:\n")
		for _, fx := range fixes {
			fmt.Fprintf(&b, "- [%s] %s\n", fx.FixType, fx.Description)
		}
	}
	return b.String()
}

// synthesizeConversationReply makes the ONE LLM call for this turn, redacting
// every message first. Falls back to a deterministic reply when llm is nil or
// the call fails — mirrors investigate.go's synthesizeNarrative().
func synthesizeConversationReply(ctx context.Context, messages []plugin.Message, llm plugin.LLMClient, red plugin.Redactor) string {
	if llm == nil {
		return deterministicConvReply(messages)
	}
	redacted := make([]plugin.Message, len(messages))
	for i, m := range messages {
		content := m.Content
		if red != nil {
			content = red.Redact(content)
		}
		redacted[i] = plugin.Message{Role: m.Role, Content: content}
	}
	resp, err := llm.Complete(ctx, plugin.CompleteRequest{System: conversationPrompt, MaxTokens: 900, Messages: redacted})
	if err != nil || strings.TrimSpace(resp.Content) == "" {
		return deterministicConvReply(messages)
	}
	return strings.TrimSpace(resp.Content)
}

// deterministicConvReply is the no-LLM fallback: it cannot synthesize a
// narrative, but it can honestly report what was checked.
func deterministicConvReply(messages []plugin.Message) string {
	if len(messages) == 0 {
		return "No information available yet — ask about a specific pod, deployment, or namespace."
	}
	return "No LLM is configured, so I can't synthesize a narrative answer, but the evidence and steps below were gathered for your question."
}

// deriveConvConfidence scores this turn the same way classify.go scores a
// finding: a recent change or several evidence items raise confidence.
func deriveConvConfidence(evidence []plugin.EvidenceItem, steps []plugin.InvestigationStep) string {
	if len(evidence) >= 3 {
		return "high"
	}
	doneCount := 0
	for _, s := range steps {
		if s.Status == "done" {
			doneCount++
		}
	}
	if len(evidence) >= 1 || doneCount >= 3 {
		return "medium"
	}
	return "low"
}
