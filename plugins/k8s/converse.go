package k8s

// converse.go — the Kubernetes entry point into the generic investigation
// framework (internal/investigate). The per-turn pipeline (focus → intents →
// deterministic plan → cached collector execution → hypotheses → confidence →
// prevention → ONE redacted LLM call → persisted transcript) lives in the
// framework engine; this file supplies only what is Kubernetes: focus
// resolution against the snapshot, the baseline pod evidence, the timeline,
// finding-anchored fixes, follow-up suggestions, and the domain collectors
// the profile registers (profile.go).
//
// No step opens a network connection outside the already-injected
// kubernetes.Interface, metrics.Provider, or LLMClient. The LLM never
// chooses collectors — it only narrates what the plan gathered.

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/internal/convo"
	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/internal/metrics"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// k8sFacts is the opaque Facts bundle the k8s profile's hooks and collectors
// unwrap: the most recent snapshot, the focus pod (resolved per turn by
// PrepareTurn), and the injected clients.
type k8sFacts struct {
	snap  Snapshot
	pod   *PodSummary
	cs    kubernetes.Interface
	newLF func(kubernetes.Interface) logFetcher
	mp    metrics.Provider
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
	incidentHistory := p.incidentHistory
	p.mu.Unlock()

	return p.engine().Converse(ctx, investigate.ConverseReq{
		ConvoID: convoID, AnchorID: findingID, Scope: namespace, Message: message,
	}, investigate.Deps{
		LLM: llm, Red: red, Store: store,
		Facts: k8sFacts{snap: snap, cs: cs, newLF: newLF, mp: mp},
		History: investigate.HistorySources{
			Convo:     store,
			Incidents: incidentHistory,
			Changes:   changeFrequency,
		},
	})
}

// changeFrequency adapts the changestore into the framework's decoupled
// recurrence closure.
func changeFrequency(scope, name string, window time.Duration, now time.Time) []investigate.ChangeSummary {
	cstore := defaultStore()
	if cstore == nil || name == "" {
		return nil
	}
	changes, err := cstore.RecentForResource(scope, name, correlationKinds, window, now)
	if err != nil {
		return nil
	}
	out := make([]investigate.ChangeSummary, 0, len(changes))
	for _, c := range changes {
		out = append(out, investigate.ChangeSummary{
			Kind: c.Kind, Name: c.Name, Action: c.Action, Actor: c.Actor, Timestamp: c.Timestamp,
		})
	}
	return out
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

// ── k8s intent patterns (deterministic, not an LLM call) ──

// k8sIntentPatterns extends the framework's common intents with the
// Kubernetes vocabulary.
var k8sIntentPatterns = append(investigate.CommonIntentPatterns(), []investigate.IntentPattern{
	{Intent: "deploy-correlation", Re: regexp.MustCompile(`(?i)deploy(ment)?|rollout|release|recent change|last (change|update)|replicaset`)},
	{Intent: "db-connectivity", Re: regexp.MustCompile(`(?i)database|\bdb\b|postgres|mysql|redis|connection (pool|refused)`)},
	{Intent: "resource-usage", Re: regexp.MustCompile(`(?i)memory|\bcpu\b|resource usage|\boom\b|out of memory`)},
	{Intent: "node-pressure", Re: regexp.MustCompile(`(?i)\bnode\b|disk pressure|node pressure|scheduling`)},
	{Intent: "configmap", Re: regexp.MustCompile(`(?i)config\s?map|configuration\b`)},
	{Intent: "secret", Re: regexp.MustCompile(`(?i)\bsecrets?\b|credential`)},
	{Intent: "dns", Re: regexp.MustCompile(`(?i)\bdns\b|resolve|resolution|no such host`)},
	{Intent: "related-services", Re: regexp.MustCompile(`(?i)related (service|pod)|depends on|dependency|dependent service|which service`)},
	{Intent: "ingress", Re: regexp.MustCompile(`(?i)ingress|external traffic|\b503\b|\b502\b|gateway`)},
	{Intent: "storage", Re: regexp.MustCompile(`(?i)\bpvc\b|\bpv\b|volume|storage ?class|disk (full|space)|persistent`)},
	{Intent: "rbac-question", Re: regexp.MustCompile(`(?i)\brbac\b|permission|forbidden|service ?account|role ?binding`)},
	{Intent: "quota", Re: regexp.MustCompile(`(?i)quota|limit ?range|namespace limit`)},
	{Intent: "scaling", Re: regexp.MustCompile(`(?i)\bhpa\b|autoscal|scale|replicas|disruption budget|\bpdb\b`)},
	{Intent: "vpa", Re: regexp.MustCompile(`(?i)\bvpa\b|vertical pod autoscal`)},
}...)

// classifyIntent keeps the historical k8s-package spelling for tests and
// callers; it is the framework classifier over the k8s patterns.
func classifyIntent(message string) []string {
	return investigate.ClassifyIntent(k8sIntentPatterns, message)
}

// hasIntent reports whether the classified intents include the given tag.
func hasIntent(intents []string, tag string) bool { return investigate.HasIntent(intents, tag) }

// matchSymptoms is the k8s-typed view over the profile's symptom matching,
// kept for the catalog tests.
func matchSymptoms(pod *PodSummary, snap Snapshot, ns, name string) []investigate.Symptom {
	return k8sProfile().MatchSymptoms(k8sFacts{snap: snap, pod: pod}, investigate.Target{Scope: ns, Name: name})
}

// ── k8s collectors (invoked via the profile's dispatch table) ──

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
