package k8s

// investigate.go implements deterministic, multi-step root-cause investigation
// for a single finding. It follows resource relationships using the data already
// collected in the last Snapshot, records exactly which checks it ran (the
// "investigation steps"), assembles the evidence chain, then makes ONE LLM call
// to synthesize a root-cause narrative over REDACTED evidence. No agentic loop,
// no hidden network calls — it reuses the already-connected client/snapshot and
// honors the redact-before-LLM trust model.

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// LogFetch returns a container's log tail using the client from the last
// analyze/watch run. previous selects the last-terminated container's logs.
// Returns an error when no cluster client is available (e.g. --from-file mode).
func (p *Plugin) LogFetch(ctx context.Context, namespace, pod, container string, previous bool, tail int) (string, error) {
	p.mu.Lock()
	cs := p.lastCS
	newLF := p.newLogFetcher
	p.mu.Unlock()
	if cs == nil || newLF == nil {
		return "", fmt.Errorf("no live cluster connection for log access")
	}
	if tail <= 0 || tail > 5000 {
		tail = 500
	}
	return newLF(cs).Tail(ctx, namespace, pod, container, int64(tail), previous)
}

// Investigate runs a root-cause investigation for the finding identified by id
// (plugin.Finding.ID()). llm and red may be nil — when so, the narrative falls
// back to a deterministic summary and no external call is made.
func (p *Plugin) Investigate(ctx context.Context, id string, llm plugin.LLMClient, red plugin.Redactor) (*plugin.Investigation, error) {
	p.mu.Lock()
	snap := p.lastSnapshot
	p.mu.Unlock()

	findings := BuildAndEnrichFindings(snap)
	var f *plugin.Finding
	for i := range findings {
		if findings[i].ID() == id {
			f = &findings[i]
			break
		}
	}
	if f == nil {
		return nil, fmt.Errorf("finding %q not found in the current snapshot", id)
	}

	steps := investigationSteps(*f, snap)

	var temporary, root []plugin.RemediationAction
	for _, fx := range f.Fixes {
		if fx.FixType == "root-cause" {
			root = append(root, fx)
		} else {
			temporary = append(temporary, fx)
		}
	}

	inv := &plugin.Investigation{
		RootCause:      f.RootCause,
		Confidence:     f.Confidence,
		Steps:          steps,
		Evidence:       f.Evidence,
		TemporaryFixes: temporary,
		RootCauseFixes: root,
	}
	inv.Summary = synthesizeNarrative(ctx, *f, steps, llm, red)
	return inv, nil
}

var titleNsNameRe = regexp.MustCompile(`([a-z0-9][a-z0-9.-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)`)

// findingTarget returns the (namespace, name) a finding is about.
func findingTarget(f plugin.Finding) (ns, name string) {
	if f.Remediation != nil && f.Remediation.Name != "" {
		return f.Remediation.Namespace, f.Remediation.Name
	}
	// Prefer the path after ": " (titles read "<Reason>: <ns>/<name>").
	t := f.Title
	if i := strings.LastIndex(t, ": "); i >= 0 {
		if m := titleNsNameRe.FindStringSubmatch(t[i:]); m != nil {
			return m[1], m[2]
		}
	}
	if m := titleNsNameRe.FindStringSubmatch(t); m != nil {
		return m[1], m[2]
	}
	return "", ""
}

// findPod locates a pod summary in the snapshot by namespace/name.
func findPod(snap Snapshot, ns, name string) *PodSummary {
	for i := range snap.UnhealthyPods {
		ps := &snap.UnhealthyPods[i]
		if ps.Name == name && (ns == "" || ps.Namespace == ns) {
			return ps
		}
	}
	return nil
}

// step is a small builder helper.
func step(label, status, detail, anchor string) plugin.InvestigationStep {
	return plugin.InvestigationStep{Label: label, Status: status, Detail: detail, Anchor: anchor}
}

// investigationSteps records the checks the engine ran for this finding,
// following the resource relationships relevant to its category. Each step is
// marked "done" (data was available), "unavailable" (the relationship exists but
// we have no data), or "skipped" (not relevant to this finding type).
func investigationSteps(f plugin.Finding, snap Snapshot) []plugin.InvestigationStep {
	ns, name := findingTarget(f)
	ref := joinNsName(ns, name)
	var steps []plugin.InvestigationStep

	pod := findPod(snap, ns, name)
	group := f.Category

	// 1. Pod status / container state.
	if pod != nil {
		detail := fmt.Sprintf("phase=%s reason=%s restarts=%d", pod.Phase, pod.Reason, pod.RestartCount)
		steps = append(steps, step("Pod status & container state inspected", "done", detail,
			"kubectl describe pod "+name+" -n "+ns))
	} else if group == "Pods" {
		steps = append(steps, step("Pod status inspected", "unavailable", "pod not in the collected snapshot", ""))
	}

	// 2. Container logs (current + previous).
	if pod != nil {
		logged := false
		for _, lt := range pod.LogTails {
			if lt.Lines != "" {
				logged = true
				break
			}
		}
		if logged {
			steps = append(steps, step("Container logs inspected (current + previous)", "done",
				fmt.Sprintf("%d container log tail(s) collected", len(pod.LogTails)),
				"kubectl logs "+name+" -n "+ns+" --previous"))
		} else {
			steps = append(steps, step("Container logs inspected", "unavailable", "no readable log tail", ""))
		}
		if len(pod.LogAnomalies) > 0 {
			cats := make([]string, 0, len(pod.LogAnomalies))
			for _, a := range pod.LogAnomalies {
				cats = append(cats, a.Category)
			}
			steps = append(steps, step("Log anomaly patterns scanned", "done",
				"matched: "+strings.Join(cats, ", "), ""))
		}
	}

	// 3. Resource limits (OOM / scheduling relevance).
	if pod != nil {
		if pod.HasNoLimits {
			steps = append(steps, step("Resource limits checked", "done", "container has no CPU/memory limits", ""))
		} else {
			steps = append(steps, step("Resource limits checked", "done", "limits are set", ""))
		}
	}

	// 4. Warning events for the resource.
	if eventsFor(snap, ns, name) {
		steps = append(steps, step("Warning events inspected", "done", "warning events found for this resource",
			"kubectl get events -n "+ns+" --field-selector type=Warning"))
	} else {
		steps = append(steps, step("Warning events inspected", "done", "no warning events for this resource", ""))
	}

	// 5. Owning workload (Deployment/StatefulSet).
	if dep := deploymentFor(snap, ns); dep != "" {
		steps = append(steps, step("Owning workload inspected", "done", "deployment(s) in namespace examined",
			"kubectl get deploy -n "+ns))
	}

	// 6. Service endpoints — relevant for networking/service findings.
	if group == "Networking" || group == "Services" || strings.Contains(strings.ToLower(f.Title), "endpoint") {
		steps = append(steps, step("Service endpoints inspected", "done", "selector/endpoint state examined",
			"kubectl get endpoints -n "+ns))
	}

	// 7. Node conditions — relevant for scheduling/node/storage pressure.
	if len(snap.NodeIssues) > 0 || group == "Nodes" || strings.Contains(strings.ToLower(f.Title), "pressure") {
		steps = append(steps, step("Node conditions inspected", "done",
			fmt.Sprintf("%d node(s) with conditions", len(snap.NodeIssues)), "kubectl describe nodes"))
	}

	// 8. Change correlation.
	if f.LikelyCause != nil {
		steps = append(steps, step("Recent changes correlated", "done",
			fmt.Sprintf("linked to %s %s", f.LikelyCause.Kind, joinNsName(f.LikelyCause.Namespace, f.LikelyCause.Name)), ""))
	} else {
		steps = append(steps, step("Recent changes correlated", "done", "no correlated change in the last 30m", ""))
	}

	if ref != "" {
		// Stamp the target into the first step's detail when otherwise empty.
		if len(steps) > 0 && steps[0].Detail == "" {
			steps[0].Detail = ref
		}
	}
	return steps
}

func eventsFor(snap Snapshot, ns, name string) bool {
	for _, e := range snap.Events {
		if e.Namespace == ns && e.PodName == name {
			return true
		}
	}
	return false
}

func deploymentFor(snap Snapshot, ns string) string {
	for _, d := range snap.Deployments {
		if d.Namespace == ns {
			return d.Name
		}
	}
	return ""
}

// synthesizeNarrative produces the root-cause narrative. With a live LLM it
// redacts the assembled evidence and makes ONE completion call; otherwise (or on
// error) it returns a deterministic summary built from the finding + evidence.
func synthesizeNarrative(ctx context.Context, f plugin.Finding, steps []plugin.InvestigationStep, llm plugin.LLMClient, red plugin.Redactor) string {
	if llm == nil {
		return deterministicNarrative(f)
	}
	msg := buildInvestigationMessage(f, steps)
	if red != nil {
		msg = red.Redact(msg) // CRITICAL: redact before anything leaves the process
	}
	resp, err := llm.Complete(ctx, plugin.CompleteRequest{
		System:    investigationPrompt,
		MaxTokens: 700,
		Messages:  []plugin.Message{{Role: "user", Content: msg}},
	})
	if err != nil || strings.TrimSpace(resp.Content) == "" {
		return deterministicNarrative(f)
	}
	return strings.TrimSpace(resp.Content)
}

// buildInvestigationMessage assembles the (pre-redaction) context for the LLM.
func buildInvestigationMessage(f plugin.Finding, steps []plugin.InvestigationStep) string {
	var b strings.Builder
	fmt.Fprintf(&b, "FINDING: %s\nSEVERITY: %s\nDETAIL: %s\n", f.Title, f.Severity, f.Detail)
	if f.RootCause != "" {
		fmt.Fprintf(&b, "PRELIMINARY ROOT CAUSE: %s\n", f.RootCause)
	}
	if f.LikelyCause != nil {
		fmt.Fprintf(&b, "CORRELATED CHANGE: %s %s by %s\n", f.LikelyCause.Kind,
			joinNsName(f.LikelyCause.Namespace, f.LikelyCause.Name), f.LikelyCause.Actor)
	}
	b.WriteString("\nCHECKS PERFORMED:\n")
	for _, s := range steps {
		fmt.Fprintf(&b, "- [%s] %s — %s\n", s.Status, s.Label, s.Detail)
	}
	if len(f.Evidence) > 0 {
		b.WriteString("\nEVIDENCE:\n")
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "- (%s/%s) %s\n", e.Kind, e.Source, e.Excerpt)
		}
	}
	if len(f.Fixes) > 0 {
		b.WriteString("\nCANDIDATE FIXES:\n")
		for _, fx := range f.Fixes {
			fmt.Fprintf(&b, "- [%s] %s\n", fx.FixType, fx.Description)
		}
	}
	return b.String()
}

// deterministicNarrative is the no-LLM fallback: a grounded summary built from
// the finding's classification and evidence.
func deterministicNarrative(f plugin.Finding) string {
	var b strings.Builder
	if f.RootCause != "" {
		b.WriteString(f.RootCause)
	} else {
		b.WriteString(firstSentenceOf(f.Detail))
	}
	if len(f.Evidence) > 0 {
		fmt.Fprintf(&b, " Supported by %d piece(s) of evidence (logs, events, and changes).", len(f.Evidence))
	}
	hasRoot := false
	for _, fx := range f.Fixes {
		if fx.FixType == "root-cause" {
			hasRoot = true
			break
		}
	}
	if hasRoot {
		b.WriteString(" A restart or delete only mitigates the symptom; apply the root-cause fix below to resolve it.")
	}
	return b.String()
}
