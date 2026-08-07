package k8s

// classify.go turns a bare RemediationAction into an explainable, classified
// fix: is it a temporary mitigation (restart/delete/scale — buys time but the
// issue recurs) or a root-cause fix (raise limits, fix the probe, update the
// secret)? It also derives a confidence level and a root-cause sentence, and
// assembles the Finding.Fixes set the dashboard renders. Everything here is
// deterministic — the LLM investigation (investigate.go) refines the narrative
// but never gates classification.

import (
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// fixKindMeta is the classification applied to a remediation kind.
type fixKindMeta struct {
	fixType         string // "temporary" | "root-cause"
	risk            string // "low" | "medium" | "high"
	rollback        string
	expectedOutcome string
	downtime        string
}

// classifyKind maps a remediation Kind to its classification by keyword, so it
// tolerates both canonical kinds (delete-pod, add-limits) and descriptive ones
// (PatchDeployment, ExpandPVC).
func classifyKind(kind string) fixKindMeta {
	k := strings.ToLower(kind)
	switch {
	case containsAny(k, "delete", "evict"):
		return fixKindMeta{"temporary", "low",
			"Not required — the controller recreates the pod automatically.",
			"The pod restarts with fresh state; if the cause persists it will fail again.",
			"Brief restart of the affected pod."}
	case containsAny(k, "restart", "rollout"):
		return fixKindMeta{"temporary", "low",
			"Revert with `kubectl rollout undo`.",
			"All pods restart cleanly; a recurring cause will resurface after restart.",
			"None (rolling restart keeps the service available)."}
	case containsAny(k, "scale"):
		return fixKindMeta{"temporary", "medium",
			"Scale back to the previous replica count.",
			"Extra replicas absorb load; this masks rather than fixes the cause.",
			"None."}
	case containsAny(k, "cordon", "drain"):
		return fixKindMeta{"temporary", "medium",
			"Re-enable scheduling with `kubectl uncordon`.",
			"The node stops accepting new pods; existing workloads keep running.",
			"None immediately; draining reschedules pods elsewhere."}
	case containsAny(k, "patch", "expand", "limit", "label", "resume", "set", "update", "secret", "probe", "image"):
		return fixKindMeta{"root-cause", "medium",
			"Re-apply the previous spec, or `kubectl rollout undo` for workloads.",
			"The underlying spec is corrected, so the issue should not recur.",
			"Pods may restart to adopt the new spec."}
	default:
		// Unknown/shell action describing a specific change — treat as root-cause
		// guidance the user reviews before applying.
		return fixKindMeta{"root-cause", "medium",
			"Review before applying; revert by restoring the prior configuration.",
			"Addresses the underlying cause so the issue does not recur.",
			"Depends on the change."}
	}
}

// applyKindMeta fills in the classification fields of a, without overwriting any
// the plugin already set explicitly.
func applyKindMeta(a *plugin.RemediationAction) {
	m := classifyKind(a.Kind)
	if a.FixType == "" {
		a.FixType = m.fixType
	}
	if a.Risk == "" {
		a.Risk = m.risk
	}
	if a.Rollback == "" {
		a.Rollback = m.rollback
	}
	if a.ExpectedOutcome == "" {
		a.ExpectedOutcome = m.expectedOutcome
	}
	if a.Downtime == "" {
		a.Downtime = m.downtime
	}
}

// Classify enriches a finding in place: classifies its primary remediation,
// derives confidence + a root-cause sentence, and assembles Fixes (primary +
// any complementary root-cause guidance). Idempotent.
func Classify(f *plugin.Finding) {
	if f.Remediation != nil {
		applyKindMeta(f.Remediation)
	}
	if f.Confidence == "" {
		f.Confidence = deriveConfidence(*f)
	}
	if f.RootCause == "" {
		f.RootCause = deriveRootCause(*f)
	}
	f.Fixes = buildFixes(*f)
}

// deriveConfidence scores how sure we are about the root cause from the strength
// of the signals already attached to the finding.
func deriveConfidence(f plugin.Finding) string {
	// A recent, specific change correlation is the strongest signal.
	if f.LikelyCause != nil && f.LikelyCause.AgoSeconds > 0 && f.LikelyCause.AgoSeconds <= 600 {
		return "high"
	}
	if len(f.Evidence) >= 3 {
		return "high"
	}
	// A multi-pod cascade finding aggregates corroborating signals.
	if strings.Contains(strings.ToLower(f.Title), "cascade") {
		return "high"
	}
	if f.LikelyCause != nil || len(f.Evidence) >= 1 {
		return "medium"
	}
	return "low"
}

// deriveRootCause produces a one-sentence cause from the strongest available
// signal. The LLM investigation can replace this with a richer narrative.
func deriveRootCause(f plugin.Finding) string {
	if f.LikelyCause != nil {
		lc := f.LikelyCause
		who := ""
		if lc.Actor != "" {
			who = " by " + lc.Actor
		}
		return "Likely introduced by a recent " + lc.Kind + " change to " +
			joinNsName(lc.Namespace, lc.Name) + who + "."
	}
	title := strings.ToLower(f.Title)
	switch {
	case strings.Contains(title, "crashloopbackoff"):
		return "The container exits on startup and Kubernetes keeps restarting it; inspect the previous-container logs for the failing call."
	case strings.Contains(title, "oomkilled"):
		return "The container exceeded its memory limit and was OOM-killed — the limit is too low for the workload's working set."
	case strings.Contains(title, "imagepullbackoff"), strings.Contains(title, "errimagepull"):
		return "The image cannot be pulled — usually a missing/expired imagePullSecret or a wrong image reference."
	case strings.Contains(title, "no ready endpoints"), strings.Contains(title, "endpoint"):
		return "The Service selector matches no ready pods — likely a label/selector mismatch after a deploy."
	case strings.Contains(title, "diskpressure"), strings.Contains(title, "pvc"):
		return "Storage is at or near capacity, triggering pressure/evictions."
	}
	return firstSentenceOf(f.Detail)
}

// buildFixes assembles the classified fix set: the primary remediation plus a
// complementary root-cause suggestion when the primary is only a mitigation.
func buildFixes(f plugin.Finding) []plugin.RemediationAction {
	var fixes []plugin.RemediationAction
	if f.Remediation != nil {
		fixes = append(fixes, *f.Remediation)
	}
	// When the only action is a mitigation, surface the real fix as guidance so
	// the user understands a restart is not the cure.
	primaryIsTemporary := f.Remediation != nil && f.Remediation.FixType == "temporary"
	noRemediation := f.Remediation == nil
	if (primaryIsTemporary || noRemediation) && strings.TrimSpace(f.Suggestion) != "" {
		fixes = append(fixes, plugin.RemediationAction{
			Kind:            "advice", // not auto-applicable; UI shows copy/guidance, not Apply
			FixType:         "root-cause",
			Risk:            "low",
			Description:     f.Suggestion,
			Rollback:        "N/A — review and apply manually.",
			ExpectedOutcome: "Addresses the underlying cause so the issue does not recur.",
			Downtime:        "Depends on the change.",
		})
	}
	return fixes
}

// ── small helpers ──

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func joinNsName(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "/" + name
}

func firstSentenceOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "Root cause not yet determined — run an investigation for details."
	}
	if i := strings.IndexAny(s, ".\n"); i > 0 {
		return strings.TrimSpace(s[:i]) + "."
	}
	return s
}
