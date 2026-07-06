package k8s

// loganalyze.go implements per-log-entry AI analysis (the "✦ Analyze line"
// action in the log viewer): one redacted LLM call over a single log line
// plus its surrounding context, answering with Root Cause / Impact /
// Remediation / Prevention. Same trust model as the rest of the plugin —
// everything through the redactor first, deterministic fallback without an
// LLM, no network surface beyond the injected LLMClient.

import (
	"context"
	"fmt"
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Input caps: a log line is small; the surrounding context is bounded well
// under MaxInputBytes so this endpoint can never balloon a prompt.
const (
	maxLogLineBytes    = 4 * 1024
	maxLogContextBytes = 24 * 1024
)

// LogLineRequest is one log entry to analyze, with whatever context the
// caller has. All fields except Message are optional.
type LogLineRequest struct {
	Namespace string
	Pod       string
	Container string
	Severity  string
	Source    string
	Labels    string
	Message   string // the selected log line
	Context   string // surrounding lines (already fetched by the log viewer)
}

// AnalyzeLogLine fills the analysis template with REDACTED values and makes
// one LLM call. Falls back to a deterministic answer when llm is nil or the
// call fails.
func (p *Plugin) AnalyzeLogLine(ctx context.Context, req LogLineRequest, llm plugin.LLMClient, red plugin.Redactor) (string, error) {
	if strings.TrimSpace(req.Message) == "" {
		return "", fmt.Errorf("message is required")
	}
	r := func(s string) string { return redactStr(red, s) }

	var b strings.Builder
	b.WriteString("LOG DETAILS:\n")
	writeIf := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(&b, "- %s: %s\n", k, r(v))
		}
	}
	writeIf("Namespace", req.Namespace)
	writeIf("Pod", req.Pod)
	writeIf("Container", req.Container)
	writeIf("Severity", req.Severity)
	writeIf("Source", req.Source)
	writeIf("Labels", req.Labels)
	fmt.Fprintf(&b, "- Message: %s\n", truncateString(r(req.Message), maxLogLineBytes))
	if strings.TrimSpace(req.Context) != "" {
		fmt.Fprintf(&b, "\nSURROUNDING LOG CONTEXT:\n%s\n", truncateString(r(req.Context), maxLogContextBytes))
	}

	if llm == nil {
		return deterministicLogAnalysis(req), nil
	}
	resp, err := llm.Complete(ctx, plugin.CompleteRequest{
		System:    logLineAnalysisPrompt,
		MaxTokens: 900,
		Messages:  []plugin.Message{{Role: "user", Content: b.String()}},
	})
	if err != nil || strings.TrimSpace(resp.Content) == "" {
		return deterministicLogAnalysis(req), nil
	}
	return strings.TrimSpace(resp.Content), nil
}

// deterministicLogAnalysis is the honest no-LLM fallback: it classifies the
// line against the known anomaly patterns and reports what to check.
func deterministicLogAnalysis(req LogLineRequest) string {
	lower := strings.ToLower(req.Message)
	hint := "No LLM is configured, so this is a pattern-match classification, not a synthesized analysis."
	var cause, check string
	switch {
	case strings.Contains(lower, "oom") || strings.Contains(lower, "out of memory"):
		cause = "The line matches an out-of-memory pattern — the container likely exceeded its memory limit."
		check = "kubectl describe pod " + req.Pod + " -n " + req.Namespace + " (look at lastState.terminated.reason) and the workload's resources.limits.memory."
	case strings.Contains(lower, "connection refused") || strings.Contains(lower, "timeout"):
		cause = "The line matches a connectivity-failure pattern — a dependency is unreachable or slow."
		check = "kubectl get endpoints -n " + req.Namespace + " for the target service, and any NetworkPolicies selecting this pod."
	case strings.Contains(lower, "no such host") || strings.Contains(lower, "could not resolve"):
		cause = "The line matches a DNS-resolution failure pattern."
		check = "CoreDNS pod health in kube-system and NetworkPolicy egress rules for this namespace."
	case strings.Contains(lower, "permission") || strings.Contains(lower, "forbidden") || strings.Contains(lower, "unauthorized"):
		cause = "The line matches an authorization-failure pattern — RBAC or credentials."
		check = "the pod's ServiceAccount bindings (kubectl get rolebindings,clusterrolebindings -A | grep <sa>) and any recently rotated secrets."
	case strings.Contains(lower, "panic") || strings.Contains(lower, "fatal") || strings.Contains(lower, "error"):
		cause = "The line matches a generic application-error pattern."
		check = "kubectl logs " + req.Pod + " -n " + req.Namespace + " --previous for the crash output, and recent deployments to this workload."
	default:
		cause = "The line matches no known failure pattern — it may be informational."
		check = "surrounding log context and warning events (kubectl get events -n " + req.Namespace + ")."
	}
	return "## Root Cause Analysis\n" + cause + "\n\n## Impact Assessment\nCannot be assessed without more context — check whether the pattern repeats and whether the pod is ready.\n\n## Remediation Steps\nStart with: " + check + "\n\n## Prevention\nWire an LLM provider to get a full synthesized analysis.\n\n_" + hint + "_"
}
