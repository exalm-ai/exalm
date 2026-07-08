package k8s

// loganalyze.go — the k8s wrapper for the framework's per-log-entry analysis
// (internal/investigate/lineanalyze.go): maps the k8s-shaped request into the
// generic field list, and supplies the kubectl-flavored deterministic
// fallback the framework calls when no LLM is wired.

import (
	"context"
	"strings"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
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

// AnalyzeLogLine runs the framework's single-entry analysis over the k8s
// request shape: exactly one redacted LLM call, deterministic fallback.
func (p *Plugin) AnalyzeLogLine(ctx context.Context, req LogLineRequest, llm plugin.LLMClient, red plugin.Redactor) (string, error) {
	return p.engine().AnalyzeLine(ctx, investigate.LineRequest{
		Fields: []investigate.KV{
			{Key: "Namespace", Value: req.Namespace},
			{Key: "Pod", Value: req.Pod},
			{Key: "Container", Value: req.Container},
			{Key: "Severity", Value: req.Severity},
			{Key: "Source", Value: req.Source},
			{Key: "Labels", Value: req.Labels},
		},
		Message: req.Message,
		Context: req.Context,
	}, llm, red)
}

// lineRequestToK8s reconstructs the k8s request shape from the generic field
// list, for the deterministic fallback's kubectl-flavored guidance.
func lineRequestToK8s(req investigate.LineRequest) LogLineRequest {
	out := LogLineRequest{Message: req.Message, Context: req.Context}
	for _, f := range req.Fields {
		switch f.Key {
		case "Namespace":
			out.Namespace = f.Value
		case "Pod":
			out.Pod = f.Value
		case "Container":
			out.Container = f.Value
		case "Severity":
			out.Severity = f.Value
		case "Source":
			out.Source = f.Value
		case "Labels":
			out.Labels = f.Value
		}
	}
	return out
}

// deterministicLogAnalysis is the honest no-LLM fallback: it classifies the
// line against the known anomaly patterns and reports the next kubectl
// command to run.
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
