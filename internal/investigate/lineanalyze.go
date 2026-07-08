package investigate

// lineanalyze.go — per-log-entry AI analysis: one redacted LLM call over a
// single log line plus its surrounding context, answering with Root Cause /
// Impact / Remediation / Prevention. Generalized from plugins/k8s: the
// entry's metadata is an ordered field list instead of k8s-specific columns.

import (
	"context"
	"fmt"
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Input caps: a log line is small; the surrounding context stays bounded so
// this endpoint can never balloon a prompt.
const (
	maxLineBytes        = 4 * 1024
	maxLineContextBytes = 24 * 1024
)

// KV is one ordered metadata field ("Namespace: prod", "Host: web-01", …).
type KV struct{ Key, Value string }

// LineRequest is one log entry to analyze, with whatever context the caller
// has. All fields except Message are optional.
type LineRequest struct {
	Fields  []KV
	Message string
	Context string
}

// AnalyzeLine fills the analysis template with REDACTED values and makes one
// LLM call using the profile's LogLinePrompt. Falls back to the profile's
// deterministic fallback (or the generic one) when llm is nil or fails.
func (e *Engine) AnalyzeLine(ctx context.Context, req LineRequest, llm plugin.LLMClient, red plugin.Redactor) (string, error) {
	if strings.TrimSpace(req.Message) == "" {
		return "", fmt.Errorf("message is required")
	}
	r := func(s string) string {
		if red == nil {
			return s
		}
		return red.Redact(s)
	}

	var b strings.Builder
	b.WriteString("LOG DETAILS:\n")
	for _, f := range req.Fields {
		if strings.TrimSpace(f.Value) != "" {
			fmt.Fprintf(&b, "- %s: %s\n", f.Key, r(f.Value))
		}
	}
	fmt.Fprintf(&b, "- Message: %s\n", truncate(r(req.Message), maxLineBytes))
	if strings.TrimSpace(req.Context) != "" {
		fmt.Fprintf(&b, "\nSURROUNDING LOG CONTEXT:\n%s\n", truncate(r(req.Context), maxLineContextBytes))
	}

	fallback := e.profile.DeterministicLineFallback
	if fallback == nil {
		fallback = genericLineFallback
	}
	if llm == nil {
		return fallback(req), nil
	}
	resp, err := llm.Complete(ctx, plugin.CompleteRequest{
		System:    e.profile.LogLinePrompt,
		MaxTokens: 900,
		Messages:  []plugin.Message{{Role: "user", Content: b.String()}},
	})
	if err != nil || strings.TrimSpace(resp.Content) == "" {
		return fallback(req), nil
	}
	return strings.TrimSpace(resp.Content), nil
}

// genericLineFallback is the honest no-LLM answer: pattern-match
// classification plus what to check next, with no domain-specific commands.
func genericLineFallback(req LineRequest) string {
	lower := strings.ToLower(req.Message)
	var cause, check string
	switch {
	case strings.Contains(lower, "oom") || strings.Contains(lower, "out of memory"):
		cause = "The line matches an out-of-memory pattern — a process exceeded available memory."
		check = "memory usage around the timestamp and any OOM-killer entries in the kernel/system log."
	case strings.Contains(lower, "no space left") || strings.Contains(lower, "disk full"):
		cause = "The line matches a disk-full pattern."
		check = "filesystem usage (df -h) and which path filled up."
	case strings.Contains(lower, "connection refused") || strings.Contains(lower, "timeout"):
		cause = "The line matches a connectivity-failure pattern — a dependency is unreachable or slow."
		check = "the target service's health and any firewall/network-policy changes."
	case strings.Contains(lower, "no such host") || strings.Contains(lower, "could not resolve"):
		cause = "The line matches a DNS-resolution failure pattern."
		check = "resolver health and recent DNS or network configuration changes."
	case strings.Contains(lower, "permission") || strings.Contains(lower, "forbidden") || strings.Contains(lower, "unauthorized") || strings.Contains(lower, "authentication failure"):
		cause = "The line matches an authorization-failure pattern — permissions or credentials."
		check = "recent credential rotations and the account's permissions."
	case strings.Contains(lower, "panic") || strings.Contains(lower, "fatal") || strings.Contains(lower, "error"):
		cause = "The line matches a generic application-error pattern."
		check = "the surrounding log context and any recent deployments or configuration changes."
	default:
		cause = "The line matches no known failure pattern — it may be informational."
		check = "the surrounding log context for related warnings or errors."
	}
	return "## Root Cause Analysis\n" + cause +
		"\n\n## Impact Assessment\nCannot be assessed without more context — check whether the pattern repeats and whether the affected component is healthy.\n\n## Remediation Steps\nStart with: " + check +
		"\n\n## Prevention\nWire an LLM provider to get a full synthesized analysis.\n\n_No LLM is configured, so this is a pattern-match classification, not a synthesized analysis._"
}
