package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MockLLM is a deterministic LLM adapter for integration and end-to-end tests.
//
// It returns a canned Markdown response containing every section header that
// Exalm plugins expect, so downstream parsing does not fail. The response
// intentionally signals a healthy cluster to avoid false alerts in CI.
//
// Activate with EXALM_LLM_PROVIDER=mock (no API key required).
// Token counts are synthetic (100 input / 50 output) so usage tracking works.
type MockLLM struct{}

// NewMock returns a MockLLM. It never returns an error.
func NewMock() *MockLLM { return &MockLLM{} }

// Name returns the provider identifier used in usage records.
func (m *MockLLM) Name() string { return "mock" }

// Complete returns a deterministic response whose content depends on keywords
// in the system prompt so that different plugins receive plausible output.
func (m *MockLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	content := mockResponse(req.System)
	return plugin.CompleteResponse{
		Content:      content,
		InputTokens:  100,
		OutputTokens: 50,
	}, nil
}

// mockResponse picks a canned reply based on keywords in the system prompt.
// The responses are minimal but valid Markdown so plugin parsers do not panic.
func mockResponse(system string) string {
	sys := strings.ToLower(system)

	switch {
	case contains(sys, "kubernetes", "k8s", "cluster", "pod"):
		return fmt.Sprintf("## Kubernetes Cluster Analysis\n\n%s\n\n### Findings\n\nNo critical issues detected.\n\n### Recommendations\n\nCluster is healthy. No action required.", mockHealthyMsg)

	case contains(sys, "log", "syslog", "httplog", "access"):
		return fmt.Sprintf("## Log Analysis\n\n%s\n\n### Findings\n\nNo anomalies detected in the log sample.\n\n### Recommendations\n\nLogs appear normal.", mockHealthyMsg)

	case contains(sys, "dora", "deployment", "lead time", "change failure"):
		return "## DORA Metrics Analysis\n\nAll four DORA metrics are within Elite performance thresholds.\n\n- Deployment Frequency: Daily\n- Lead Time for Changes: < 1 hour\n- Change Failure Rate: < 1%\n- Mean Time to Recovery: < 1 hour"

	case contains(sys, "incident", "postmortem", "blameless"):
		return "## Blameless Postmortem\n\n### Summary\n\nMock postmortem for CI testing.\n\n### Timeline\n\nNo real events.\n\n### Action Items\n\nNone required."

	case contains(sys, "chaos", "resilience", "fault"):
		return "## Resilience Analysis\n\nServices reviewed for chaos engineering readiness.\n\n### Score\n\n85/100 — Good resilience posture.\n\n### Recommendations\n\nConsider adding pod disruption budgets."

	case contains(sys, "aws", "cost", "billing", "cloud"):
		return "## AWS Cost Analysis\n\nNo cost anomalies detected in the selected period."

	case contains(sys, "terraform", "tf ", "plan"):
		return "## Terraform Plan Review\n\nNo high-risk changes detected. The plan looks safe to apply."

	default:
		return fmt.Sprintf("## Analysis\n\n%s\n\n### Findings\n\nNo issues detected.", mockHealthyMsg)
	}
}

// contains reports whether s contains any of the given substrings.
func contains(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

const mockHealthyMsg = "Mock analysis complete. All systems operating within normal parameters."
