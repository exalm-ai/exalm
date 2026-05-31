package incident

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// postmortemLLMResponse mirrors the JSON shape the LLM is asked to return.
type postmortemLLMResponse struct {
	Summary             string   `json:"summary"`
	RootCauses          []string `json:"root_causes"`
	ContributingFactors []string `json:"contributing_factors"`
	Mitigation          string   `json:"mitigation"`
	ActionItems         []string `json:"action_items"`
}

// generatePostmortem sends the incident timeline to the LLM and parses the
// response into a structured Postmortem.
//
// SRE use case: after an incident is closed, the SRE runs
// `exalm incident postmortem --incident-id INC-001`. Exalm serialises the
// timeline (each finding as a compact text block), sends it to the configured
// LLM, and returns a structured postmortem ready for pasting into a Confluence
// or Notion page.
//
// All timeline text is redacted before being sent to the LLM.
func generatePostmortem(ctx context.Context, llmClient plugin.LLMClient, redactor plugin.Redactor, inc Incident) (Postmortem, error) {
	timeline := serializeTimeline(inc.Timeline)

	// CRITICAL: redact before any data leaves the process.
	redacted := redactor.Redact(timeline)

	resp, err := llmClient.Complete(ctx, plugin.CompleteRequest{
		System:    postmortemPrompt,
		MaxTokens: 2048,
		Messages: []plugin.Message{
			{
				Role:    "user",
				Content: fmt.Sprintf("Incident: %s\nTitle: %s\nSeverity: %s\n\nTimeline:\n%s", inc.ID, inc.Title, inc.Severity, redacted),
			},
		},
	})
	if err != nil {
		return Postmortem{}, fmt.Errorf("llm complete: %w", err)
	}

	pm := parsePostmortemResponse(resp.Content, inc)
	return pm, nil
}

// serializeTimeline converts a slice of TimelineEntry to a compact text block
// suitable for inclusion in the LLM prompt.
//
// Format per entry:
//
//	[<timestamp>] [<source>] [<severity>] <event>
//	  Detail: <finding.Detail>
//	  Suggestion: <finding.Suggestion>
func serializeTimeline(entries []TimelineEntry) string {
	if len(entries) == 0 {
		return "(no timeline entries recorded)"
	}
	var sb strings.Builder
	for _, e := range entries {
		severity := ""
		if e.Finding != nil {
			severity = fmt.Sprintf(" [%s]", e.Finding.Severity)
		}
		sb.WriteString(fmt.Sprintf("[%s] [%s]%s %s\n", //nolint:staticcheck // QF1012: fmt.Fprintf alternative would need errcheck suppression too
			e.At.UTC().Format(time.RFC3339),
			e.Source,
			severity,
			e.Event,
		))
		if e.Finding != nil {
			if e.Finding.Detail != "" {
				sb.WriteString(fmt.Sprintf("  Detail: %s\n", e.Finding.Detail)) //nolint:staticcheck // QF1012
			}
			if e.Finding.Suggestion != "" {
				sb.WriteString(fmt.Sprintf("  Suggestion: %s\n", e.Finding.Suggestion)) //nolint:staticcheck // QF1012
			}
		}
	}
	return sb.String()
}

// parsePostmortemResponse attempts to unmarshal the LLM response as JSON.
// On parse failure it stores the raw text in Summary so the user always gets output.
func parsePostmortemResponse(raw string, inc Incident) Postmortem {
	now := time.Now().UTC()
	pm := Postmortem{
		GeneratedAt: now,
	}

	// Compute MTTR when the incident is closed.
	if inc.ClosedAt != nil {
		pm.MTTR = inc.ClosedAt.Sub(inc.OpenedAt)
	}

	// Strip markdown code fences if the LLM wrapped the JSON.
	content := strings.TrimSpace(raw)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var llmResp postmortemLLMResponse
	if err := json.Unmarshal([]byte(content), &llmResp); err != nil {
		// Fall back: store raw LLM output in Summary so the user still gets output.
		pm.Summary = raw
		return pm
	}

	pm.Summary = llmResp.Summary
	pm.RootCauses = llmResp.RootCauses
	pm.ContributingFactors = llmResp.ContributingFactors
	pm.Mitigation = llmResp.Mitigation
	pm.ActionItems = llmResp.ActionItems
	return pm
}
