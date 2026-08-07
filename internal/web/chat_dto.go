package web

// chat_dto.go maps plugin.Conversation into the same camelCase front-end
// shape dashboard.go already established for findings (dashFix/dashEvidence)
// — so chat.js can reuse the dashboard's shared fix/evidence renderers
// without an adapter, and so RemediationAction's computed Applicable flag
// (server-only, not part of the plugin type) reaches the chat UI too.

import "github.com/exalm-ai/exalm/pkg/plugin"

// dashConvMessage is one chat turn in the shape the front-end expects.
type dashConvMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	At      string `json:"at"`
	// Assistant-only enrichment; empty for user turns.
	Confidence  string                     `json:"confidence,omitempty"`
	Steps       []plugin.InvestigationStep `json:"steps,omitempty"`
	Evidence    []dashEvidence             `json:"evidence,omitempty"`
	Fixes       []dashFix                  `json:"fixes,omitempty"`
	Timeline    []plugin.TimelineEvent     `json:"timeline,omitempty"`
	Suggestions []string                   `json:"suggestions,omitempty"`
	// Copilot enrichment (absent on transcripts recorded before the
	// investigation planner shipped — the front-end null-guards all of it).
	Score          int                 `json:"score,omitempty"`
	ScoreRationale string              `json:"scoreRationale,omitempty"`
	Plan           []dashPlanStep      `json:"plan,omitempty"`
	Hypotheses     []plugin.Hypothesis `json:"hypotheses,omitempty"`
	Prevention     []dashFix           `json:"prevention,omitempty"`
}

// dashPlanStep is the camelCase front-end shape of one plan step.
type dashPlanStep struct {
	ID        string `json:"id"`
	Collector string `json:"collector"`
	Target    string `json:"target,omitempty"`
	Edge      string `json:"edge,omitempty"`
	Reason    string `json:"reason"`
	Status    string `json:"status"`
	FromCache bool   `json:"fromCache,omitempty"`
}

// dashConversation is the front-end shape of a conversation, served by
// POST /api/chat and GET /api/chat/{id}.
type dashConversation struct {
	ID        string            `json:"id"`
	FindingID string            `json:"findingId,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Focus     string            `json:"focus,omitempty"`
	Messages  []dashConvMessage `json:"messages"`
}

func mapConversation(c *plugin.Conversation) dashConversation {
	msgs := make([]dashConvMessage, 0, len(c.Messages))
	for _, m := range c.Messages {
		msgs = append(msgs, dashConvMessage{
			Role:           m.Role,
			Content:        m.Content,
			At:             m.At.Format("15:04:05"),
			Confidence:     m.Confidence,
			Steps:          m.Steps,
			Evidence:       mapEvidence(m.Evidence),
			Fixes:          mapFixes(m.Fixes),
			Timeline:       m.Timeline,
			Suggestions:    m.Suggestions,
			Score:          m.Score,
			ScoreRationale: m.ScoreRationale,
			Plan:           mapPlan(m.Plan),
			Hypotheses:     m.Hypotheses,
			Prevention:     mapFixes(m.Prevention),
		})
	}
	return dashConversation{
		ID: c.ID, FindingID: c.FindingID, Namespace: c.Namespace, Focus: c.Focus,
		Messages: msgs,
	}
}

func mapPlan(plan []plugin.PlanStep) []dashPlanStep {
	if len(plan) == 0 {
		return nil
	}
	out := make([]dashPlanStep, 0, len(plan))
	for _, p := range plan {
		out = append(out, dashPlanStep{
			ID: p.ID, Collector: p.Collector, Target: p.Target, Edge: p.Edge,
			Reason: p.Reason, Status: p.Status, FromCache: p.FromCache,
		})
	}
	return out
}
