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
			Role:        m.Role,
			Content:     m.Content,
			At:          m.At.Format("15:04:05"),
			Confidence:  m.Confidence,
			Steps:       m.Steps,
			Evidence:    mapEvidence(m.Evidence),
			Fixes:       mapFixes(m.Fixes),
			Timeline:    m.Timeline,
			Suggestions: m.Suggestions,
		})
	}
	return dashConversation{
		ID: c.ID, FindingID: c.FindingID, Namespace: c.Namespace, Focus: c.Focus,
		Messages: msgs,
	}
}
