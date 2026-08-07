package web

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestMapConversation_FixesUseCamelCaseFrontEndShape(t *testing.T) {
	conv := &plugin.Conversation{
		ID: "c1", FindingID: "f1", Namespace: "prod", Focus: "prod/payment-api",
		Messages: []plugin.ConversationMessage{
			{Role: "user", Content: "why is it crashing?", At: time.Now()},
			{
				Role: "assistant", Content: "OOMKilled.", At: time.Now(), Confidence: "high",
				Steps: []plugin.InvestigationStep{{Label: "Logs inspected", Status: "done"}},
				Evidence: []plugin.EvidenceItem{
					{Kind: "log", Source: "pod", Excerpt: "OOMKilled", Anchor: "kubectl logs pod"},
				},
				Fixes: []plugin.RemediationAction{
					{
						Kind: "rollout-restart", FixType: "temporary", Description: "Restart the pod",
						KubectlCmd: "kubectl rollout restart deployment/payment-api", ExpectedOutcome: "Pod recovers",
					},
				},
				Timeline:    []plugin.TimelineEvent{{At: time.Now(), Label: "OOMKilled", Severity: "critical"}},
				Suggestions: []string{"Show me the previous logs"},
			},
		},
	}

	dc := mapConversation(conv)
	blob, err := json.Marshal(dc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(blob)

	// The RemediationAction's Go JSON tags are snake_case (kubectl_cmd,
	// fix_type, expected_outcome); mapConversation must translate them to the
	// camelCase shape chat.js's shared renderers expect (same contract as
	// /api/dashboard's dashFix), and must attach the server-computed
	// Applicable flag, which doesn't exist on the raw plugin type at all.
	for _, want := range []string{`"kubectlCmd"`, `"fixType"`, `"expectedOutcome"`, `"applicable"`} {
		if !strings.Contains(body, want) {
			t.Errorf("expected camelCase field %s in mapped conversation JSON, got: %s", want, body)
		}
	}
	for _, unwanted := range []string{`"kubectl_cmd"`, `"fix_type"`, `"expected_outcome"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("did not expect raw snake_case field %s to leak through, got: %s", unwanted, body)
		}
	}

	if len(dc.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(dc.Messages))
	}
	assistant := dc.Messages[1]
	if len(assistant.Fixes) != 1 || assistant.Fixes[0].Kind != "rollout-restart" {
		t.Fatalf("expected the rollout-restart fix to survive mapping, got: %+v", assistant.Fixes)
	}
	if !assistant.Fixes[0].Applicable {
		t.Error("rollout-restart is in applicableKinds and should map to Applicable=true")
	}
	if len(assistant.Evidence) != 1 || assistant.Evidence[0].Anchor != "kubectl logs pod" {
		t.Fatalf("expected evidence to survive mapping, got: %+v", assistant.Evidence)
	}
	if len(assistant.Steps) != 1 || assistant.Steps[0].Label != "Logs inspected" {
		t.Fatalf("expected steps to pass through unchanged, got: %+v", assistant.Steps)
	}
	if len(assistant.Timeline) != 1 || assistant.Timeline[0].Label != "OOMKilled" {
		t.Fatalf("expected timeline to pass through unchanged, got: %+v", assistant.Timeline)
	}
	if len(assistant.Suggestions) != 1 || assistant.Suggestions[0] != "Show me the previous logs" {
		t.Fatalf("expected suggestions to pass through unchanged, got: %+v", assistant.Suggestions)
	}
}
