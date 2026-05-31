package llm

import (
	"context"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/internal/config"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestMockLLM_Name(t *testing.T) {
	m := NewMock()
	if m.Name() != "mock" {
		t.Errorf("Name(): want %q, got %q", "mock", m.Name())
	}
}

func TestMockLLM_Complete_ReturnsContent(t *testing.T) {
	m := NewMock()
	resp, err := m.Complete(context.Background(), plugin.CompleteRequest{
		System: "You are analysing a Kubernetes cluster for issues.",
	})
	if err != nil {
		t.Fatalf("Complete() unexpected error: %v", err)
	}
	if resp.Content == "" {
		t.Error("Complete() returned empty content")
	}
	if resp.InputTokens != 100 {
		t.Errorf("InputTokens: want 100, got %d", resp.InputTokens)
	}
	if resp.OutputTokens != 50 {
		t.Errorf("OutputTokens: want 50, got %d", resp.OutputTokens)
	}
}

func TestMockLLM_Complete_RoutesOnSystemPrompt(t *testing.T) {
	m := NewMock()
	cases := []struct {
		system string
		want   string // expected substring in content
	}{
		{"Analyse this Kubernetes cluster.", "Kubernetes Cluster Analysis"},
		{"Summarise these log lines from syslog.", "Log Analysis"},
		{"Analyse DORA metrics for this team.", "DORA Metrics Analysis"},
		{"Write a blameless postmortem for this incident.", "Blameless Postmortem"},
		{"Score this service's chaos engineering resilience.", "Resilience Analysis"},
		{"Review this AWS cost report.", "AWS Cost Analysis"},
		{"Review this Terraform plan for safety.", "Terraform Plan Review"},
		{"General analysis with no specific keyword.", "Analysis"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			resp, err := m.Complete(context.Background(), plugin.CompleteRequest{System: tc.system})
			if err != nil {
				t.Fatalf("Complete() error: %v", err)
			}
			if !strings.Contains(resp.Content, tc.want) {
				t.Errorf("expected content to contain %q; got:\n%s", tc.want, resp.Content)
			}
		})
	}
}

func TestNewFromConfig_MockProvider(t *testing.T) {
	// Verify the "mock" provider is wired in NewFromConfig without needing
	// an API key.
	client, err := NewFromConfig(config.Config{LLMProvider: "mock"})
	if err != nil {
		t.Fatalf("NewFromConfig(mock): %v", err)
	}
	if client.Name() != "mock" {
		t.Errorf("Name(): want %q, got %q", "mock", client.Name())
	}
}
