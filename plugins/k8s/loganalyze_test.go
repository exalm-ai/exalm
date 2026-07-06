package k8s

// loganalyze_test.go — the per-log-entry analyzer: redaction before the LLM,
// single call, input caps, and the deterministic fallback.

import (
	"context"
	"strings"
	"testing"
)

func TestAnalyzeLogLine_RedactsBeforeLLM(t *testing.T) {
	p := New()
	llm := &chatRecordingLLM{replies: []string{"## Root Cause Analysis\nOOM."}}

	out, err := p.AnalyzeLogLine(context.Background(), LogLineRequest{
		Namespace: "prod", Pod: "payment-api", Container: "app",
		Message: "ERROR connecting with token sk-secret to db",
		Context: "line1\nERROR connecting with token sk-secret to db\nline3",
	}, llm, fakeRedactor{})
	if err != nil {
		t.Fatalf("AnalyzeLogLine: %v", err)
	}
	if out == "" {
		t.Fatal("expected an analysis")
	}
	if len(llm.calls) != 1 {
		t.Fatalf("expected exactly 1 LLM call, got %d", len(llm.calls))
	}
	sent := llm.calls[0][len(llm.calls[0])-1].Content
	if strings.Contains(sent, "sk-secret") {
		t.Fatalf("SECRET LEAKED to the LLM: %s", sent)
	}
	if !strings.Contains(sent, "[REDACTED]") {
		t.Errorf("expected redaction markers in the prompt, got: %s", sent)
	}
	if !strings.Contains(sent, "LOG DETAILS:") || !strings.Contains(sent, "SURROUNDING LOG CONTEXT:") {
		t.Errorf("prompt missing template sections: %s", sent)
	}
}

func TestAnalyzeLogLine_RequiresMessage(t *testing.T) {
	p := New()
	if _, err := p.AnalyzeLogLine(context.Background(), LogLineRequest{Namespace: "prod"}, nil, fakeRedactor{}); err == nil {
		t.Error("expected an error for an empty message")
	}
}

func TestAnalyzeLogLine_DeterministicFallback(t *testing.T) {
	p := New()
	cases := map[string]string{
		"container killed: out of memory": "out-of-memory",
		"dial tcp: connection refused":    "connectivity",
		"lookup db: no such host":         "DNS",
		"403 Forbidden: access denied":    "authorization",
		"panic: nil pointer dereference":  "application-error",
	}
	for msg, want := range cases {
		out, err := p.AnalyzeLogLine(context.Background(), LogLineRequest{Namespace: "prod", Pod: "x", Message: msg}, nil, fakeRedactor{})
		if err != nil {
			t.Fatalf("fallback for %q: %v", msg, err)
		}
		if !strings.Contains(out, "## Root Cause Analysis") || !strings.Contains(out, "## Prevention") {
			t.Errorf("fallback for %q missing sections: %s", msg, out)
		}
		if !strings.Contains(out, want) {
			t.Errorf("fallback for %q should mention %q pattern, got: %s", msg, want, out)
		}
	}
}

func TestAnalyzeLogLine_CapsOversizedContext(t *testing.T) {
	p := New()
	llm := &chatRecordingLLM{replies: []string{"ok"}}
	huge := strings.Repeat("x", maxLogContextBytes*2)
	_, err := p.AnalyzeLogLine(context.Background(), LogLineRequest{Message: "ERROR y", Context: huge}, llm, fakeRedactor{})
	if err != nil {
		t.Fatalf("AnalyzeLogLine: %v", err)
	}
	sent := llm.calls[0][len(llm.calls[0])-1].Content
	if len(sent) > maxLogContextBytes+maxLogLineBytes+4096 {
		t.Errorf("prompt not capped: %d bytes", len(sent))
	}
}
