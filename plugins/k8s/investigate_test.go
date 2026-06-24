package k8s

import (
	"context"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// recordingLLM captures the user message it receives so tests can assert what
// was (and wasn't) sent to the model.
type recordingLLM struct{ lastUser string }

func (m *recordingLLM) Name() string { return "mock" }
func (m *recordingLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	if len(req.Messages) > 0 {
		m.lastUser = req.Messages[0].Content
	}
	return plugin.CompleteResponse{Content: "## ROOT CAUSE\nThe container was OOM-killed."}, nil
}

// fakeRedactor redacts a known token so we can prove redaction-before-LLM.
type fakeRedactor struct{}

func (fakeRedactor) Redact(s string) string { return strings.ReplaceAll(s, "sk-secret", "[REDACTED]") }

func crashSnapshot() Snapshot {
	return Snapshot{
		Namespace: "prod",
		TotalPods: 10,
		UnhealthyPods: []PodSummary{{
			Namespace:    "prod",
			Name:         "payment-api",
			Phase:        "Running",
			Reason:       "CrashLoopBackOff",
			RestartCount: 22,
			LogTails:     []LogTail{{Container: "app", Lines: "panic: boom token=sk-secret"}},
		}},
	}
}

func TestInvestigate_RedactsBeforeLLMAndRecordsSteps(t *testing.T) {
	p := New()
	snap := crashSnapshot()
	p.setLastSnapshot(snap)

	findings := BuildAndEnrichFindings(snap)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from the crash snapshot")
	}
	id := findings[0].ID()

	llm := &recordingLLM{}
	inv, err := p.Investigate(context.Background(), id, llm, fakeRedactor{})
	if err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	if inv == nil || inv.Summary == "" {
		t.Fatal("expected a non-empty investigation summary")
	}
	if !strings.Contains(inv.Summary, "OOM-killed") {
		t.Errorf("summary should come from the LLM, got %q", inv.Summary)
	}
	if len(inv.Steps) == 0 {
		t.Error("expected recorded investigation steps")
	}
	// CRITICAL: the secret must have been redacted before reaching the model.
	if strings.Contains(llm.lastUser, "sk-secret") {
		t.Errorf("raw secret leaked to the LLM:\n%s", llm.lastUser)
	}
	if !strings.Contains(llm.lastUser, "[REDACTED]") {
		t.Errorf("expected the redacted marker in the LLM input:\n%s", llm.lastUser)
	}
}

func TestInvestigate_NilLLMFallsBackDeterministically(t *testing.T) {
	p := New()
	snap := crashSnapshot()
	p.setLastSnapshot(snap)
	id := BuildAndEnrichFindings(snap)[0].ID()

	inv, err := p.Investigate(context.Background(), id, nil, nil)
	if err != nil {
		t.Fatalf("Investigate (nil llm): %v", err)
	}
	if inv == nil || strings.TrimSpace(inv.Summary) == "" {
		t.Error("nil LLM should still yield a deterministic narrative")
	}
}

func TestInvestigate_UnknownIDErrors(t *testing.T) {
	p := New()
	p.setLastSnapshot(crashSnapshot())
	if _, err := p.Investigate(context.Background(), "fdeadbeef", nil, nil); err == nil {
		t.Error("expected an error for an unknown finding id")
	}
}
