package logs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/convo"
	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func newTestStore(t *testing.T) convo.Store {
	t.Helper()
	convo.ConversationDir = t.TempDir()
	t.Cleanup(func() { convo.ConversationDir = "" })
	return convo.NewStore()
}

func newTestEngine(t *testing.T) *investigate.Engine {
	t.Helper()
	e, err := investigate.NewEngine(New().InvestigationProfile())
	if err != nil {
		t.Fatalf("NewEngine(InvestigationProfile): %v", err)
	}
	return e
}

func errorBurstSession() *investigate.LogSession {
	s := investigate.NewLogSession("logs")
	src := s.AddSource(investigate.SourceDesc{Path: "app.log"})
	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		s.Append(investigate.LogEvent{
			At: now.Add(time.Duration(-6+i) * time.Second), Severity: "error", Unit: "worker",
			Message: "error: failed to process job", Raw: "error: failed to process job", Source: src,
		})
	}
	return s
}

// ── profile validation ───────────────────────────────────────────────────────

func TestLogsProfile_Validates(t *testing.T) {
	if err := New().InvestigationProfile().Validate(); err != nil {
		t.Fatalf("InvestigationProfile().Validate(): %v", err)
	}
}

// ── symptom matching ─────────────────────────────────────────────────────────

func TestLogsSymptoms_ErrorBurst(t *testing.T) {
	s := errorBurstSession()
	matched := New().InvestigationProfile().MatchSymptoms(s, investigate.Target{Name: "worker"})
	if len(matched) == 0 || matched[0].Key != "error-burst" {
		t.Fatalf("expected top symptom error-burst, got %+v", matched)
	}
}

func TestLogsSymptoms_EmptySessionOnlyMatchesFallback(t *testing.T) {
	empty := investigate.NewLogSession("logs")
	matched := New().InvestigationProfile().MatchSymptoms(empty, investigate.Target{})
	for _, m := range matched {
		if !m.Fallback {
			t.Errorf("empty session should only match the fallback symptom, got specific match %q", m.Key)
		}
	}
}

func TestLogsSymptoms_NilFactsMatchNothing(t *testing.T) {
	matched := New().InvestigationProfile().MatchSymptoms(nil, investigate.Target{})
	if len(matched) != 0 {
		t.Errorf("nil facts should match no symptom (not even the fallback), got %+v", matched)
	}
}

// ── plan ─────────────────────────────────────────────────────────────────────

func TestLogsPlan_ErrorBurstLeadsWithCorpusErrors(t *testing.T) {
	e := newTestEngine(t)
	s := errorBurstSession()
	plan := e.PlanPreview("why is the worker failing?", nil, "app/worker", s)
	if len(plan) == 0 {
		t.Fatal("expected a non-empty plan")
	}
	if plan[0].Collector != "corpus-errors" {
		t.Errorf("expected top plan step corpus-errors, got %q (full plan %+v)", plan[0].Collector, plan)
	}
}

// ── full turn (nil LLM → deterministic fallback) ────────────────────────────

func TestLogsConverse_DeterministicTurn(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := errorBurstSession()

	conv, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "app", Message: "why is the worker failing?",
	}, investigate.Deps{Red: fakeRedactor{}, Store: store, Facts: s})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	if len(conv.Messages) != 2 {
		t.Fatalf("expected 2 messages (user+assistant), got %d", len(conv.Messages))
	}
	msg := conv.Messages[len(conv.Messages)-1]
	for _, want := range []string{"**Root cause**", "**Prevention**", "confidence"} {
		if !strings.Contains(msg.Content, want) {
			t.Errorf("reply missing %q\nreply:\n%s", want, msg.Content)
		}
	}
	if len(msg.Plan) == 0 {
		t.Error("expected a non-empty plan")
	}
	if len(msg.Evidence) == 0 {
		t.Error("expected non-empty evidence")
	}
	if msg.Evidence[0].Label == "" {
		t.Error("expected evidence to carry citation labels (E1..)")
	}
	if msg.Score <= 0 {
		t.Errorf("expected a positive confidence score, got %d", msg.Score)
	}
	if len(msg.Hypotheses) == 0 || msg.Hypotheses[0].Title == "" {
		t.Error("expected a ranked hypothesis")
	}
	if len(msg.Prevention) == 0 {
		t.Error("expected prevention advice for the matched symptom")
	}
}

// ── redaction-before-LLM (the trust-model guard) ────────────────────────────

type fakeRedactor struct{}

func (fakeRedactor) Redact(s string) string {
	return strings.ReplaceAll(s, "sk-logs-secret", "[REDACTED]")
}

type recordingLLM struct {
	calls [][]plugin.Message
}

func (m *recordingLLM) Name() string { return "mock" }
func (m *recordingLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	m.calls = append(m.calls, req.Messages)
	return plugin.CompleteResponse{Content: "OK"}, nil
}

func TestLogsConverse_RedactsBeforeLLM(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := investigate.NewLogSession("logs")
	src := s.AddSource(investigate.SourceDesc{Path: "app.log"})
	s.Append(investigate.LogEvent{At: time.Now().UTC(), Severity: "error", Unit: "worker",
		Message: "error: failed to process job token=sk-logs-secret",
		Raw:     "error: failed to process job token=sk-logs-secret", Source: src})
	llm := &recordingLLM{}

	_, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "app", Message: "why is the worker failing?",
	}, investigate.Deps{LLM: llm, Red: fakeRedactor{}, Store: store, Facts: s})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	if len(llm.calls) != 1 {
		t.Fatalf("expected exactly one LLM call, got %d", len(llm.calls))
	}
	for _, m := range llm.calls[0] {
		if strings.Contains(m.Content, "sk-logs-secret") {
			t.Fatalf("unredacted secret reached the LLM: %q", m.Content)
		}
	}
}
