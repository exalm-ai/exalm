package httplog

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

func burst5xxSession() *investigate.LogSession {
	s := investigate.NewLogSession("httplog")
	src := s.AddSource(investigate.SourceDesc{Path: "/var/log/nginx/access.log"})
	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		s.Append(investigate.LogEvent{
			At: now.Add(time.Duration(-4+i) * time.Minute), Severity: "5xx", Unit: "/api",
			Code: "502", Message: "GET /api/orders → 502", Raw: "GET /api/orders → 502", Source: src,
		})
	}
	return s
}

// ── profile validation ───────────────────────────────────────────────────────

func TestHTTPLogProfile_Validates(t *testing.T) {
	if err := New().InvestigationProfile().Validate(); err != nil {
		t.Fatalf("InvestigationProfile().Validate(): %v", err)
	}
}

// ── symptom matching ─────────────────────────────────────────────────────────

func TestHTTPLogSymptoms_Burst5xx(t *testing.T) {
	s := burst5xxSession()
	matched := New().InvestigationProfile().MatchSymptoms(s, investigate.Target{Name: "/api"})
	if len(matched) == 0 || matched[0].Key != "burst-5xx" {
		t.Fatalf("expected top symptom burst-5xx, got %+v", matched)
	}
}

func TestHTTPLogSymptoms_EmptySessionOnlyMatchesFallback(t *testing.T) {
	empty := investigate.NewLogSession("httplog")
	matched := New().InvestigationProfile().MatchSymptoms(empty, investigate.Target{})
	for _, m := range matched {
		if !m.Fallback {
			t.Errorf("empty session should only match the fallback symptom, got specific match %q", m.Key)
		}
	}
}

// ── plan ─────────────────────────────────────────────────────────────────────

func TestHTTPLogPlan_Burst5xxLeadsWithCorpus5xx(t *testing.T) {
	e := newTestEngine(t)
	s := burst5xxSession()
	plan := e.PlanPreview("why is /api returning 502?", nil, "site/api", s)
	if len(plan) == 0 {
		t.Fatal("expected a non-empty plan")
	}
	if plan[0].Collector != "corpus-5xx" {
		t.Errorf("expected top plan step corpus-5xx, got %q (full plan %+v)", plan[0].Collector, plan)
	}
}

// ── full turn (nil LLM → deterministic fallback) ────────────────────────────

func TestHTTPLogConverse_DeterministicTurn(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := burst5xxSession()

	conv, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "site", Message: "why is /api returning 502?",
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
	return strings.ReplaceAll(s, "sk-httplog-secret", "[REDACTED]")
}

type recordingLLM struct {
	calls [][]plugin.Message
}

func (m *recordingLLM) Name() string { return "mock" }
func (m *recordingLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	m.calls = append(m.calls, req.Messages)
	return plugin.CompleteResponse{Content: "OK"}, nil
}

func TestHTTPLogConverse_RedactsBeforeLLM(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := investigate.NewLogSession("httplog")
	src := s.AddSource(investigate.SourceDesc{Path: "/var/log/nginx/access.log"})
	s.Append(investigate.LogEvent{At: time.Now().UTC(), Severity: "5xx", Unit: "/api", Code: "502",
		Message: "GET /api/orders?token=sk-httplog-secret → 502",
		Raw:     "GET /api/orders?token=sk-httplog-secret → 502", Source: src})
	llm := &recordingLLM{}

	_, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "site", Message: "why is /api returning 502?",
	}, investigate.Deps{LLM: llm, Red: fakeRedactor{}, Store: store, Facts: s})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	if len(llm.calls) != 1 {
		t.Fatalf("expected exactly one LLM call, got %d", len(llm.calls))
	}
	for _, m := range llm.calls[0] {
		if strings.Contains(m.Content, "sk-httplog-secret") {
			t.Fatalf("unredacted secret reached the LLM: %q", m.Content)
		}
	}
}

// ── remote diagnostics (no SSH attached → collectors report unavailable) ───

func TestHTTPLogDiagCollectors_UnavailableWithoutSSH(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := burst5xxSession() // s.SSH is nil

	conv, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "site", Message: "check the upstream backend",
	}, investigate.Deps{Red: fakeRedactor{}, Store: store, Facts: s})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	msg := conv.Messages[len(conv.Messages)-1]
	foundDiagStep := false
	for _, step := range msg.Plan {
		if step.Collector == "http-error-log" {
			foundDiagStep = true
			if step.Status == "done" {
				t.Errorf("http-error-log should not succeed without an attached SSH host, got status %q", step.Status)
			}
		}
	}
	if !foundDiagStep {
		t.Error("expected the upstream intent to schedule the http-error-log collector")
	}
}
