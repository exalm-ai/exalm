package eventlog

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

func serviceCrashSession() *investigate.LogSession {
	s := investigate.NewLogSession("eventlog")
	src := s.AddSource(investigate.SourceDesc{Host: "web-01", Channel: "System"})
	now := time.Now().UTC()
	s.Append(
		investigate.LogEvent{At: now.Add(-2 * time.Minute), Severity: "Error", Unit: "Service Control Manager",
			Code: "7031", Message: "The World Wide Web Publishing Service service terminated unexpectedly.",
			Raw: "7031 The World Wide Web Publishing Service service terminated unexpectedly.", Source: src},
		investigate.LogEvent{At: now.Add(-1 * time.Minute), Severity: "Information", Unit: "Service Control Manager",
			Code: "7036", Message: "The World Wide Web Publishing Service entered the running state.",
			Raw: "7036 The World Wide Web Publishing Service entered the running state.", Source: src},
	)
	return s
}

// ── profile validation ───────────────────────────────────────────────────────

func TestEventlogProfile_Validates(t *testing.T) {
	if err := New().InvestigationProfile().Validate(); err != nil {
		t.Fatalf("InvestigationProfile().Validate(): %v", err)
	}
}

// ── symptom matching ─────────────────────────────────────────────────────────

func TestEventlogSymptoms_ServiceCrash(t *testing.T) {
	s := serviceCrashSession()
	matched := New().InvestigationProfile().MatchSymptoms(s, investigate.Target{Name: "Service Control Manager"})
	if len(matched) == 0 || matched[0].Key != "service-crash" {
		t.Fatalf("expected top symptom service-crash, got %+v", matched)
	}
}

func TestEventlogSymptoms_NoMatchOnEmptySession(t *testing.T) {
	empty := investigate.NewLogSession("eventlog")
	matched := New().InvestigationProfile().MatchSymptoms(empty, investigate.Target{})
	for _, m := range matched {
		if m.Key != "" {
			t.Errorf("empty session should not match any symptom, got %q", m.Key)
		}
	}
}

// ── plan ─────────────────────────────────────────────────────────────────────

func TestEventlogPlan_ServiceCrashLeadsWithCorpusSvc(t *testing.T) {
	e := newTestEngine(t)
	s := serviceCrashSession()
	plan := e.PlanPreview("why did the web service crash?", nil, "web-01/Service Control Manager", s)
	if len(plan) == 0 {
		t.Fatal("expected a non-empty plan")
	}
	if plan[0].Collector != "corpus-svc" {
		t.Errorf("expected top plan step corpus-svc, got %q (full plan %+v)", plan[0].Collector, plan)
	}
}

// ── full turn (nil LLM → deterministic fallback) ────────────────────────────

func TestEventlogConverse_DeterministicTurn(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := serviceCrashSession()

	conv, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "web-01", Message: "why did the web service crash?",
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
	return strings.ReplaceAll(s, "sk-eventlog-secret", "[REDACTED]")
}

type recordingLLM struct {
	calls [][]plugin.Message
}

func (m *recordingLLM) Name() string { return "mock" }
func (m *recordingLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	m.calls = append(m.calls, req.Messages)
	return plugin.CompleteResponse{Content: "OK"}, nil
}

func TestEventlogConverse_RedactsBeforeLLM(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := investigate.NewLogSession("eventlog")
	src := s.AddSource(investigate.SourceDesc{Host: "web-01", Channel: "System"})
	s.Append(investigate.LogEvent{At: time.Now().UTC(), Severity: "Error", Unit: "Service Control Manager",
		Code: "7031", Message: "service terminated unexpectedly token=sk-eventlog-secret",
		Raw: "7031 service terminated unexpectedly token=sk-eventlog-secret", Source: src})
	llm := &recordingLLM{}

	_, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "web-01", Message: "why did the web service crash?",
	}, investigate.Deps{LLM: llm, Red: fakeRedactor{}, Store: store, Facts: s})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	if len(llm.calls) != 1 {
		t.Fatalf("expected exactly one LLM call, got %d", len(llm.calls))
	}
	for _, m := range llm.calls[0] {
		if strings.Contains(m.Content, "sk-eventlog-secret") {
			t.Fatalf("unredacted secret reached the LLM: %q", m.Content)
		}
	}
}

// ── remote diagnostics (no SSH attached → collectors report unavailable) ───

func TestEventlogDiagCollectors_UnavailableWithoutSSH(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := serviceCrashSession() // s.SSH is nil

	conv, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "web-01", Message: "check disk health",
	}, investigate.Deps{Red: fakeRedactor{}, Store: store, Facts: s})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	msg := conv.Messages[len(conv.Messages)-1]
	foundDiagStep := false
	for _, step := range msg.Plan {
		if step.Collector == "sys-disk" {
			foundDiagStep = true
			if step.Status == "done" {
				t.Errorf("sys-disk should not succeed without an attached SSH host, got status %q", step.Status)
			}
		}
	}
	if !foundDiagStep {
		t.Error("expected the disk intent to schedule the sys-disk collector")
	}
}
