package syslog

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
	e, err := investigate.NewEngine(syslogProfile())
	if err != nil {
		t.Fatalf("NewEngine(syslogProfile): %v", err)
	}
	return e
}

func oomSession() *investigate.LogSession {
	s := investigate.NewLogSession("syslog")
	src := s.AddSource(investigate.SourceDesc{Path: "/var/log/syslog"})
	now := time.Now().UTC()
	s.Append(
		investigate.LogEvent{At: now.Add(-2 * time.Minute), Severity: "info", Unit: "app.service",
			Message: "app.service: memory usage climbing", Raw: "app.service: memory usage climbing", Source: src},
		investigate.LogEvent{At: now.Add(-1 * time.Minute), Severity: "err", Unit: "app.service",
			Message: "kernel: Out of memory: Killed process 1234 (app)",
			Raw:     "kernel: Out of memory: Killed process 1234 (app)", Source: src},
	)
	return s
}

// ── profile validation ───────────────────────────────────────────────────────

func TestSyslogProfile_Validates(t *testing.T) {
	if err := syslogProfile().Validate(); err != nil {
		t.Fatalf("syslogProfile().Validate(): %v", err)
	}
}

// ── symptom matching ─────────────────────────────────────────────────────────

func TestSyslogSymptoms_OOMKill(t *testing.T) {
	s := oomSession()
	matched := syslogProfile().MatchSymptoms(s, investigate.Target{Name: "app.service"})
	if len(matched) == 0 || matched[0].Key != "oom-kill" {
		t.Fatalf("expected top symptom oom-kill, got %+v", matched)
	}
	for _, m := range matched {
		if m.Key == "unknown-degraded" && m.Key == matched[0].Key {
			t.Errorf("fallback symptom should not outrank a specific match")
		}
	}
}

func TestSyslogSymptoms_NoMatchOnEmptySession(t *testing.T) {
	empty := investigate.NewLogSession("syslog")
	matched := syslogProfile().MatchSymptoms(empty, investigate.Target{})
	for _, m := range matched {
		if m.Key != "" {
			t.Errorf("empty session should not match any symptom, got %q", m.Key)
		}
	}
}

// ── plan ─────────────────────────────────────────────────────────────────────

func TestSyslogPlan_OOMKillLeadsWithCorpusOOM(t *testing.T) {
	e := newTestEngine(t)
	s := oomSession()
	plan := e.PlanPreview("why is app.service unhealthy?", nil, "host/app.service", s)
	if len(plan) == 0 {
		t.Fatal("expected a non-empty plan")
	}
	if plan[0].Collector != "corpus-oom" {
		t.Errorf("expected top plan step corpus-oom, got %q (full plan %+v)", plan[0].Collector, plan)
	}
}

// ── full turn (nil LLM → deterministic fallback) ────────────────────────────

func TestSyslogConverse_DeterministicTurn(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := oomSession()

	conv, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "host", Message: "why is app.service unhealthy?",
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
	return strings.ReplaceAll(s, "sk-syslog-secret", "[REDACTED]")
}

type recordingLLM struct {
	calls [][]plugin.Message
}

func (m *recordingLLM) Name() string { return "mock" }
func (m *recordingLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	m.calls = append(m.calls, req.Messages)
	return plugin.CompleteResponse{Content: "OK"}, nil
}

func TestSyslogConverse_RedactsBeforeLLM(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := investigate.NewLogSession("syslog")
	src := s.AddSource(investigate.SourceDesc{Path: "/var/log/syslog"})
	s.Append(investigate.LogEvent{At: time.Now().UTC(), Severity: "err", Unit: "app.service",
		Message: "kernel: Out of memory: Killed process 1 (app) token=sk-syslog-secret",
		Raw:     "kernel: Out of memory: Killed process 1 (app) token=sk-syslog-secret", Source: src})
	llm := &recordingLLM{}

	_, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "host", Message: "why is app.service unhealthy?",
	}, investigate.Deps{LLM: llm, Red: fakeRedactor{}, Store: store, Facts: s})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	if len(llm.calls) != 1 {
		t.Fatalf("expected exactly one LLM call, got %d", len(llm.calls))
	}
	for _, msg := range llm.calls[0] {
		if strings.Contains(msg.Content, "sk-syslog-secret") {
			t.Fatalf("unredacted secret reached the LLM: %q", msg.Content)
		}
	}
}

// ── remote diagnostics (no SSH attached → collectors report unavailable) ───

func TestSyslogDiagCollectors_UnavailableWithoutSSH(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := oomSession() // s.SSH is nil

	conv, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "host", Message: "check disk space",
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
