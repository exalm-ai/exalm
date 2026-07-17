package cloudtrail

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
	e, err := investigate.NewEngine(cloudtrailProfile())
	if err != nil {
		t.Fatalf("NewEngine(cloudtrailProfile): %v", err)
	}
	return e
}

// rootUsageSession returns a session containing one routine call and one
// root-account API call — the clearest, highest-priority symptom.
func rootUsageSession() *investigate.LogSession {
	s := investigate.NewLogSession("cloudtrail")
	src := s.AddSource(investigate.SourceDesc{Path: "trail.ndjson"})
	now := time.Now().UTC()
	s.Append(
		investigate.LogEvent{At: now.Add(-2 * time.Minute), Severity: "info", Unit: "DescribeInstances", Scope: "us-east-1",
			Message: "alice called DescribeInstances from 10.0.0.1",
			Raw:     `{"eventTime":"2026-05-13T09:58:00Z","eventName":"DescribeInstances","userIdentity":{"userName":"alice"},"awsRegion":"us-east-1"}`, Source: src},
		investigate.LogEvent{At: now.Add(-1 * time.Minute), Severity: "crit", Unit: "CreateUser", Scope: "us-east-1",
			Message: "Root called CreateUser from 198.51.100.10",
			Raw:     `{"eventTime":"2026-05-13T09:59:00Z","eventName":"CreateUser","userIdentity":{"type":"Root"},"awsRegion":"us-east-1"}`, Source: src},
	)
	return s
}

// ── profile validation ───────────────────────────────────────────────────────

func TestCloudTrailProfile_Validates(t *testing.T) {
	if err := cloudtrailProfile().Validate(); err != nil {
		t.Fatalf("cloudtrailProfile().Validate(): %v", err)
	}
}

// ── symptom matching ─────────────────────────────────────────────────────────

func TestCloudTrailSymptoms_RootUsage(t *testing.T) {
	s := rootUsageSession()
	matched := cloudtrailProfile().MatchSymptoms(s, investigate.Target{Name: "CreateUser"})
	if len(matched) == 0 || matched[0].Key != "root-account-usage" {
		t.Fatalf("expected top symptom root-account-usage, got %+v", matched)
	}
}

func TestCloudTrailSymptoms_NoMatchOnEmptySession(t *testing.T) {
	empty := investigate.NewLogSession("cloudtrail")
	matched := cloudtrailProfile().MatchSymptoms(empty, investigate.Target{})
	for _, m := range matched {
		if m.Key != "" {
			t.Errorf("empty session should not match any symptom, got %q", m.Key)
		}
	}
}

func TestCloudTrailSymptoms_AccessDeniedNeedsThreeOrMore(t *testing.T) {
	s := investigate.NewLogSession("cloudtrail")
	src := s.AddSource(investigate.SourceDesc{Path: "trail.ndjson"})
	// Only two denials — below the threshold, should not match.
	for i := 0; i < 2; i++ {
		s.Append(investigate.LogEvent{Severity: "err", Unit: "DeleteBucket", Code: "AccessDenied",
			Message: "alice called DeleteBucket — AccessDenied: denied",
			Raw:     `{"eventName":"DeleteBucket","errorCode":"AccessDenied","userIdentity":{"userName":"alice"}}`, Source: src})
	}
	matched := cloudtrailProfile().MatchSymptoms(s, investigate.Target{})
	for _, m := range matched {
		if m.Key == "access-denied-spike" {
			t.Error("access-denied-spike should not match below the 3-event threshold")
		}
	}
}

// ── plan ─────────────────────────────────────────────────────────────────────

func TestCloudTrailPlan_RootUsageLeadsWithCorpusRoot(t *testing.T) {
	e := newTestEngine(t)
	s := rootUsageSession()
	plan := e.PlanPreview("why did CreateUser happen?", nil, "aws/CreateUser", s)
	if len(plan) == 0 {
		t.Fatal("expected a non-empty plan")
	}
	if plan[0].Collector != "corpus-root" {
		t.Errorf("expected top plan step corpus-root, got %q (full plan %+v)", plan[0].Collector, plan)
	}
}

// ── full turn (nil LLM → deterministic fallback) ────────────────────────────

func TestCloudTrailConverse_DeterministicTurn(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := rootUsageSession()

	conv, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "aws", Message: "why did CreateUser happen?",
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
	return strings.ReplaceAll(s, "sk-cloudtrail-secret", "[REDACTED]")
}

type recordingLLM struct {
	calls [][]plugin.Message
}

func (m *recordingLLM) Name() string { return "mock" }
func (m *recordingLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	m.calls = append(m.calls, req.Messages)
	return plugin.CompleteResponse{Content: "OK"}, nil
}

func TestCloudTrailConverse_RedactsBeforeLLM(t *testing.T) {
	e := newTestEngine(t)
	store := newTestStore(t)
	s := investigate.NewLogSession("cloudtrail")
	src := s.AddSource(investigate.SourceDesc{Path: "trail.ndjson"})
	s.Append(investigate.LogEvent{At: time.Now().UTC(), Severity: "crit", Unit: "CreateUser",
		Message: "Root called CreateUser — token=sk-cloudtrail-secret",
		Raw:     `{"eventName":"CreateUser","userIdentity":{"type":"Root"},"token":"sk-cloudtrail-secret"}`, Source: src})
	llm := &recordingLLM{}

	_, err := e.Converse(context.Background(), investigate.ConverseReq{
		Scope: "aws", Message: "why did CreateUser happen?",
	}, investigate.Deps{LLM: llm, Red: fakeRedactor{}, Store: store, Facts: s})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	if len(llm.calls) != 1 {
		t.Fatalf("expected exactly one LLM call, got %d", len(llm.calls))
	}
	for _, msg := range llm.calls[0] {
		if strings.Contains(msg.Content, "sk-cloudtrail-secret") {
			t.Fatalf("unredacted secret reached the LLM: %q", msg.Content)
		}
	}
}
