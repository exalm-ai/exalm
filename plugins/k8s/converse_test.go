package k8s

import (
	"context"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/internal/convo"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// chatRecordingLLM records every Complete() call's full message slice (unlike
// investigate_test.go's recordingLLM, which only keeps Messages[0] — fine for
// investigate.go's always-single-message calls, but Converse() needs the
// full multi-turn history visible for assertions).
type chatRecordingLLM struct {
	calls   [][]plugin.Message
	replies []string // dequeued in order; last reply repeats once exhausted
}

func (m *chatRecordingLLM) Name() string { return "mock" }
func (m *chatRecordingLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	m.calls = append(m.calls, req.Messages)
	reply := "OK"
	if len(m.replies) > 0 {
		idx := len(m.calls) - 1
		if idx < len(m.replies) {
			reply = m.replies[idx]
		} else {
			reply = m.replies[len(m.replies)-1]
		}
	}
	return plugin.CompleteResponse{Content: reply}, nil
}

func newTestConvoStore(t *testing.T) convo.Store {
	t.Helper()
	convo.ConversationDir = t.TempDir()
	t.Cleanup(func() { convo.ConversationDir = "" })
	return convo.NewStore()
}

func crashPod(ns, name string) PodSummary {
	return PodSummary{
		Namespace: ns, Name: name, Phase: "Running", Reason: "CrashLoopBackOff", RestartCount: 12,
		LogTails: []LogTail{{Container: "app", Lines: "panic: boom token=sk-secret"}},
	}
}

// ── intent classification ───────────────────────────────────────────────────

func TestClassifyIntent_Table(t *testing.T) {
	cases := []struct {
		message string
		want    string
	}{
		{"show me the previous logs", "previous-logs"},
		{"was this caused by the last deployment?", "deploy-correlation"},
		{"compare with yesterday", "comparison"},
		{"could this be related to the database?", "db-connectivity"},
		{"is memory the real problem?", "resource-usage"},
		{"check node resource pressure", "node-pressure"},
		{"check the configmap", "configmap"},
		{"check the secret", "secret"},
		{"is this a dns issue?", "dns"},
		{"show me the timeline", "timeline"},
		{"generate an rca", "rca"},
		{"which service depends on this pod?", "related-services"},
		{"why am I getting 503s on ingress?", "ingress"},
		{"why is this happening", "general"},
	}
	for _, tc := range cases {
		got := classifyIntent(tc.message)
		found := false
		for _, g := range got {
			if g == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("classifyIntent(%q) = %v, want to contain %q", tc.message, got, tc.want)
		}
	}
}

// ── redaction-before-LLM (the critical trust-model guard) ───────────────────

func TestConverse_RedactsBeforeLLM(t *testing.T) {
	p := New()
	p.setLastSnapshot(Snapshot{UnhealthyPods: []PodSummary{crashPod("prod", "payment-api")}})
	store := newTestConvoStore(t)
	llm := &chatRecordingLLM{}

	conv, err := p.Converse(context.Background(), "", "", "prod", "Why is payment-api crashing?", llm, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	if conv == nil || len(conv.Messages) != 2 {
		t.Fatalf("expected 2 messages (user+assistant), got %+v", conv)
	}
	if len(llm.calls) != 1 {
		t.Fatalf("expected exactly 1 LLM call per turn, got %d", len(llm.calls))
	}
	sent := llm.calls[0]
	for _, m := range sent {
		if strings.Contains(m.Content, "sk-secret") {
			t.Fatalf("raw secret leaked to the LLM in a %s message:\n%s", m.Role, m.Content)
		}
	}
	last := sent[len(sent)-1]
	if !strings.Contains(last.Content, "[REDACTED]") {
		t.Errorf("expected the redacted marker in the enriched turn, got: %s", last.Content)
	}
}

func TestConverse_NilLLMFallsBackDeterministically(t *testing.T) {
	p := New()
	p.setLastSnapshot(Snapshot{UnhealthyPods: []PodSummary{crashPod("prod", "payment-api")}})
	store := newTestConvoStore(t)

	conv, err := p.Converse(context.Background(), "", "", "prod", "Why is payment-api crashing?", nil, nil, store, nil)
	if err != nil {
		t.Fatalf("Converse (nil llm): %v", err)
	}
	last := conv.Messages[len(conv.Messages)-1]
	if strings.TrimSpace(last.Content) == "" {
		t.Error("nil LLM should still yield a non-empty deterministic reply")
	}
}

// ── multi-turn history + focus resolution (pronoun-style follow-ups) ───────

func TestConverse_MultiTurn_FocusPersistsAcrossFollowUps(t *testing.T) {
	p := New()
	p.setLastSnapshot(Snapshot{UnhealthyPods: []PodSummary{crashPod("prod", "payment-api")}})
	store := newTestConvoStore(t)
	llm := &chatRecordingLLM{replies: []string{"first reply", "second reply"}}
	red := fakeRedactor{}

	first, err := p.Converse(context.Background(), "", "", "prod", "Why is payment-api crashing?", llm, red, store, nil)
	if err != nil {
		t.Fatalf("first turn: %v", err)
	}
	if first.Focus != "prod/payment-api" {
		t.Fatalf("expected focus to resolve to prod/payment-api, got %q", first.Focus)
	}

	// Follow-up names no pod at all — focus must carry over from turn 1.
	second, err := p.Converse(context.Background(), first.ID, "", "prod", "Show me the previous logs.", llm, red, store, nil)
	if err != nil {
		t.Fatalf("second turn: %v", err)
	}
	if second.Focus != "prod/payment-api" {
		t.Fatalf("expected focus to persist as prod/payment-api on follow-up, got %q", second.Focus)
	}
	if len(second.Messages) != 4 {
		t.Fatalf("expected 4 messages after 2 turns, got %d", len(second.Messages))
	}

	// The second LLM call's history must include turn 1's exchange, not just
	// the new question — that's what makes "the previous logs" resolvable.
	if len(llm.calls) != 2 {
		t.Fatalf("expected 2 LLM calls, got %d", len(llm.calls))
	}
	secondCallMsgs := llm.calls[1]
	if len(secondCallMsgs) < 3 {
		t.Fatalf("expected turn 2's call to carry turn 1's history (>= 3 messages), got %d", len(secondCallMsgs))
	}
	foundFirstQuestion := false
	for _, m := range secondCallMsgs[:len(secondCallMsgs)-1] {
		if strings.Contains(m.Content, "Why is payment-api crashing") {
			foundFirstQuestion = true
		}
	}
	if !foundFirstQuestion {
		t.Error("expected turn 1's question to still be present in turn 2's message history")
	}
}

func TestConverse_PersistsAcrossInvocations(t *testing.T) {
	p := New()
	p.setLastSnapshot(Snapshot{UnhealthyPods: []PodSummary{crashPod("prod", "payment-api")}})
	store := newTestConvoStore(t)
	llm := &chatRecordingLLM{}

	first, err := p.Converse(context.Background(), "", "", "prod", "Why is payment-api crashing?", llm, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("first turn: %v", err)
	}

	got, err := store.Get(context.Background(), first.ID)
	if err != nil {
		t.Fatalf("Get after Converse: %v", err)
	}
	if len(got.Messages) != 2 {
		t.Errorf("expected the persisted conversation to have 2 messages, got %d", len(got.Messages))
	}
}

// ── deterministic follow-up suggestions (no second LLM call) ────────────────

func TestSuggestFollowUps_DoesNotRepeatWhatWasJustChecked(t *testing.T) {
	pod := crashPod("prod", "payment-api")
	pod.HasNoLimits = true
	steps := []plugin.InvestigationStep{{Label: "x", Status: "done"}}

	withResourceIntent := suggestFollowUps([]string{"resource-usage"}, &pod, steps)
	for _, s := range withResourceIntent {
		if s == "Investigate memory usage" {
			t.Error("should not suggest re-checking memory usage when this turn already did")
		}
	}

	withoutResourceIntent := suggestFollowUps([]string{"general"}, &pod, steps)
	found := false
	for _, s := range withoutResourceIntent {
		if s == "Investigate memory usage" {
			found = true
		}
	}
	if !found {
		t.Error("expected a memory-usage suggestion when the pod has no limits and it wasn't checked this turn")
	}
}

func TestResolveFocus_ExplicitMentionOverridesPriorFocus(t *testing.T) {
	snap := Snapshot{UnhealthyPods: []PodSummary{crashPod("prod", "payment-api"), crashPod("prod", "order-service")}}
	got := resolveFocus("prod/payment-api", "", "is order-service also affected?", snap)
	if got != "prod/order-service" {
		t.Errorf("expected an explicit mention to switch focus, got %q", got)
	}
}

func TestResolveFocus_KeepsPriorFocusWhenNothingMentioned(t *testing.T) {
	snap := Snapshot{UnhealthyPods: []PodSummary{crashPod("prod", "payment-api")}}
	got := resolveFocus("prod/payment-api", "", "is this related to the database?", snap)
	if got != "prod/payment-api" {
		t.Errorf("expected focus to persist when nothing new is mentioned, got %q", got)
	}
}

// ─── copilot turn context: citations, plan, hypotheses in the prompt ────────

func TestConverse_PromptCarriesPlanHypothesesAndCitations(t *testing.T) {
	p := New()
	p.setLastSnapshot(Snapshot{UnhealthyPods: []PodSummary{crashPod("prod", "payment-api")}})
	store := newTestConvoStore(t)
	llm := &chatRecordingLLM{}

	conv, err := p.Converse(context.Background(), "", "", "prod", "Why is payment-api crashing?", llm, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	if len(llm.calls) != 1 {
		t.Fatalf("expected exactly 1 LLM call, got %d", len(llm.calls))
	}
	enriched := llm.calls[0][len(llm.calls[0])-1].Content
	for _, want := range []string{"INVESTIGATION PLAN EXECUTED:", "HYPOTHESES", "CONFIDENCE:", "[E1]"} {
		if !strings.Contains(enriched, want) {
			t.Errorf("enriched turn missing %q:\n%s", want, truncateString(enriched, 1200))
		}
	}
	last := conv.Messages[len(conv.Messages)-1]
	if last.Score <= 0 || last.ScoreRationale == "" {
		t.Errorf("assistant message should carry a numeric score + rationale, got %d %q", last.Score, last.ScoreRationale)
	}
	if len(last.Hypotheses) == 0 {
		t.Error("assistant message should carry ranked hypotheses")
	}
	if len(last.Prevention) == 0 {
		t.Error("assistant message should carry prevention actions for a crashloop")
	}
	if len(last.Plan) == 0 {
		t.Error("assistant message should carry the executed plan")
	}
	for _, e := range last.Evidence {
		if e.Label == "" {
			t.Errorf("every evidence item must carry a citation label: %+v", e)
		}
	}
}
