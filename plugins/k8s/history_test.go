package k8s

// history_test.go — recurrence evidence from prior conversations, the
// decoupled incident source, and fingerprint matching.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/convo"
	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func seedPriorConversation(t *testing.T, store convo.Store, id, focus, ns, fingerprint, conclusion string, at time.Time) {
	t.Helper()
	err := store.Create(context.Background(), plugin.Conversation{
		ID: id, Namespace: ns, Focus: focus, Fingerprint: fingerprint,
		CreatedAt: at, UpdatedAt: at,
		Messages: []plugin.ConversationMessage{
			{Role: "user", Content: "why is it crashing?", At: at},
			{Role: "assistant", Content: conclusion, At: at},
		},
	})
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
}

func TestGatherHistory_PriorConversationAndFingerprint(t *testing.T) {
	store := newTestConvoStore(t)
	past := time.Now().Add(-48 * time.Hour)
	seedPriorConversation(t, store, "old-1", "prod/payment-api", "prod",
		"oom-killed\x1fprod/payment-api", "Memory limit too low — raised to 512Mi.", past)

	steps, evid := investigate.GatherHistory(context.Background(), investigate.HistoryDeps{
		Sources: investigate.HistorySources{Convo: store}, SelfID: "current-1",
		Focus: "prod/payment-api", Fingerprint: "oom-killed\x1fprod/payment-api",
	}, "prod", "payment-api", time.Now())

	if len(steps) != 1 || steps[0].Status != "done" {
		t.Fatalf("steps: %+v", steps)
	}
	if len(evid) == 0 {
		t.Fatal("expected history evidence from the prior conversation")
	}
	dump := evid[0].Excerpt
	if !strings.Contains(dump, "investigated 1 time(s) before") {
		t.Errorf("expected recurrence count, got %q", dump)
	}
	if !strings.Contains(dump, "Memory limit too low") {
		t.Errorf("expected the prior conclusion, got %q", dump)
	}
	if !strings.Contains(dump, "SAME symptom") {
		t.Errorf("matching fingerprint should be flagged as recurring, got %q", dump)
	}
	if evid[0].Kind != "history" {
		t.Errorf("kind: %q", evid[0].Kind)
	}
}

func TestGatherHistory_ExcludesCurrentConversation(t *testing.T) {
	store := newTestConvoStore(t)
	seedPriorConversation(t, store, "current-1", "prod/payment-api", "prod", "", "in progress", time.Now())

	_, evid := investigate.GatherHistory(context.Background(), investigate.HistoryDeps{
		Sources: investigate.HistorySources{Convo: store}, SelfID: "current-1", Focus: "prod/payment-api",
	}, "prod", "payment-api", time.Now())
	for _, e := range evid {
		if strings.Contains(e.Excerpt, "investigated") {
			t.Errorf("the current conversation must not count as prior history: %q", e.Excerpt)
		}
	}
}

func TestGatherHistory_IncidentSourceWithResolution(t *testing.T) {
	now := time.Now()
	incFn := func(_ context.Context, from, to time.Time) ([]PastIncident, error) {
		return []PastIncident{
			{Title: "payment-api OOM storm", Namespace: "prod", Service: "payment-api",
				Status: "closed", OpenedAt: now.Add(-7 * 24 * time.Hour),
				Resolution: "Raised memory limit to 512Mi and added burn-rate alert."},
			{Title: "unrelated", Namespace: "staging", Service: "other", OpenedAt: now.Add(-time.Hour)},
		}, nil
	}
	_, evid := investigate.GatherHistory(context.Background(), investigate.HistoryDeps{
		Sources: investigate.HistorySources{Incidents: incFn}, Focus: "prod/payment-api-7d8-xkp",
	}, "prod", "payment-api-7d8-xkp", now)

	found := false
	for _, e := range evid {
		if strings.Contains(e.Excerpt, "1 incident(s)") && strings.Contains(e.Excerpt, "Raised memory limit") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the matching incident with its resolution, got %+v", evid)
	}
}

func TestConverse_FirstTurnChecksHistoryAutomatically(t *testing.T) {
	p := New()
	p.setLastSnapshot(Snapshot{UnhealthyPods: []PodSummary{crashPod("prod", "payment-api")}})
	store := newTestConvoStore(t)

	conv, err := p.Converse(context.Background(), "", "", "prod", "Why is payment-api crashing?", nil, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	last := conv.Messages[len(conv.Messages)-1]
	foundHistoryStep := false
	for _, ps := range last.Plan {
		if ps.Collector == "history" {
			foundHistoryStep = true
		}
	}
	if !foundHistoryStep {
		t.Errorf("the first turn should plan a history check automatically, plan=%+v", last.Plan)
	}
	if conv.Fingerprint == "" {
		t.Error("a matched symptom should set the conversation fingerprint")
	}
}
