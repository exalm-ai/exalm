package k8s

// converse_golden_test.go is the CHARACTERIZATION GATE for extracting the
// generic investigation framework: it pins the full observable output of the
// current per-turn pipeline (plan, evidence labels, hypotheses, confidence,
// prevention, suggestions, deterministic reply, fingerprint, cache behavior)
// across three scripted turns. The framework refactor must keep every
// assertion here passing WITHOUT edits — any change to this file during the
// extraction means behavior changed.

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// goldenFixture builds a deterministic plugin state: an OOMKilled pod backed
// by a live fake clientset (so owner-chain/configmaps collectors run), no
// LLM, no metrics provider.
func goldenFixture(t *testing.T) (*Plugin, func() []int) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "payment-api", Namespace: "prod",
			Labels:          map[string]string{"app": "payment-api"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "payment-api-7d8", Controller: boolPtr(true)}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry.example.com/payment-api:v2"}}},
	}
	cs := fake.NewSimpleClientset(pod)
	p := New()
	p.newLogFetcher = func(kubernetes.Interface) logFetcher {
		return &fakeLogFetcher{logs: map[string]string{"prod/payment-api/": "previous run: OOMKilled after allocation spike"}}
	}
	p.setLastClient(cs)
	p.setLastSnapshot(Snapshot{
		UnhealthyPods: []PodSummary{{
			Namespace: "prod", Name: "payment-api", Phase: "Running", Reason: "OOMKilled", RestartCount: 7,
			LogTails: []LogTail{{Container: "app", Lines: "fatal: out of memory"}},
		}},
		Events: []EventSummary{{
			Namespace: "prod", PodName: "payment-api", Reason: "OOMKilling",
			Message: "Memory cgroup out of memory: Killed process 1234", Count: 3,
		}},
	})
	actionCount := func() []int { return []int{len(cs.Fake.Actions())} }
	return p, actionCount
}

func TestGolden_ConverseThreeTurnPipeline(t *testing.T) {
	p, actions := goldenFixture(t)
	store := newTestConvoStore(t)
	ctx := context.Background()

	// ── Turn 1: open question → symptom-driven plan, history auto-check ──
	c1, err := p.Converse(ctx, "", "", "prod", "Why is payment-api failing?", nil, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("turn 1: %v", err)
	}
	m1 := c1.Messages[len(c1.Messages)-1]

	// Focus + fingerprint.
	if c1.Focus != "prod/payment-api" {
		t.Errorf("focus: %q", c1.Focus)
	}
	if c1.Fingerprint != "oom-killed\x1fprod/payment-api" {
		t.Errorf("fingerprint: %q", c1.Fingerprint)
	}

	// Plan: the OOM symptom's ordered collector set + the auto history check,
	// deduped, priority-sorted (stable), with edges + per-step reasons. This
	// exact order is the deterministic contract.
	wantCollectors := []string{"owner-chain", "history", "metrics", "change-history", "node-detail", "scaling"}
	var gotCollectors []string
	for _, ps := range m1.Plan {
		gotCollectors = append(gotCollectors, ps.Collector)
		if ps.ID == "" || ps.Reason == "" {
			t.Errorf("plan step missing id/reason: %+v", ps)
		}
		if ps.Status != "done" && ps.Status != "unavailable" {
			t.Errorf("plan step %s: unexpected status %q", ps.Collector, ps.Status)
		}
	}
	if strings.Join(gotCollectors, ",") != strings.Join(wantCollectors, ",") {
		t.Errorf("plan collectors:\n got %v\nwant %v", gotCollectors, wantCollectors)
	}
	for _, ps := range m1.Plan {
		if ps.Collector == "owner-chain" && ps.Edge != "pod→ownerDeployment" {
			t.Errorf("owner-chain edge: %q", ps.Edge)
		}
	}

	// Evidence: labeled E1..En in order, first items from the pod baseline.
	if len(m1.Evidence) == 0 {
		t.Fatal("no evidence gathered")
	}
	for i, e := range m1.Evidence {
		want := "E" + itoaTest(i+1)
		if e.Label != want {
			t.Errorf("evidence %d label: got %q want %q", i, e.Label, want)
		}
	}

	// Confidence: explicit terminal state (OOMKilled) → 95 + corroboration,
	// capped ≤98, tier high.
	if m1.Score < 95 || m1.Score > 98 {
		t.Errorf("score: %d (rationale %q)", m1.Score, m1.ScoreRationale)
	}
	if m1.Confidence != "high" {
		t.Errorf("tier: %q", m1.Confidence)
	}
	if !strings.Contains(m1.ScoreRationale, "terminal state") {
		t.Errorf("rationale: %q", m1.ScoreRationale)
	}

	// Hypotheses: memory-limit cause ranked first with evidence-for labels.
	if len(m1.Hypotheses) == 0 {
		t.Fatal("no hypotheses")
	}
	if !strings.Contains(strings.ToLower(m1.Hypotheses[0].Title), "memory limit") {
		t.Errorf("top hypothesis: %q", m1.Hypotheses[0].Title)
	}
	if len(m1.Hypotheses) > maxHypotheses {
		t.Errorf("hypotheses over cap: %d", len(m1.Hypotheses))
	}

	// Prevention: the OOM prevention advice, copy-only.
	if len(m1.Prevention) == 0 || m1.Prevention[0].FixType != "prevention" || m1.Prevention[0].Kind != "advice" {
		t.Errorf("prevention: %+v", m1.Prevention)
	}

	// Deterministic reply (nil LLM): sectioned, cites the top hypothesis.
	for _, want := range []string{"**Root cause**", "[E", "confidence " + itoaTest(m1.Score) + "%", "**Prevention**"} {
		if !strings.Contains(m1.Content, want) {
			t.Errorf("deterministic reply missing %q:\n%s", want, m1.Content)
		}
	}

	// Suggestions exist and are bounded.
	if len(m1.Suggestions) == 0 || len(m1.Suggestions) > 5 {
		t.Errorf("suggestions: %v", m1.Suggestions)
	}

	// ── Turn 2: repeat within TTL → done collectors served from cache. ──
	// Characterized nuance: collectors that came back "unavailable" on turn 1
	// (here node-detail — the pod has no NodeName) are NOT cached, so their
	// cheap failed probe repeats. Exactly one extra API action is allowed.
	before := actions()[0]
	c2, err := p.Converse(ctx, c1.ID, "", "prod", "Why is payment-api failing?", nil, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("turn 2: %v", err)
	}
	if got := actions()[0]; got > before+1 {
		t.Errorf("turn 2 should serve done collectors from cache: API actions %d → %d", before, got)
	}
	m2 := c2.Messages[len(c2.Messages)-1]
	fromCache := map[string]bool{}
	for _, ps := range m2.Plan {
		fromCache[ps.Collector] = ps.FromCache
	}
	for _, c := range []string{"owner-chain", "scaling"} {
		if !fromCache[c] {
			t.Errorf("turn 2: %s should be served from cache, plan=%+v", c, m2.Plan)
		}
	}
	// Evidence relabeled consistently on the cached turn too.
	for i, e := range m2.Evidence {
		if e.Label != "E"+itoaTest(i+1) {
			t.Errorf("turn-2 evidence %d label: %q", i, e.Label)
		}
	}

	// ── Turn 3: explicit refresh → cache bypassed, API called again ──
	c3, err := p.Converse(ctx, c1.ID, "", "prod", "refresh and re-check everything", nil, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("turn 3: %v", err)
	}
	if got := actions()[0]; got == before {
		t.Error("refresh turn must re-collect (API actions should grow)")
	}
	m3 := c3.Messages[len(c3.Messages)-1]
	for _, ps := range m3.Plan {
		if ps.FromCache {
			t.Errorf("refresh turn must not serve from cache: %+v", ps)
		}
	}

	// Transcript persisted: 6 messages (3 user + 3 assistant), same convo.
	final, err := store.Get(ctx, c1.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if len(final.Messages) != 6 {
		t.Errorf("persisted messages: %d", len(final.Messages))
	}
}

// TestGolden_ConverseLLMPromptShape pins the enriched-turn sections and the
// single-call + full-redaction guarantees with an LLM wired.
func TestGolden_ConverseLLMPromptShape(t *testing.T) {
	p, _ := goldenFixture(t)
	store := newTestConvoStore(t)
	llm := &chatRecordingLLM{replies: []string{"synthesized"}}

	_, err := p.Converse(context.Background(), "", "", "prod", "Why is payment-api failing?", llm, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	if len(llm.calls) != 1 {
		t.Fatalf("exactly one LLM call per turn, got %d", len(llm.calls))
	}
	enriched := llm.calls[0][len(llm.calls[0])-1].Content
	for _, section := range []string{
		"QUESTION: Why is payment-api failing?",
		"FOCUS RESOURCE: prod/payment-api",
		"INVESTIGATION PLAN EXECUTED:",
		"CHECKS PERFORMED THIS TURN:",
		"EVIDENCE:",
		"- [E1]",
		"HYPOTHESES (deterministic ranking",
		"CONFIDENCE:",
		"PREVENTION:",
	} {
		if !strings.Contains(enriched, section) {
			t.Errorf("enriched turn missing %q", section)
		}
	}
}

// itoaTest is a tiny local int→string helper so the golden file has no
// dependency on the code under test beyond the public surface.
func itoaTest(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoaTest(n/10) + string(rune('0'+n%10))
}
