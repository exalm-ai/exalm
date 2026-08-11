package investigate

// engine_test.go — framework mechanics over a TOY profile (no domain
// dependencies): plan dedupe/cap/determinism/cache-marking, cache TTLs and
// bounds, the deterministic fallback's sections, evidence labeling, and the
// one-redacted-LLM-call guarantee.

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/convo"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ── toy domain ──────────────────────────────────────────────────────────────

type toyFacts struct {
	sick bool
}

type toyLLM struct {
	calls [][]plugin.Message
	sys   []string
}

func (m *toyLLM) Name() string { return "toy" }
func (m *toyLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	m.calls = append(m.calls, req.Messages)
	m.sys = append(m.sys, req.System)
	return plugin.CompleteResponse{Content: "toy reply"}, nil
}

type toyRedactor struct{}

func (toyRedactor) Redact(s string) string {
	return strings.ReplaceAll(s, "sk-toy-secret", "[REDACTED]")
}

func toyCollector(kind, source, excerpt string) Collector {
	return func(_ context.Context, cc CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return []plugin.InvestigationStep{{Label: source + " checked", Status: "done"}},
			[]plugin.EvidenceItem{{Kind: kind, Source: source, Excerpt: excerpt}}
	}
}

func toyProfile() Profile {
	return Profile{
		Name: "toy",
		Symptoms: []Symptom{
			{
				Key:   "sickness",
				Match: func(f Facts, _ Target) bool { t, _ := f.(toyFacts); return t.sick },
				Checks: []Check{
					{Collector: "alpha", Reason: "sickness needs alpha", Priority: 1},
					{Collector: "beta", Reason: "sickness needs beta", Priority: 2},
				},
				Causes: []CauseTemplate{
					{Title: "Alpha trouble", Base: 60, For: []EvidenceMatcher{{Kind: "log", Pattern: Re(`boom`), Weight: 20}}},
					{Title: "Beta trouble", Base: 30},
				},
			},
			{
				Key: "catchall", Fallback: true,
				Match:  func(_ Facts, _ Target) bool { return true },
				Checks: []Check{{Collector: "alpha", Reason: "always start at alpha", Priority: 1}},
			},
		},
		Edges: []Edge{{Name: "toy→alpha", Collector: "alpha", Why: "alpha explains toys"}},
		IntentPatterns: append(CommonIntentPatterns(),
			IntentPattern{Intent: "beta-question", Re: Re(`beta`)}),
		IntentChecks: map[string][]Check{
			"beta-question": {{Collector: "beta", Reason: "you asked about beta", Priority: 1}},
			"history":       {{Collector: "history", Reason: "recurrence", Priority: 9}},
		},
		Collectors: map[string]Collector{
			"alpha": toyCollector("log", "alpha", "boom sk-toy-secret"),
			"beta":  toyCollector("metric", "beta", "value=1"),
			"history": func(ctx context.Context, cc CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
				return GatherHistory(ctx, cc.History, cc.Target.Scope, cc.Target.Name, cc.Now)
			},
		},
		ConfidenceRules: []ConfidenceRule{
			{Score: 60, Reason: "log pattern only", Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ Facts) bool {
				return EvidenceMatching(ev, "log", Re(`boom`))
			}},
		},
		Prevention: map[string][]plugin.RemediationAction{
			"sickness": {{Kind: "advice", FixType: "prevention", Description: "Vaccinate the toy"}},
		},
		TTLs:               map[string]time.Duration{"alpha": time.Minute, "beta": time.Second},
		ConversationPrompt: ConversationPromptFor("a toy engineer", ""),
		LogLinePrompt:      LineAnalysisPromptFor("a toy engineer", ""),
		ResolveFocus: func(prev, _, message string, _ Facts) string {
			if strings.Contains(message, "widget") {
				return "factory/widget"
			}
			return prev
		},
	}
}

func newToyEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(toyProfile())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func newTestStore(t *testing.T) convo.Store {
	t.Helper()
	convo.ConversationDir = t.TempDir()
	t.Cleanup(func() { convo.ConversationDir = "" })
	return convo.NewStore()
}

// ── profile validation ──────────────────────────────────────────────────────

func TestProfileValidate(t *testing.T) {
	p := toyProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	bad := toyProfile()
	bad.Symptoms[0].Checks = append(bad.Symptoms[0].Checks, Check{Collector: "ghost"})
	if err := bad.Validate(); err == nil {
		t.Error("unknown collector should fail validation")
	}
	dup := toyProfile()
	dup.Symptoms = append(dup.Symptoms, dup.Symptoms[0])
	if err := dup.Validate(); err == nil {
		t.Error("duplicate symptom key should fail validation")
	}
}

// ── plan mechanics ──────────────────────────────────────────────────────────

func TestPlanPreview_DedupesCapsAndIsDeterministic(t *testing.T) {
	e := newToyEngine(t)
	// symptom wants alpha+beta; intent wants beta again → dedupe.
	plan := e.PlanPreview("check beta", []string{"beta-question"}, "factory/widget", toyFacts{sick: true})
	seen := map[string]int{}
	for _, ps := range plan {
		seen[ps.Collector]++
		if ps.ID == "" || ps.Reason == "" {
			t.Errorf("plan step missing id/reason: %+v", ps)
		}
	}
	if seen["beta"] != 1 || seen["alpha"] != 1 {
		t.Errorf("dedupe failed: %v", seen)
	}
	// Edge attached from the registry.
	for _, ps := range plan {
		if ps.Collector == "alpha" && ps.Edge != "toy→alpha" {
			t.Errorf("alpha edge: %q", ps.Edge)
		}
	}
	// Determinism.
	again := e.PlanPreview("check beta", []string{"beta-question"}, "factory/widget", toyFacts{sick: true})
	if !reflect.DeepEqual(plan, again) {
		t.Error("same input must yield the same plan")
	}
}

func TestPlanPreview_FallbackSymptomOnlyWhenNothingMatches(t *testing.T) {
	e := newToyEngine(t)
	healthy := e.PlanPreview("why?", []string{"general"}, "factory/widget", toyFacts{sick: false})
	if len(healthy) == 0 || healthy[0].Collector != "alpha" {
		t.Errorf("fallback symptom should schedule alpha: %+v", healthy)
	}
	sick := e.profile.MatchSymptoms(toyFacts{sick: true}, Target{})
	if len(sick) != 1 || sick[0].Key != "sickness" {
		t.Errorf("fallback must not match when a specific symptom does: %+v", sick)
	}
}

func TestEngineMaxPlanStepsCap(t *testing.T) {
	p := toyProfile()
	p.MaxPlanSteps = 1
	e, err := NewEngine(p)
	if err != nil {
		t.Fatal(err)
	}
	plan := e.PlanPreview("check beta", []string{"beta-question"}, "f/w", toyFacts{sick: true})
	if len(plan) != 1 {
		t.Errorf("cap not respected: %d steps", len(plan))
	}
}

// ── full turn: labeling, redaction, single call, cache, fallback ───────────

func TestConverse_ToyTurnPipeline(t *testing.T) {
	e := newToyEngine(t)
	store := newTestStore(t)
	llm := &toyLLM{}

	conv, err := e.Converse(context.Background(), ConverseReq{Scope: "factory", Message: "why is the widget sick?"},
		Deps{LLM: llm, Red: toyRedactor{}, Store: store, Facts: toyFacts{sick: true}})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	if len(llm.calls) != 1 {
		t.Fatalf("exactly one LLM call per turn, got %d", len(llm.calls))
	}
	if llm.sys[0] != e.profile.ConversationPrompt {
		t.Error("system prompt must be the profile's conversation prompt")
	}
	enriched := llm.calls[0][len(llm.calls[0])-1].Content
	if strings.Contains(enriched, "sk-toy-secret") {
		t.Fatal("SECRET LEAKED to the LLM")
	}
	if !strings.Contains(enriched, "[REDACTED]") {
		t.Error("expected redaction markers in the enriched turn")
	}
	m := conv.Messages[len(conv.Messages)-1]
	for i, ev := range m.Evidence {
		want := "E" + string(rune('0'+i+1))
		if i < 9 && ev.Label != want {
			t.Errorf("evidence %d label: %q", i, ev.Label)
		}
	}
	if len(m.Hypotheses) == 0 || m.Hypotheses[0].Title != "Alpha trouble" {
		t.Errorf("hypotheses: %+v", m.Hypotheses)
	}
	if m.Score < 60 || m.Confidence == "" {
		t.Errorf("score/tier: %d %q", m.Score, m.Confidence)
	}
	if len(m.Prevention) != 1 {
		t.Errorf("prevention: %+v", m.Prevention)
	}
	if conv.Fingerprint != "sickness\x1ffactory/widget" {
		t.Errorf("fingerprint: %q", conv.Fingerprint)
	}

	// Turn 2 within TTL: alpha served from cache.
	conv2, err := e.Converse(context.Background(), ConverseReq{ConvoID: conv.ID, Scope: "factory", Message: "why is the widget sick?"},
		Deps{LLM: llm, Red: toyRedactor{}, Store: store, Facts: toyFacts{sick: true}})
	if err != nil {
		t.Fatalf("turn 2: %v", err)
	}
	m2 := conv2.Messages[len(conv2.Messages)-1]
	alphaCached := false
	for _, ps := range m2.Plan {
		if ps.Collector == "alpha" && ps.FromCache {
			alphaCached = true
		}
	}
	if !alphaCached {
		t.Errorf("alpha should be cached on turn 2: %+v", m2.Plan)
	}

	// Turn 3: refresh bypasses the cache.
	conv3, err := e.Converse(context.Background(), ConverseReq{ConvoID: conv.ID, Scope: "factory", Message: "refresh everything"},
		Deps{LLM: llm, Red: toyRedactor{}, Store: store, Facts: toyFacts{sick: true}})
	if err != nil {
		t.Fatalf("turn 3: %v", err)
	}
	for _, ps := range conv3.Messages[len(conv3.Messages)-1].Plan {
		if ps.FromCache {
			t.Errorf("refresh must bypass the cache: %+v", ps)
		}
	}
}

// The transcript is written to disk/SQLite and re-rendered in exports, so the
// user's own turn must be stored redacted — synthesizeReply only redacts the
// copy handed to the LLM. Documented contract: engine.go's package comment and
// convo.Store ("only the message transcript (already redacted) persists").
func TestConverse_PersistedTranscriptIsRedacted(t *testing.T) {
	e := newToyEngine(t)
	store := newTestStore(t)

	conv, err := e.Converse(context.Background(),
		ConverseReq{Scope: "factory", Message: "why is the widget sick? token=sk-toy-secret"},
		Deps{LLM: &toyLLM{}, Red: toyRedactor{}, Store: store, Facts: toyFacts{sick: true}})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}

	var user plugin.ConversationMessage
	for _, m := range conv.Messages {
		if m.Role == "user" {
			user = m
			break
		}
	}
	if user.Content == "" {
		t.Fatal("no user turn recorded")
	}
	if strings.Contains(user.Content, "sk-toy-secret") {
		t.Errorf("SECRET PERSISTED in the returned transcript: %q", user.Content)
	}
	if !strings.Contains(user.Content, "[REDACTED]") {
		t.Errorf("user turn should carry a redaction marker, got %q", user.Content)
	}

	// And it must be redacted at rest, not just in the returned value.
	stored, err := store.Get(context.Background(), conv.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, m := range stored.Messages {
		if strings.Contains(m.Content, "sk-toy-secret") {
			t.Errorf("SECRET PERSISTED AT REST in %s turn: %q", m.Role, m.Content)
		}
	}
}

// Collectors are not trusted to redact their own excerpts — the engine redacts
// at the collection chokepoint so a collector that forgets (the "alpha" toy
// collector here, mirroring k8s previous-logs) still cannot leak a raw secret
// into the persisted transcript, the browser, or an exported report.
func TestConverse_EvidenceExcerptsRedactedAtChokepoint(t *testing.T) {
	e := newToyEngine(t)
	store := newTestStore(t)

	conv, err := e.Converse(context.Background(),
		ConverseReq{Scope: "factory", Message: "why is the widget sick?"},
		Deps{LLM: &toyLLM{}, Red: toyRedactor{}, Store: store, Facts: toyFacts{sick: true}})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}

	last := conv.Messages[len(conv.Messages)-1]
	var sawAlpha bool
	for _, ev := range last.Evidence {
		if ev.Source == "alpha" {
			sawAlpha = true
			if strings.Contains(ev.Excerpt, "sk-toy-secret") {
				t.Errorf("SECRET LEAKED in evidence excerpt: %q", ev.Excerpt)
			}
			if !strings.Contains(ev.Excerpt, "[REDACTED]") {
				t.Errorf("excerpt should carry a redaction marker, got %q", ev.Excerpt)
			}
		}
	}
	if !sawAlpha {
		t.Fatal("expected evidence from the un-redacting alpha collector")
	}
}

func TestConverse_NilLLMFallbackSections(t *testing.T) {
	e := newToyEngine(t)
	store := newTestStore(t)
	conv, err := e.Converse(context.Background(), ConverseReq{Scope: "factory", Message: "why is the widget sick?"},
		Deps{Red: toyRedactor{}, Store: store, Facts: toyFacts{sick: true}})
	if err != nil {
		t.Fatalf("Converse: %v", err)
	}
	content := conv.Messages[len(conv.Messages)-1].Content
	for _, want := range []string{"**Root cause**", "Alpha trouble", "**Prevention**", "confidence"} {
		if !strings.Contains(content, want) {
			t.Errorf("fallback missing %q:\n%s", want, content)
		}
	}
}

// ── evidence cache unit behavior (ported from plugins/k8s) ─────────────────

func cacheEntry(label string, at time.Time) cachedEvidence {
	return cachedEvidence{
		Steps:    []plugin.InvestigationStep{{Label: label, Status: "done"}},
		Evidence: []plugin.EvidenceItem{{Kind: "config", Source: label}},
		At:       at,
	}
}

func TestEvidenceCache_TTLAndScoping(t *testing.T) {
	c := newEvidenceCache(map[string]time.Duration{"fast": time.Second, "slow": time.Hour})
	now := time.Now()
	c.put("c1", "slow", "t", cacheEntry("x", now), now)
	c.put("c1", "fast", "t", cacheEntry("y", now), now)

	if _, ok := c.get("c1", "slow", "t", now.Add(time.Minute)); !ok {
		t.Error("slow entry should still be fresh")
	}
	if _, ok := c.get("c1", "fast", "t", now.Add(time.Minute)); ok {
		t.Error("fast entry should have expired")
	}
	if _, ok := c.get("c2", "slow", "t", now); ok {
		t.Error("cache must be scoped per conversation")
	}
	// Unknown collector gets the 5m default.
	c.put("c1", "other", "t", cacheEntry("z", now), now)
	if _, ok := c.get("c1", "other", "t", now.Add(6*time.Minute)); ok {
		t.Error("default TTL should be 5 minutes")
	}
}

func TestEvidenceCache_PurgeCapsNilSafety(t *testing.T) {
	c := newEvidenceCache(nil)
	now := time.Now()
	c.put("idle", "k", "t", cacheEntry("x", now), now)
	c.purge(now.Add(evidCacheIdleTTL + time.Minute))
	if _, ok := c.get("idle", "k", "t", now.Add(evidCacheIdleTTL+time.Minute)); ok {
		t.Error("idle conversation should be purged")
	}

	for i := 0; i < evidCacheMaxConvos+1; i++ {
		id := string(rune('a'+i%26)) + string(rune('a'+i/26))
		c.put(id, "k", "t", cacheEntry("x", now), now.Add(time.Duration(i)*time.Second))
	}
	c.mu.Lock()
	n := len(c.convos)
	c.mu.Unlock()
	if n > evidCacheMaxConvos {
		t.Errorf("conversation cap exceeded: %d", n)
	}
	for i := 0; i < evidCacheMaxEntries+5; i++ {
		c.put("one", "k", string(rune('A'+i%26))+string(rune('A'+i/26)), cacheEntry("x", now), now)
	}
	c.mu.Lock()
	ne := len(c.convos["one"].entries)
	c.mu.Unlock()
	if ne > evidCacheMaxEntries {
		t.Errorf("entry cap exceeded: %d", ne)
	}

	var nilCache *evidenceCache
	nilCache.put("c", "k", "t", cachedEvidence{}, now) // must not panic
	nilCache.purge(now)
	if nilCache.has("c", "k", "t", now) {
		t.Error("nil cache should never report has")
	}
}

// ── hypotheses + confidence mechanics ───────────────────────────────────────

func TestRankHypotheses_ForAgainstAndCap(t *testing.T) {
	syms := []Symptom{{
		Key: "s",
		Causes: []CauseTemplate{
			{Title: "Supported", Base: 40, For: []EvidenceMatcher{{Kind: "log", Pattern: Re(`boom`), Weight: 30}}},
			{Title: "Refuted", Base: 40, Against: []EvidenceMatcher{{Kind: "log", Pattern: Re(`boom`), Weight: 30}}},
			{Title: "C3", Base: 10}, {Title: "C4", Base: 9}, {Title: "C5", Base: 8},
		},
	}}
	ev := LabelEvidence([]plugin.EvidenceItem{{Kind: "log", Source: "p", Excerpt: "boom"}})
	hyps := RankHypotheses(syms, ev)
	if len(hyps) > MaxHypotheses {
		t.Errorf("cap exceeded: %d", len(hyps))
	}
	if hyps[0].Title != "Supported" || hyps[0].Score != 70 {
		t.Errorf("top: %+v", hyps[0])
	}
	if hyps[0].EvidenceFor[0] != "E1" {
		t.Errorf("for labels: %+v", hyps[0].EvidenceFor)
	}
	for _, h := range hyps {
		if h.Title == "Refuted" && (h.Score != 10 || len(h.EvidenceAgainst) == 0) {
			t.Errorf("refuted: %+v", h)
		}
		if h.Rationale == "" {
			t.Errorf("rationale missing: %+v", h)
		}
	}
}

func TestScoreConfidence_MechanicsAndTier(t *testing.T) {
	rules := []ConfidenceRule{
		{Score: 45, Reason: "metrics only", Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ Facts) bool {
			return EvidenceMatching(ev, "metric", Re(`.`))
		}},
	}
	// Modeled metrics deduction.
	score, rationale := ScoreConfidence(rules, []plugin.EvidenceItem{{Kind: "metric", Source: "m", Excerpt: "x (modeled)"}}, nil, nil)
	if score != 30 || !strings.Contains(rationale, "modeled") {
		t.Errorf("modeled deduction: %d %q", score, rationale)
	}
	// Corroboration bonus across kinds.
	score2, _ := ScoreConfidence(rules, []plugin.EvidenceItem{
		{Kind: "metric", Source: "m", Excerpt: "x"},
		{Kind: "log", Source: "l", Excerpt: "y"},
		{Kind: "event", Source: "e", Excerpt: "z"},
	}, nil, nil)
	if score2 != 45+4 {
		t.Errorf("corroboration: %d", score2)
	}
	// Floor.
	if s, _ := ScoreConfidence(rules, nil, nil, nil); s != 10 {
		t.Errorf("floor: %d", s)
	}
	// Tiers.
	if TierFor(75) != "high" || TierFor(45) != "medium" || TierFor(44) != "low" {
		t.Error("tier mapping broken")
	}
}
