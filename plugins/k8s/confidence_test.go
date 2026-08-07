package k8s

// confidence_test.go — table-driven tests for the evidence-quality scoring
// table, the tier mapping, and the deterministic hypothesis ranking.

import (
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// maxHypotheses keeps the golden characterization test compiling unchanged
// now that the cap lives in the framework.
const maxHypotheses = investigate.MaxHypotheses

func TestScoreConfidence_Table(t *testing.T) {
	oom := &PodSummary{Reason: "OOMKilled"}
	cases := []struct {
		name     string
		evidence []plugin.EvidenceItem
		pod      *PodSummary
		wantMin  int
		wantMax  int
		tier     string
	}{
		{
			name:    "explicit terminal state scores ~95",
			pod:     oom,
			wantMin: 95, wantMax: 98, tier: "high",
		},
		{
			name: "probe failure with matching events scores ~90",
			evidence: []plugin.EvidenceItem{
				{Kind: "event", Source: "pod/x", Excerpt: "Unhealthy: readiness probe failed"},
				{Kind: "config", Source: "deployment/x", Excerpt: "probes: app readiness (initialDelay=5s)"},
			},
			wantMin: 90, wantMax: 98, tier: "high",
		},
		{
			name: "recent change scores ~85",
			evidence: []plugin.EvidenceItem{
				{Kind: "change", Source: "Deployment/x", Excerpt: "updated by ci-bot, 12m ago"},
			},
			wantMin: 85, wantMax: 98, tier: "high",
		},
		{
			name: "log pattern only scores ~60",
			evidence: []plugin.EvidenceItem{
				{Kind: "log", Source: "pod/x", Excerpt: "ERROR: connection reset"},
			},
			wantMin: 60, wantMax: 74, tier: "medium",
		},
		{
			name: "modeled metrics only scores ~30 (45 - 15)",
			evidence: []plugin.EvidenceItem{
				{Kind: "metric", Source: "findings-activity", Excerpt: "latest=3.0 threshold=5.0 (modeled — no real metrics backend wired)"},
			},
			wantMin: 25, wantMax: 44, tier: "low",
		},
		{
			name:    "nothing gathered floors at 10",
			wantMin: 10, wantMax: 10, tier: "low",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, rationale := investigate.ScoreConfidence(confidenceRules, tc.evidence, nil, k8sFacts{pod: tc.pod})
			if score < tc.wantMin || score > tc.wantMax {
				t.Errorf("score=%d want [%d,%d] (rationale: %s)", score, tc.wantMin, tc.wantMax, rationale)
			}
			if rationale == "" {
				t.Error("rationale must always explain the score")
			}
			if got := investigate.TierFor(score); got != tc.tier {
				t.Errorf("tier=%q want %q (score=%d)", got, tc.tier, score)
			}
		})
	}
}

func TestScoreConfidence_CorroborationBonus(t *testing.T) {
	single := []plugin.EvidenceItem{{Kind: "log", Source: "p", Excerpt: "ERROR x"}}
	multi := append(single,
		plugin.EvidenceItem{Kind: "event", Source: "p", Excerpt: "BackOff restarting"},
		plugin.EvidenceItem{Kind: "config", Source: "d", Excerpt: "memLimits=false"},
	)
	s1, _ := investigate.ScoreConfidence(confidenceRules, single, nil, k8sFacts{})
	s2, _ := investigate.ScoreConfidence(confidenceRules, multi, nil, k8sFacts{})
	if s2 <= s1 {
		t.Errorf("independent corroborating kinds should raise the score: %d vs %d", s1, s2)
	}
}

func TestRankHypotheses_ForAndAgainstLabels(t *testing.T) {
	pod := &PodSummary{Namespace: "prod", Name: "api-1", Reason: "OOMKilled"}
	syms := matchSymptoms(pod, Snapshot{}, "prod", "api-1")

	evidence := investigate.LabelEvidence([]plugin.EvidenceItem{
		{Kind: "config", Source: "deployment/api", Excerpt: "ready 1/3 · memLimits=false cpuLimits=false"},
		{Kind: "change", Source: "Deployment/api", Excerpt: "updated by ci-bot, 2h ago"},
		{Kind: "log", Source: "pod/api-1", Excerpt: "OOMKilled: container exceeded memory limit"},
	})

	hyps := investigate.RankHypotheses(syms, evidence)
	if len(hyps) == 0 {
		t.Fatal("expected hypotheses for an OOM symptom")
	}
	if len(hyps) > investigate.MaxHypotheses {
		t.Errorf("hypotheses exceed cap: %d", len(hyps))
	}
	top := hyps[0]
	if !strings.Contains(strings.ToLower(top.Title), "memory limit") {
		t.Errorf("expected the memory-limit cause to rank first with this evidence, got %q (score %d)", top.Title, top.Score)
	}
	if len(top.EvidenceFor) == 0 {
		t.Errorf("top hypothesis must cite supporting evidence labels, got %+v", top)
	}
	for _, h := range hyps {
		if h.Rationale == "" {
			t.Errorf("every hypothesis needs a rationale: %+v", h)
		}
		if h.Score < 0 || h.Score > 98 {
			t.Errorf("score out of range: %+v", h)
		}
	}
}

func TestRankHypotheses_Deterministic(t *testing.T) {
	pod := &PodSummary{Namespace: "prod", Name: "api-1", Reason: "CrashLoopBackOff"}
	syms := matchSymptoms(pod, Snapshot{}, "prod", "api-1")
	ev := investigate.LabelEvidence([]plugin.EvidenceItem{{Kind: "log", Source: "p", Excerpt: "panic: nil pointer"}})
	a := investigate.RankHypotheses(syms, ev)
	b := investigate.RankHypotheses(syms, ev)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic ranking: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Title != b[i].Title || a[i].Score != b[i].Score {
			t.Errorf("non-deterministic at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestPreventionFor_MappedAndDeduped(t *testing.T) {
	pod := &PodSummary{Namespace: "prod", Name: "api-1", Reason: "OOMKilled"}
	syms := matchSymptoms(pod, Snapshot{}, "prod", "api-1")
	prev := investigate.PreventionFor(preventionCatalog, syms)
	if len(prev) == 0 {
		t.Fatal("expected prevention actions for OOM")
	}
	for _, a := range prev {
		if a.FixType != "prevention" {
			t.Errorf("prevention action must carry FixType prevention: %+v", a)
		}
		if a.Kind != "advice" {
			t.Errorf("prevention must be copy-only advice, never auto-applied: %+v", a)
		}
	}
}
