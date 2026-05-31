package slo

import (
	"testing"
	"time"
)

// Reference spec used across tests: a 99.9% / 30-day SLO.
// allowed_error_rate = 0.001 → multiplier 14.4 needs ~1.44% errors in 1h.
func refSpec() SLOSpec {
	return SLOSpec{
		Name:      "ref-slo",
		Service:   "ref-svc",
		Namespace: "default",
		Window:    "30d",
		Objective: 0.999,
	}
}

// fillWindow produces N samples linearly spaced over `dur` ending at `end`,
// each with the given good/total counts.
func fillWindow(end time.Time, dur time.Duration, n int, good, total float64) []Sample {
	if n < 1 {
		n = 1
	}
	step := dur / time.Duration(n)
	out := make([]Sample, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Sample{
			At:    end.Add(-time.Duration(n-1-i) * step),
			Good:  good,
			Total: total,
		})
	}
	return out
}

func TestComputeMultiWindow_NoSamples(t *testing.T) {
	now := time.Now()
	got := ComputeMultiWindow(refSpec(), nil, now, DefaultMultiWindowConfig())
	if len(got) != 3 {
		t.Fatalf("want 3 windows, got %d", len(got))
	}
	for _, b := range got {
		if b.Triggered {
			t.Errorf("window %s: should not trigger with zero samples, got mult=%g", b.Window, b.Multiplier)
		}
		if b.ObservedRate != 0 {
			t.Errorf("window %s: observed rate should be 0, got %g", b.Window, b.ObservedRate)
		}
	}
}

func TestComputeMultiWindow_NoBurn(t *testing.T) {
	now := time.Now()
	// Perfectly healthy: 100 good / 100 total across all windows.
	samples := fillWindow(now, 72*time.Hour, 72, 100, 100)
	got := ComputeMultiWindow(refSpec(), samples, now, DefaultMultiWindowConfig())
	for _, b := range got {
		if b.Triggered {
			t.Errorf("window %s: should not trigger when error rate is 0, got mult=%g", b.Window, b.Multiplier)
		}
	}
	if WorstTier(got) != "" {
		t.Errorf("WorstTier should be empty for healthy SLO, got %q", WorstTier(got))
	}
}

func TestComputeMultiWindow_FastBurn(t *testing.T) {
	now := time.Now()
	// 10% error rate over the last 1h only (everything before is clean).
	// observed=0.10, allowed=0.001 → multiplier=100, way above 14.4 page threshold.
	healthy := fillWindow(now.Add(-1*time.Hour), 71*time.Hour, 71, 1000, 1000)
	burning := fillWindow(now, 1*time.Hour, 6, 900, 1000) // 10% errors
	samples := append(healthy, burning...)

	got := ComputeMultiWindow(refSpec(), samples, now, DefaultMultiWindowConfig())
	if !got[0].Triggered {
		t.Errorf("1h window should trigger on fast burn, got mult=%g threshold=%g", got[0].Multiplier, got[0].Threshold)
	}
	if got[0].Tier != "page" {
		t.Errorf("1h triggered tier should be page, got %q", got[0].Tier)
	}
	if tier := WorstTier(got); tier != "page" {
		t.Errorf("WorstTier should be page during fast burn, got %q", tier)
	}
}

func TestComputeMultiWindow_SlowBurn(t *testing.T) {
	now := time.Now()
	// Sustained 0.5% error rate across all 72 hours.
	// observed=0.005, allowed=0.001 → multiplier=5.0 → triggers 72h (>1.0) and
	// 6h (>1, but 6 threshold is 6.0 so should NOT trigger 6h); 1h should not trigger.
	samples := fillWindow(now, 72*time.Hour, 72, 995, 1000)

	got := ComputeMultiWindow(refSpec(), samples, now, DefaultMultiWindowConfig())

	if got[0].Triggered {
		t.Errorf("1h should NOT trigger on slow burn, got mult=%g", got[0].Multiplier)
	}
	if got[1].Triggered {
		t.Errorf("6h should NOT trigger when multiplier=5 < threshold=6, got mult=%g", got[1].Multiplier)
	}
	if !got[2].Triggered {
		t.Errorf("72h should trigger sustained over-burn, got mult=%g threshold=%g", got[2].Multiplier, got[2].Threshold)
	}
	if tier := WorstTier(got); tier != "warn" {
		t.Errorf("WorstTier should be warn during slow burn, got %q", tier)
	}
}

func TestComputeMultiWindow_MediumBurn(t *testing.T) {
	now := time.Now()
	// 1% error rate over last 6h (everything else clean).
	// observed_6h=0.01, allowed=0.001 → mult=10.0 → triggers 6h (>6) and 72h (>1).
	healthy := fillWindow(now.Add(-6*time.Hour), 66*time.Hour, 66, 1000, 1000)
	burning := fillWindow(now, 6*time.Hour, 36, 990, 1000)
	samples := append(healthy, burning...)

	got := ComputeMultiWindow(refSpec(), samples, now, DefaultMultiWindowConfig())

	// At 1% errors → mult=10. 1h threshold is 14.4 → does NOT trigger page.
	// 6h threshold is 6 → triggers ticket. 72h threshold is 1 → triggers warn.
	if got[0].Triggered {
		t.Errorf("1h should NOT trigger at multiplier 10 (< page threshold 14.4), got mult=%g", got[0].Multiplier)
	}
	if !got[1].Triggered {
		t.Errorf("6h should trigger at multiplier 10 (> ticket threshold 6), got mult=%g", got[1].Multiplier)
	}
	if !got[2].Triggered {
		t.Errorf("72h should trigger sustained over-burn, got mult=%g", got[2].Multiplier)
	}
	if tier := WorstTier(got); tier != "ticket" {
		t.Errorf("WorstTier should be ticket during medium burn, got %q", tier)
	}
}

func TestComputeMultiWindow_ImpossibleObjective(t *testing.T) {
	now := time.Now()
	spec := refSpec()
	spec.Objective = 1.0 // allowed = 0
	samples := fillWindow(now, 1*time.Hour, 6, 999, 1000)

	got := ComputeMultiWindow(spec, samples, now, DefaultMultiWindowConfig())
	if !got[0].Triggered {
		t.Errorf("1h should trigger when objective=1 and any error exists")
	}
	if got[0].Multiplier < 1e8 {
		t.Errorf("multiplier sentinel should be ~1e9, got %g", got[0].Multiplier)
	}
}

func TestWorstTier_Precedence(t *testing.T) {
	cases := []struct {
		name  string
		burns []BurnRate
		want  string
	}{
		{"none", []BurnRate{{Tier: "page"}, {Tier: "ticket"}, {Tier: "warn"}}, ""},
		{"only-warn", []BurnRate{{Tier: "warn", Triggered: true}}, "warn"},
		{"only-ticket", []BurnRate{{Tier: "ticket", Triggered: true}, {Tier: "warn", Triggered: true}}, "ticket"},
		{"page-wins", []BurnRate{{Tier: "page", Triggered: true}, {Tier: "ticket", Triggered: true}, {Tier: "warn", Triggered: true}}, "page"},
	}
	for _, c := range cases {
		if got := WorstTier(c.burns); got != c.want {
			t.Errorf("%s: WorstTier=%q, want %q", c.name, got, c.want)
		}
	}
}
