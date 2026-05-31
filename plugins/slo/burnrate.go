package slo

// Multi-window burn-rate computation following the Google SRE Workbook §5
// pattern (https://sre.google/workbook/alerting-on-slos/).
//
// Competitive gap: OpenObserve (opp #1, HIGH) and Komodor (opp #2, HIGH) both
// explicitly lack a native SLO/error-budget engine. OpenObserve users hand-code
// burn-rate logic in VRL multi-window functions; Komodor delegates to external
// PagerDuty/Datadog. Exalm fills the gap with a first-class, declarative engine
// that runs on any sample stream (Prometheus today, OpenObserve / Mimir / Cortex
// tomorrow — the engine math is backend-agnostic).
//
// The three-window pattern catches both acute outages and slow degradation:
//   - Short  (1h)  threshold 14.4  → page  alert (acute: 2% of budget in 1h)
//   - Medium (6h)  threshold  6    → ticket alert (slow burn: 5% in 6h)
//   - Long   (72h) threshold  1    → warning      (sustained over-burn)
//
// Multiplier semantics: burn_rate = observed_error_rate / allowed_error_rate.
// allowed_error_rate = 1 - SLO_target. A multiplier of N means the budget is
// being consumed N times faster than the SLO allows. At multiplier 1.0, the
// budget will be exhausted exactly at the end of the SLO window.

import (
	"time"
)

// BurnRate is the burn-rate result for a single window of a single SLO.
type BurnRate struct {
	// Window is the human label ("1h", "6h", "72h").
	Window string `json:"window"`
	// WindowDur is the parsed duration.
	WindowDur time.Duration `json:"-"`
	// ObservedRate is the measured error rate over the window: 1 - good/total.
	// 0.0 = perfect; 1.0 = total failure.
	ObservedRate float64 `json:"observed_rate"`
	// AllowedRate is the SLO's allowed error rate: 1 - Objective.
	AllowedRate float64 `json:"allowed_rate"`
	// Multiplier is ObservedRate / AllowedRate. 1.0 = budget consumed exactly
	// over window; > Threshold = action required.
	Multiplier float64 `json:"multiplier"`
	// Threshold is the multiplier at which this window's alert tier fires.
	Threshold float64 `json:"threshold"`
	// Triggered is Multiplier > Threshold.
	Triggered bool `json:"triggered"`
	// Tier is one of "page", "ticket", "warn".
	Tier string `json:"tier"`
}

// Sample is one observation of good/total counts at a moment in time.
// Backends (Prometheus, OpenObserve, etc.) emit a slice of these per query.
type Sample struct {
	At    time.Time `json:"at"`
	Good  float64   `json:"good"`
	Total float64   `json:"total"`
}

// MultiWindowConfig defines the three windows and their alert thresholds.
// DefaultMultiWindowConfig returns the Google SRE Workbook recommendation,
// calibrated against a 99.9% / 30-day SLO; the same numbers work for any
// SLO target — the multiplier is dimensionless.
type MultiWindowConfig struct {
	Short, Medium, Long                           time.Duration
	PageThreshold, TicketThreshold, WarnThreshold float64
}

// DefaultMultiWindowConfig returns the Google SRE Workbook §5 defaults:
// 1h/6h/72h windows with 14.4/6/1 thresholds.
func DefaultMultiWindowConfig() MultiWindowConfig {
	return MultiWindowConfig{
		Short:           1 * time.Hour,
		Medium:          6 * time.Hour,
		Long:            72 * time.Hour,
		PageThreshold:   14.4,
		TicketThreshold: 6.0,
		WarnThreshold:   1.0,
	}
}

// ComputeMultiWindow evaluates a single SLO against a stream of samples,
// returning one BurnRate per window. The result is ordered short → medium → long.
//
// Required: `now` is the evaluation timestamp; each window looks back from
// `now`. Samples outside any window are ignored.
//
// Edge cases:
//   - No samples in a window → ObservedRate=0, Multiplier=0, Triggered=false.
//   - AllowedRate==0 (Objective==1.0, i.e. impossible 100% SLO) → Multiplier=+Inf
//     iff ObservedRate > 0; we set Triggered=true and Multiplier to a large
//     sentinel (1e9) for stable JSON serialization.
func ComputeMultiWindow(spec SLOSpec, samples []Sample, now time.Time, cfg MultiWindowConfig) []BurnRate {
	allowed := 1.0 - spec.Objective
	windows := []struct {
		name string
		dur  time.Duration
		thr  float64
		tier string
	}{
		{"1h", cfg.Short, cfg.PageThreshold, "page"},
		{"6h", cfg.Medium, cfg.TicketThreshold, "ticket"},
		{"72h", cfg.Long, cfg.WarnThreshold, "warn"},
	}
	out := make([]BurnRate, 0, 3)
	for _, w := range windows {
		obs := errorRateOver(samples, now.Add(-w.dur), now)
		mult := 0.0
		switch {
		case allowed <= 0 && obs > 0:
			mult = 1e9 // sentinel: impossible objective + any error
		case allowed > 0:
			mult = obs / allowed
		}
		out = append(out, BurnRate{
			Window:       w.name,
			WindowDur:    w.dur,
			ObservedRate: obs,
			AllowedRate:  allowed,
			Multiplier:   mult,
			Threshold:    w.thr,
			Triggered:    mult > w.thr,
			Tier:         w.tier,
		})
	}
	return out
}

// errorRateOver returns 1 - (sum good / sum total) for samples in [start, end].
// Returns 0 if no samples fall in the window or total==0.
func errorRateOver(samples []Sample, start, end time.Time) float64 {
	var good, total float64
	for _, s := range samples {
		if s.At.Before(start) || s.At.After(end) {
			continue
		}
		good += s.Good
		total += s.Total
	}
	if total == 0 {
		return 0
	}
	return 1.0 - good/total
}

// WorstTier returns the most severe alert tier triggered across a set of
// burn-rate results. Used by the dashboard status bar to render a single
// chip per SLO ("🔥 fast-burn", "⚠ slow-burn", "ℹ exhaustion-warn").
// Returns "" if nothing is triggered.
func WorstTier(burns []BurnRate) string {
	for _, b := range burns {
		if b.Triggered && b.Tier == "page" {
			return "page"
		}
	}
	for _, b := range burns {
		if b.Triggered && b.Tier == "ticket" {
			return "ticket"
		}
	}
	for _, b := range burns {
		if b.Triggered && b.Tier == "warn" {
			return "warn"
		}
	}
	return ""
}
