package slo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// defaultPromStep is the query_range step used for all Prometheus queries.
// 5 minutes balances resolution (fine enough for 1h burn-rate windows) against
// the number of data points returned (≤ 8640 for a 30d SLO window).
const defaultPromStep = 5 * time.Minute

// promRangeResult is the JSON envelope returned by GET /api/v1/query_range.
type promRangeResult struct {
	Status string         `json:"status"`
	Data   promResultData `json:"data"`
	Error  string         `json:"error,omitempty"`
}

type promResultData struct {
	ResultType string       `json:"resultType"`
	Result     []promMatrix `json:"result"`
}

// promMatrix is one time-series in a Prometheus matrix result.
// Each element of Values is a 2-element JSON array [unix_timestamp_float, "value_string"].
type promMatrix struct {
	Metric map[string]string   `json:"metric"`
	Values [][]json.RawMessage `json:"values"`
}

// queryPromSeries executes a PromQL expression via /api/v1/query_range over
// [start, end] at the given step and returns a map of unix-second timestamp →
// summed value across all returned series.
//
// Summing handles both single-series aggregates (e.g. sum(rate(...))) and
// multi-series results; callers typically use a pre-aggregated PromQL expression
// so only one series is returned in practice.
func queryPromSeries(ctx context.Context, promURL, query string, start, end time.Time, step time.Duration, hc *http.Client) (map[int64]float64, error) {
	params := url.Values{}
	params.Set("query", query)
	params.Set("start", strconv.FormatInt(start.Unix(), 10))
	params.Set("end", strconv.FormatInt(end.Unix(), 10))
	params.Set("step", strconv.FormatInt(int64(step.Seconds()), 10)+"s") //nolint:gosec // G115: step is always a positive duration; truncation is intentional

	reqURL := promURL + "/api/v1/query_range?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil) //nolint:gosec // G107: Prometheus URL is operator-configured, not end-user input
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := hc.Do(req) //nolint:gosec // G704: URL comes from operator-configured SLO endpoint, not user-supplied input
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("prometheus returned %d: %.500s", resp.StatusCode, body)
	}

	var result promRangeResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if result.Status != "success" {
		return nil, fmt.Errorf("prometheus error: %s", result.Error)
	}

	summed := make(map[int64]float64)
	for _, series := range result.Data.Result {
		for _, pair := range series.Values {
			if len(pair) < 2 {
				continue
			}
			var ts float64
			if err := json.Unmarshal(pair[0], &ts); err != nil {
				continue
			}
			var valStr string
			if err := json.Unmarshal(pair[1], &valStr); err != nil {
				continue
			}
			v, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				continue
			}
			summed[int64(ts)] += v //nolint:gosec // G115: Prometheus timestamp; truncation to seconds is intentional
		}
	}
	return summed, nil
}

// fetchSamplesFromProm queries Prometheus for each SLOSpec's GoodQuery and
// TotalQuery over [now-window, now] and returns a map[specName][]Sample.
//
// The returned samples are joined on matching unix-second timestamps. Points
// where good and total timestamps don't align are dropped. With identical step
// values — the common case for PromQL rate() queries — all timestamps align.
func fetchSamplesFromProm(ctx context.Context, specs []SLOSpec, promURL string, window time.Duration, hc *http.Client) (map[string][]Sample, error) {
	now := time.Now()
	start := now.Add(-window)

	out := make(map[string][]Sample, len(specs))
	for _, spec := range specs {
		goods, err := queryPromSeries(ctx, promURL, spec.SLI.GoodQuery, start, now, defaultPromStep, hc)
		if err != nil {
			return nil, fmt.Errorf("spec %q good query: %w", spec.Name, err)
		}
		totals, err := queryPromSeries(ctx, promURL, spec.SLI.TotalQuery, start, now, defaultPromStep, hc)
		if err != nil {
			return nil, fmt.Errorf("spec %q total query: %w", spec.Name, err)
		}

		var samples []Sample
		for ts, total := range totals {
			good, ok := goods[ts]
			if !ok {
				continue
			}
			samples = append(samples, Sample{
				At:    time.Unix(ts, 0).UTC(),
				Good:  good,
				Total: total,
			})
		}
		out[spec.Name] = samples
	}
	return out, nil
}

// parseWindow parses a compact window string ("30d", "7d", "24h", "90m") into
// a time.Duration. Returns an error for unknown formats; callers fall back to 72h.
func parseWindow(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid window %q", s)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid window %q: %w", s, err)
	}
	switch s[len(s)-1] {
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	}
	return 0, fmt.Errorf("unknown window unit in %q", s)
}

// collectErrorBudgets queries Prometheus for SLI data and computes a single-window
// error budget for each SLOSpec.
//
// The query window equals the SLO compliance window (spec.Window, e.g. "30d").
// If the window cannot be parsed, 72h is used as a fallback.
//
// Compatible with Prometheus, Thanos, Cortex, and Mimir — all expose the same
// GET /api/v1/query_range HTTP endpoint.
//
// ErrorBudget.Remaining is 1 - burnRate_fraction (clamped to [0,1]):
//   - 1.0  = full budget; error rate exactly 0
//   - 0.5  = half budget consumed; error rate at half the allowed rate
//   - 0.0  = budget exhausted; error rate ≥ 1 - objective
//
// ExhaustionETA is non-zero only when BurnRate > 1 (over-burning).
func collectErrorBudgets(ctx context.Context, specs []SLOSpec, promURL string) ([]ErrorBudget, error) {
	if promURL == "" {
		return nil, fmt.Errorf("slo: prometheus URL required (set --prometheus-url or EXALM_PROMETHEUS_URL)")
	}

	hc := &http.Client{Timeout: 30 * time.Second}
	now := time.Now()

	out := make([]ErrorBudget, 0, len(specs))
	for _, spec := range specs {
		window, err := parseWindow(spec.Window)
		if err != nil {
			window = 72 * time.Hour
		}

		start := now.Add(-window)
		goods, err := queryPromSeries(ctx, promURL, spec.SLI.GoodQuery, start, now, defaultPromStep, hc)
		if err != nil {
			return nil, fmt.Errorf("spec %q good query: %w", spec.Name, err)
		}
		totals, err := queryPromSeries(ctx, promURL, spec.SLI.TotalQuery, start, now, defaultPromStep, hc)
		if err != nil {
			return nil, fmt.Errorf("spec %q total query: %w", spec.Name, err)
		}

		var samples []Sample
		for ts, total := range totals {
			good, ok := goods[ts]
			if !ok {
				continue
			}
			samples = append(samples, Sample{
				At:    time.Unix(ts, 0).UTC(),
				Good:  good,
				Total: total,
			})
		}

		errRate := errorRateOver(samples, start, now)
		allowed := 1.0 - spec.Objective

		burnRate := 0.0
		if allowed > 0 {
			burnRate = errRate / allowed
		}

		remaining := 1.0
		if allowed > 0 {
			remaining = 1.0 - errRate/allowed
			if remaining < 0 {
				remaining = 0
			}
		}

		var eta time.Time
		if burnRate > 1 {
			// At current burn rate, remaining budget depletes in: remaining×window÷burnRate.
			secsLeft := (remaining * window.Seconds()) / burnRate
			eta = now.Add(time.Duration(int64(secsLeft)) * time.Second) //nolint:gosec // G115: secsLeft is a calculated positive float; truncation is intentional
		}

		out = append(out, ErrorBudget{
			Spec:          spec,
			Remaining:     remaining,
			BurnRate:      burnRate,
			ExhaustionETA: eta,
		})
	}
	return out, nil
}
