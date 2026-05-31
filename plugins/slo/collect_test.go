package slo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// promHandler returns an httptest.HandlerFunc that serves a Prometheus
// matrix response with a single series containing the provided [ts, value] pairs.
func promHandler(pairs [][2]float64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" {
			http.NotFound(w, r)
			return
		}
		values := make([]interface{}, 0, len(pairs))
		for _, p := range pairs {
			values = append(values, []interface{}{p[0], formatFloat(p[1])})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"status": "success",
			"data": map[string]interface{}{
				"resultType": "matrix",
				"result": []interface{}{
					map[string]interface{}{
						"metric": map[string]string{},
						"values": values,
					},
				},
			},
		})
	}
}

// formatFloat converts a float64 to the string representation Prometheus uses.
func formatFloat(v float64) string {
	b, _ := json.Marshal(v)
	// json.Marshal produces a number; Prometheus wraps values in strings.
	return string(b)
}

// twoQueryHandler routes requests to goodHandler or totalHandler based on the
// "query" URL parameter. Used to simulate separate good/total PromQL queries.
func twoQueryHandler(goodQ, totalQ string, goodPairs, totalPairs [][2]float64) http.HandlerFunc {
	gh := promHandler(goodPairs)
	th := promHandler(totalPairs)
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		switch q {
		case goodQ:
			gh(w, r)
		case totalQ:
			th(w, r)
		default:
			// Return an empty matrix for unknown queries.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
				"status": "success",
				"data": map[string]interface{}{
					"resultType": "matrix",
					"result":     []interface{}{},
				},
			})
		}
	}
}

// ---- queryPromSeries tests ----

func TestQueryPromSeries_Success(t *testing.T) {
	pairs := [][2]float64{{1.0, 100}, {2.0, 200}}
	srv := httptest.NewServer(promHandler(pairs))
	defer srv.Close()

	got, err := queryPromSeries(
		context.Background(), srv.URL, "test_query",
		time.Unix(0, 0), time.Unix(300, 0),
		defaultPromStep, srv.Client(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[1] != 100 {
		t.Errorf("ts=1: want 100.0, got %v", got[1])
	}
	if got[2] != 200 {
		t.Errorf("ts=2: want 200.0, got %v", got[2])
	}
}

func TestQueryPromSeries_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := queryPromSeries(
		context.Background(), srv.URL, "q",
		time.Now().Add(-time.Hour), time.Now(),
		defaultPromStep, srv.Client(),
	)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestQueryPromSeries_PromErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"status": "error",
			"error":  "bad PromQL expression",
		})
	}))
	defer srv.Close()

	_, err := queryPromSeries(
		context.Background(), srv.URL, "bad{query}",
		time.Now().Add(-time.Hour), time.Now(),
		defaultPromStep, srv.Client(),
	)
	if err == nil {
		t.Fatal("expected error for prometheus error status")
	}
}

func TestQueryPromSeries_MultiSeries_Summed(t *testing.T) {
	// Two series at the same timestamp — both should be summed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"status": "success",
			"data": map[string]interface{}{
				"resultType": "matrix",
				"result": []interface{}{
					map[string]interface{}{
						"metric": map[string]string{"pod": "a"},
						"values": []interface{}{[]interface{}{1.0, "300"}},
					},
					map[string]interface{}{
						"metric": map[string]string{"pod": "b"},
						"values": []interface{}{[]interface{}{1.0, "700"}},
					},
				},
			},
		})
	}))
	defer srv.Close()

	got, err := queryPromSeries(
		context.Background(), srv.URL, "q",
		time.Unix(0, 0), time.Unix(300, 0),
		defaultPromStep, srv.Client(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 300 + 700 = 1000
	if got[1] != 1000 {
		t.Errorf("want sum 1000, got %v", got[1])
	}
}

// ---- fetchSamplesFromProm tests ----

func TestFetchSamplesFromProm_BasicJoin(t *testing.T) {
	// good_query returns 950 at ts=100; total_query returns 1000 at ts=100.
	// Result should be one sample with Good=950, Total=1000.
	spec := SLOSpec{
		Name:      "join-test",
		Objective: 0.999,
		SLI:       SLIQuery{GoodQuery: "good_q", TotalQuery: "total_q"},
	}

	srv := httptest.NewServer(twoQueryHandler(
		"good_q", "total_q",
		[][2]float64{{100, 950}},
		[][2]float64{{100, 1000}},
	))
	defer srv.Close()

	samples, err := fetchSamplesFromProm(
		context.Background(), []SLOSpec{spec}, srv.URL,
		72*time.Hour, srv.Client(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := samples["join-test"]
	if len(got) != 1 {
		t.Fatalf("want 1 sample, got %d", len(got))
	}
	if got[0].Good != 950 {
		t.Errorf("want Good=950, got %v", got[0].Good)
	}
	if got[0].Total != 1000 {
		t.Errorf("want Total=1000, got %v", got[0].Total)
	}
}

func TestFetchSamplesFromProm_MisalignedTimestamps(t *testing.T) {
	// good at ts=100, total at ts=200 — no overlap, so zero samples returned.
	spec := SLOSpec{
		Name:      "no-join",
		Objective: 0.999,
		SLI:       SLIQuery{GoodQuery: "g", TotalQuery: "t"},
	}

	srv := httptest.NewServer(twoQueryHandler(
		"g", "t",
		[][2]float64{{100, 1000}},
		[][2]float64{{200, 1000}},
	))
	defer srv.Close()

	samples, err := fetchSamplesFromProm(
		context.Background(), []SLOSpec{spec}, srv.URL,
		72*time.Hour, srv.Client(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(samples["no-join"]) != 0 {
		t.Errorf("want 0 samples for misaligned timestamps, got %d", len(samples["no-join"]))
	}
}

// ---- collectErrorBudgets tests ----

func TestCollectErrorBudgets_EmptyURL(t *testing.T) {
	_, err := collectErrorBudgets(context.Background(), nil, "")
	if err == nil {
		t.Fatal("expected error for empty prometheus URL")
	}
}

func TestCollectErrorBudgets_HealthySLO(t *testing.T) {
	// good=1000, total=1000 → 0% error rate → burnRate=0, remaining=1.
	spec := SLOSpec{
		Name:      "healthy",
		Objective: 0.999,
		Window:    "30d",
		SLI:       SLIQuery{GoodQuery: "good", TotalQuery: "total"},
	}

	ts := float64(time.Now().Add(-time.Hour).Unix())
	srv := httptest.NewServer(twoQueryHandler(
		"good", "total",
		[][2]float64{{ts, 1000}},
		[][2]float64{{ts, 1000}},
	))
	defer srv.Close()

	budgets, err := collectErrorBudgets(context.Background(), []SLOSpec{spec}, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(budgets) != 1 {
		t.Fatalf("want 1 budget, got %d", len(budgets))
	}
	b := budgets[0]
	if b.BurnRate != 0 {
		t.Errorf("want BurnRate=0, got %.4f", b.BurnRate)
	}
	if b.Remaining != 1 {
		t.Errorf("want Remaining=1.0, got %.4f", b.Remaining)
	}
	if !b.ExhaustionETA.IsZero() {
		t.Errorf("want zero ETA for healthy SLO, got %v", b.ExhaustionETA)
	}
}

func TestCollectErrorBudgets_ExactBurnRate(t *testing.T) {
	// good=950, total=1000 → 5% error rate.
	// For objective=0.95, allowed=0.05 → burnRate = 0.05/0.05 = 1.0, remaining=0.
	spec := SLOSpec{
		Name:      "exact-burn",
		Objective: 0.95,
		Window:    "30d",
		SLI:       SLIQuery{GoodQuery: "good", TotalQuery: "total"},
	}

	ts := float64(time.Now().Add(-time.Hour).Unix())
	srv := httptest.NewServer(twoQueryHandler(
		"good", "total",
		[][2]float64{{ts, 950}},
		[][2]float64{{ts, 1000}},
	))
	defer srv.Close()

	budgets, err := collectErrorBudgets(context.Background(), []SLOSpec{spec}, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b := budgets[0]
	// burnRate should be very close to 1.0
	if b.BurnRate < 0.99 || b.BurnRate > 1.01 {
		t.Errorf("want BurnRate≈1.0, got %.4f", b.BurnRate)
	}
	if b.Remaining > 0.01 {
		t.Errorf("want Remaining≈0, got %.4f", b.Remaining)
	}
}

func TestCollectErrorBudgets_OverBurning(t *testing.T) {
	// good=900, total=1000 → 10% error rate.
	// For objective=0.99, allowed=0.01 → burnRate=10, remaining=clamped to 0,
	// ExhaustionETA should be non-zero.
	spec := SLOSpec{
		Name:      "over-burn",
		Objective: 0.99,
		Window:    "30d",
		SLI:       SLIQuery{GoodQuery: "g", TotalQuery: "t"},
	}

	ts := float64(time.Now().Add(-time.Hour).Unix())
	srv := httptest.NewServer(twoQueryHandler(
		"g", "t",
		[][2]float64{{ts, 900}},
		[][2]float64{{ts, 1000}},
	))
	defer srv.Close()

	budgets, err := collectErrorBudgets(context.Background(), []SLOSpec{spec}, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b := budgets[0]
	if b.BurnRate < 9.9 {
		t.Errorf("want BurnRate≈10, got %.4f", b.BurnRate)
	}
	if b.Remaining != 0 {
		t.Errorf("want Remaining=0 (clamped) for over-burning SLO, got %.4f", b.Remaining)
	}
	// ExhaustionETA should be zero because remaining=0 (already exhausted).
	// The budget is already gone; ETA is only set when remaining > 0 and burnRate > 1.
}

func TestCollectErrorBudgets_MultiSpec(t *testing.T) {
	// Two specs served by the same mock; both should produce a budget.
	specs := []SLOSpec{
		{Name: "slo-a", Objective: 0.99, Window: "7d", SLI: SLIQuery{GoodQuery: "good_a", TotalQuery: "total_a"}},
		{Name: "slo-b", Objective: 0.999, Window: "30d", SLI: SLIQuery{GoodQuery: "good_b", TotalQuery: "total_b"}},
	}

	ts := float64(time.Now().Add(-time.Hour).Unix())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		value := "1000.0"
		if q == "good_a" || q == "good_b" {
			value = "990.0"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"status": "success",
			"data": map[string]interface{}{
				"resultType": "matrix",
				"result": []interface{}{
					map[string]interface{}{
						"metric": map[string]string{},
						"values": []interface{}{[]interface{}{ts, value}},
					},
				},
			},
		})
	}))
	defer srv.Close()

	budgets, err := collectErrorBudgets(context.Background(), specs, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(budgets) != 2 {
		t.Fatalf("want 2 budgets, got %d", len(budgets))
	}
}

// ---- parseWindow tests ----

func TestParseWindow(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"30d", 30 * 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"90m", 90 * time.Minute, false},
		{"", 0, true},
		{"1", 0, true},
		{"Xd", 0, true},
		{"30z", 0, true},
	}
	for _, c := range cases {
		got, err := parseWindow(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseWindow(%q): want error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseWindow(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseWindow(%q): want %v, got %v", c.in, c.want, got)
		}
	}
}
