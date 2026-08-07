package web

// analyzer_test.go — the analyzer stats + drilldown endpoints and the
// dashboard payload's analyzer stamping.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestHandleAnalyzerStats(t *testing.T) {
	srv := newTestServer(plugin.Report{Title: "t"})

	// Unwired → 503 (the k8s dashboard).
	rr := httptest.NewRecorder()
	srv.handleAnalyzerStats(rr, httptest.NewRequest(http.MethodGet, "/api/analyzer/stats", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("unwired should 503, got %d", rr.Code)
	}

	srv.analyzer = "syslog"
	srv.analyzerStatsFn = func() any { return map[string]int{"authFailures": 7} }
	rr = httptest.NewRecorder()
	srv.handleAnalyzerStats(rr, httptest.NewRequest(http.MethodGet, "/api/analyzer/stats", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"analyzer":"syslog"`) || !strings.Contains(body, `"authFailures":7`) {
		t.Errorf("stats body: %s", body)
	}

	rr = httptest.NewRecorder()
	srv.handleAnalyzerStats(rr, httptest.NewRequest(http.MethodPost, "/api/analyzer/stats", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST should 405, got %d", rr.Code)
	}
}

func TestHandleAnalyzerLogs(t *testing.T) {
	srv := newTestServer(plugin.Report{Title: "t"})

	rr := httptest.NewRecorder()
	srv.handleAnalyzerLogs(rr, httptest.NewRequest(http.MethodGet, "/api/analyzer/logs", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("unwired should 503, got %d", rr.Code)
	}

	var got LogQueryRequest
	srv.logQueryFn = func(_ context.Context, req LogQueryRequest) (LogQueryResponse, error) {
		got = req
		return LogQueryResponse{
			Events: []LogQueryEvent{{Severity: "err", Unit: "nginx.service", Raw: "12:01 nginx worker crashed"}},
			Total:  1,
		}, nil
	}
	rr = httptest.NewRecorder()
	srv.handleAnalyzerLogs(rr, httptest.NewRequest(http.MethodGet,
		"/api/analyzer/logs?severity=err&unit=nginx.service&contains=crashed&limit=50&offset=10&from=2026-07-08T12:00:00Z", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if got.Severity != "err" || got.Unit != "nginx.service" || got.Contains != "crashed" ||
		got.Limit != 50 || got.Offset != 10 || got.From.IsZero() {
		t.Errorf("decoded query: %+v", got)
	}
	if got.AroundIdx != -1 || got.Context != 0 {
		t.Errorf("context params must default to unset (idx -1, context 0): %+v", got)
	}
	var resp LogQueryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || resp.Total != 1 || len(resp.Events) != 1 {
		t.Errorf("response: %+v err=%v", resp, err)
	}
}

func TestServeLogQuery_AroundContextParams(t *testing.T) {
	srv := newTestServer(plugin.Report{Title: "t"})
	var got LogQueryRequest
	srv.logQueryFn = func(_ context.Context, req LogQueryRequest) (LogQueryResponse, error) {
		got = req
		return LogQueryResponse{}, nil
	}

	cases := []struct {
		name, query string
		wantIdx     int
		wantTimeSet bool
		wantContext int
	}{
		{"index anchor", "around=17&context=30", 17, false, 30},
		{"timestamp anchor", "around=2026-07-08T12:02:00Z&context=5", -1, true, 5},
		{"garbage anchor ignored", "around=banana&context=5", -1, false, 5},
		{"negative context ignored", "around=17&context=-2", 17, false, 0},
		{"context without anchor still parses", "context=10", -1, false, 10},
	}
	for _, tc := range cases {
		rr := httptest.NewRecorder()
		srv.handleAnalyzerLogs(rr, httptest.NewRequest(http.MethodGet, "/api/analyzer/logs?"+tc.query, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", tc.name, rr.Code)
		}
		if got.AroundIdx != tc.wantIdx || got.AroundTime.IsZero() == tc.wantTimeSet || got.Context != tc.wantContext {
			t.Errorf("%s: decoded %+v (wantIdx=%d wantTimeSet=%v wantContext=%d)",
				tc.name, got, tc.wantIdx, tc.wantTimeSet, tc.wantContext)
		}
	}
}

func TestDashboardPayload_AnalyzerStamping(t *testing.T) {
	srv := newTestServer(plugin.Report{Title: "t"})

	// k8s path: no analyzer → fields absent from the JSON.
	payload := buildDashboard(srv.getReport(), srv.podInfo(), srv.provider, srv.autoRefresh)
	srv.attachAnalyzer(&payload)
	blob, _ := json.Marshal(payload)
	if strings.Contains(string(blob), `"analyzer"`) || strings.Contains(string(blob), `"stats"`) {
		t.Errorf("k8s payload must not carry analyzer fields: %s", blob)
	}

	// Analyzer path: both stamped.
	srv.analyzer = "httplog"
	srv.analyzerStatsFn = func() any { return map[string]int{"slowRequests": 3} }
	payload2 := buildDashboard(srv.getReport(), srv.podInfo(), srv.provider, srv.autoRefresh)
	srv.attachAnalyzer(&payload2)
	blob2, _ := json.Marshal(payload2)
	if !strings.Contains(string(blob2), `"analyzer":"httplog"`) || !strings.Contains(string(blob2), `"slowRequests":3`) {
		t.Errorf("analyzer payload: %s", blob2)
	}
}
