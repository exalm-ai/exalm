package web

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/remediation"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func newTestServer(report plugin.Report) *liveServer {
	tmpl := template.Must(template.New("index.html").Funcs(template.FuncMap{
		"catIcon":         categoryIcon,
		"remediationJSON": remediationJSON,
		"sourceHost":      sourceHost,
		"sourcePlatform":  sourcePlatform,
	}).ParseFS(assets, "templates/index.html", "templates/timeline.html", "templates/dora.html"))
	return &liveServer{report: report, tmpl: tmpl, startTime: time.Now()}
}

func TestHandleDashboard_StatusOK(t *testing.T) {
	report := plugin.Report{
		Title:   "K8s analysis test",
		Summary: "test summary",
		Raw:     "## VERDICT\nAll good.",
		Findings: []plugin.Finding{
			{Severity: plugin.SeverityCritical, Title: "CrashLoopBackOff: prod/api-0", Detail: "22 restarts"},
		},
	}
	srv := newTestServer(report)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	srv.handleDashboard(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "K8s analysis test") {
		t.Error("report title not found in HTML output")
	}
	if !strings.Contains(body, "CrashLoopBackOff") {
		t.Error("finding title not found in HTML output")
	}
}

func TestHandleReportJSON_ValidJSON(t *testing.T) {
	report := plugin.Report{Title: "JSON test", Summary: "ok"}
	srv := newTestServer(report)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/report", nil)
	srv.handleReportJSON(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	if !strings.Contains(rr.Body.String(), "JSON test") {
		t.Error("title not found in JSON response")
	}
}

func TestBuildTemplateData_SeverityCounts(t *testing.T) {
	report := plugin.Report{
		Findings: []plugin.Finding{
			{Severity: plugin.SeverityCritical},
			{Severity: plugin.SeverityCritical},
			{Severity: plugin.SeverityHigh},
			{Severity: plugin.SeverityInfo},
		},
	}
	data := buildTemplateData(report, false, false)
	if data.SeverityCounts["critical"] != 2 {
		t.Errorf("expected 2 critical, got %d", data.SeverityCounts["critical"])
	}
	if data.SeverityCounts["high"] != 1 {
		t.Errorf("expected 1 high, got %d", data.SeverityCounts["high"])
	}
	if data.SeverityCounts["medium"] != 0 {
		t.Errorf("expected 0 medium, got %d", data.SeverityCounts["medium"])
	}
}

func TestBuildTemplateData_HasApplyFix(t *testing.T) {
	report := plugin.Report{}
	data := buildTemplateData(report, true, false)
	if !data.HasApplyFix {
		t.Error("HasApplyFix should be true when applyFix closure is set")
	}
	if data.HasCreatePR {
		t.Error("HasCreatePR should be false when not set")
	}
}

func TestBuildTemplateData_HasCreatePR(t *testing.T) {
	report := plugin.Report{}
	data := buildTemplateData(report, false, true)
	if data.HasApplyFix {
		t.Error("HasApplyFix should be false when not set")
	}
	if !data.HasCreatePR {
		t.Error("HasCreatePR should be true when createPR closure is set")
	}
}

func TestHandleHealthz_StatusOK(t *testing.T) {
	srv := newTestServer(plugin.Report{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	srv.handleHealthz(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("expected status ok in response, got: %s", body)
	}
	if !strings.Contains(body, `"uptime_seconds"`) {
		t.Errorf("expected uptime_seconds in response, got: %s", body)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected application/json content-type, got %q", ct)
	}
}

func TestHandleTimeline_StatusOK(t *testing.T) {
	srv := newTestServer(plugin.Report{Title: "timeline test"})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/timeline", nil)
	srv.handleTimeline(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html content-type, got %q", ct)
	}
}

func TestHandleTimelineJSON_StatusOK(t *testing.T) {
	srv := newTestServer(plugin.Report{
		Findings: []plugin.Finding{
			{Severity: plugin.SeverityHigh, Title: "test finding", Category: "Pods"},
		},
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/timeline", nil)
	srv.handleTimelineJSON(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected application/json content-type, got %q", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"events"`) {
		t.Errorf("expected 'events' field in JSON response, got: %s", body)
	}
}

func TestHandleDORAPage_StatusOK(t *testing.T) {
	srv := newTestServer(plugin.Report{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/dora", nil)
	srv.handleDORAPage(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html content-type, got %q", ct)
	}
}

func TestHandleDORAJSON_StatusOK(t *testing.T) {
	srv := newTestServer(plugin.Report{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/dora", nil)
	srv.handleDORAJSON(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected application/json content-type, got %q", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"overall_band"`) {
		t.Errorf("expected 'overall_band' in JSON response, got: %s", body)
	}
}

// ── requireToken middleware tests ─────────────────────────────────────────────

// okHandler is a trivial HTTP handler that always returns 200.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestRequireToken_NoToken_PassesThrough(t *testing.T) {
	h := requireToken(okHandler, "")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/report", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with no token configured, got %d", rr.Code)
	}
}

func TestRequireToken_ValidBearer_Passes(t *testing.T) {
	h := requireToken(okHandler, "supersecret")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/report", nil)
	req.Header.Set("Authorization", "Bearer supersecret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with valid Bearer token, got %d", rr.Code)
	}
}

func TestRequireToken_InvalidBearer_Returns401(t *testing.T) {
	h := requireToken(okHandler, "supersecret")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/report", nil)
	req.Header.Set("Authorization", "Bearer wrongtoken")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong Bearer token, got %d", rr.Code)
	}
}

func TestRequireToken_NoHeader_Returns401(t *testing.T) {
	h := requireToken(okHandler, "supersecret")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dora", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with no auth header, got %d", rr.Code)
	}
}

func TestRequireToken_QueryParam_Passes(t *testing.T) {
	h := requireToken(okHandler, "supersecret")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/report?token=supersecret", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with valid ?token= query param, got %d", rr.Code)
	}
}

func TestRequireToken_WrongQueryParam_Returns401(t *testing.T) {
	h := requireToken(okHandler, "supersecret")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/report?token=badtoken", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong ?token= query param, got %d", rr.Code)
	}
}

func TestRequireToken_HealthzBypassesAuth(t *testing.T) {
	h := requireToken(okHandler, "supersecret")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	// No Authorization header — /healthz must pass through anyway.
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/healthz should bypass auth, got %d", rr.Code)
	}
}

func TestRequireToken_MetricsBypassesAuth(t *testing.T) {
	h := requireToken(okHandler, "supersecret")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	// No Authorization header — /metrics must pass through anyway.
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/metrics should bypass auth, got %d", rr.Code)
	}
}

// ── requireCSRF middleware tests ──────────────────────────────────────────────

func TestRequireCSRF_GetPassesThrough(t *testing.T) {
	h := requireCSRF(okHandler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/report", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("GET should bypass CSRF check, got %d", rr.Code)
	}
}

func TestRequireCSRF_PostWithHeader_Passes(t *testing.T) {
	h := requireCSRF(okHandler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fix", nil)
	req.Header.Set("X-Exalm-Request", "true")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("POST with X-Exalm-Request should pass, got %d", rr.Code)
	}
}

func TestRequireCSRF_PostMissingHeader_Returns403(t *testing.T) {
	h := requireCSRF(okHandler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fix", nil)
	// No X-Exalm-Request header — simulates a cross-origin browser request.
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("POST without X-Exalm-Request should return 403, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "csrf") {
		t.Errorf("expected csrf error in body, got: %s", rr.Body.String())
	}
}

func TestRequireCSRF_InvalidOrigin_Returns403(t *testing.T) {
	h := requireCSRF(okHandler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fix", nil)
	req.Header.Set("X-Exalm-Request", "true")
	req.Header.Set("Origin", "https://evil.example.com")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("POST with non-localhost origin should return 403, got %d", rr.Code)
	}
}

func TestRequireCSRF_LocalhostOrigin_Passes(t *testing.T) {
	h := requireCSRF(okHandler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fix", nil)
	req.Header.Set("X-Exalm-Request", "true")
	req.Header.Set("Origin", "http://localhost:7433")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("POST with localhost origin should pass, got %d", rr.Code)
	}
}

// ── Prometheus metrics test ───────────────────────────────────────────────────

func TestHandleMetrics_PrometheusFormat(t *testing.T) {
	report := plugin.Report{
		Findings: []plugin.Finding{
			{Severity: plugin.SeverityHigh, Title: "test finding"},
		},
	}
	srv := newTestServer(report)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	srv.handleMetrics(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"exalm_uptime_seconds",
		"exalm_findings_total",
		"exalm_report_refreshes_total",
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected metric %q in response", want)
		}
	}
}

// ── Auto-refresh (analyze-mode) tests ─────────────────────────────────────────

func TestRefreshOnce_UpdatesFindingsPreservesNarrative(t *testing.T) {
	srv := newTestServer(plugin.Report{
		Title:   "K8s analysis",
		Summary: "initial",
		Raw:     "## VERDICT\nthe one-shot narrative",
		Findings: []plugin.Finding{
			{Severity: plugin.SeverityCritical, Title: "old/pod-aaa"},
		},
	})
	srv.refreshFindings = func(_ context.Context) ([]plugin.Finding, error) {
		return []plugin.Finding{
			{Severity: plugin.SeverityHigh, Title: "new/pod-bbb"},
			{Severity: plugin.SeverityLow, Title: "new/pod-ccc"},
		}, nil
	}

	srv.refreshOnce(context.Background())

	got := srv.getReport()
	if len(got.Findings) != 2 {
		t.Fatalf("expected 2 refreshed findings, got %d", len(got.Findings))
	}
	if got.Findings[0].Title != "new/pod-bbb" {
		t.Errorf("findings not refreshed: got %q", got.Findings[0].Title)
	}
	if got.Raw != "## VERDICT\nthe one-shot narrative" {
		t.Errorf("LLM narrative (Raw) must be preserved across a findings refresh, got %q", got.Raw)
	}
	if got.Title != "K8s analysis" {
		t.Errorf("Title must be preserved, got %q", got.Title)
	}
}

func TestRefreshOnce_ErrorKeepsLastGood(t *testing.T) {
	original := []plugin.Finding{{Severity: plugin.SeverityCritical, Title: "keep/me"}}
	srv := newTestServer(plugin.Report{Findings: original})
	srv.refreshFindings = func(_ context.Context) ([]plugin.Finding, error) {
		return nil, errors.New("cluster unreachable")
	}

	srv.refreshOnce(context.Background())

	got := srv.getReport()
	if len(got.Findings) != 1 || got.Findings[0].Title != "keep/me" {
		t.Errorf("a refresh error must keep the last good findings, got %+v", got.Findings)
	}
}

func TestRefreshOnce_NilCallbackNoOp(t *testing.T) {
	srv := newTestServer(plugin.Report{Findings: []plugin.Finding{{Title: "x"}}})
	// refreshFindings left nil — must not panic and must leave findings intact.
	srv.refreshOnce(context.Background())
	if len(srv.getReport().Findings) != 1 {
		t.Error("nil refreshFindings should be a no-op")
	}
}

func TestHandleFix_AppliesThenReCollects(t *testing.T) {
	var appliedKind string
	srv := newTestServer(plugin.Report{
		Findings: []plugin.Finding{{Severity: plugin.SeverityCritical, Title: "stale/pod"}},
	})
	srv.fixSem = make(chan struct{}, maxConcurrentFixes)
	srv.applyFix = func(_ context.Context, a plugin.RemediationAction) error {
		appliedKind = a.Kind
		return nil
	}
	srv.refreshFindings = func(_ context.Context) ([]plugin.Finding, error) {
		// After the fix the stale pod is gone.
		return []plugin.Finding{}, nil
	}

	body, _ := json.Marshal(plugin.RemediationAction{Kind: "delete-pod"})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fix", strings.NewReader(string(body)))
	srv.handleFix(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if appliedKind != "delete-pod" {
		t.Errorf("applyFix should have received the posted action, got kind %q", appliedKind)
	}
	if n := len(srv.getReport().Findings); n != 0 {
		t.Errorf("handleFix must re-collect after applying; expected 0 findings, got %d", n)
	}
}

func TestHandleFixAll_OrdersAppliesAllAndReCollects(t *testing.T) {
	var appliedOrder []string
	srv := newTestServer(plugin.Report{
		Findings: []plugin.Finding{
			{Title: "no-fix"}, // no Remediation — must be skipped
			{Title: "z-delete", Remediation: &plugin.RemediationAction{Kind: "delete-pod"}},
			{Title: "a-restart", Remediation: &plugin.RemediationAction{Kind: "rollout-restart"}},
		},
	})
	srv.fixSem = make(chan struct{}, maxConcurrentFixes)
	srv.applyFix = func(_ context.Context, a plugin.RemediationAction) error {
		appliedOrder = append(appliedOrder, a.Kind)
		if a.Kind == "delete-pod" {
			return errors.New("delete failed")
		}
		return nil
	}
	srv.refreshFindings = func(_ context.Context) ([]plugin.Finding, error) {
		return []plugin.Finding{}, nil // fixed
	}

	rr := httptest.NewRecorder()
	srv.handleFixAll(rr, httptest.NewRequest(http.MethodPost, "/api/fix-all", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if !reflect.DeepEqual(appliedOrder, []string{"rollout-restart", "delete-pod"}) {
		t.Errorf("expected restart applied before delete, got %v", appliedOrder)
	}

	var results []remediation.Result
	if err := json.Unmarshal(rr.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results (no-fix skipped), got %+v", results)
	}
	if results[0].Title != "a-restart" || !results[0].OK {
		t.Errorf("result[0]: %+v", results[0])
	}
	if results[1].Title != "z-delete" || results[1].OK || results[1].Error != "delete failed" {
		t.Errorf("result[1]: %+v", results[1])
	}
	if n := len(srv.getReport().Findings); n != 0 {
		t.Errorf("handleFixAll must re-collect after applying; expected 0 findings, got %d", n)
	}
}

func TestHandleFixAll_Unwired503AndGateChecks(t *testing.T) {
	srv := newTestServer(plugin.Report{})
	srv.fixSem = make(chan struct{}, maxConcurrentFixes)

	rr := httptest.NewRecorder()
	srv.handleFixAll(rr, httptest.NewRequest(http.MethodPost, "/api/fix-all", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("unwired should 503, got %d", rr.Code)
	}

	srv.applyFix = func(context.Context, plugin.RemediationAction) error { return nil }
	rr = httptest.NewRecorder()
	srv.handleFixAll(rr, httptest.NewRequest(http.MethodGet, "/api/fix-all", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET should 405, got %d", rr.Code)
	}

	for i := 0; i < maxConcurrentFixes; i++ { // fill the gate
		srv.fixSem <- struct{}{}
	}
	rr = httptest.NewRecorder()
	srv.handleFixAll(rr, httptest.NewRequest(http.MethodPost, "/api/fix-all", nil))
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("full gate should 429, got %d", rr.Code)
	}
}

func TestHandleDashboard_AutoRefreshFlag(t *testing.T) {
	// The redesigned dashboard is client-rendered; the autoRefresh flag rides in
	// the embedded JSON blob (window.__DASH__), not in server-rendered markup.
	cases := []struct {
		autoRefresh bool
		want        string
	}{
		{true, `"autoRefresh":true`},
		{false, `"autoRefresh":false`},
	}
	for _, tc := range cases {
		srv := newTestServer(plugin.Report{Title: "t", Findings: []plugin.Finding{{Title: "f"}}})
		srv.autoRefresh = tc.autoRefresh
		rr := httptest.NewRecorder()
		srv.handleDashboard(rr, httptest.NewRequest("GET", "/", nil))
		body := rr.Body.String()
		if !strings.Contains(body, tc.want) {
			t.Errorf("autoRefresh=%v: expected embedded JSON to contain %q", tc.autoRefresh, tc.want)
		}
		if !strings.Contains(body, "/static/dashboard.js") {
			t.Error("expected the dashboard to load /static/dashboard.js")
		}
		// logexplorer.js must load before its two consumers (analyzer.js,
		// logviewer.js) — definition-before-use across the module set.
		leIdx := strings.Index(body, "/static/logexplorer.js")
		if leIdx == -1 {
			t.Error("expected the dashboard to load /static/logexplorer.js")
		} else if anIdx := strings.Index(body, "/static/analyzer.js"); anIdx != -1 && leIdx > anIdx {
			t.Error("logexplorer.js must load before analyzer.js")
		}
	}
}
