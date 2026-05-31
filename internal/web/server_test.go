package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
