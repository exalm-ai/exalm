package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/metrics"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func explainTestServer() (*liveServer, plugin.Finding) {
	f := plugin.Finding{
		Severity: plugin.SeverityCritical, Category: "Pods",
		Title:  "CrashLoopBackOff: prod/api-0",
		Detail: "Pod has restarted 22 times.",
		Source: "k8s/test",
		Remediation: &plugin.RemediationAction{
			Kind: "delete-pod", Namespace: "prod", Name: "api-0", FixType: "temporary",
		},
		Confidence: "high",
	}
	srv := newTestServer(plugin.Report{Title: "t", Findings: []plugin.Finding{f}})
	srv.fixSem = make(chan struct{}, maxConcurrentFixes)
	srv.investigateSem = make(chan struct{}, maxConcurrentFixes)
	return srv, f
}

func TestHandleFinding_Detail(t *testing.T) {
	srv, f := explainTestServer()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings/"+f.ID(), nil)
	srv.handleFinding(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "CrashLoopBackOff") {
		t.Errorf("detail should include the finding title, got: %s", rr.Body.String())
	}
}

func TestHandleFinding_InvestigateWired(t *testing.T) {
	srv, f := explainTestServer()
	srv.investigateFn = func(_ context.Context, id string) (*plugin.Investigation, error) {
		return &plugin.Investigation{Summary: "root cause here", Confidence: "high",
			Steps: []plugin.InvestigationStep{{Label: "Pod logs inspected", Status: "done"}}}, nil
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/findings/"+f.ID()+"/investigate", nil)
	srv.handleFinding(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "root cause here") {
		t.Errorf("expected investigation summary in response, got: %s", rr.Body.String())
	}
}

func TestHandleFinding_InvestigateUnwiredReturns503(t *testing.T) {
	srv, f := explainTestServer() // investigateFn nil
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/findings/"+f.ID()+"/investigate", nil)
	srv.handleFinding(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when investigation is unwired, got %d", rr.Code)
	}
}

func TestHandleLogs(t *testing.T) {
	srv, _ := explainTestServer()
	// Unwired → 503.
	rr := httptest.NewRecorder()
	srv.handleLogs(rr, httptest.NewRequest(http.MethodGet, "/api/logs?pod=x", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 without LogFetch, got %d", rr.Code)
	}
	// Missing pod → 400.
	srv.logFetchFn = func(_ context.Context, ns, pod, c string, prev bool, tail int) (string, error) {
		return "line1\nline2", nil
	}
	rr = httptest.NewRecorder()
	srv.handleLogs(rr, httptest.NewRequest(http.MethodGet, "/api/logs", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 with no pod, got %d", rr.Code)
	}
	// Happy path.
	rr = httptest.NewRecorder()
	srv.handleLogs(rr, httptest.NewRequest(http.MethodGet, "/api/logs?pod=api-0&ns=prod", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "line1") {
		t.Errorf("expected 200 with log lines, got %d: %s", rr.Code, rr.Body.String())
	}
}

// stubMetrics is a minimal metrics.Provider for the endpoint test.
type stubMetrics struct{}

func (stubMetrics) Available() bool { return true }
func (stubMetrics) Series(_ context.Context, _ metrics.Query) ([]metrics.Series, error) {
	return []metrics.Series{{Name: "Findings activity", Modeled: true, Threshold: 5,
		Points: []metrics.Point{{T: time.Unix(0, 0), V: 3}}}}, nil
}

func TestHandleMetricsJSON(t *testing.T) {
	srv, _ := explainTestServer()
	// No provider → "[]".
	rr := httptest.NewRecorder()
	srv.handleMetricsJSON(rr, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))
	if strings.TrimSpace(rr.Body.String()) != "[]" {
		t.Errorf("expected [] without a metrics provider, got: %s", rr.Body.String())
	}
	// With provider → series JSON.
	srv.metrics = stubMetrics{}
	rr = httptest.NewRecorder()
	srv.handleMetricsJSON(rr, httptest.NewRequest(http.MethodGet, "/api/metrics?window=24h", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Findings activity") {
		t.Errorf("expected series JSON, got %d: %s", rr.Code, rr.Body.String())
	}
}
