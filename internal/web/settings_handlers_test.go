package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/internal/settings"
)

func TestHandleSettings_Unwired503(t *testing.T) {
	s := &liveServer{}
	rec := httptest.NewRecorder()
	s.handleSettings(rec, httptest.NewRequest("GET", "/api/settings", nil))
	if rec.Code != 503 {
		t.Errorf("expected 503 without a settings store, got %d", rec.Code)
	}
}

func TestHandleSettings_GetDefaultThenPut(t *testing.T) {
	settings.SettingsDir = t.TempDir()
	t.Cleanup(func() { settings.SettingsDir = "" })
	s := &liveServer{settings: settings.NewStore()}

	rec := httptest.NewRecorder()
	s.handleSettings(rec, httptest.NewRequest("GET", "/api/settings", nil))
	if rec.Code != 200 {
		t.Fatalf("GET: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"enableAll":true`) {
		t.Errorf("expected default enableAll:true, got %s", rec.Body.String())
	}

	body := `{"dashboards":{"enableAll":false,"enabled":{"dora":false,"k8s":true}},"supportsAI":true,"version":1}`
	rec = httptest.NewRecorder()
	s.handleSettings(rec, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("PUT: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"dora":false`) {
		t.Errorf("PUT response should echo the stored document, got %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.handleSettings(rec, httptest.NewRequest("GET", "/api/settings", nil))
	if !strings.Contains(rec.Body.String(), `"enableAll":false`) {
		t.Errorf("expected persisted enableAll:false, got %s", rec.Body.String())
	}
}

func TestHandleSettings_BadJSONAndMethod(t *testing.T) {
	settings.SettingsDir = t.TempDir()
	t.Cleanup(func() { settings.SettingsDir = "" })
	s := &liveServer{settings: settings.NewStore()}

	rec := httptest.NewRecorder()
	s.handleSettings(rec, httptest.NewRequest("PUT", "/api/settings", strings.NewReader("{oops")))
	if rec.Code != 400 {
		t.Errorf("expected 400 for bad JSON, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleSettings(rec, httptest.NewRequest("DELETE", "/api/settings", nil))
	if rec.Code != 405 {
		t.Errorf("expected 405 for DELETE, got %d", rec.Code)
	}
}
