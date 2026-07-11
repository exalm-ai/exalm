package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/internal/settings"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// newScopedMux builds a mux with just the scoped routes, mirroring Serve().
func newScopedMux(s *liveServer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/dashboards/{id}/stats", s.handleDashStats)
	mux.HandleFunc("GET /api/dashboards/{id}/logs", s.handleDashLogs)
	mux.HandleFunc("POST /api/dashboards/{id}/chat", s.handleDashChat)
	return mux
}

func TestDashRoutes_StatsScoping(t *testing.T) {
	s := &liveServer{
		dashboards:      testRegistry(),
		analyzer:        "syslog",
		analyzerStatsFn: func() any { return map[string]int{"n": 7} },
		incidentsFn:     func() any { return map[string]int{"open": 2} },
	}
	mux := newScopedMux(s)

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}

	if rec := get("/api/dashboards/syslog/stats"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"n":7`) {
		t.Errorf("live analyzer stats: got %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/api/dashboards/incidents/stats"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"open":2`) {
		t.Errorf("incidents stats: got %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/api/dashboards/httplog/stats"); rec.Code != 503 {
		t.Errorf("known-but-unattached dashboard should 503, got %d", rec.Code)
	}
	if rec := get("/api/dashboards/nope/stats"); rec.Code != 404 {
		t.Errorf("unknown dashboard should 404, got %d", rec.Code)
	}
}

func TestDashRoutes_DisabledDashboard404s(t *testing.T) {
	settings.SettingsDir = t.TempDir()
	t.Cleanup(func() { settings.SettingsDir = "" })
	store := settings.NewStore()
	if err := store.Put(settings.Settings{
		Dashboards: settings.Dashboards{Enabled: map[string]bool{"syslog": false, "k8s": true}},
		SupportsAI: true, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	s := &liveServer{
		dashboards:      testRegistry(),
		settings:        store,
		analyzer:        "syslog",
		analyzerStatsFn: func() any { return "x" },
	}
	rec := httptest.NewRecorder()
	newScopedMux(s).ServeHTTP(rec, httptest.NewRequest("GET", "/api/dashboards/syslog/stats", nil))
	if rec.Code != 404 {
		t.Errorf("disabled dashboard should 404, got %d", rec.Code)
	}
}

func TestDashRoutes_ChatAIGating(t *testing.T) {
	settings.SettingsDir = t.TempDir()
	t.Cleanup(func() { settings.SettingsDir = "" })
	store := settings.NewStore()
	if err := store.Put(settings.Settings{
		Dashboards: settings.Dashboards{EnableAll: true},
		SupportsAI: false, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	s := &liveServer{
		dashboards: testRegistry(),
		settings:   store,
		analyzer:   "syslog",
		converseFn: func(_ context.Context, _ ConverseRequest) (*plugin.Conversation, error) {
			return &plugin.Conversation{}, nil
		},
		chatSem: make(chan struct{}, 1),
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/dashboards/syslog/chat", strings.NewReader(`{"message":"hi"}`))
	newScopedMux(s).ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Errorf("chat with SupportsAI=false should 503, got %d: %s", rec.Code, rec.Body.String())
	}
}
