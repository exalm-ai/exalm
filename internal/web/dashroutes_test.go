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

// ── incident action route tests ───────────────────────────────────────────────

// incidentActionMux registers the action route the way Serve() does, with a
// fake action closure that records the request it received.
func incidentActionMux(s *liveServer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/dashboards/incidents/action", s.handleIncidentAction)
	return mux
}

func postIncidentAction(mux *http.ServeMux, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/dashboards/incidents/action", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)
	return rec
}

func TestIncidentAction_OpenHappyPath(t *testing.T) {
	var got IncidentActionRequest
	s := &liveServer{
		dashboards: testRegistry(),
		incidentActFn: func(_ context.Context, req IncidentActionRequest) (any, error) {
			got = req
			return map[string]string{"id": "INC-1", "status": "open"}, nil
		},
	}
	rec := postIncidentAction(incidentActionMux(s), `{"action":"open","title":"db down","severity":"high","service":"db"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("open: got %d %s", rec.Code, rec.Body.String())
	}
	if got.Title != "db down" || got.Severity != "high" || got.Service != "db" {
		t.Errorf("closure received wrong request: %+v", got)
	}
}

func TestIncidentAction_Validation(t *testing.T) {
	s := &liveServer{
		dashboards: testRegistry(),
		incidentActFn: func(_ context.Context, _ IncidentActionRequest) (any, error) {
			t.Error("closure must not run on invalid input")
			return nil, nil
		},
	}
	mux := incidentActionMux(s)
	cases := []struct {
		name, body string
	}{
		{"open without title", `{"action":"open"}`},
		{"close without id", `{"action":"close"}`},
		{"reopen without id", `{"action":"reopen"}`},
		{"unknown action", `{"action":"delete","id":"INC-1"}`},
		{"invalid json", `{{{`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rec := postIncidentAction(mux, tc.body); rec.Code != 400 {
				t.Errorf("got %d %s, want 400", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIncidentAction_UnwiredReturns503(t *testing.T) {
	s := &liveServer{dashboards: testRegistry()}
	if rec := postIncidentAction(incidentActionMux(s), `{"action":"open","title":"t"}`); rec.Code != 503 {
		t.Errorf("got %d, want 503 when the action closure is nil", rec.Code)
	}
}

func TestIncidentAction_ClosureErrorReturns422(t *testing.T) {
	s := &liveServer{
		dashboards: testRegistry(),
		incidentActFn: func(_ context.Context, _ IncidentActionRequest) (any, error) {
			return nil, context.DeadlineExceeded
		},
	}
	if rec := postIncidentAction(incidentActionMux(s), `{"action":"close","id":"INC-1"}`); rec.Code != 422 {
		t.Errorf("got %d, want 422 on closure error", rec.Code)
	}
}
