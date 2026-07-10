package web

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/internal/settings"
)

func testRegistry() []DashboardDesc {
	reg := BuiltinDashboards(true)
	return append(reg, AnalyzerDashboards([]string{"syslog", "httplog"})...)
}

func TestBuiltinDashboards_K8sGating(t *testing.T) {
	withK8s := BuiltinDashboards(true)
	if withK8s[0].ID != "k8s" {
		t.Errorf("expected k8s first with hasK8s=true, got %q", withK8s[0].ID)
	}
	for _, d := range BuiltinDashboards(false) {
		if d.ID == "k8s" {
			t.Error("k8s dashboard should be absent with hasK8s=false")
		}
	}
}

func TestAnalyzerDashboards_SortedAndKnownOnly(t *testing.T) {
	ds := AnalyzerDashboards([]string{"syslog", "nope", "httplog"})
	if len(ds) != 2 || ds[0].ID != "httplog" || ds[1].ID != "syslog" {
		t.Errorf("expected sorted [httplog syslog], got %+v", ds)
	}
	if len(ds[0].Widgets) == 0 || !ds[0].SupportsAI {
		t.Errorf("analyzer descriptor missing widgets or AI support: %+v", ds[0])
	}
}

func TestHandleDashboardsJSON_SettingsFiltering(t *testing.T) {
	settings.SettingsDir = t.TempDir()
	t.Cleanup(func() { settings.SettingsDir = "" })
	store := settings.NewStore()
	s := &liveServer{dashboards: testRegistry(), settings: store}

	rec := httptest.NewRecorder()
	s.handleDashboardsJSON(rec, httptest.NewRequest("GET", "/api/dashboards", nil))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp struct{ Dashboards []DashboardDesc }
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Dashboards) != 6 { // k8s dora timeline incidents httplog syslog
		t.Errorf("expected 6 dashboards, got %d: %+v", len(resp.Dashboards), resp.Dashboards)
	}

	// Disable dora + turn off AI globally.
	err := store.Put(settings.Settings{
		Dashboards: settings.Dashboards{Enabled: map[string]bool{"dora": false, "k8s": true}},
		SupportsAI: false, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	s.handleDashboardsJSON(rec, httptest.NewRequest("GET", "/api/dashboards", nil))
	body := rec.Body.String()
	if strings.Contains(body, `"id":"dora"`) {
		t.Error("disabled dora should be filtered out")
	}
	if strings.Contains(body, `"supportsAI":true`) {
		t.Error("global SupportsAI=false should clear every descriptor's AI flag")
	}
}

func TestDashboardPayload_RegistryStamping(t *testing.T) {
	// Legacy mode: no registry => payload has neither dashboards nor supportsAI.
	legacy := &liveServer{}
	p := dashboardPayload{}
	legacy.attachAnalyzer(&p)
	blob, _ := json.Marshal(p)
	if strings.Contains(string(blob), "dashboards") || strings.Contains(string(blob), "supportsAI") {
		t.Errorf("legacy payload must omit registry fields, got %s", blob)
	}

	// Registry mode: both stamped.
	reg := &liveServer{dashboards: testRegistry()}
	p2 := dashboardPayload{}
	reg.attachAnalyzer(&p2)
	if len(p2.Dashboards) == 0 || p2.SupportsAI == nil || !*p2.SupportsAI {
		t.Errorf("registry payload missing dashboards/supportsAI: %+v", p2)
	}
}
