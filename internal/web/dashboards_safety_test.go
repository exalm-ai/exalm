package web

import (
	"testing"

	"github.com/exalm-ai/exalm/internal/settings"
)

// TestEnabledDashboards_AllDisabledSafetyNet proves a settings file that
// disables every registered dashboard cannot brick the UI.
func TestEnabledDashboards_AllDisabledSafetyNet(t *testing.T) {
	settings.SettingsDir = t.TempDir()
	t.Cleanup(func() { settings.SettingsDir = "" })
	store := settings.NewStore()
	reg := testRegistry()
	off := map[string]bool{}
	for _, d := range reg {
		off[d.ID] = false
	}
	if err := store.Put(settings.Settings{
		Dashboards: settings.Dashboards{Enabled: off}, SupportsAI: true, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	s := &liveServer{dashboards: reg, settings: store}
	got := s.enabledDashboards()
	if len(got) != len(reg) {
		t.Errorf("all-disabled settings should degrade to the full registry, got %d of %d", len(got), len(reg))
	}
}
