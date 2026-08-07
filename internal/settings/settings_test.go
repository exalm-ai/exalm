package settings

import (
	"os"
	"path/filepath"
	"testing"
)

func withTempDir(t *testing.T) {
	t.Helper()
	SettingsDir = t.TempDir()
	t.Cleanup(func() { SettingsDir = "" })
}

func TestGet_MissingFileReturnsDefault(t *testing.T) {
	withTempDir(t)
	s, err := NewStore().Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !s.Dashboards.EnableAll || !s.SupportsAI || s.Version != 1 {
		t.Errorf("expected Default(), got %+v", s)
	}
}

func TestPutGet_RoundTrip(t *testing.T) {
	withTempDir(t)
	st := NewStore()
	want := Settings{
		Dashboards: Dashboards{EnableAll: false, Enabled: map[string]bool{"dora": false, "syslog": true}},
		SupportsAI: false,
		Version:    1,
	}
	if err := st.Put(want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := st.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Dashboards.EnableAll || got.SupportsAI {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if got.Dashboards.Enabled["dora"] || !got.Dashboards.Enabled["syslog"] {
		t.Errorf("Enabled map mismatch: %+v", got.Dashboards.Enabled)
	}
}

func TestPut_Atomic_NoTempLeftBehind(t *testing.T) {
	withTempDir(t)
	if err := NewStore().Put(Default()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	entries, err := os.ReadDir(SettingsDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "settings.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected only settings.json, got %v", names)
	}
}

func TestGet_CorruptFileErrors(t *testing.T) {
	withTempDir(t)
	if err := os.WriteFile(filepath.Join(SettingsDir, "settings.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore().Get(); err == nil {
		t.Error("expected an error for a corrupt settings file")
	}
}

func TestDashboardEnabled(t *testing.T) {
	cases := []struct {
		name string
		s    Settings
		id   string
		want bool
	}{
		{"enable-all wins", Settings{Dashboards: Dashboards{EnableAll: true, Enabled: map[string]bool{"k8s": false}}}, "k8s", true},
		{"missing id defaults on", Settings{Dashboards: Dashboards{Enabled: map[string]bool{"dora": false}}}, "syslog", true},
		{"explicit off", Settings{Dashboards: Dashboards{Enabled: map[string]bool{"dora": false, "k8s": true}}}, "dora", false},
		{"explicit on", Settings{Dashboards: Dashboards{Enabled: map[string]bool{"dora": false, "k8s": true}}}, "k8s", true},
		{"empty map means all on", Settings{}, "anything", true},
		{"only-disabled entries: listed ids off, missing ids on", Settings{Dashboards: Dashboards{Enabled: map[string]bool{"a": false, "b": false}}}, "a", false},
		{"only-disabled entries: missing id stays on", Settings{Dashboards: Dashboards{Enabled: map[string]bool{"a": false, "b": false}}}, "c", true},
	}
	for _, tc := range cases {
		if got := tc.s.DashboardEnabled(tc.id); got != tc.want {
			t.Errorf("%s: DashboardEnabled(%q) = %v, want %v", tc.name, tc.id, got, tc.want)
		}
	}
}
