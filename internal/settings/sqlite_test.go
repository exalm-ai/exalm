package settings

import (
	"path/filepath"
	"testing"

	exalmstore "github.com/exalm-ai/exalm/internal/store"
)

// openTestDB opens a throwaway SQLite DB and routes the settings package at
// it for the duration of the test. settingsDB is package-global, so cleanup
// MUST revert to nil or later tests would silently hit this DB.
func openTestDB(t *testing.T) {
	t.Helper()
	db, err := exalmstore.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	SetSettingsDB(db)
	t.Cleanup(func() {
		SetSettingsDB(nil)
		db.Close() //nolint:errcheck
	})
}

func TestSQLite_EmptyTableReturnsDefault(t *testing.T) {
	openTestDB(t)
	got, err := NewStore().Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Dashboards.EnableAll || !got.SupportsAI || got.Version != 1 {
		t.Errorf("empty table should yield Default(), got %+v", got)
	}
}

func TestSQLite_PutGetRoundTrip(t *testing.T) {
	openTestDB(t)
	st := NewStore()
	in := Settings{
		Dashboards: Dashboards{EnableAll: false, Enabled: map[string]bool{"dora": false, "k8s": true}},
		SupportsAI: false,
		// Version 0 exercises normalization.
	}
	if err := st.Put(in); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := st.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version not normalized: %d", got.Version)
	}
	if got.SupportsAI || got.Dashboards.EnableAll {
		t.Errorf("round-trip lost toggles: %+v", got)
	}
	if got.Dashboards.Enabled["dora"] || !got.Dashboards.Enabled["k8s"] {
		t.Errorf("round-trip lost Enabled map: %+v", got.Dashboards.Enabled)
	}

	// Second Put must overwrite (upsert), not accumulate rows.
	in.SupportsAI = true
	if err := st.Put(in); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	got, err = st.Get()
	if err != nil {
		t.Fatalf("Get after upsert: %v", err)
	}
	if !got.SupportsAI {
		t.Errorf("upsert did not overwrite: %+v", got)
	}
}

func TestSQLite_NilRevertsToFileStore(t *testing.T) {
	openTestDB(t)
	SetSettingsDB(nil)

	SettingsDir = t.TempDir()
	t.Cleanup(func() { SettingsDir = "" })

	st := NewStore()
	if err := st.Put(Settings{SupportsAI: true, Version: 1}); err != nil {
		t.Fatalf("file-store Put after revert: %v", err)
	}
	got, err := st.Get()
	if err != nil || !got.SupportsAI {
		t.Fatalf("file-store Get after revert: %+v, %v", got, err)
	}
}
