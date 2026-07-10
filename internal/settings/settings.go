// Package settings persists user-facing dashboard preferences at
// ~/.exalm/settings.json. It follows the internal/convo file-store pattern:
// an override var for tests, 0o700 directory / 0o600 file permissions, and
// atomic temp-file + rename writes.
//
// Settings are preferences, not security controls: disabling a dashboard
// hides it from the UI and its scoped API routes, but authentication remains
// the web server's token middleware.
package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SettingsDir overrides the directory holding settings.json. Empty means
// ~/.exalm. Tests point it at t.TempDir().
var SettingsDir string

// Dashboards holds the per-dashboard visibility preferences.
type Dashboards struct {
	// EnableAll shows every registered dashboard regardless of Enabled.
	EnableAll bool `json:"enableAll"`
	// Enabled maps dashboard ID to visibility. A missing key defaults to
	// enabled, so newly added plugins appear without a settings migration.
	Enabled map[string]bool `json:"enabled,omitempty"`
}

// Settings is the persisted preference document.
type Settings struct {
	Dashboards Dashboards `json:"dashboards"`
	// SupportsAI globally toggles AI affordances (chat, ✦ analyze, invest-
	// igations) across every dashboard.
	SupportsAI bool `json:"supportsAI"`
	// Version is the schema version, for future migrations.
	Version int `json:"version"`
}

// Default returns the out-of-the-box settings: everything on.
func Default() Settings {
	return Settings{
		Dashboards: Dashboards{EnableAll: true},
		SupportsAI: true,
		Version:    1,
	}
}

// DashboardEnabled reports whether the dashboard should be visible.
// A dashboard absent from the Enabled map defaults to enabled; an Enabled
// map that disables everything is treated as EnableAll so a bad write can
// never brick the UI.
func (s Settings) DashboardEnabled(id string) bool {
	if s.Dashboards.EnableAll {
		return true
	}
	if len(s.Dashboards.Enabled) == 0 {
		return true
	}
	on, ok := s.Dashboards.Enabled[id]
	if !ok {
		return true
	}
	if !on && allDisabled(s.Dashboards.Enabled) {
		return true
	}
	return on
}

// allDisabled reports whether every entry in the map is false.
func allDisabled(m map[string]bool) bool {
	for _, on := range m {
		if on {
			return false
		}
	}
	return true
}

// Store reads and writes the settings file. Safe for concurrent use.
type Store struct {
	mu sync.Mutex
}

// NewStore returns a settings store bound to SettingsDir (or ~/.exalm).
func NewStore() *Store { return &Store{} }

// baseDir resolves the settings directory.
func baseDir() (string, error) {
	if SettingsDir != "" {
		return SettingsDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".exalm"), nil
}

// path resolves the settings file path.
func path() (string, error) {
	dir, err := baseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "settings.json"), nil
}

// Get loads the persisted settings. A missing file returns Default() with
// no error; a corrupt file returns an error (never a half-parsed document).
func (st *Store) Get() (Settings, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, err := path()
	if err != nil {
		return Settings{}, err
	}
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("read settings: %w", err)
	}
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return Settings{}, fmt.Errorf("parse settings: %w", err)
	}
	if s.Version == 0 {
		s.Version = 1
	}
	return s, nil
}

// Put persists the settings atomically (temp file + rename).
func (st *Store) Put(s Settings) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	dir, err := baseDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create settings dir: %w", err)
	}
	if s.Version == 0 {
		s.Version = 1
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode settings: %w", err)
	}
	p := filepath.Join(dir, "settings.json")
	tmp, err := os.CreateTemp(dir, ".settings-*.json")
	if err != nil {
		return fmt.Errorf("create temp settings file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()        //nolint:errcheck // best-effort cleanup on write failure
		os.Remove(tmpName) //nolint:errcheck
		return fmt.Errorf("write settings: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) //nolint:errcheck
		return fmt.Errorf("close settings file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName) //nolint:errcheck
		return fmt.Errorf("chmod settings file: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		os.Remove(tmpName) //nolint:errcheck
		return fmt.Errorf("persist settings: %w", err)
	}
	return nil
}
