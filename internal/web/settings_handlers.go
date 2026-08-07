package web

// settings_handlers.go — GET/PUT /api/settings, backed by the persisted
// preference store at ~/.exalm/settings.json (internal/settings). Settings
// are preferences (dashboard visibility, AI affordances), not security
// controls; auth stays with the token middleware.

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/exalm-ai/exalm/internal/settings"
)

// maxSettingsBody bounds the PUT body — a settings document is tiny.
const maxSettingsBody = 64 * 1024

// handleSettings serves the persisted dashboard preferences.
//
//	GET  /api/settings → current Settings (Default() when no file exists)
//	PUT  /api/settings → validate + persist, echo the stored document
func (s *liveServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		http.Error(w, "settings not available on this server", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		cur, err := s.settings.Get()
		if err != nil {
			http.Error(w, "load settings: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cur) //nolint:errcheck
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, maxSettingsBody+1))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(body) > maxSettingsBody {
			http.Error(w, "settings document too large", http.StatusRequestEntityTooLarge)
			return
		}
		var next settings.Settings
		if err := json.Unmarshal(body, &next); err != nil {
			http.Error(w, "parse settings: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.settings.Put(next); err != nil {
			http.Error(w, "persist settings: "+err.Error(), http.StatusInternalServerError)
			return
		}
		stored, err := s.settings.Get()
		if err != nil {
			http.Error(w, "reload settings: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stored) //nolint:errcheck
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// currentSettings returns the effective settings: the persisted document
// when a store is wired, Default() otherwise. Errors degrade to Default()
// so a corrupt settings file can never blank the dashboard.
func (s *liveServer) currentSettings() settings.Settings {
	if s.settings == nil {
		return settings.Default()
	}
	cur, err := s.settings.Get()
	if err != nil {
		return settings.Default()
	}
	return cur
}
