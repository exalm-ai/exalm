package settings

// sqlite.go — optional SQLite persistence for the settings document, selected
// at process start the same way plugins/incident and internal/convo switch
// backends: cmd/exalm calls SetSettingsDB(db) after opening ~/.exalm/exalm.db,
// and the concrete Store branches inside Get/Put. web.Options keeps its
// concrete *Store type, so no handler or wiring changes anywhere.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
)

// settingsDB switches the Store from settings.json to SQLite. Nil = file store.
var settingsDB atomic.Pointer[sql.DB]

// SetSettingsDB configures the settings package to persist via db.
// Passing nil reverts to the JSON file store. Call before the web server
// starts serving; the switch is process-wide.
func SetSettingsDB(db *sql.DB) {
	settingsDB.Store(db)
}

// sqliteGet loads the single settings row. An empty table returns Default()
// with no error (mirrors the file store's missing-file behavior); a corrupt
// document returns an error, never a half-parsed one.
func sqliteGet(db *sql.DB) (Settings, error) {
	var data string
	err := db.QueryRow(`SELECT data FROM settings WHERE id = 1`).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return Default(), nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("read settings row: %w", err)
	}
	var s Settings
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		return Settings{}, fmt.Errorf("parse settings row: %w", err)
	}
	if s.Version == 0 {
		s.Version = 1
	}
	return s, nil
}

// sqlitePut upserts the single settings row.
func sqlitePut(db *sql.DB, s Settings) error {
	if s.Version == 0 {
		s.Version = 1
	}
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode settings: %w", err)
	}
	_, err = db.Exec(
		`INSERT INTO settings(id, data, updated_at) VALUES(1, ?, datetime('now'))
		 ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
		string(data),
	)
	if err != nil {
		return fmt.Errorf("persist settings row: %w", err)
	}
	return nil
}
