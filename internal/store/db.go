// Package store manages the Exalm SQLite database: schema creation, DB lifecycle,
// and one-time migrations from legacy file-based stores (JSONL deployments,
// per-incident JSON files).
//
// Design: the database lives at $HOME/.exalm/exalm.db. Key fields are stored in
// indexed columns for query performance; the full record is kept in a 'data' TEXT
// column (JSON) for forward compatibility. New fields added to plugin structs appear
// in 'data' without a schema migration.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // register "sqlite" driver in database/sql
)

// Open opens (or creates) the SQLite database at path and ensures the schema
// is up to date. WAL mode is enabled so that concurrent reads do not block writes.
// Caller must call db.Close() when done.
func Open(path string) (*sql.DB, error) {
	// DSN pragmas: WAL journal, FK enforcement, 5 s busy timeout.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// SQLite allows only one concurrent writer; WAL readers are non-blocking.
	db.SetMaxOpenConns(1)
	if err := applySchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	return db, nil
}

// DefaultPath returns the canonical path for the Exalm database
// ($HOME/.exalm/exalm.db) and creates the directory if it does not exist.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("store: home dir: %w", err)
	}
	dir := filepath.Join(home, ".exalm")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("store: mkdir %s: %w", dir, err)
	}
	return filepath.Join(dir, "exalm.db"), nil
}

// applySchema creates all tables and indexes if they do not already exist.
// The schema is intentionally minimal: domain logic lives in the plugins, not
// in the DB layer.
func applySchema(db *sql.DB) error {
	stmts := []string{
		// Deployments: one row per DeploymentEvent.
		// 'data' holds the full JSON blob; indexed columns enable window queries.
		`CREATE TABLE IF NOT EXISTS deployments (
			id          TEXT    PRIMARY KEY,
			service     TEXT    NOT NULL DEFAULT '',
			deployed_at TEXT    NOT NULL DEFAULT '',
			success     INTEGER NOT NULL DEFAULT 1,
			data        TEXT    NOT NULL DEFAULT '{}'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dep_at ON deployments(deployed_at)`,

		// Incidents: one row per Incident record.
		`CREATE TABLE IF NOT EXISTS incidents (
			id        TEXT PRIMARY KEY,
			status    TEXT NOT NULL DEFAULT 'open',
			opened_at TEXT NOT NULL DEFAULT '',
			closed_at TEXT,
			data      TEXT NOT NULL DEFAULT '{}'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_inc_at ON incidents(opened_at)`,

		// LLM usage: one row per Complete() call, keyed by a unique ID.
		// input_tokens + output_tokens are populated from CompleteResponse.
		`CREATE TABLE IF NOT EXISTS llm_usage (
			id            TEXT    PRIMARY KEY,
			recorded_at   TEXT    NOT NULL DEFAULT (datetime('now')),
			provider      TEXT    NOT NULL DEFAULT '',
			model         TEXT    NOT NULL DEFAULT '',
			plugin        TEXT    NOT NULL DEFAULT '',
			subcommand    TEXT    NOT NULL DEFAULT '',
			input_tokens  INTEGER NOT NULL DEFAULT 0,
			output_tokens INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_usage_at ON llm_usage(recorded_at)`,

		// Schema migrations: prevents duplicate migration runs across restarts.
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("exec %q: %w", s[:min(len(s), 40)], err)
		}
	}
	return nil
}
