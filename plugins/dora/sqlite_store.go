package dora

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// sqliteDeployStore provides SQLite-backed deployment event persistence.
// It reads/writes from the 'deployments' table managed by internal/store.
type sqliteDeployStore struct{ db *sql.DB }

// append inserts ev into the deployments table. Duplicate IDs are silently
// ignored (INSERT OR IGNORE), which prevents double-counting when the webhook
// handler and CLI both record the same deployment.
func (s *sqliteDeployStore) append(ev DeploymentEvent) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("sqlite deploy: marshal: %w", err)
	}
	successInt := 0
	if ev.Success {
		successInt = 1
	}
	_, err = s.db.Exec(
		`INSERT OR IGNORE INTO deployments(id,service,deployed_at,success,data) VALUES(?,?,?,?,?)`,
		ev.ID,
		ev.Service,
		ev.DeployedAt.UTC().Format(time.RFC3339Nano),
		successInt,
		string(data),
	)
	if err != nil {
		return fmt.Errorf("sqlite deploy: insert: %w", err)
	}
	return nil
}

// load returns all deployment events ordered by deployed_at ascending.
func (s *sqliteDeployStore) load() ([]DeploymentEvent, error) {
	rows, err := s.db.Query(`SELECT data FROM deployments ORDER BY deployed_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite deploy: query all: %w", err)
	}
	defer rows.Close()
	return scanDeployRows(rows)
}

// loadInWindow returns deployment events whose deployed_at falls within
// [now-window, now], leveraging the idx_dep_at index.
func (s *sqliteDeployStore) loadInWindow(window time.Duration) ([]DeploymentEvent, error) {
	cutoff := time.Now().UTC().Add(-window).Format(time.RFC3339Nano)
	rows, err := s.db.Query(
		`SELECT data FROM deployments WHERE deployed_at >= ? ORDER BY deployed_at ASC`,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite deploy: query window: %w", err)
	}
	defer rows.Close()
	return scanDeployRows(rows)
}

// scanDeployRows unmarshals the 'data' column from each row into a DeploymentEvent.
// Rows with malformed JSON are silently skipped.
func scanDeployRows(rows *sql.Rows) ([]DeploymentEvent, error) {
	var events []DeploymentEvent
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("sqlite deploy: scan: %w", err)
		}
		var ev DeploymentEvent
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			continue // skip malformed rows; do not abort the load
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}
