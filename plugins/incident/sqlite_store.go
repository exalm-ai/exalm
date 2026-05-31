package incident

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// sqliteIncStore implements the Store interface against a SQLite 'incidents' table
// managed by internal/store. The full Incident struct is marshalled to JSON and
// stored in the 'data' column; indexed columns (id, status, opened_at, closed_at)
// support common filter queries.
type sqliteIncStore struct{ db *sql.DB }

// NewSQLiteStore returns an incident Store backed by db.
// db must have been opened with internal/store.Open(), which ensures the schema.
func NewSQLiteStore(db *sql.DB) Store { return &sqliteIncStore{db: db} }

// Create writes a new incident record. Returns an error if the ID already exists.
func (s *sqliteIncStore) Create(_ context.Context, inc Incident) error {
	data, err := json.Marshal(inc)
	if err != nil {
		return fmt.Errorf("sqlite incident: marshal: %w", err)
	}
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO incidents(id,status,opened_at,data) VALUES(?,?,?,?)`,
		inc.ID,
		string(inc.Status),
		inc.OpenedAt.UTC().Format(time.RFC3339),
		string(data),
	)
	if err != nil {
		return fmt.Errorf("sqlite incident: create %s: %w", inc.ID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("incident %s already exists", inc.ID)
	}
	return nil
}

// Get retrieves the incident with the given ID.
func (s *sqliteIncStore) Get(_ context.Context, id string) (Incident, error) {
	var data string
	err := s.db.QueryRow(`SELECT data FROM incidents WHERE id = ?`, id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return Incident{}, fmt.Errorf("incident %s not found", id)
	}
	if err != nil {
		return Incident{}, fmt.Errorf("sqlite incident: get %s: %w", id, err)
	}
	return unmarshalIncident(data)
}

// List returns all incidents sorted by OpenedAt descending (most recent first).
func (s *sqliteIncStore) List(_ context.Context) ([]Incident, error) {
	rows, err := s.db.Query(`SELECT data FROM incidents ORDER BY opened_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite incident: list: %w", err)
	}
	defer rows.Close()
	return scanIncidentRows(rows)
}

// Update overwrites an existing incident record with new field values.
func (s *sqliteIncStore) Update(_ context.Context, inc Incident) error {
	data, err := json.Marshal(inc)
	if err != nil {
		return fmt.Errorf("sqlite incident: marshal: %w", err)
	}
	var closedAt interface{}
	if inc.ClosedAt != nil {
		closedAt = inc.ClosedAt.UTC().Format(time.RFC3339)
	}
	res, err := s.db.Exec(
		`UPDATE incidents SET status=?, closed_at=?, data=? WHERE id=?`,
		string(inc.Status), closedAt, string(data), inc.ID,
	)
	if err != nil {
		return fmt.Errorf("sqlite incident: update %s: %w", inc.ID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("sqlite incident: update %s: not found", inc.ID)
	}
	return nil
}

// QueryByDateRange returns incidents whose OpenedAt falls within [from, to].
func (s *sqliteIncStore) QueryByDateRange(_ context.Context, from, to time.Time) ([]Incident, error) {
	rows, err := s.db.Query(
		`SELECT data FROM incidents WHERE opened_at >= ? AND opened_at <= ? ORDER BY opened_at DESC`,
		from.UTC().Format(time.RFC3339),
		to.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite incident: query range: %w", err)
	}
	defer rows.Close()
	return scanIncidentRows(rows)
}

// scanIncidentRows unmarshals the 'data' column of each row into an Incident.
// Rows with malformed JSON are silently skipped.
// The result is sorted by OpenedAt descending (newest first) after scanning —
// the ORDER BY in the query handles this for direct queries but re-sorting
// ensures correctness after any in-process filtering.
func scanIncidentRows(rows *sql.Rows) ([]Incident, error) {
	var incidents []Incident
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("sqlite incident: scan: %w", err)
		}
		inc, err := unmarshalIncident(data)
		if err != nil {
			continue // skip malformed rows
		}
		incidents = append(incidents, inc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite incident: rows: %w", err)
	}
	sort.Slice(incidents, func(i, j int) bool {
		return incidents[i].OpenedAt.After(incidents[j].OpenedAt)
	})
	return incidents, nil
}

// unmarshalIncident decodes a JSON string into an Incident.
func unmarshalIncident(data string) (Incident, error) {
	var inc Incident
	if err := json.Unmarshal([]byte(data), &inc); err != nil {
		return Incident{}, fmt.Errorf("sqlite incident: parse: %w", err)
	}
	return inc, nil
}
