package convo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// sqliteConvoStore implements Store against the SQLite 'conversations' table
// managed by internal/store. The full Conversation is marshalled to JSON in
// the 'data' column; indexed columns (id, finding_id, updated_at) support the
// lookups the chat endpoints need.
type sqliteConvoStore struct{ db *sql.DB }

// NewSQLiteStore returns a conversation Store backed by db. db must have been
// opened with internal/store.Open(), which ensures the schema.
func NewSQLiteStore(db *sql.DB) Store { return &sqliteConvoStore{db: db} }

func (s *sqliteConvoStore) Create(_ context.Context, c plugin.Conversation) error {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("sqlite convo: marshal: %w", err)
	}
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO conversations(id,finding_id,namespace,created_at,updated_at,data) VALUES(?,?,?,?,?,?)`,
		c.ID, c.FindingID, c.Namespace,
		c.CreatedAt.UTC().Format(time.RFC3339), c.UpdatedAt.UTC().Format(time.RFC3339),
		string(data),
	)
	if err != nil {
		return fmt.Errorf("sqlite convo: create %s: %w", c.ID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("conversation %s already exists", c.ID)
	}
	return nil
}

func (s *sqliteConvoStore) Get(_ context.Context, id string) (plugin.Conversation, error) {
	var data string
	err := s.db.QueryRow(`SELECT data FROM conversations WHERE id = ?`, id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return plugin.Conversation{}, fmt.Errorf("conversation %s not found", id)
	}
	if err != nil {
		return plugin.Conversation{}, fmt.Errorf("sqlite convo: get %s: %w", id, err)
	}
	return unmarshalConvo(data)
}

func (s *sqliteConvoStore) List(_ context.Context) ([]plugin.Conversation, error) {
	rows, err := s.db.Query(`SELECT data FROM conversations ORDER BY updated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite convo: list: %w", err)
	}
	defer rows.Close()
	return scanConvoRows(rows)
}

func (s *sqliteConvoStore) ListByFocus(_ context.Context, focus, namespace string) ([]plugin.Conversation, error) {
	// Namespace is an indexed column; focus lives only inside the JSON blob,
	// so narrow by namespace in SQL and filter focus in Go (bounded scan —
	// conversations are small and capped by the recent-first LIMIT).
	query, args := `SELECT data FROM conversations ORDER BY updated_at DESC LIMIT 100`, []any{}
	if namespace != "" {
		query = `SELECT data FROM conversations WHERE namespace IN (?, '') ORDER BY updated_at DESC LIMIT 100`
		args = append(args, namespace)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite convo: list by focus: %w", err)
	}
	defer rows.Close()
	convos, err := scanConvoRows(rows)
	if err != nil {
		return nil, err
	}
	return filterByFocus(convos, focus, namespace), nil
}

func (s *sqliteConvoStore) Update(_ context.Context, c plugin.Conversation) error {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("sqlite convo: marshal: %w", err)
	}
	res, err := s.db.Exec(
		`UPDATE conversations SET finding_id=?, namespace=?, updated_at=?, data=? WHERE id=?`,
		c.FindingID, c.Namespace, c.UpdatedAt.UTC().Format(time.RFC3339), string(data), c.ID,
	)
	if err != nil {
		return fmt.Errorf("sqlite convo: update %s: %w", c.ID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Upsert semantics: a chat turn may arrive before Create ran (e.g.
		// after a restart with an unknown conversationId from the client).
		return s.Create(context.Background(), c)
	}
	return nil
}

// scanConvoRows unmarshals the 'data' column of each row into a Conversation.
// Rows with malformed JSON are silently skipped.
func scanConvoRows(rows *sql.Rows) ([]plugin.Conversation, error) {
	var convos []plugin.Conversation
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("sqlite convo: scan: %w", err)
		}
		c, err := unmarshalConvo(data)
		if err != nil {
			continue // skip malformed rows
		}
		convos = append(convos, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite convo: rows: %w", err)
	}
	sort.Slice(convos, func(i, j int) bool {
		return convos[i].UpdatedAt.After(convos[j].UpdatedAt)
	})
	return convos, nil
}

func unmarshalConvo(data string) (plugin.Conversation, error) {
	var c plugin.Conversation
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return plugin.Conversation{}, fmt.Errorf("sqlite convo: parse: %w", err)
	}
	return c, nil
}
