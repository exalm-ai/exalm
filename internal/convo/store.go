// Package convo persists multi-turn investigation Conversations between CLI
// invocations. It is persistence-only — the conversation/evidence-gathering
// logic lives in plugins/k8s/converse.go; this package mirrors
// plugins/incident's Store pattern exactly: a SQLite-backed implementation
// when a *sql.DB is configured, falling back to JSON files in
// ~/.exalm/conversations/ otherwise.
package convo

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// convoDB is set via SetConvoDB to switch all conversation store operations
// from JSON files to a SQLite database. Zero value (nil pointer) means the
// JSON file store is used. Accessed atomically so concurrent goroutines see a
// consistent value without data races — mirrors plugins/incident/store.go.
var convoDB atomic.Pointer[sql.DB]

// SetConvoDB configures this package to use db for all store operations.
// Passing nil reverts to the JSON file store. Must be called before NewStore().
func SetConvoDB(db *sql.DB) { convoDB.Store(db) }

// ConversationDir overrides the default conversations directory when
// non-empty. Set this in tests via t.TempDir() to avoid touching
// ~/.exalm/conversations/.
var ConversationDir string

// Store persists Conversation records between CLI invocations / server
// restarts. The cached evidence gathered mid-conversation (logs, events,
// metrics) is deliberately NOT part of this interface — that cache is
// in-memory only, owned by the k8s plugin's conversation engine, and is
// rebuilt on demand. Only the message transcript (already redacted) persists.
type Store interface {
	Create(ctx context.Context, c plugin.Conversation) error
	Get(ctx context.Context, id string) (plugin.Conversation, error)
	List(ctx context.Context) ([]plugin.Conversation, error)
	Update(ctx context.Context, c plugin.Conversation) error
	// ListByFocus returns conversations about a focus resource ("ns/name"),
	// newest-updated first — feeds "has this happened before?" answers.
	// Namespace narrows the scan when the focus alone is ambiguous; either
	// argument may be empty to match all.
	ListByFocus(ctx context.Context, focus, namespace string) ([]plugin.Conversation, error)
}

// NewStore returns the active Store implementation: SQLite when SetConvoDB
// has been called, otherwise the JSON file store.
func NewStore() Store {
	if db := convoDB.Load(); db != nil {
		return &sqliteConvoStore{db: db}
	}
	return &fileStore{}
}

// baseDir returns the conversations directory path, respecting
// ConversationDir for tests.
func baseDir() (string, error) {
	if ConversationDir != "" {
		return ConversationDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".exalm", "conversations"), nil
}

// fileStore persists conversations as JSON files in baseDir().
// mu serialises Create/Update within a single process — same rationale as
// plugins/incident/store.go's fileStore: avoid a TOCTOU race on the
// existence check in Create and give a clear last-write-wins on Update.
type fileStore struct {
	mu sync.Mutex
}

func (s *fileStore) Create(_ context.Context, c plugin.Conversation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := baseDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create conversations dir: %w", err)
	}
	path := filepath.Join(dir, c.ID+".json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("conversation %s already exists", c.ID)
	}
	return writeJSON(path, c)
}

func (s *fileStore) Get(_ context.Context, id string) (plugin.Conversation, error) {
	dir, err := baseDir()
	if err != nil {
		return plugin.Conversation{}, err
	}
	return readJSON(filepath.Join(dir, id+".json"))
}

func (s *fileStore) List(_ context.Context) ([]plugin.Conversation, error) {
	dir, err := baseDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read conversations dir: %w", err)
	}

	var convos []plugin.Conversation
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		c, err := readJSON(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // skip unreadable files rather than aborting the list
		}
		convos = append(convos, c)
	}
	sort.Slice(convos, func(i, j int) bool {
		return convos[i].UpdatedAt.After(convos[j].UpdatedAt)
	})
	return convos, nil
}

func (s *fileStore) ListByFocus(ctx context.Context, focus, namespace string) ([]plugin.Conversation, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	return filterByFocus(all, focus, namespace), nil
}

// filterByFocus keeps conversations matching the focus and/or namespace.
// Shared by both store implementations (focus is not an indexed column, so
// SQLite also filters in Go after narrowing by namespace).
func filterByFocus(convos []plugin.Conversation, focus, namespace string) []plugin.Conversation {
	var out []plugin.Conversation
	for _, c := range convos {
		if focus != "" && c.Focus != focus {
			continue
		}
		if namespace != "" && c.Namespace != namespace && c.Namespace != "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

func (s *fileStore) Update(_ context.Context, c plugin.Conversation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := baseDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create conversations dir: %w", err)
	}
	return writeJSON(filepath.Join(dir, c.ID+".json"), c)
}

// writeJSON marshals c and atomically writes it to path (temp file + rename).
func writeJSON(path string, c plugin.Conversation) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal conversation: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".convo-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()            //nolint:errcheck // best-effort close before cleanup
		_ = os.Remove(tmpName) // best-effort cleanup; ignore error
		return fmt.Errorf("write conversation: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName) // best-effort cleanup; ignore error
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName) // best-effort cleanup; ignore error
		return fmt.Errorf("rename conversation file: %w", err)
	}
	return nil
}

// readJSON reads and unmarshals a conversation from path.
func readJSON(path string) (plugin.Conversation, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is an internal conversation data file
	if err != nil {
		return plugin.Conversation{}, fmt.Errorf("read conversation file: %w", err)
	}
	var c plugin.Conversation
	if err := json.Unmarshal(data, &c); err != nil {
		return plugin.Conversation{}, fmt.Errorf("parse conversation file %s: %w", path, err)
	}
	return c, nil
}
