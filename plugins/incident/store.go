package incident

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
	"time"
)

// incidentDB is set via SetIncidentDB to switch all incident store operations
// from JSON files to a SQLite database. Zero value (nil pointer) means the JSON
// file store is used. The pointer is accessed atomically so that concurrent
// goroutines observe a consistent value without data races.
var incidentDB atomic.Pointer[sql.DB]

// SetIncidentDB configures the incident package to use db for all store
// operations. Passing nil reverts to the JSON file store.
// Must be called before New() or NewFileStore().
func SetIncidentDB(db *sql.DB) { incidentDB.Store(db) }

// newStore returns the active Store implementation. When incidentDB is set it
// returns a SQLite-backed store; otherwise a JSON file store is returned.
func newStore() Store {
	if db := incidentDB.Load(); db != nil {
		return &sqliteIncStore{db: db}
	}
	return &fileStore{}
}

// IncidentDir overrides the default incidents directory when non-empty.
// Set this in tests via t.TempDir() to avoid polluting ~/.exalm/incidents/.
var IncidentDir string

// Store persists incident records between CLI invocations.
//
// fileStore uses JSON files in ~/.exalm/incidents/<id>.json.
// Each incident is one file; List reads all files in the directory.
type Store interface {
	Create(ctx context.Context, inc Incident) error
	Get(ctx context.Context, id string) (Incident, error)
	List(ctx context.Context) ([]Incident, error)
	Update(ctx context.Context, inc Incident) error
	QueryByDateRange(ctx context.Context, from, to time.Time) ([]Incident, error)
}

// baseDir returns the incidents directory path.
// It respects the IncidentDir override for testing.
func baseDir() (string, error) {
	if IncidentDir != "" {
		return IncidentDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".exalm", "incidents"), nil
}

// fileStore persists incident records as JSON files in baseDir().
// mu serialises Create and Update operations within a single process to
// prevent TOCTOU races on the existence check in Create and to give
// callers a clear last-write-wins semantic on Update.
type fileStore struct {
	mu sync.Mutex
}

// newFileStore returns the active Store (SQLite if configured, file otherwise).
// The name is retained for internal callers that predate the SQLite store.
func newFileStore() Store { return newStore() }

// NewFileStore returns the active Store. Exported for use by the DORA plugin
// which queries incidents for CFR and MTTR calculations. When SetIncidentDB has
// been called it returns the SQLite store; otherwise the JSON file store.
func NewFileStore() Store { return newStore() }

// Create writes a new incident file. Returns an error if the ID already exists.
func (s *fileStore) Create(_ context.Context, inc Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := baseDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create incidents dir: %w", err)
	}
	path := filepath.Join(dir, inc.ID+".json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("incident %s already exists", inc.ID)
	}
	return writeJSON(path, inc)
}

// Get reads the incident with the given ID.
func (s *fileStore) Get(_ context.Context, id string) (Incident, error) {
	dir, err := baseDir()
	if err != nil {
		return Incident{}, err
	}
	path := filepath.Join(dir, id+".json")
	return readJSON(path)
}

// List reads all incident files and returns them sorted by OpenedAt descending
// (most recent first).
func (s *fileStore) List(_ context.Context) ([]Incident, error) {
	dir, err := baseDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read incidents dir: %w", err)
	}

	var incidents []Incident
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		inc, err := readJSON(path)
		if err != nil {
			// Skip unreadable files rather than aborting the list.
			continue
		}
		incidents = append(incidents, inc)
	}

	sort.Slice(incidents, func(i, j int) bool {
		return incidents[i].OpenedAt.After(incidents[j].OpenedAt)
	})
	return incidents, nil
}

// Update overwrites an existing incident file.
func (s *fileStore) Update(_ context.Context, inc Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := baseDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, inc.ID+".json")
	return writeJSON(path, inc)
}

// QueryByDateRange returns incidents whose OpenedAt falls within [from, to].
func (s *fileStore) QueryByDateRange(ctx context.Context, from, to time.Time) ([]Incident, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	var result []Incident
	for _, inc := range all {
		if !inc.OpenedAt.Before(from) && !inc.OpenedAt.After(to) {
			result = append(result, inc)
		}
	}
	return result, nil
}

// writeJSON marshals inc to JSON and atomically writes it to path.
func writeJSON(path string, inc Incident) error {
	data, err := json.MarshalIndent(inc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal incident: %w", err)
	}
	// Write to a temp file in the same directory, then rename for atomicity.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".inc-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName) // best-effort cleanup; ignore error
		return fmt.Errorf("write incident: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName) // best-effort cleanup; ignore error
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName) // best-effort cleanup; ignore error
		return fmt.Errorf("rename incident file: %w", err)
	}
	return nil
}

// readJSON reads and unmarshals an incident from path.
func readJSON(path string) (Incident, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is an internal incident data file
	if err != nil {
		return Incident{}, fmt.Errorf("read incident file: %w", err)
	}
	var inc Incident
	if err := json.Unmarshal(data, &inc); err != nil {
		return Incident{}, fmt.Errorf("parse incident file %s: %w", path, err)
	}
	return inc, nil
}

// idCounter provides a monotonic suffix to ensure uniqueness within the same second.
var idCounter uint64

// newIncidentID returns a timestamp-based incident ID in the form INC-YYYYMMDD-HHMMSS-NNN.
// The three-digit suffix is a process-local counter that prevents collisions when
// multiple incidents are opened within the same second (common in tests).
func newIncidentID(now time.Time) string {
	n := atomic.AddUint64(&idCounter, 1)
	return fmt.Sprintf("%s-%03d", now.UTC().Format("INC-20060102-150405"), n)
}
