package dora

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// deployDB is set via SetDeployDB to switch all deployment store operations from
// the JSONL file to a SQLite database. Zero value (nil pointer) means the JSONL
// file store is used. The pointer is accessed atomically so that concurrent
// goroutines (web server, webhook handler) observe a consistent value without
// data races.
var deployDB atomic.Pointer[sql.DB]

// SetDeployDB configures the dora package to use db for all deployment
// persistence. Passing nil reverts to the JSONL file store.
// Must be called before the first appendDeployment or loadDeployments call.
func SetDeployDB(db *sql.DB) { deployDB.Store(db) }

// DeploymentDir overrides the default deployments directory when non-empty.
// Set this in tests via t.TempDir() to avoid polluting ~/.exalm/.
var DeploymentDir string

// deploymentsPath returns the path to the deployments JSONL file.
// Respects the DeploymentDir override for testing.
func deploymentsPath() (string, error) {
	if DeploymentDir != "" {
		return filepath.Join(DeploymentDir, "deployments.jsonl"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".exalm", "deployments.jsonl"), nil
}

// deployCounter provides monotonic suffix to ensure ID uniqueness within a second.
var deployCounter uint64

// newDeploymentID generates a unique deployment ID.
func newDeploymentID(now time.Time) string {
	n := atomic.AddUint64(&deployCounter, 1)
	return fmt.Sprintf("DEP-%s-%03d", now.UTC().Format("20060102-150405"), n)
}

// appendDeployment persists a single DeploymentEvent. When a SQLite database
// has been configured via SetDeployDB it is used; otherwise the record is
// appended to the JSONL file.
func appendDeployment(ev DeploymentEvent) error {
	if db := deployDB.Load(); db != nil {
		return (&sqliteDeployStore{db: db}).append(ev)
	}
	// JSONL file store fallback.
	path, err := deploymentsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create deployments dir: %w", err)
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal deployment: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is an internal data file from config
	if err != nil {
		return fmt.Errorf("open deployments file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	if _, err := fmt.Fprintf(f, "%s\n", data); err != nil {
		return fmt.Errorf("write deployment: %w", err)
	}
	return nil
}

// loadDeployments returns all recorded deployment events. When a SQLite database
// has been configured via SetDeployDB it is queried; otherwise the JSONL file is
// read. Returns an empty slice (no error) if no data exists yet.
func loadDeployments() ([]DeploymentEvent, error) {
	if db := deployDB.Load(); db != nil {
		return (&sqliteDeployStore{db: db}).load()
	}
	// JSONL file store fallback.
	path, err := deploymentsPath()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path) //nolint:gosec // G304: path is an internal data file from config
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open deployments file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var events []DeploymentEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var ev DeploymentEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			// Skip malformed lines rather than aborting the load.
			continue
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read deployments file: %w", err)
	}
	return events, nil
}

// AppendDeploymentPublic is the exported form of appendDeployment for use by
// the webhook handler and other external callers outside the dora package.
func AppendDeploymentPublic(ev DeploymentEvent) error {
	return appendDeployment(ev)
}

// loadDeploymentsInWindow filters events to those within [now-window, now].
// When SQLite is configured the query is pushed down to the database for
// efficiency; otherwise all records are loaded and filtered in memory.
func loadDeploymentsInWindow(window time.Duration) ([]DeploymentEvent, error) {
	if db := deployDB.Load(); db != nil {
		return (&sqliteDeployStore{db: db}).loadInWindow(window)
	}
	all, err := loadDeployments()
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().UTC().Add(-window)
	var result []DeploymentEvent
	for _, ev := range all {
		if ev.DeployedAt.After(cutoff) {
			result = append(result, ev)
		}
	}
	return result, nil
}
