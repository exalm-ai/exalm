package dora

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/store"
)

// openTestDeployStore opens a fresh in-memory SQLite database for the test and
// returns a sqliteDeployStore that wraps it. Tests use the store struct directly
// rather than mutating the package-level deployDB global, so they are safe to
// run with t.Parallel().
func openTestDeployStore(t *testing.T) *sqliteDeployStore {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("openTestDeployStore: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &sqliteDeployStore{db: db}
}

func TestSQLite_Deploy_AppendAndLoad(t *testing.T) {
	s := openTestDeployStore(t)

	now := time.Now().UTC()
	ev := DeploymentEvent{
		ID:         "DEP-SQL-001",
		Service:    "payment-api",
		Version:    "v1.5.0",
		DeployedAt: now,
		Success:    true,
		CommitSHA:  "deadbeef",
		CommitTime: now.Add(-30 * time.Minute),
	}
	if err := s.append(ev); err != nil {
		t.Fatalf("append: %v", err)
	}

	loaded, err := s.load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 deployment, got %d", len(loaded))
	}
	got := loaded[0]
	if got.Service != "payment-api" {
		t.Errorf("Service: got %q", got.Service)
	}
	if got.Version != "v1.5.0" {
		t.Errorf("Version: got %q", got.Version)
	}
	if got.CommitSHA != "deadbeef" {
		t.Errorf("CommitSHA: got %q", got.CommitSHA)
	}
	if got.CommitTime.IsZero() {
		t.Error("CommitTime should not be zero after round-trip")
	}
}

func TestSQLite_Deploy_LoadInWindow_FiltersOldRecords(t *testing.T) {
	s := openTestDeployStore(t)

	now := time.Now().UTC()
	old := DeploymentEvent{ID: "DEP-OLD", Service: "svc", DeployedAt: now.Add(-60 * 24 * time.Hour), Success: true}
	recent := DeploymentEvent{ID: "DEP-NEW", Service: "svc", DeployedAt: now.Add(-5 * 24 * time.Hour), Success: true}

	for _, ev := range []DeploymentEvent{old, recent} {
		if err := s.append(ev); err != nil {
			t.Fatalf("append %s: %v", ev.ID, err)
		}
	}

	result, err := s.loadInWindow(30 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("loadInWindow: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result in window, got %d", len(result))
	}
	if result[0].ID != "DEP-NEW" {
		t.Errorf("expected DEP-NEW, got %s", result[0].ID)
	}
}

func TestSQLite_Deploy_DuplicateIDIgnored(t *testing.T) {
	s := openTestDeployStore(t)

	ev := DeploymentEvent{
		ID:         "DEP-DUP",
		Service:    "svc",
		DeployedAt: time.Now().UTC(),
		Success:    true,
	}
	if err := s.append(ev); err != nil {
		t.Fatalf("first append: %v", err)
	}
	// Second append with the same ID must not error and must not create a duplicate.
	if err := s.append(ev); err != nil {
		t.Fatalf("second append (dupe): %v", err)
	}

	loaded, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Errorf("expected 1 (dedup), got %d", len(loaded))
	}
}

func TestSQLite_Deploy_EmptyLoad(t *testing.T) {
	s := openTestDeployStore(t)
	loaded, err := s.load()
	if err != nil {
		t.Fatalf("load empty: %v", err)
	}
	if len(loaded) != 0 {
		t.Errorf("expected 0, got %d", len(loaded))
	}
}

func TestSQLite_Deploy_FailedDeployment(t *testing.T) {
	s := openTestDeployStore(t)

	ev := DeploymentEvent{
		ID:         "DEP-FAIL",
		Service:    "broken",
		DeployedAt: time.Now().UTC(),
		Success:    false,
	}
	if err := s.append(ev); err != nil {
		t.Fatalf("append failed deploy: %v", err)
	}

	loaded, _ := s.load()
	if len(loaded) != 1 {
		t.Fatalf("expected 1, got %d", len(loaded))
	}
	if loaded[0].Success {
		t.Error("Success should be false for failed deployment")
	}
}
