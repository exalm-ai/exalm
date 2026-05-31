package store_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/exalm-ai/exalm/internal/store"
)

// openTestDB opens a fresh SQLite database in a temp directory and registers
// a cleanup function to close it. Helper shared by all tests in this package.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("openTestDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ─── schema tests ─────────────────────────────────────────────────────────────

func TestOpen_CreatesAllTables(t *testing.T) {
	db := openTestDB(t)
	for _, tbl := range []string{"deployments", "incidents", "schema_migrations"} {
		var count int
		row := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl)
		if err := row.Scan(&count); err != nil || count != 1 {
			t.Errorf("table %q not found in schema", tbl)
		}
	}
}

func TestOpen_CreatesIndexes(t *testing.T) {
	db := openTestDB(t)
	for _, idx := range []string{"idx_dep_at", "idx_inc_at"} {
		var count int
		db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&count) //nolint:errcheck
		if count != 1 {
			t.Errorf("index %q not found in schema", idx)
		}
	}
}

// Open must be idempotent: a second call on the same file must not fail.
func TestOpen_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exalm.db")
	db1, err := store.Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	db1.Close()

	db2, err := store.Open(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	db2.Close()
}

// ─── DefaultPath ──────────────────────────────────────────────────────────────

func TestDefaultPath_CreatesDir(t *testing.T) {
	// Override HOME so we don't write to the real ~/.exalm directory.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)        // Linux/macOS
	t.Setenv("USERPROFILE", tmp) // Windows

	path, err := store.DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Errorf("directory not created: %v", err)
	}
	if filepath.Base(path) != "exalm.db" {
		t.Errorf("unexpected db filename: %q", filepath.Base(path))
	}
}

// ─── MigrateDeployments ───────────────────────────────────────────────────────

func TestMigrateDeployments_MissingFile(t *testing.T) {
	db := openTestDB(t)
	n, err := store.MigrateDeployments(db, filepath.Join(t.TempDir(), "none.jsonl"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 imported from missing file, got %d", n)
	}
}

func TestMigrateDeployments_ValidJSONL(t *testing.T) {
	dir := t.TempDir()
	jsonl := `{"id":"DEP-1","service":"api","deployed_at":"2026-01-01T10:00:00Z","success":true}` + "\n" +
		`{"id":"DEP-2","service":"worker","deployed_at":"2026-01-02T10:00:00Z","success":false}` + "\n" +
		`` + "\n" + // blank line must be skipped
		`{not json}` + "\n" // malformed line must be skipped
	path := filepath.Join(dir, "deployments.jsonl")
	if err := os.WriteFile(path, []byte(jsonl), 0o600); err != nil {
		t.Fatal(err)
	}

	db := openTestDB(t)
	n, err := store.MigrateDeployments(db, path)
	if err != nil {
		t.Fatalf("MigrateDeployments: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 imported, got %d", n)
	}

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM deployments`).Scan(&count) //nolint:errcheck
	if count != 2 {
		t.Errorf("expected 2 rows in deployments, got %d", count)
	}
}

func TestMigrateDeployments_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deployments.jsonl")
	os.WriteFile(path, []byte(`{"id":"DEP-1","service":"api","deployed_at":"2026-01-01T10:00:00Z","success":true}`+"\n"), 0o600) //nolint:errcheck

	db := openTestDB(t)

	n1, err := store.MigrateDeployments(db, path)
	if err != nil {
		t.Fatal(err)
	}
	if n1 != 1 {
		t.Fatalf("first migration: expected 1, got %d", n1)
	}

	// Second call on the same file must be a no-op.
	n2, err := store.MigrateDeployments(db, path)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Errorf("second migration should import 0 (already done), got %d", n2)
	}
}

func TestMigrateDeployments_DuplicateIDSkipped(t *testing.T) {
	db := openTestDB(t)
	// Pre-insert a row with the same ID.
	db.Exec(`INSERT INTO deployments(id,service,deployed_at,success,data) VALUES('DEP-X','svc','2026-01-01T00:00:00Z',1,'{}')`) //nolint:errcheck

	dir := t.TempDir()
	path := filepath.Join(dir, "deployments.jsonl")
	os.WriteFile(path, []byte(`{"id":"DEP-X","service":"api","deployed_at":"2026-01-01T10:00:00Z","success":true}`+"\n"), 0o600) //nolint:errcheck

	n, err := store.MigrateDeployments(db, path)
	if err != nil {
		t.Fatal(err)
	}
	_ = n // duplicate silently skipped; count may be 0 or 1 depending on INSERT OR IGNORE

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM deployments WHERE id='DEP-X'`).Scan(&count) //nolint:errcheck
	if count != 1 {
		t.Errorf("expected exactly 1 row for DEP-X, got %d", count)
	}
}

// ─── MigrateIncidents ─────────────────────────────────────────────────────────

func TestMigrateIncidents_MissingDir(t *testing.T) {
	db := openTestDB(t)
	n, err := store.MigrateIncidents(db, filepath.Join(t.TempDir(), "no-such-dir"))
	if err != nil {
		t.Fatalf("missing dir should not error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestMigrateIncidents_ValidJSONFiles(t *testing.T) {
	dir := t.TempDir()
	for _, inc := range []struct{ name, content string }{
		{"INC-001.json", `{"id":"INC-001","title":"disk full","status":"open","opened_at":"2026-01-01T10:00:00Z"}`},
		{"INC-002.json", `{"id":"INC-002","title":"oom kill","status":"closed","opened_at":"2026-01-02T10:00:00Z"}`},
		{"not-an-incident.txt", `ignored`},
	} {
		os.WriteFile(filepath.Join(dir, inc.name), []byte(inc.content), 0o600) //nolint:errcheck
	}

	db := openTestDB(t)
	n, err := store.MigrateIncidents(db, dir)
	if err != nil {
		t.Fatalf("MigrateIncidents: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 imported, got %d", n)
	}
}

func TestMigrateIncidents_Idempotent(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "INC-001.json"), []byte(`{"id":"INC-001","title":"t","status":"open","opened_at":"2026-01-01T10:00:00Z"}`), 0o600) //nolint:errcheck

	db := openTestDB(t)
	if _, err := store.MigrateIncidents(db, dir); err != nil {
		t.Fatal(err)
	}
	// Second run must be a no-op.
	n2, err := store.MigrateIncidents(db, dir)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Errorf("second migration should import 0 (already done), got %d", n2)
	}
}
