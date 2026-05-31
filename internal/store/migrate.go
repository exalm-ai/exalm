package store

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MigrateDeployments imports DeploymentEvent records from a JSONL file at
// jsonlPath into db. Each JSON object must contain at minimum an "id" field.
// Records whose IDs already exist in the database are silently skipped
// (INSERT OR IGNORE). The migration key "deployments_jsonl_v1" is tracked in
// schema_migrations so the import runs exactly once regardless of path changes.
//
// Returns the number of records imported and any non-fatal I/O error.
// A missing jsonlPath is not an error (returns 0, nil).
func MigrateDeployments(db *sql.DB, jsonlPath string) (int, error) {
	const key = "deployments_jsonl_v1"
	migrated, err := alreadyMigrated(db, key)
	if err != nil || migrated {
		return 0, err
	}

	f, err := os.Open(jsonlPath) //nolint:gosec // G304: path is an internal data file, not user-controlled
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("migrate deployments: open %s: %w", jsonlPath, err)
	}
	defer f.Close() //nolint:errcheck

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("migrate deployments: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	imported := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB line buffer
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		var id, service, deployedAt string
		success := true
		// id is required — skip the record if it cannot be parsed.
		if err := json.Unmarshal(raw["id"], &id); err != nil || id == "" {
			continue
		}
		// Optional fields: use zero values when absent or unparseable.
		_ = json.Unmarshal(raw["service"], &service)
		_ = json.Unmarshal(raw["deployed_at"], &deployedAt)
		_ = json.Unmarshal(raw["success"], &success)
		successInt := 0
		if success {
			successInt = 1
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO deployments(id,service,deployed_at,success,data) VALUES(?,?,?,?,?)`,
			id, service, deployedAt, successInt, line,
		); err == nil {
			imported++
		}
	}
	if err := scanner.Err(); err != nil {
		return imported, fmt.Errorf("migrate deployments: scan: %w", err)
	}

	if err := recordMigration(tx, key); err != nil {
		return imported, err
	}
	if err := tx.Commit(); err != nil {
		return imported, fmt.Errorf("migrate deployments: commit: %w", err)
	}
	return imported, nil
}

// maxIncidentFileBytes caps the size of a single incident JSON file read during
// migration. Files larger than this are skipped. 10 MB is generous for a
// postmortem document and prevents unbounded memory growth during import.
const maxIncidentFileBytes = 10 << 20 // 10 MB

// MigrateIncidents imports Incident JSON files from incidentDir into db.
// Each file must be a *.json file with at minimum an "id" field.
// Already-existing IDs are skipped. Returns the number of records imported.
// A missing incidentDir is not an error (returns 0, nil).
// The migration key "incidents_dir_v1" is tracked in schema_migrations so the
// import runs exactly once regardless of path changes.
func MigrateIncidents(db *sql.DB, incidentDir string) (int, error) {
	const key = "incidents_dir_v1"
	migrated, err := alreadyMigrated(db, key)
	if err != nil || migrated {
		return 0, err
	}

	entries, err := os.ReadDir(incidentDir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("migrate incidents: readdir %s: %w", incidentDir, err)
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("migrate incidents: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	imported := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		f, err := os.Open(filepath.Join(incidentDir, e.Name())) //nolint:gosec // G304: incidentDir is an internal data dir
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(f, maxIncidentFileBytes))
		f.Close()
		if readErr != nil {
			continue
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(data, &raw) != nil {
			continue
		}
		var id, status, openedAt string
		var closedAt *string
		// id is required — skip the record if it cannot be parsed.
		if err := json.Unmarshal(raw["id"], &id); err != nil || id == "" {
			continue
		}
		// Optional fields: use zero values when absent or unparseable.
		_ = json.Unmarshal(raw["status"], &status)
		_ = json.Unmarshal(raw["opened_at"], &openedAt)
		if ca, ok := raw["closed_at"]; ok {
			var s string
			if json.Unmarshal(ca, &s) == nil && s != "" {
				closedAt = &s
			}
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO incidents(id,status,opened_at,closed_at,data) VALUES(?,?,?,?,?)`,
			id, status, openedAt, closedAt, string(data),
		); err == nil {
			imported++
		}
	}

	if err := recordMigration(tx, key); err != nil {
		return imported, err
	}
	if err := tx.Commit(); err != nil {
		return imported, fmt.Errorf("migrate incidents: commit: %w", err)
	}
	return imported, nil
}

// alreadyMigrated reports whether the named migration has already been applied.
// Returns (false, err) if the check itself fails so the caller can decide
// whether to proceed or abort.
func alreadyMigrated(db *sql.DB, name string) (bool, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, name).Scan(&count); err != nil {
		return false, fmt.Errorf("check migration %q: %w", name, err)
	}
	return count > 0, nil
}

// recordMigration inserts the migration name into schema_migrations within tx.
func recordMigration(tx *sql.Tx, name string) error {
	if _, err := tx.Exec(`INSERT OR IGNORE INTO schema_migrations(name) VALUES(?)`, name); err != nil {
		return fmt.Errorf("record migration %q: %w", name, err)
	}
	return nil
}
