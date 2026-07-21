package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func writeReportFile(t *testing.T, r plugin.Report) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write report file: %v", err)
	}
	return path
}

func TestLoadReportFile_ValidReport(t *testing.T) {
	want := plugin.Report{
		Title:   "k8s findings",
		Summary: "1 critical",
		Findings: []plugin.Finding{
			{Title: "prod/api", Severity: plugin.SeverityCritical},
		},
	}
	path := writeReportFile(t, want)

	got, err := loadReportFile(path)
	if err != nil {
		t.Fatalf("loadReportFile: %v", err)
	}
	if got.Title != want.Title || len(got.Findings) != 1 || got.Findings[0].Title != "prod/api" {
		t.Errorf("loadReportFile roundtrip: got %+v", got)
	}
}

func TestLoadReportFile_MissingFile(t *testing.T) {
	if _, err := loadReportFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestLoadReportFile_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}
	_, err := loadReportFile(path)
	if err == nil {
		t.Fatal("expected a JSON parse error")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should name the parse failure, got: %v", err)
	}
}

func TestLoadReportFile_OversizedRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create huge file: %v", err)
	}
	if err := f.Truncate(maxMCPReportFileBytes + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	_, err = loadReportFile(path)
	if err == nil {
		t.Fatal("expected the size-limit error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should explain the size limit, got: %v", err)
	}
}
