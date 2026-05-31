package store_test

import (
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/store"
)

func TestRecordUsage_BasicInsert(t *testing.T) {
	db := openTestDB(t)

	r := store.UsageRecord{
		Provider:     "claude",
		Model:        "claude-sonnet-4-6",
		Plugin:       "k8s",
		Subcommand:   "analyze",
		InputTokens:  1500,
		OutputTokens: 400,
	}
	if err := store.RecordUsage(db, r); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM llm_usage`).Scan(&count) //nolint:errcheck
	if count != 1 {
		t.Errorf("expected 1 usage row, got %d", count)
	}
}

func TestRecordUsage_AutoID(t *testing.T) {
	db := openTestDB(t)

	// Two records with no ID set → both should get unique IDs.
	r := store.UsageRecord{Provider: "openai", Plugin: "logs", Subcommand: "summarize", InputTokens: 100, OutputTokens: 50}
	if err := store.RecordUsage(db, r); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordUsage(db, r); err != nil {
		t.Fatal(err)
	}

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM llm_usage`).Scan(&count) //nolint:errcheck
	if count != 2 {
		t.Errorf("expected 2 usage rows (different auto IDs), got %d", count)
	}
}

func TestRecordUsage_NilDB(t *testing.T) {
	// Recording against a nil DB must not panic and must return nil error.
	if err := store.RecordUsage(nil, store.UsageRecord{}); err != nil {
		t.Errorf("nil DB: expected nil error, got %v", err)
	}
}

func TestQueryUsageSummary_Empty(t *testing.T) {
	db := openTestDB(t)
	summaries, err := store.QueryUsageSummary(db, 30)
	if err != nil {
		t.Fatalf("QueryUsageSummary empty: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0, got %d", len(summaries))
	}
}

func TestQueryUsageSummary_Aggregation(t *testing.T) {
	db := openTestDB(t)

	// Insert 3 records: 2 for k8s/analyze, 1 for logs/summarize.
	records := []store.UsageRecord{
		{Provider: "claude", Model: "sonnet", Plugin: "k8s", Subcommand: "analyze", InputTokens: 1000, OutputTokens: 200},
		{Provider: "claude", Model: "sonnet", Plugin: "k8s", Subcommand: "analyze", InputTokens: 800, OutputTokens: 150},
		{Provider: "claude", Model: "sonnet", Plugin: "logs", Subcommand: "summarize", InputTokens: 500, OutputTokens: 100},
	}
	for _, r := range records {
		if err := store.RecordUsage(db, r); err != nil {
			t.Fatalf("RecordUsage: %v", err)
		}
	}

	summaries, err := store.QueryUsageSummary(db, 30)
	if err != nil {
		t.Fatalf("QueryUsageSummary: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summary rows, got %d", len(summaries))
	}

	// First row should be k8s/analyze (highest total: 1800+350=2150).
	if summaries[0].Plugin != "k8s" || summaries[0].Subcommand != "analyze" {
		t.Errorf("expected k8s/analyze first, got %s/%s", summaries[0].Plugin, summaries[0].Subcommand)
	}
	if summaries[0].Calls != 2 {
		t.Errorf("k8s/analyze: expected 2 calls, got %d", summaries[0].Calls)
	}
	if summaries[0].InputTokens != 1800 {
		t.Errorf("k8s/analyze: expected 1800 input tokens, got %d", summaries[0].InputTokens)
	}
	if summaries[0].TotalTokens != 2150 {
		t.Errorf("k8s/analyze: expected 2150 total, got %d", summaries[0].TotalTokens)
	}
}

func TestQueryUsageSummary_WindowFiltering(t *testing.T) {
	db := openTestDB(t)

	// Insert one old record and one recent record.
	old := store.UsageRecord{
		Provider: "claude", Plugin: "k8s", Subcommand: "analyze",
		InputTokens: 999, OutputTokens: 111,
		RecordedAt: time.Now().UTC().AddDate(0, 0, -60), // 60 days ago
	}
	recent := store.UsageRecord{
		Provider: "claude", Plugin: "logs", Subcommand: "summarize",
		InputTokens: 200, OutputTokens: 50,
		RecordedAt: time.Now().UTC(),
	}
	// We need to set explicit IDs to avoid collision.
	old.ID = "usage-old-001"
	recent.ID = "usage-new-001"

	for _, r := range []store.UsageRecord{old, recent} {
		if err := store.RecordUsage(db, r); err != nil {
			t.Fatalf("RecordUsage: %v", err)
		}
	}

	// 30-day window: only the recent record should appear.
	summaries, err := store.QueryUsageSummary(db, 30)
	if err != nil {
		t.Fatalf("QueryUsageSummary: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary (30d window), got %d", len(summaries))
	}
	if summaries[0].Plugin != "logs" {
		t.Errorf("expected logs plugin, got %s", summaries[0].Plugin)
	}
}

func TestQueryUsageTotals(t *testing.T) {
	db := openTestDB(t)

	records := []store.UsageRecord{
		{Provider: "claude", Plugin: "k8s", Subcommand: "analyze", InputTokens: 1000, OutputTokens: 200},
		{Provider: "openai", Plugin: "logs", Subcommand: "summarize", InputTokens: 500, OutputTokens: 100},
	}
	for _, r := range records {
		if err := store.RecordUsage(db, r); err != nil {
			t.Fatal(err)
		}
	}

	inp, out, total, err := store.QueryUsageTotals(db, 30)
	if err != nil {
		t.Fatalf("QueryUsageTotals: %v", err)
	}
	if inp != 1500 {
		t.Errorf("input: expected 1500, got %d", inp)
	}
	if out != 300 {
		t.Errorf("output: expected 300, got %d", out)
	}
	if total != 1800 {
		t.Errorf("total: expected 1800, got %d", total)
	}
}

func TestQueryUsageTotals_NilDB(t *testing.T) {
	inp, out, total, err := store.QueryUsageTotals(nil, 30)
	if err != nil {
		t.Errorf("nil DB: expected nil error, got %v", err)
	}
	if inp != 0 || out != 0 || total != 0 {
		t.Errorf("nil DB: expected zeros, got %d/%d/%d", inp, out, total)
	}
}
