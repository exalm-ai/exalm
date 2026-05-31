package incident

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/store"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// openSQLiteStore opens a fresh SQLite database in a temp directory and
// returns an incident Store backed by it. Cleanup is registered automatically.
func openSQLiteStore(t *testing.T) Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("openSQLiteStore: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewSQLiteStore(db)
}

// ─── Create + Get ─────────────────────────────────────────────────────────────

func TestSQLiteIncStore_CreateAndGet(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()

	inc := Incident{
		ID:        "INC-SQL-001",
		Title:     "DB connection pool exhausted",
		Status:    IncidentOpen,
		Severity:  plugin.SeverityCritical,
		OpenedAt:  time.Now().UTC(),
		Namespace: "production",
		Service:   "payments-api",
	}
	if err := s.Create(ctx, inc); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, inc.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Title != inc.Title {
		t.Errorf("Title: got %q want %q", got.Title, inc.Title)
	}
	if got.Severity != inc.Severity {
		t.Errorf("Severity: got %q want %q", got.Severity, inc.Severity)
	}
	if got.Namespace != inc.Namespace {
		t.Errorf("Namespace: got %q want %q", got.Namespace, inc.Namespace)
	}
	if got.Service != inc.Service {
		t.Errorf("Service: got %q want %q", got.Service, inc.Service)
	}
}

func TestSQLiteIncStore_GetNotFound(t *testing.T) {
	s := openSQLiteStore(t)
	_, err := s.Get(context.Background(), "INC-DOES-NOT-EXIST")
	if err == nil {
		t.Error("expected error for missing incident, got nil")
	}
}

func TestSQLiteIncStore_DuplicateCreate(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()

	inc := Incident{ID: "INC-DUP", Title: "dup", Status: IncidentOpen, OpenedAt: time.Now()}
	if err := s.Create(ctx, inc); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := s.Create(ctx, inc); err == nil {
		t.Error("expected error on duplicate Create, got nil")
	}
}

// ─── Update ───────────────────────────────────────────────────────────────────

func TestSQLiteIncStore_Update_CloseIncident(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()

	openedAt := time.Now().UTC()
	inc := Incident{ID: "INC-CLOSE", Title: "flapping pod", Status: IncidentOpen, OpenedAt: openedAt}
	if err := s.Create(ctx, inc); err != nil {
		t.Fatalf("Create: %v", err)
	}

	closedAt := time.Now().UTC()
	inc.Status = IncidentClosed
	inc.ClosedAt = &closedAt
	if err := s.Update(ctx, inc); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Get(ctx, inc.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if got.Status != IncidentClosed {
		t.Errorf("Status: got %q want %q", got.Status, IncidentClosed)
	}
	if got.ClosedAt == nil {
		t.Error("ClosedAt should be set after close")
	}
}

func TestSQLiteIncStore_Update_Timeline(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()

	inc := Incident{ID: "INC-TIMELINE", Title: "test", Status: IncidentOpen, OpenedAt: time.Now()}
	if err := s.Create(ctx, inc); err != nil {
		t.Fatalf("Create: %v", err)
	}

	inc.Timeline = []TimelineEntry{
		{At: time.Now(), Event: "alert fired", Source: "pagerduty"},
		{At: time.Now(), Event: "on-call ack", Source: "user"},
	}
	if err := s.Update(ctx, inc); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Get(ctx, inc.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Timeline) != 2 {
		t.Errorf("Timeline: got %d entries, want 2", len(got.Timeline))
	}
}

// ─── List ─────────────────────────────────────────────────────────────────────

func TestSQLiteIncStore_List_SortedNewestFirst(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()

	base := time.Now().UTC()
	titles := []string{"alpha", "beta", "gamma"}
	for i, title := range titles {
		inc := Incident{
			ID:       fmt.Sprintf("INC-%03d", i),
			Title:    title,
			Status:   IncidentOpen,
			OpenedAt: base.Add(time.Duration(i) * time.Minute),
		}
		if err := s.Create(ctx, inc); err != nil {
			t.Fatalf("Create %s: %v", title, err)
		}
	}

	all, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3, got %d", len(all))
	}
	// gamma was created last (highest OpenedAt) → should be first.
	if all[0].Title != "gamma" {
		t.Errorf("expected gamma first, got %s", all[0].Title)
	}
}

func TestSQLiteIncStore_List_Empty(t *testing.T) {
	s := openSQLiteStore(t)
	all, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("expected 0, got %d", len(all))
	}
}

// ─── QueryByDateRange ─────────────────────────────────────────────────────────

func TestSQLiteIncStore_QueryByDateRange(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, title := range []string{"jan1", "jan5", "jan10"} {
		inc := Incident{
			ID:       fmt.Sprintf("INC-RANGE-%d", i),
			Title:    title,
			Status:   IncidentOpen,
			OpenedAt: base.Add(time.Duration(i*5) * 24 * time.Hour),
		}
		if err := s.Create(ctx, inc); err != nil {
			t.Fatalf("Create %s: %v", title, err)
		}
	}

	// Query [jan1, jan6]: should include jan1 (day 0) and jan5 (day 5).
	from := base
	to := base.Add(6 * 24 * time.Hour)
	result, err := s.QueryByDateRange(ctx, from, to)
	if err != nil {
		t.Fatalf("QueryByDateRange: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 incidents in [jan1, jan6], got %d", len(result))
	}

	// Query [jan11, jan20]: no incidents.
	empty, err := s.QueryByDateRange(ctx,
		base.Add(11*24*time.Hour),
		base.Add(20*24*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Errorf("expected 0 outside range, got %d", len(empty))
	}
}

// ─── Postmortem round-trip ────────────────────────────────────────────────────

func TestSQLiteIncStore_PostmortemRoundTrip(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()

	inc := Incident{ID: "INC-PM", Title: "test", Status: IncidentOpen, OpenedAt: time.Now()}
	if err := s.Create(ctx, inc); err != nil {
		t.Fatal(err)
	}

	closedAt := time.Now()
	inc.ClosedAt = &closedAt
	inc.Status = IncidentClosed
	inc.Postmortem = &Postmortem{
		GeneratedAt: time.Now(),
		Summary:     "Root cause was a missing circuit breaker.",
		RootCauses:  []string{"no circuit breaker", "missing retry budget"},
		ActionItems: []string{"add circuit breaker", "add tests"},
	}
	if err := s.Update(ctx, inc); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Postmortem == nil {
		t.Fatal("Postmortem is nil after round-trip")
	}
	if got.Postmortem.Summary != inc.Postmortem.Summary {
		t.Errorf("Summary: got %q", got.Postmortem.Summary)
	}
	if len(got.Postmortem.ActionItems) != 2 {
		t.Errorf("ActionItems: got %d", len(got.Postmortem.ActionItems))
	}
}
