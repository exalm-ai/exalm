package convo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/store"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// openSQLiteStore opens a fresh SQLite database in a temp directory and
// returns a conversation Store backed by it. Mirrors
// plugins/incident/sqlite_store_test.go's helper.
func openSQLiteStore(t *testing.T) Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("openSQLiteStore: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewSQLiteStore(db)
}

func sampleConversation(id string) plugin.Conversation {
	now := time.Now().UTC()
	return plugin.Conversation{
		ID:        id,
		FindingID: "f00001",
		Namespace: "prod",
		Focus:     "prod/payment-api",
		CreatedAt: now,
		UpdatedAt: now,
		Messages: []plugin.ConversationMessage{
			{Role: "user", Content: "Why is payment-api crashing?", At: now},
			{Role: "assistant", Content: "It was OOM-killed.", At: now, Confidence: "high"},
		},
	}
}

// ─── SQLite backend ────────────────────────────────────────────────────────

func TestSQLiteConvoStore_CreateAndGet(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()
	c := sampleConversation("convo-001")

	if err := s.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, c.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Focus != c.Focus {
		t.Errorf("Focus: got %q want %q", got.Focus, c.Focus)
	}
	if len(got.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(got.Messages))
	}
	if got.Messages[1].Confidence != "high" {
		t.Errorf("expected assistant confidence preserved, got %q", got.Messages[1].Confidence)
	}
}

func TestSQLiteConvoStore_GetNotFound(t *testing.T) {
	s := openSQLiteStore(t)
	if _, err := s.Get(context.Background(), "does-not-exist"); err == nil {
		t.Error("expected an error for an unknown conversation id")
	}
}

func TestSQLiteConvoStore_Update_AppendsMessage(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()
	c := sampleConversation("convo-002")
	if err := s.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	c.Messages = append(c.Messages, plugin.ConversationMessage{Role: "user", Content: "Show me the previous logs.", At: time.Now().UTC()})
	c.UpdatedAt = time.Now().UTC()
	if err := s.Update(ctx, c); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Get(ctx, c.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if len(got.Messages) != 3 {
		t.Fatalf("expected 3 messages after update, got %d", len(got.Messages))
	}
}

func TestSQLiteConvoStore_Update_UpsertsWhenMissing(t *testing.T) {
	// A chat turn may arrive with an id the store has never seen (e.g. after a
	// restart with a client-cached conversationId) — Update must not fail.
	s := openSQLiteStore(t)
	c := sampleConversation("convo-never-created")
	if err := s.Update(context.Background(), c); err != nil {
		t.Fatalf("Update on unknown id should upsert, got error: %v", err)
	}
	got, err := s.Get(context.Background(), c.ID)
	if err != nil {
		t.Fatalf("Get after upsert: %v", err)
	}
	if got.ID != c.ID {
		t.Errorf("expected upserted conversation to be retrievable, got %+v", got)
	}
}

func TestSQLiteConvoStore_List_SortedNewestFirst(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()

	older := sampleConversation("convo-older")
	older.UpdatedAt = time.Now().UTC().Add(-time.Hour)
	newer := sampleConversation("convo-newer")
	newer.UpdatedAt = time.Now().UTC()

	if err := s.Create(ctx, older); err != nil {
		t.Fatalf("Create older: %v", err)
	}
	if err := s.Create(ctx, newer); err != nil {
		t.Fatalf("Create newer: %v", err)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 conversations, got %d", len(list))
	}
	if list[0].ID != "convo-newer" {
		t.Errorf("expected newest first, got %q first", list[0].ID)
	}
}

// ─── File-store fallback ───────────────────────────────────────────────────

func TestFileStore_CreateGetUpdate_RoundTrip(t *testing.T) {
	ConversationDir = t.TempDir()
	t.Cleanup(func() { ConversationDir = "" })

	s := NewStore() // SetConvoDB not called -> file store
	ctx := context.Background()
	c := sampleConversation("convo-file-001")

	if err := s.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, c.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Focus != c.Focus {
		t.Errorf("Focus: got %q want %q", got.Focus, c.Focus)
	}

	got.Messages = append(got.Messages, plugin.ConversationMessage{Role: "user", Content: "follow-up", At: time.Now().UTC()})
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got2, err := s.Get(ctx, c.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if len(got2.Messages) != 3 {
		t.Fatalf("expected 3 messages after update, got %d", len(got2.Messages))
	}
}

func TestFileStore_List_EmptyWhenDirMissing(t *testing.T) {
	ConversationDir = filepath.Join(t.TempDir(), "does-not-exist-yet")
	t.Cleanup(func() { ConversationDir = "" })

	list, err := NewStore().List(context.Background())
	if err != nil {
		t.Fatalf("List on missing dir should not error, got: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

func TestNewStore_PrefersSQLiteWhenConfigured(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close(); SetConvoDB(nil) })
	SetConvoDB(db)

	s := NewStore()
	if _, ok := s.(*sqliteConvoStore); !ok {
		t.Errorf("expected NewStore() to return a *sqliteConvoStore once SetConvoDB is called, got %T", s)
	}
}

// ─── ListByFocus (both backends) ───────────────────────────────────────────

func TestListByFocus_BothBackends(t *testing.T) {
	backends := map[string]func(t *testing.T) Store{
		"sqlite": openSQLiteStore,
		"file": func(t *testing.T) Store {
			old := ConversationDir
			ConversationDir = t.TempDir()
			t.Cleanup(func() { ConversationDir = old })
			return &fileStore{}
		},
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			ctx := context.Background()

			match := sampleConversation("c-match")
			otherFocus := sampleConversation("c-other-focus")
			otherFocus.Focus = "prod/other-api"
			otherNs := sampleConversation("c-other-ns")
			otherNs.Namespace = "staging"
			otherNs.Focus = "staging/payment-api"
			for _, c := range []plugin.Conversation{match, otherFocus, otherNs} {
				if err := s.Create(ctx, c); err != nil {
					t.Fatalf("Create %s: %v", c.ID, err)
				}
			}

			got, err := s.ListByFocus(ctx, "prod/payment-api", "prod")
			if err != nil {
				t.Fatalf("ListByFocus: %v", err)
			}
			if len(got) != 1 || got[0].ID != "c-match" {
				t.Errorf("expected only c-match, got %+v", got)
			}

			all, err := s.ListByFocus(ctx, "", "")
			if err != nil {
				t.Fatalf("ListByFocus(all): %v", err)
			}
			if len(all) != 3 {
				t.Errorf("empty filters should match everything, got %d", len(all))
			}
		})
	}
}

func TestConversation_FingerprintRoundTrip(t *testing.T) {
	s := openSQLiteStore(t)
	ctx := context.Background()
	c := sampleConversation("c-fp")
	c.Fingerprint = "oom-killed\x1fprod/payment-api"
	if err := s.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, c.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Fingerprint != c.Fingerprint {
		t.Errorf("Fingerprint: got %q want %q", got.Fingerprint, c.Fingerprint)
	}
}
