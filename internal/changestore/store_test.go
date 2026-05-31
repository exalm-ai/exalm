package changestore

import (
	"path/filepath"
	"testing"
	"time"
)

func tmpStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "changes.jsonl"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestAppendAndAll(t *testing.T) {
	s := tmpStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	e := ChangeEvent{
		Kind:      "Deployment",
		Namespace: "exalm-prod",
		Name:      "api-gateway",
		Action:    "updated",
		Actor:     "alice",
		NewRev:    "12345",
		Timestamp: now,
	}
	if err := s.Append(e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	all, err := s.All(time.Time{})
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("want 1 event, got %d", len(all))
	}
	if all[0].ID == "" {
		t.Errorf("expected ID to be populated by Append, got empty")
	}
	if all[0].Kind != "Deployment" || all[0].Actor != "alice" {
		t.Errorf("round-trip lost fields: %+v", all[0])
	}
}

func TestAppendRequiresKindAndName(t *testing.T) {
	s := tmpStore(t)
	if err := s.Append(ChangeEvent{Kind: "Deployment"}); err == nil {
		t.Errorf("Append without Name should fail")
	}
	if err := s.Append(ChangeEvent{Name: "foo"}); err == nil {
		t.Errorf("Append without Kind should fail")
	}
}

func TestRecentForResource_Window(t *testing.T) {
	s := tmpStore(t)
	now := time.Now().UTC()

	// Old change (way outside window).
	_ = s.Append(ChangeEvent{
		Kind: "Deployment", Namespace: "ns1", Name: "api", Action: "updated",
		Timestamp: now.Add(-2 * time.Hour),
	})
	// Recent change (inside 30min window).
	_ = s.Append(ChangeEvent{
		Kind: "Deployment", Namespace: "ns1", Name: "api", Action: "updated",
		Timestamp: now.Add(-10 * time.Minute),
	})
	// Recent change to a different namespace.
	_ = s.Append(ChangeEvent{
		Kind: "Deployment", Namespace: "ns2", Name: "api", Action: "updated",
		Timestamp: now.Add(-5 * time.Minute),
	})

	got, err := s.RecentForResource("ns1", "api", []string{"Deployment"}, 30*time.Minute, now)
	if err != nil {
		t.Fatalf("RecentForResource: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 match in window, got %d", len(got))
	}
	if got[0].Namespace != "ns1" {
		t.Errorf("wrong namespace: %+v", got[0])
	}
}

func TestRecentForResource_PodOwnerPrefix(t *testing.T) {
	s := tmpStore(t)
	now := time.Now().UTC()
	_ = s.Append(ChangeEvent{
		Kind: "Deployment", Namespace: "ns1", Name: "api-gateway",
		Action: "updated", Timestamp: now.Add(-5 * time.Minute),
	})
	// A pod is queried by its full name "api-gateway-7c9b-abc" — the store
	// should match the owning Deployment "api-gateway".
	got, err := s.RecentForResource("ns1", "api-gateway-7c9b-abc", []string{"Deployment"}, 30*time.Minute, now)
	if err != nil {
		t.Fatalf("RecentForResource: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 match via prefix, got %d", len(got))
	}
}

func TestRecentForResource_KindFilter(t *testing.T) {
	s := tmpStore(t)
	now := time.Now().UTC()
	_ = s.Append(ChangeEvent{
		Kind: "ConfigMap", Namespace: "ns1", Name: "api", Action: "updated",
		Timestamp: now.Add(-5 * time.Minute),
	})
	// Only ask for Deployments — ConfigMap change must not match.
	got, _ := s.RecentForResource("ns1", "api", []string{"Deployment"}, 30*time.Minute, now)
	if len(got) != 0 {
		t.Errorf("kind filter ignored, got %d", len(got))
	}
	// Empty kinds = match any kind.
	got, _ = s.RecentForResource("ns1", "api", nil, 30*time.Minute, now)
	if len(got) != 1 {
		t.Errorf("empty kinds should match anything, got %d", len(got))
	}
}

func TestMakeID_Deterministic(t *testing.T) {
	t1 := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	e := ChangeEvent{Kind: "Deployment", Namespace: "ns", Name: "api", NewRev: "v1", Timestamp: t1}
	id1, id2 := MakeID(e), MakeID(e)
	if id1 != id2 {
		t.Errorf("MakeID should be deterministic")
	}
	e2 := e
	e2.NewRev = "v2"
	if MakeID(e) == MakeID(e2) {
		t.Errorf("MakeID should differ when NewRev differs")
	}
}
