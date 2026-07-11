package investigate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSnapshot_RoundTrip(t *testing.T) {
	s := NewLogSession("syslog")
	src := s.AddSource(SourceDesc{Path: "/var/log/syslog", Host: "db-01"})
	now := time.Now().UTC().Truncate(time.Second)
	s.SSH = &RemoteParams{Host: "db-01", User: "ops", Password: "hunter2", OSFamily: "linux"}
	s.DiagTier = "readonly"
	s.Stats = map[string]int{"authFailures": 4}
	s.Append(
		LogEvent{At: now, Severity: "err", Unit: "sshd", Message: "Failed password", Raw: "raw1", Source: src},
		LogEvent{At: now.Add(time.Second), Severity: "crit", Unit: "kernel", Message: "OOM", Raw: "raw2", Source: src},
	)

	snap, err := s.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(wire), "hunter2") {
		t.Fatal("SSH password must never appear in the snapshot wire form")
	}
	if !strings.Contains(string(wire), `"authFailures":4`) {
		t.Errorf("stats must round-trip verbatim, got %s", wire)
	}

	var decoded SessionSnapshot
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	restored, err := RestoreLogSession(decoded)
	if err != nil {
		t.Fatalf("RestoreLogSession: %v", err)
	}
	if restored.Analyzer != "syslog" || restored.Len() != 2 {
		t.Errorf("restored session mismatch: analyzer=%q len=%d", restored.Analyzer, restored.Len())
	}
	if restored.SSH == nil || restored.SSH.Password != "" {
		t.Errorf("restored session must have SSH metadata but no password: %+v", restored.SSH)
	}
	events, total := restored.Query(LogQuery{Unit: "sshd", Limit: 10})
	if total != 1 || events[0].Message != "Failed password" {
		t.Errorf("restored corpus not queryable: total=%d events=%+v", total, events)
	}
	from, to := restored.TimeRange()
	if !from.Equal(now) || !to.Equal(now.Add(time.Second)) {
		t.Errorf("time range mismatch: %v → %v", from, to)
	}
}

func TestRestoreLogSession_EnforcesCaps(t *testing.T) {
	events := make([]LogEvent, 0, 1000)
	for i := 0; i < 1000; i++ {
		events = append(events, LogEvent{Severity: "info", Message: strings.Repeat("x", 100_000), Raw: strings.Repeat("y", 100_000)})
	}
	restored, err := RestoreLogSession(SessionSnapshot{Analyzer: "logs", Events: events})
	if err != nil {
		t.Fatalf("RestoreLogSession: %v", err)
	}
	if restored.Len() >= 1000 {
		t.Errorf("caps must apply on restore: kept %d of 1000 oversized events", restored.Len())
	}
	if restored.Truncated() == 0 {
		t.Error("truncation must be visible after capped restore")
	}
}

func TestRestoreLogSession_RejectsAnonymous(t *testing.T) {
	if _, err := RestoreLogSession(SessionSnapshot{}); err == nil {
		t.Error("a snapshot without an analyzer name must be rejected")
	}
}

func TestRestore_CarriesPriorTruncation(t *testing.T) {
	restored, err := RestoreLogSession(SessionSnapshot{Analyzer: "logs", Truncated: 7})
	if err != nil {
		t.Fatal(err)
	}
	if restored.Truncated() != 7 {
		t.Errorf("pre-ingest truncation must carry over, got %d", restored.Truncated())
	}
}
