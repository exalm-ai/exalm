package investigate

// logsession_test.go — corpus bounds/truncation, query/window/vocabulary,
// and generic focus resolution.

import (
	"strings"
	"testing"
	"time"
)

func sessionFixture() *LogSession {
	s := NewLogSession("syslog")
	src := s.AddSource(SourceDesc{Path: "/var/log/syslog"})
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	s.Append(
		LogEvent{At: base, Severity: "info", Scope: "web-01", Unit: "nginx.service", Message: "started", Raw: "raw1", Source: src},
		LogEvent{At: base.Add(1 * time.Minute), Severity: "err", Scope: "web-01", Unit: "nginx.service", Code: "500", Message: "upstream timed out", Raw: "raw2", Source: src},
		LogEvent{At: base.Add(2 * time.Minute), Severity: "crit", Scope: "web-01", Unit: "kernel", Message: "Out of memory: Killed process 1234", Raw: "raw3", Source: src},
		LogEvent{At: base.Add(3 * time.Minute), Severity: "warn", Scope: "db-01", Unit: "postgres.service", Message: "checkpoint slow", Raw: "raw4", Source: src},
	)
	return s
}

func TestLogSession_QueryFiltersAndPagination(t *testing.T) {
	s := sessionFixture()

	got, total := s.Query(LogQuery{Severity: "err"})
	if total != 1 || len(got) != 1 || got[0].Code != "500" {
		t.Errorf("severity filter: total=%d got=%+v", total, got)
	}
	got, total = s.Query(LogQuery{Unit: "nginx.service"})
	if total != 2 {
		t.Errorf("unit filter: total=%d", total)
	}
	got, total = s.Query(LogQuery{Contains: "out of memory"})
	if total != 1 || !strings.Contains(got[0].Message, "Killed process") {
		t.Errorf("contains filter: total=%d got=%+v", total, got)
	}
	// Pagination: total counts all matches; Limit/Offset slice the page.
	got, total = s.Query(LogQuery{Scope: "web-01", Limit: 2, Offset: 1})
	if total != 3 || len(got) != 2 {
		t.Errorf("pagination: total=%d page=%d", total, len(got))
	}
	// Time range.
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	_, total = s.Query(LogQuery{From: base.Add(90 * time.Second), To: base.Add(4 * time.Minute)})
	if total != 2 {
		t.Errorf("time filter: total=%d", total)
	}
}

func TestLogSession_WindowAndVocabularyAndRange(t *testing.T) {
	s := sessionFixture()
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

	win := s.Window(base.Add(2*time.Minute), time.Minute, time.Minute, 10)
	if len(win) != 3 { // 12:01, 12:02, 12:03
		t.Errorf("window: %d events", len(win))
	}

	units, scopes := s.Vocabulary()
	if len(units) != 3 || units[0] != "kernel" {
		t.Errorf("units: %v", units)
	}
	if len(scopes) != 2 || scopes[0] != "db-01" {
		t.Errorf("scopes: %v", scopes)
	}

	from, to := s.TimeRange()
	if !from.Equal(base) || !to.Equal(base.Add(3*time.Minute)) {
		t.Errorf("range: %v → %v", from, to)
	}
}

func TestLogSession_CapsDropOldest(t *testing.T) {
	s := NewLogSession("logs")
	for i := 0; i < MaxSessionEvents+50; i++ {
		s.Append(LogEvent{Message: "m", Raw: "r"})
	}
	if s.Len() != MaxSessionEvents {
		t.Errorf("event cap: %d", s.Len())
	}
	if s.Truncated() != 50 {
		t.Errorf("truncated: %d", s.Truncated())
	}
}

func TestResolveFocusFromVocabulary(t *testing.T) {
	s := sessionFixture()
	if got := ResolveFocusFromVocabulary("", "why is nginx.service failing?", s); got != "db-01/nginx.service" && !strings.HasSuffix(got, "/nginx.service") {
		t.Errorf("unit mention: %q", got)
	}
	if got := ResolveFocusFromVocabulary("web-01/nginx.service", "what happened before?", s); got != "web-01/nginx.service" {
		t.Errorf("pronoun follow-up must keep focus: %q", got)
	}
	if got := ResolveFocusFromVocabulary("", "is db-01 healthy?", s); got != "db-01" {
		t.Errorf("scope mention: %q", got)
	}
	if got := ResolveFocusFromVocabulary("prev", "nothing matches", nil); got != "prev" {
		t.Errorf("nil session: %q", got)
	}
}
