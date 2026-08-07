package eventlog

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/internal/redact"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestParseSessionEvents_ArrayAndDateForms(t *testing.T) {
	chunk := []byte(`[
	  {"TimeCreated":"/Date(1770000000000)/","Id":4625,"Level":2,"LevelDisplayName":"Error","ProviderName":"Microsoft-Windows-Security-Auditing","MachineName":"DC01","Message":"An account failed to log on"},
	  {"TimeCreated":"2026-05-13T10:01:00","Id":7036,"Level":4,"LevelDisplayName":"Information","ProviderName":"Service Control Manager","MachineName":"DC01","Message":"The Print Spooler service entered the stopped state."},
	  {"TimeCreated":"2026-05-13T10:02:00Z","Id":1074,"Level":4,"ProviderName":"User32","MachineName":"DC01","Message":"The process wininit.exe has initiated the restart of computer DC01"},
	  {"TimeCreated":"2026-05-13T10:03:00","Id":1102,"Level":1,"LevelDisplayName":"Critical","ProviderName":"Microsoft-Windows-Eventlog","MachineName":"DC01","Message":"The audit log was cleared."}
	]`)
	events := parseSessionEvents(3, chunk)
	if len(events) != 4 {
		t.Fatalf("parseSessionEvents kept %d events, want 4 (all levels)", len(events))
	}

	e := events[0]
	if e.Severity != "Error" || e.Scope != "DC01" || e.Code != "4625" {
		t.Errorf("event[0] = Severity %q Scope %q Code %q, want Error/DC01/4625", e.Severity, e.Scope, e.Code)
	}
	if e.Unit != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("event[0] Unit = %q", e.Unit)
	}
	if want := time.UnixMilli(1770000000000).UTC(); !e.At.Equal(want) {
		t.Errorf("event[0] At = %v, want %v (from /Date(ms)/)", e.At, want)
	}
	if e.Source != 3 {
		t.Errorf("Source = %d, want 3", e.Source)
	}

	if events[1].At.IsZero() {
		t.Error("ISO timestamp without zone should parse")
	}
	// Level int fallback: record 3 has no LevelDisplayName, Level 4.
	if events[2].Severity != "Information" {
		t.Errorf("event[2] Severity = %q, want Information (from Level=4)", events[2].Severity)
	}
	if events[3].Severity != "Critical" {
		t.Errorf("event[3] Severity = %q, want Critical", events[3].Severity)
	}
}

func TestParseSessionEvents_SingleObjectConcatenatedAndGarbage(t *testing.T) {
	single := parseSessionEvents(0, []byte(`{"TimeCreated":"2026-01-01T00:00:00","Id":1,"Level":2,"Message":"boom"}`))
	if len(single) != 1 || single[0].Code != "1" {
		t.Fatalf("single object: got %+v, want 1 event with Code 1", single)
	}

	concat := parseSessionEvents(0, []byte(`{"Id":1,"Level":2,"Message":"a"}
{"Id":2,"Level":3,"Message":"b"}`))
	if len(concat) != 2 {
		t.Fatalf("concatenated objects: got %d events, want 2", len(concat))
	}
	if concat[1].Severity != "Warning" {
		t.Errorf("concat[1] Severity = %q, want Warning", concat[1].Severity)
	}

	if got := parseSessionEvents(0, []byte("not json at all")); len(got) != 0 {
		t.Errorf("garbage input: got %d events, want 0 (never error)", len(got))
	}
	if got := parseSessionEvents(0, nil); got != nil {
		t.Errorf("empty input: got %v, want nil", got)
	}
}

func TestBuildStats_EventLog(t *testing.T) {
	s := investigate.NewLogSession("eventlog")
	idx := s.AddSource(investigate.SourceDesc{Path: "test"})
	at := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	s.Append(
		investigate.LogEvent{At: at, Severity: "Error", Scope: "DC01", Unit: "Security-Auditing", Code: "4625", Message: "An account failed to log on", Raw: "x", Source: idx},
		investigate.LogEvent{At: at.Add(30 * time.Second), Severity: "Critical", Scope: "DC01", Unit: "Kernel-Power", Code: "41", Message: "The system has rebooted without cleanly shutting down", Raw: "x", Source: idx},
		investigate.LogEvent{At: at.Add(2 * time.Minute), Severity: "Information", Scope: "DC01", Unit: "Service Control Manager", Code: "7036", Message: "service entered the running state", Raw: "x", Source: idx},
	)
	st := buildStats(s)
	if st.AuthFailures != 1 {
		t.Errorf("AuthFailures = %d, want 1", st.AuthFailures)
	}
	if st.Reboots != 1 {
		t.Errorf("Reboots = %d, want 1", st.Reboots)
	}
	if st.ServiceEvents != 1 {
		t.Errorf("ServiceEvents = %d, want 1", st.ServiceEvents)
	}
	if len(st.LevelTimeline) != 2 {
		t.Fatalf("LevelTimeline = %+v, want 2 buckets", st.LevelTimeline)
	}
	if st.LevelTimeline[0].T != "10:00" || st.LevelTimeline[0].Count != 2 || st.LevelTimeline[0].Sev != "Critical" {
		t.Errorf("bucket[0] = %+v, want {10:00 2 Critical}", st.LevelTimeline[0])
	}
	if len(st.TopEventIDs) != 3 || len(st.TopProviders) != 3 {
		t.Errorf("TopEventIDs/TopProviders = %+v / %+v", st.TopEventIDs, st.TopProviders)
	}
}

func TestSummarize_BuildsInvestigationSession(t *testing.T) {
	p := New()
	if p.InvestigationSession() != nil {
		t.Fatal("session must be nil before the first analysis")
	}

	llm := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}
	body := `[
	  {"TimeCreated":"2026-05-13T10:00:00","Id":4625,"Level":2,"LevelDisplayName":"Error","ProviderName":"Security-Auditing","MachineName":"DC01","Message":"An account failed to log on"},
	  {"TimeCreated":"2026-05-13T10:00:30","Id":7036,"Level":4,"LevelDisplayName":"Information","ProviderName":"Service Control Manager","MachineName":"DC01","Message":"service state change"}
	]`
	args := plugin.RunArgs{
		Stdin:    strings.NewReader(body),
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		LLM:      llm,
		Redactor: red,
	}
	if _, err := p.Subcommands()[0].Run(context.Background(), args); err != nil {
		t.Fatalf("Run: %v", err)
	}

	s := p.InvestigationSession()
	if s == nil {
		t.Fatal("InvestigationSession() = nil after successful summarize")
	}
	if s.Len() != 2 {
		t.Errorf("session has %d events, want 2 (information kept in corpus)", s.Len())
	}
	if len(s.Sources) != 1 || s.Sources[0].Path != "<stdin>" {
		t.Errorf("Sources = %+v, want one <stdin> source", s.Sources)
	}
	st, ok := s.Stats.(EventLogStats)
	if !ok {
		t.Fatalf("Stats type = %T, want EventLogStats", s.Stats)
	}
	if st.AuthFailures != 1 || st.ServiceEvents != 1 {
		t.Errorf("Stats = %+v, want AuthFailures=1 ServiceEvents=1", st)
	}
}
