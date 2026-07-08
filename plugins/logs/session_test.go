package logs

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

func TestParseEvents_GenericLines(t *testing.T) {
	chunk := []byte(`2026-05-13T10:00:00Z ERROR failed to connect to db
2026-05-13 10:00:01 WARN retrying connection
May 13 10:00:02 app[9]: fatal: shutting down
plain line with no timestamp or level
2026/05/13 10:00:04 INFO listening on :8080
DEBUG verbose trace output
`)
	events := parseEvents(1, chunk)
	if len(events) != 6 {
		t.Fatalf("parseEvents kept %d events, want 6", len(events))
	}

	e := events[0]
	if e.Severity != "error" {
		t.Errorf("event[0] Severity = %q, want error", e.Severity)
	}
	want := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	if !e.At.Equal(want) {
		t.Errorf("event[0] At = %v, want %v", e.At, want)
	}
	if e.Scope != "" || e.Unit != "" || e.Code != "" {
		t.Errorf("generic events must leave Scope/Unit/Code empty, got %+v", e)
	}
	if e.Message != e.Raw || !strings.Contains(e.Raw, "failed to connect") {
		t.Errorf("Message/Raw = %q/%q", e.Message, e.Raw)
	}
	if e.Source != 1 {
		t.Errorf("Source = %d, want 1", e.Source)
	}

	if events[1].Severity != "warn" || events[1].At.IsZero() {
		t.Errorf("event[1] = %q at %v, want warn with parsed time", events[1].Severity, events[1].At)
	}
	// Syslog-style prefix: current year assumed.
	if events[2].Severity != "fatal" {
		t.Errorf("event[2] Severity = %q, want fatal", events[2].Severity)
	}
	if events[2].At.IsZero() || events[2].At.Year() != time.Now().Year() {
		t.Errorf("event[2] At = %v, want current-year syslog time", events[2].At)
	}
	if events[3].Severity != "info" || !events[3].At.IsZero() {
		t.Errorf("event[3] = %q at %v, want default info and zero time", events[3].Severity, events[3].At)
	}
	if events[4].Severity != "info" || events[4].At.IsZero() {
		t.Errorf("event[4] = %q at %v, want info with slash-date time", events[4].Severity, events[4].At)
	}
	if events[5].Severity != "debug" {
		t.Errorf("event[5] Severity = %q, want debug", events[5].Severity)
	}
}

func TestBuildStats_Logs(t *testing.T) {
	s := investigate.NewLogSession("logs")
	idx := s.AddSource(investigate.SourceDesc{Path: "test"})
	s.Append(parseEvents(idx, []byte(`2026-05-13T10:00:00Z ERROR one
2026-05-13T10:00:30Z FATAL two
2026-05-13T10:02:00Z ERROR three
2026-05-13T10:02:10Z INFO fine
no level here
`))...)
	st := buildStats(s)

	if len(st.ErrorTimeline) != 2 {
		t.Fatalf("ErrorTimeline = %+v, want 2 buckets", st.ErrorTimeline)
	}
	if st.ErrorTimeline[0].T != "10:00" || st.ErrorTimeline[0].Count != 2 || st.ErrorTimeline[0].Sev != "fatal" {
		t.Errorf("bucket[0] = %+v, want {10:00 2 fatal}", st.ErrorTimeline[0])
	}
	if st.ErrorTimeline[1].T != "10:02" || st.ErrorTimeline[1].Count != 1 || st.ErrorTimeline[1].Sev != "error" {
		t.Errorf("bucket[1] = %+v, want {10:02 1 error}", st.ErrorTimeline[1])
	}
	// error:2, info:2 (INFO line + default), fatal:1.
	if len(st.SeverityCounts) != 3 {
		t.Fatalf("SeverityCounts = %+v, want 3 severities", st.SeverityCounts)
	}
	counts := map[string]int{}
	for _, nc := range st.SeverityCounts {
		counts[nc.Name] = nc.Count
	}
	if counts["error"] != 2 || counts["fatal"] != 1 || counts["info"] != 2 {
		t.Errorf("SeverityCounts = %+v", st.SeverityCounts)
	}
}

func TestSummarize_BuildsInvestigationSession(t *testing.T) {
	p := New()
	if p.InvestigationSession() != nil {
		t.Fatal("session must be nil before the first analysis")
	}

	llm := &fakeLLM{resp: "ok"}
	args := plugin.RunArgs{
		Stdin:    strings.NewReader("2026-05-13T10:00:00Z ERROR db down\n2026-05-13T10:00:01Z INFO retry ok\n"),
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		LLM:      llm,
		Redactor: redact.New(),
	}
	if _, err := p.Subcommands()[0].Run(context.Background(), args); err != nil {
		t.Fatalf("Run: %v", err)
	}

	s := p.InvestigationSession()
	if s == nil {
		t.Fatal("InvestigationSession() = nil after successful summarize")
	}
	if s.Len() != 2 {
		t.Errorf("session has %d events, want 2", s.Len())
	}
	if len(s.Sources) != 1 || s.Sources[0].Path != "<stdin>" {
		t.Errorf("Sources = %+v, want one <stdin> source", s.Sources)
	}
	st, ok := s.Stats.(LogsStats)
	if !ok {
		t.Fatalf("Stats type = %T, want LogsStats", s.Stats)
	}
	if len(st.ErrorTimeline) != 1 || len(st.SeverityCounts) != 2 {
		t.Errorf("Stats = %+v", st)
	}
}

func TestSummarize_NoSessionOnLLMError(t *testing.T) {
	p := New()
	args := plugin.RunArgs{
		Stdin:    strings.NewReader("2026-05-13T10:00:00Z ERROR db down\n"),
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		LLM:      &failingLLM{},
		Redactor: redact.New(),
	}
	if _, err := p.Subcommands()[0].Run(context.Background(), args); err == nil {
		t.Fatal("expected LLM error")
	}
	if p.InvestigationSession() != nil {
		t.Fatal("session must not be published when the analysis fails")
	}
}

type failingLLM struct{}

func (f *failingLLM) Name() string { return "failing" }

func (f *failingLLM) Complete(context.Context, plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	return plugin.CompleteResponse{}, context.DeadlineExceeded
}
