package syslog

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

func TestParseEvents_Formats(t *testing.T) {
	chunk := []byte(`<3>May 13 10:00:00 web01 sshd[1234]: Failed password for root from 10.0.0.1
<6>May 13 10:00:01 web01 cron: starting daily job
<34>1 2026-05-13T10:00:02.003Z db01 postgres 999 ID47 - checkpoint starting
{"PRIORITY":"3","__REALTIME_TIMESTAMP":"1770000000000000","_HOSTNAME":"app01","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"upstream timed out"}
May 13 10:00:04 web02 kernel: Out of memory: kill process 100
not a syslog line at all
`)
	events := parseEvents(2, chunk)
	if len(events) != 5 {
		t.Fatalf("parseEvents kept %d events, want 5", len(events))
	}

	e := events[0] // RFC3164 with PRI
	if e.Severity != "err" {
		t.Errorf("rfc3164 Severity = %q, want err", e.Severity)
	}
	if e.Scope != "web01" {
		t.Errorf("rfc3164 Scope = %q, want web01", e.Scope)
	}
	if e.Unit != "sshd" {
		t.Errorf("rfc3164 Unit = %q, want sshd (pid stripped)", e.Unit)
	}
	if e.Code != "" {
		t.Errorf("rfc3164 Code = %q, want empty", e.Code)
	}
	if e.Source != 2 {
		t.Errorf("Source = %d, want 2", e.Source)
	}
	wantAt := time.Date(time.Now().Year(), time.May, 13, 10, 0, 0, 0, time.UTC)
	if !e.At.Equal(wantAt) {
		t.Errorf("rfc3164 At = %v, want %v (current year assumed)", e.At, wantAt)
	}

	if events[1].Severity != "info" {
		t.Errorf("info line Severity = %q, want info", events[1].Severity)
	}

	e = events[2] // RFC5424: pri 34 => severity 2 (crit)
	if e.Severity != "crit" {
		t.Errorf("rfc5424 Severity = %q, want crit", e.Severity)
	}
	if e.Scope != "db01" || e.Unit != "postgres" {
		t.Errorf("rfc5424 Scope/Unit = %q/%q, want db01/postgres", e.Scope, e.Unit)
	}
	if e.At.IsZero() || e.At.Year() != 2026 {
		t.Errorf("rfc5424 At = %v, want parsed 2026 timestamp", e.At)
	}

	e = events[3] // journalctl JSON
	if e.Severity != "err" || e.Scope != "app01" || e.Unit != "nginx.service" {
		t.Errorf("journal event = %+v, want err/app01/nginx.service", e)
	}
	if e.At.IsZero() {
		t.Error("journal At should parse from __REALTIME_TIMESTAMP")
	}
	if e.Message != "upstream timed out" {
		t.Errorf("journal Message = %q", e.Message)
	}

	e = events[4] // bare BSD, no PRI => info default
	if e.Severity != "info" || e.Unit != "kernel" {
		t.Errorf("bsd event Severity/Unit = %q/%q, want info/kernel", e.Severity, e.Unit)
	}
}

func TestBuildStats_Syslog(t *testing.T) {
	s := investigate.NewLogSession("syslog")
	idx := s.AddSource(investigate.SourceDesc{Path: "test"})
	at := time.Date(2026, 5, 13, 10, 0, 30, 0, time.UTC)
	s.Append(
		investigate.LogEvent{At: at, Severity: "err", Scope: "web01", Unit: "sshd", Message: "Failed password for root", Raw: "x", Source: idx},
		investigate.LogEvent{At: at.Add(20 * time.Second), Severity: "crit", Scope: "web01", Unit: "kernel", Message: "Out of memory: kill process 100", Raw: "x", Source: idx},
		investigate.LogEvent{At: at.Add(90 * time.Second), Severity: "info", Scope: "db01", Unit: "cron", Message: "job ok", Raw: "x", Source: idx},
		investigate.LogEvent{At: at.Add(2 * time.Minute), Severity: "warn", Scope: "db01", Unit: "smartd", Message: "disk error detected on /dev/sda", Raw: "x", Source: idx},
	)
	st := buildStats(s)
	if st.AuthFailures != 1 {
		t.Errorf("AuthFailures = %d, want 1", st.AuthFailures)
	}
	if st.OOMEvents != 1 {
		t.Errorf("OOMEvents = %d, want 1", st.OOMEvents)
	}
	if st.DiskErrors != 1 {
		t.Errorf("DiskErrors = %d, want 1", st.DiskErrors)
	}
	// 10:00 bucket has err+crit (worst = crit); the info line is excluded.
	if len(st.SeverityTimeline) != 2 {
		t.Fatalf("SeverityTimeline = %+v, want 2 buckets", st.SeverityTimeline)
	}
	if st.SeverityTimeline[0].T != "10:00" || st.SeverityTimeline[0].Count != 2 || st.SeverityTimeline[0].Sev != "crit" {
		t.Errorf("bucket[0] = %+v, want {10:00 2 crit}", st.SeverityTimeline[0])
	}
	if st.SeverityTimeline[1].T != "10:02" || st.SeverityTimeline[1].Sev != "warn" {
		t.Errorf("bucket[1] = %+v, want {10:02 1 warn}", st.SeverityTimeline[1])
	}
	if len(st.TopUnits) != 4 {
		t.Errorf("TopUnits = %+v, want 4 entries", st.TopUnits)
	}
	if len(st.TopHosts) != 2 || st.TopHosts[0].Count != 2 {
		t.Errorf("TopHosts = %+v, want 2 entries with count 2 first", st.TopHosts)
	}
}

func TestAnalyze_BuildsInvestigationSession(t *testing.T) {
	p := New()
	if p.InvestigationSession() != nil {
		t.Fatal("session must be nil before the first analysis")
	}

	llm := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}
	body := `<3>May 13 10:00:00 web01 sshd[1234]: Failed password for root from 10.0.0.1 port 5022
<6>May 13 10:00:01 web01 cron: starting daily job
<2>May 13 10:00:02 web01 kernel: Out of memory: kill process 100
`
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
		t.Fatal("InvestigationSession() = nil after successful analyze")
	}
	if s.Len() != 3 {
		t.Errorf("session has %d events, want 3 (all severities kept)", s.Len())
	}
	if len(s.Sources) != 1 || s.Sources[0].Path != "<stdin>" {
		t.Errorf("Sources = %+v, want one <stdin> source", s.Sources)
	}
	if s.SSH != nil {
		t.Error("SSH params must be nil for a local analysis")
	}
	st, ok := s.Stats.(SyslogStats)
	if !ok {
		t.Fatalf("Stats type = %T, want SyslogStats", s.Stats)
	}
	if st.AuthFailures != 1 || st.OOMEvents != 1 {
		t.Errorf("Stats = %+v, want AuthFailures=1 OOMEvents=1", st)
	}
	units, _ := s.Vocabulary()
	if len(units) != 3 {
		t.Errorf("Vocabulary units = %v, want sshd/cron/kernel", units)
	}
}

// Timeline buckets must carry the instant they cover, not just a "15:04"
// label. The label alone drops the date, so a chart click cannot be resolved
// back to a time range — which is why the drilldown used to fall back to a
// text match on the timestamp.
func TestBuildStats_TimelineBucketsCarryInstant(t *testing.T) {
	s := investigate.NewLogSession("syslog")
	idx := s.AddSource(investigate.SourceDesc{Path: "test"})
	at := time.Date(2026, 5, 13, 10, 0, 30, 0, time.UTC)
	s.Append(
		investigate.LogEvent{At: at, Severity: "err", Unit: "sshd", Message: "boom", Raw: "x", Source: idx},
		investigate.LogEvent{At: at.Add(10 * time.Second), Severity: "warn", Unit: "sshd", Message: "meh", Raw: "x", Source: idx},
		investigate.LogEvent{At: at.Add(3 * time.Minute), Severity: "err", Unit: "sshd", Message: "boom again", Raw: "x", Source: idx},
	)

	tl := buildStats(s).SeverityTimeline
	if len(tl) != 2 {
		t.Fatalf("expected 2 minute buckets, got %d: %+v", len(tl), tl)
	}
	for _, b := range tl {
		if b.At.IsZero() {
			t.Fatalf("bucket %q carries no instant", b.T)
		}
		if !b.At.Equal(b.At.Truncate(time.Minute)) {
			t.Errorf("bucket instant %v is not minute-aligned", b.At)
		}
		if b.Width != time.Minute {
			t.Errorf("bucket width = %v, want 1m", b.Width)
		}
		if b.T != b.At.Format("15:04") {
			t.Errorf("label %q does not match instant %v", b.T, b.At)
		}
	}
	// Ascending by real time, so the chart's x-axis is chronological.
	if !tl[0].At.Before(tl[1].At) {
		t.Errorf("buckets not sorted by instant: %v then %v", tl[0].At, tl[1].At)
	}
	// The first bucket holds both events from that minute.
	if tl[0].Count != 2 {
		t.Errorf("first bucket count = %d, want 2", tl[0].Count)
	}
}
