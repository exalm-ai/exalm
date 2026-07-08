package httplog

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

func TestParseEvents_AccessAndErrorLines(t *testing.T) {
	chunk := []byte(`10.0.0.1 - - [13/May/2026:10:00:00 +0000] "GET /api/users/1 HTTP/1.1" 500 200 "-" "curl" 6.2
10.0.0.2 - alice [13/May/2026:10:00:01 +0000] "POST /login HTTP/1.1" 200 5 "-" "Mozilla" 0.010
10.0.0.3 - - [13/May/2026:10:00:02 +0000] "GET / HTTP/1.1" 404 0
2026/05/13 10:00:03 [error] 123#0: *1 upstream timed out while reading response header
[Wed May 13 10:00:04.123456 2026] [warn] [pid 42] [client 10.0.0.9] mod_fcgid: process busy
garbage line
`)
	events := parseEvents(1, chunk)
	if len(events) != 5 {
		t.Fatalf("parseEvents kept %d events, want 5", len(events))
	}

	e := events[0]
	if e.Severity != "5xx" || e.Code != "500" {
		t.Errorf("access[0] Severity/Code = %q/%q, want 5xx/500", e.Severity, e.Code)
	}
	if e.Unit != "/api" {
		t.Errorf("access[0] Unit = %q, want /api", e.Unit)
	}
	if e.Message != "GET /api/users/1 → 500 (6200ms)" {
		t.Errorf("access[0] Message = %q", e.Message)
	}
	want := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	if !e.At.Equal(want) {
		t.Errorf("access[0] At = %v, want %v", e.At, want)
	}
	if e.Source != 1 {
		t.Errorf("Source = %d, want 1", e.Source)
	}

	if events[1].Severity != "2xx" || events[1].Unit != "/login" {
		t.Errorf("access[1] = %q/%q, want 2xx//login", events[1].Severity, events[1].Unit)
	}
	if events[2].Severity != "4xx" || events[2].Unit != "/" {
		t.Errorf("access[2] = %q/%q, want 4xx and /", events[2].Severity, events[2].Unit)
	}

	e = events[3] // nginx error line
	if e.Severity != "error" || e.Code != "" {
		t.Errorf("nginx err Severity/Code = %q/%q, want error/empty", e.Severity, e.Code)
	}
	if e.At.IsZero() {
		t.Error("nginx err At should parse")
	}
	if !strings.Contains(e.Message, "upstream timed out") {
		t.Errorf("nginx err Message = %q", e.Message)
	}

	e = events[4] // apache error line
	if e.Severity != "warn" {
		t.Errorf("apache err Severity = %q, want warn", e.Severity)
	}
	if e.At.IsZero() || e.At.Year() != 2026 {
		t.Errorf("apache err At = %v, want parsed 2026 time", e.At)
	}
}

func TestBuildStats_HTTP(t *testing.T) {
	s := investigate.NewLogSession("httplog")
	idx := s.AddSource(investigate.SourceDesc{Path: "test"})
	chunk := []byte(`10.0.0.1 - - [13/May/2026:10:00:00 +0000] "GET /api/a HTTP/1.1" 500 1 "-" "c" 6.0
10.0.0.1 - - [13/May/2026:10:00:20 +0000] "GET /api/a HTTP/1.1" 500 1 "-" "c" 0.1
10.0.0.2 - - [13/May/2026:10:01:00 +0000] "GET /web HTTP/1.1" 200 1 "-" "c" 0.1
2026/05/13 10:02:00 [error] 1#0: backend down
`)
	s.Append(parseEvents(idx, chunk)...)
	st := buildStats(s)

	if st.SlowRequests != 1 {
		t.Errorf("SlowRequests = %d, want 1", st.SlowRequests)
	}
	if len(st.RequestTimeline) != 2 || st.RequestTimeline[0].T != "10:00" || st.RequestTimeline[0].Count != 2 {
		t.Errorf("RequestTimeline = %+v", st.RequestTimeline)
	}
	if len(st.CodeHistogram) != 2 || st.CodeHistogram[0].Name != "500" || st.CodeHistogram[0].Count != 2 {
		t.Errorf("CodeHistogram = %+v", st.CodeHistogram)
	}
	if len(st.TopURIs) != 2 || st.TopURIs[0].Name != "/api/a" {
		t.Errorf("TopURIs = %+v", st.TopURIs)
	}
	if len(st.TopClients) != 2 || st.TopClients[0].Name != "10.0.0.1" || st.TopClients[0].Count != 2 {
		t.Errorf("TopClients = %+v", st.TopClients)
	}
	if len(st.Bursts5xx) != 1 || st.Bursts5xx[0].T != "10:00" || st.Bursts5xx[0].Count != 2 {
		t.Errorf("Bursts5xx = %+v", st.Bursts5xx)
	}
}

func TestAnalyze_BuildsInvestigationSession(t *testing.T) {
	p := New()
	if p.InvestigationSession() != nil {
		t.Fatal("session must be nil before the first analysis")
	}

	llm := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}
	body := `10.0.0.1 - - [13/May/2026:10:00:00 +0000] "GET /api/x HTTP/1.1" 500 200 "-" "curl" 6.2
10.0.0.2 - - [13/May/2026:10:00:01 +0000] "GET /healthz HTTP/1.1" 200 5 "-" "kube-probe" 0.001
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
	if s.Len() != 2 {
		t.Errorf("session has %d events, want 2", s.Len())
	}
	if len(s.Sources) != 1 || s.Sources[0].Path != "<stdin>" {
		t.Errorf("Sources = %+v, want one <stdin> source", s.Sources)
	}
	st, ok := s.Stats.(HTTPStats)
	if !ok {
		t.Fatalf("Stats type = %T, want HTTPStats", s.Stats)
	}
	if st.SlowRequests != 1 || len(st.CodeHistogram) != 2 {
		t.Errorf("Stats = %+v, want SlowRequests=1 and 2 codes", st)
	}
}
