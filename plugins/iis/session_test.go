package iis

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

const w3cFixture = `#Software: Microsoft Internet Information Services 10.0
#Fields: date time s-sitename cs-method cs-uri-stem sc-status time-taken c-ip
2026-05-13 10:00:00 W3SVC1 GET /api/users/1 500 6000 10.0.0.1
2026-05-13 10:00:30 W3SVC1 GET /api/users/2 500 20 10.0.0.2
2026-05-13 10:01:00 W3SVC2 POST /login 200 15 10.0.0.3
2026-05-13 10:01:30 W3SVC1 GET / 404 5 10.0.0.4
#Fields: date time cs-method cs-uri-stem sc-status time-taken c-ip
2026-05-13 10:02:00 GET /health 200 2 10.0.0.5
`

func TestParseEvents_W3CHonorsFieldsHeader(t *testing.T) {
	events := parseEvents(2, []byte(w3cFixture))
	if len(events) != 5 {
		t.Fatalf("parseEvents kept %d events, want 5", len(events))
	}

	e := events[0]
	if e.Severity != "5xx" || e.Code != "500" {
		t.Errorf("event[0] Severity/Code = %q/%q, want 5xx/500", e.Severity, e.Code)
	}
	if e.Scope != "W3SVC1" {
		t.Errorf("event[0] Scope = %q, want W3SVC1", e.Scope)
	}
	if e.Unit != "/api" {
		t.Errorf("event[0] Unit = %q, want /api", e.Unit)
	}
	want := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	if !e.At.Equal(want) {
		t.Errorf("event[0] At = %v, want %v (UTC)", e.At, want)
	}
	if e.Message != "GET /api/users/1 → 500 (6000ms)" {
		t.Errorf("event[0] Message = %q", e.Message)
	}
	if e.Source != 2 {
		t.Errorf("Source = %d, want 2", e.Source)
	}

	if events[2].Severity != "2xx" || events[2].Unit != "/login" {
		t.Errorf("event[2] = %q/%q, want 2xx//login", events[2].Severity, events[2].Unit)
	}
	if events[3].Severity != "4xx" || events[3].Unit != "/" {
		t.Errorf("event[3] = %q/%q, want 4xx and /", events[3].Severity, events[3].Unit)
	}

	// After the second #Fields header there is no s-sitename column.
	e = events[4]
	if e.Scope != "" {
		t.Errorf("event[4] Scope = %q, want empty after header change", e.Scope)
	}
	if e.Unit != "/health" || e.Code != "200" {
		t.Errorf("event[4] Unit/Code = %q/%q, want /health/200", e.Unit, e.Code)
	}
}

func TestBuildStats_IIS(t *testing.T) {
	s := investigate.NewLogSession("iis")
	idx := s.AddSource(investigate.SourceDesc{Path: "test"})
	s.Append(parseEvents(idx, []byte(w3cFixture))...)
	st := buildStats(s)

	if st.SlowRequests != 1 {
		t.Errorf("SlowRequests = %d, want 1", st.SlowRequests)
	}
	if len(st.RequestTimeline) != 3 || st.RequestTimeline[0].T != "10:00" || st.RequestTimeline[0].Count != 2 {
		t.Errorf("RequestTimeline = %+v", st.RequestTimeline)
	}
	// 200 and 500 tie at 2; name asc breaks the tie.
	if len(st.CodeHistogram) != 3 || st.CodeHistogram[0].Name != "200" || st.CodeHistogram[1].Name != "500" || st.CodeHistogram[1].Count != 2 {
		t.Errorf("CodeHistogram = %+v", st.CodeHistogram)
	}
	if len(st.TopSites) != 2 || st.TopSites[0].Name != "W3SVC1" || st.TopSites[0].Count != 3 {
		t.Errorf("TopSites = %+v", st.TopSites)
	}
	if len(st.TopURIs) != 5 {
		t.Errorf("TopURIs = %+v, want 5 distinct URIs", st.TopURIs)
	}
}

func TestAnalyze_BuildsInvestigationSession(t *testing.T) {
	p := New()
	if p.InvestigationSession() != nil {
		t.Fatal("session must be nil before the first analysis")
	}

	llm := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}
	args := plugin.RunArgs{
		Stdin:    strings.NewReader(w3cFixture),
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
	if s.Len() != 5 {
		t.Errorf("session has %d events, want 5", s.Len())
	}
	if len(s.Sources) != 1 || s.Sources[0].Path != "<stdin>" {
		t.Errorf("Sources = %+v, want one <stdin> source", s.Sources)
	}
	st, ok := s.Stats.(IISStats)
	if !ok {
		t.Fatalf("Stats type = %T, want IISStats", s.Stats)
	}
	if st.SlowRequests != 1 || len(st.CodeHistogram) == 0 {
		t.Errorf("Stats = %+v, want SlowRequests=1 and a code histogram", st)
	}
}
