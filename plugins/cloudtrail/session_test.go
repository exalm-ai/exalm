package cloudtrail

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/internal/redact"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestParseEvents_KeepsEveryRecord(t *testing.T) {
	chunk := []byte(`{"eventTime":"2026-05-13T09:00:00Z","eventName":"DescribeInstances","userIdentity":{"userName":"alice"},"awsRegion":"us-east-1","sourceIPAddress":"10.0.0.1"}
{"eventTime":"2026-05-13T09:00:01Z","eventName":"DeleteBucket","userIdentity":{"userName":"alice"},"awsRegion":"us-east-1","sourceIPAddress":"10.0.0.1","errorCode":"AccessDenied","errorMessage":"denied"}
{"eventTime":"2026-05-13T09:00:02Z","eventName":"CreateUser","userIdentity":{"type":"Root"},"awsRegion":"us-west-2","sourceIPAddress":"10.0.0.2"}
not valid json
`)
	events := parseEvents(0, chunk)
	if len(events) != 3 {
		t.Fatalf("expected 3 events (routine call kept + invalid line skipped), got %d: %+v", len(events), events)
	}

	if events[0].Severity != "info" || events[0].Unit != "DescribeInstances" {
		t.Errorf("event 0 = %+v, want info/DescribeInstances", events[0])
	}
	if events[1].Severity != "err" || events[1].Code != "AccessDenied" {
		t.Errorf("event 1 = %+v, want err/AccessDenied", events[1])
	}
	if !strings.Contains(events[1].Message, "denied") {
		t.Errorf("event 1 message should include the error detail, got %q", events[1].Message)
	}
	if events[2].Severity != "crit" || events[2].Scope != "us-west-2" {
		t.Errorf("event 2 = %+v, want crit/us-west-2 (root usage)", events[2])
	}
	if events[2].At.IsZero() {
		t.Error("event 2 should have a parsed timestamp")
	}
}

func TestBuildStats_CloudTrail(t *testing.T) {
	s := investigate.NewLogSession("cloudtrail")
	idx := s.AddSource(investigate.SourceDesc{Path: "test"})
	chunk := []byte(`{"eventTime":"2026-05-13T10:00:00Z","eventName":"DeleteUser","userIdentity":{"userName":"alice"},"awsRegion":"us-east-1","sourceIPAddress":"10.0.0.1","errorCode":"AccessDenied","errorMessage":"denied"}
{"eventTime":"2026-05-13T10:00:05Z","eventName":"DeleteUser","userIdentity":{"userName":"alice"},"awsRegion":"us-east-1","sourceIPAddress":"10.0.0.1","errorCode":"AccessDenied","errorMessage":"denied"}
{"eventTime":"2026-05-13T10:01:00Z","eventName":"ConsoleLogin","userIdentity":{"userName":"mallory"},"awsRegion":"us-east-1","sourceIPAddress":"10.0.0.2","errorMessage":"Failed authentication"}
{"eventTime":"2026-05-13T10:02:00Z","eventName":"CreateUser","userIdentity":{"type":"Root"},"awsRegion":"us-east-1","sourceIPAddress":"10.0.0.3"}
`)
	s.Append(parseEvents(idx, chunk)...)
	st := buildStats(s)

	if st.AccessDenied != 2 {
		t.Errorf("AccessDenied = %d, want 2", st.AccessDenied)
	}
	if st.RootUsage != 1 {
		t.Errorf("RootUsage = %d, want 1", st.RootUsage)
	}
	if st.ConsoleLoginFailures != 1 {
		t.Errorf("ConsoleLoginFailures = %d, want 1", st.ConsoleLoginFailures)
	}
	if len(st.TopEventNames) != 3 || st.TopEventNames[0].Name != "DeleteUser" || st.TopEventNames[0].Count != 2 {
		t.Errorf("TopEventNames = %+v", st.TopEventNames)
	}
	if len(st.TopPrincipals) != 3 || st.TopPrincipals[0].Name != "alice" || st.TopPrincipals[0].Count != 2 {
		t.Errorf("TopPrincipals = %+v", st.TopPrincipals)
	}
	if len(st.EventTimeline) != 3 || st.EventTimeline[0].T != "10:00" || st.EventTimeline[0].Count != 2 {
		t.Errorf("EventTimeline = %+v", st.EventTimeline)
	}
}

func TestAnalyze_BuildsInvestigationSession(t *testing.T) {
	p := New()
	if p.InvestigationSession() != nil {
		t.Fatal("session must be nil before the first analysis")
	}

	llm := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}
	body := `{"eventTime":"2026-05-13T09:00:00Z","eventName":"DeleteUser","userIdentity":{"userName":"alice"},"awsRegion":"us-east-1","sourceIPAddress":"10.0.0.1","errorCode":"AccessDenied","errorMessage":"denied"}
{"eventTime":"2026-05-13T09:00:01Z","eventName":"DescribeInstances","userIdentity":{"userName":"bob"},"awsRegion":"us-east-1","sourceIPAddress":"10.0.0.2"}
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
		t.Errorf("session has %d events, want 2 (both records kept, including the routine one)", s.Len())
	}
	st, ok := s.Stats.(CloudTrailStats)
	if !ok {
		t.Fatalf("s.Stats is %T, want CloudTrailStats", s.Stats)
	}
	if st.AccessDenied != 1 {
		t.Errorf("AccessDenied = %d, want 1", st.AccessDenied)
	}
}
