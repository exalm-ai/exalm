package cloudtrail

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/exalm-ai/exalm/internal/redact"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

type fakeLLM struct {
	captured []plugin.CompleteRequest
}

func (f *fakeLLM) Name() string { return "fake" }

func (f *fakeLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	f.captured = append(f.captured, req)
	return plugin.CompleteResponse{Content: "ok"}, nil
}

type trackingRedactor struct {
	calls int64
	inner *redact.Engine
}

func (t *trackingRedactor) Redact(s string) string {
	atomic.AddInt64(&t.calls, 1)
	return t.inner.Redact(s)
}

func TestPlugin_Metadata(t *testing.T) {
	p := New()
	if p.Name() != "cloudtrail" {
		t.Errorf("Name() = %q, want cloudtrail", p.Name())
	}
	if p.Mutates() {
		t.Error("cloudtrail plugin must be read-only")
	}
}

func TestAnalyze_RedactorIsCalled(t *testing.T) {
	p := New()
	llm := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}

	body := `{"eventVersion":"1.08","userIdentity":{"type":"Root","accountId":"123456789012"},"eventTime":"2026-05-13T09:00:00Z","eventSource":"iam.amazonaws.com","eventName":"DeleteUser","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.10","errorCode":"AccessDenied","errorMessage":"secret AKIAIOSFODNN7EXAMPLE in error"}
`
	args := plugin.RunArgs{
		Stdin:    strings.NewReader(body),
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		LLM:      llm,
		Redactor: red,
	}
	_, err := p.Subcommands()[0].Run(context.Background(), args)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if atomic.LoadInt64(&red.calls) == 0 {
		t.Fatal("redactor was never called — TRUST BOUNDARY VIOLATION")
	}
	for _, req := range llm.captured {
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "AKIAIOSFODNN7EXAMPLE") {
				t.Fatalf("RAW SECRET LEAKED TO LLM: %q", m.Content)
			}
		}
	}
}

func TestParseCloudTrail_FiltersRoutineCalls(t *testing.T) {
	body := []byte(`{"eventTime":"2026-05-13T09:00:00Z","eventName":"DescribeInstances","userIdentity":{"userName":"alice"},"awsRegion":"us-east-1"}
{"eventTime":"2026-05-13T09:00:01Z","eventName":"DeleteBucket","userIdentity":{"userName":"alice"},"awsRegion":"us-east-1"}
{"eventTime":"2026-05-13T09:00:02Z","eventName":"ConsoleLogin","userIdentity":{"userName":"mallory"},"errorMessage":"Failed authentication","awsRegion":"us-east-1"}
`)
	out, err := parseCloudTrail(body)
	if err != nil {
		t.Fatalf("parseCloudTrail: %v", err)
	}
	if strings.Contains(out, "DescribeInstances") {
		t.Errorf("routine read-only call must be filtered, got: %s", out)
	}
	if !strings.Contains(out, "DeleteBucket") {
		t.Errorf("expected destructive call kept, got: %s", out)
	}
	if !strings.Contains(out, "ConsoleLogin") {
		t.Errorf("expected console login kept, got: %s", out)
	}
}

func TestParseCloudTrail_KeepsRootUsage(t *testing.T) {
	body := []byte(`{"eventTime":"2026-05-13T09:00:00Z","eventName":"CreateUser","userIdentity":{"type":"Root"},"awsRegion":"us-east-1"}
`)
	out, err := parseCloudTrail(body)
	if err != nil {
		t.Fatalf("parseCloudTrail: %v", err)
	}
	if !strings.Contains(out, "1 root-account events") {
		t.Errorf("expected root-account event counted, got: %s", out)
	}
}

func TestParseCloudTrail_SkipsInvalidLines(t *testing.T) {
	body := []byte("not json\n{\n{\"eventTime\":\"2026-05-13T09:00:00Z\",\"eventName\":\"DeleteUser\",\"userIdentity\":{\"userName\":\"alice\"},\"awsRegion\":\"us-east-1\"}\n")
	out, err := parseCloudTrail(body)
	if err != nil {
		t.Fatalf("parseCloudTrail: %v", err)
	}
	if !strings.Contains(out, "DeleteUser") {
		t.Errorf("valid line must still be parsed despite invalid neighbors, got: %s", out)
	}
}
