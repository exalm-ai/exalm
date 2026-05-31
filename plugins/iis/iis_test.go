package iis

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/exalm-ai/exalm/internal/redact"
	exassh "github.com/exalm-ai/exalm/internal/ssh"
	"github.com/exalm-ai/exalm/internal/ssh/sshtest"
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
	if p.Name() != "iis" {
		t.Errorf("Name() = %q, want iis", p.Name())
	}
	if p.Mutates() {
		t.Error("iis plugin must be read-only")
	}
}

func TestAnalyze_RedactorIsCalled(t *testing.T) {
	p := New()
	llm := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}

	body := `#Software: Microsoft Internet Information Services 10.0
#Fields: date time cs-method cs-uri-stem sc-status time-taken c-ip
2026-05-13 10:00:00 GET /api AKIAIOSFODNN7EXAMPLE 200 12 10.0.0.1
2026-05-13 10:00:01 GET /admin 500 200 10.0.0.2
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

// TestAnalyze_SSHRemoteCollection verifies that --host routes IIS log collection
// through SSH and the W3C log lines reach the LLM via the redactor.
func TestAnalyze_SSHRemoteCollection(t *testing.T) {
	const w3cLines = "#Software: Microsoft Internet Information Services 10.0\n" +
		"#Fields: date time cs-method cs-uri-stem sc-status time-taken c-ip\n" +
		"2026-05-13 10:00:00 GET /admin 403 50 10.0.0.1\n"
	cmd := exassh.IISLogCmd("", 5000) // matches default log-lines for iis

	srv := sshtest.NewServer(t, map[string]string{cmd: w3cLines})
	defer srv.Close()

	keyFile := srv.WriteClientKeyFile(t)
	llmClient := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}

	args := plugin.RunArgs{
		Stdin:    &bytes.Buffer{},
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		LLM:      llmClient,
		Redactor: red,
		Flags: map[string]string{
			"host":     srv.Host(),
			"ssh-port": srv.Port(),
			"ssh-key":  keyFile,
			"ssh-user": "testuser",
		},
		FlagsMulti: map[string][]string{},
	}

	_, err := New().Subcommands()[0].Run(context.Background(), args)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(llmClient.captured) == 0 {
		t.Fatal("LLM was never called — remote content not forwarded")
	}
	if atomic.LoadInt64(&red.calls) == 0 {
		t.Fatal("redactor was never called — TRUST BOUNDARY VIOLATION")
	}

	found := false
	for _, req := range llmClient.captured {
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "/admin") || strings.Contains(m.Content, "403") {
				found = true
			}
		}
	}
	if !found {
		t.Error("remote IIS log content not found in LLM messages")
	}
}

func TestParseW3C_SummarizesStatusCodes(t *testing.T) {
	body := []byte(`#Software: Microsoft Internet Information Services 10.0
#Fields: date time cs-method cs-uri-stem sc-status time-taken c-ip
2026-05-13 10:00:00 GET /a 200 12 10.0.0.1
2026-05-13 10:00:01 GET /b 500 30 10.0.0.2
2026-05-13 10:00:02 GET /c 500 40 10.0.0.3
2026-05-13 10:00:03 GET /d 200 6000 10.0.0.4
`)
	out, err := parseW3C(body)
	if err != nil {
		t.Fatalf("parseW3C: %v", err)
	}
	if !strings.Contains(out, "500 : 2") {
		t.Errorf("expected 500 count, got: %s", out)
	}
	if !strings.Contains(out, "6000ms") {
		t.Errorf("expected slow request line, got: %s", out)
	}
	if !strings.Contains(out, "Top URIs") {
		t.Errorf("expected URI histogram, got: %s", out)
	}
}

func TestParseW3C_HandlesNoFieldsHeader(t *testing.T) {
	out, err := parseW3C([]byte("just random text\nanother line\n"))
	if err != nil {
		t.Fatalf("parseW3C: %v", err)
	}
	if !strings.Contains(out, "0 request(s) parsed") {
		t.Errorf("expected zero parse summary, got: %s", out)
	}
}
