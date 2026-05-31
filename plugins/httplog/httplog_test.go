package httplog

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
	if p.Name() != "httplog" {
		t.Errorf("Name() = %q, want httplog", p.Name())
	}
	if p.Mutates() {
		t.Error("httplog plugin must be read-only")
	}
}

func TestAnalyze_RedactorIsCalled(t *testing.T) {
	p := New()
	llm := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}

	body := `10.0.0.1 - - [13/May/2026:10:00:00 +0000] "GET /api?key=AKIAIOSFODNN7EXAMPLE HTTP/1.1" 500 200 "-" "curl" 6.2
10.0.0.2 - - [13/May/2026:10:00:01 +0000] "GET /healthz HTTP/1.1" 200 5 "-" "kube-probe" 0.001
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

// TestAnalyze_SSHRemoteCollection verifies that --host routes collection through
// SSH, the remote access log lines reach the LLM, and the redactor fires.
func TestAnalyze_SSHRemoteCollection(t *testing.T) {
	const accessLine = `10.0.0.1 - - [13/May/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 403 512 "-" "curl"` + "\n"
	cmd := exassh.HTTPLogCmd("", 10000) // matches default log-lines for httplog

	srv := sshtest.NewServer(t, map[string]string{cmd: accessLine})
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
			if strings.Contains(m.Content, "/admin") {
				found = true
			}
		}
	}
	if !found {
		t.Error("remote access log content not found in LLM messages")
	}
}

func TestParseHTTP_RecognizesCombinedFormat(t *testing.T) {
	body := []byte(`10.0.0.1 - - [13/May/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 5 "-" "curl" 0.1
10.0.0.2 - - [13/May/2026:10:00:01 +0000] "GET /b HTTP/1.1" 500 12 "-" "curl" 0.2
10.0.0.3 - - [13/May/2026:10:00:02 +0000] "GET /c HTTP/1.1" 500 14 "-" "curl" 0.3
10.0.0.4 - - [13/May/2026:10:00:03 +0000] "GET /d HTTP/1.1" 200 5 "-" "curl" 7.5
`)
	out, err := parseHTTP(body)
	if err != nil {
		t.Fatalf("parseHTTP: %v", err)
	}
	if !strings.Contains(out, "500 : 2") {
		t.Errorf("expected 500 count, got: %s", out)
	}
	if !strings.Contains(out, "7500ms") {
		t.Errorf("expected slow request 7500ms, got: %s", out)
	}
}

func TestParseHTTP_RecognizesNginxError(t *testing.T) {
	body := []byte(`2026/05/13 10:00:00 [error] 1234#0: *5 upstream timed out
2026/05/13 10:00:01 [warn] 1234#0: *6 client closed connection
`)
	out, err := parseHTTP(body)
	if err != nil {
		t.Fatalf("parseHTTP: %v", err)
	}
	if !strings.Contains(out, "error : 1") {
		t.Errorf("expected nginx error level count, got: %s", out)
	}
	if !strings.Contains(out, "upstream timed out") {
		t.Errorf("expected nginx error sample, got: %s", out)
	}
}

func TestParseHTTP_RecognizesApacheError(t *testing.T) {
	body := []byte(`[Wed Oct 11 14:32:52.764 2026] [error] [pid 1234] [client 10.0.0.1] AH00094: Command line: '/usr/sbin/apache2'
`)
	out, err := parseHTTP(body)
	if err != nil {
		t.Fatalf("parseHTTP: %v", err)
	}
	if !strings.Contains(out, "apache") {
		t.Errorf("expected apache error sample, got: %s", out)
	}
}
