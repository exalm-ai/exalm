package syslog

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
	if p.Name() != "syslog" {
		t.Errorf("Name() = %q, want syslog", p.Name())
	}
	if p.Mutates() {
		t.Error("syslog plugin must be read-only")
	}
}

func TestAnalyze_RedactorIsCalled(t *testing.T) {
	p := New()
	llm := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}

	body := `<3>May 13 10:00:00 web01 sshd[1234]: Failed password for root from 10.0.0.1 port 5022
<3>May 13 10:00:01 web01 app: secret AKIAIOSFODNN7EXAMPLE in error
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

func TestParseSyslog_FiltersByPriority(t *testing.T) {
	body := []byte(`<3>May 13 10:00:00 web01 sshd[1234]: Failed password for root
<6>May 13 10:00:01 web01 cron: starting daily job
<2>May 13 10:00:02 web01 kernel: Out of memory: kill process 100
`)
	out, err := parseSyslog(body)
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
	}
	if !strings.Contains(out, "Failed password") {
		t.Errorf("expected err-level event kept, got: %s", out)
	}
	if !strings.Contains(out, "Out of memory") {
		t.Errorf("expected crit event kept, got: %s", out)
	}
	if strings.Contains(out, "starting daily job") {
		t.Errorf("info-level event must be filtered, got: %s", out)
	}
}

func TestParseSyslog_AcceptsJournalctlJSON(t *testing.T) {
	body := []byte(`{"PRIORITY":"3","_HOSTNAME":"web01","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"upstream timed out"}` + "\n")
	out, err := parseSyslog(body)
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
	}
	if !strings.Contains(out, "upstream timed out") {
		t.Errorf("expected journal message in output, got: %s", out)
	}
	if !strings.Contains(out, "nginx.service") {
		t.Errorf("expected unit name in output, got: %s", out)
	}
}

// TestAnalyze_SSHRemoteCollection verifies that when --host is set the plugin
// dials an SSH server, receives the remote syslog output, and passes it
// through the redactor before calling the LLM. Uses an embedded sshtest
// server — no real SSH daemon or on-disk key files needed.
func TestAnalyze_SSHRemoteCollection(t *testing.T) {
	const syslogLine = `<3>May 13 10:00:00 web01 sshd[9000]: Failed password for root from 192.168.1.5 port 22` + "\n"
	cmd := exassh.SyslogCmd(true, 5000) // matches the default LogLinesFromArgs

	srv := sshtest.NewServer(t, map[string]string{cmd: syslogLine})
	defer srv.Close()

	keyFile := srv.WriteClientKeyFile(t)
	llmClient := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}

	args := plugin.RunArgs{
		Stdin:    &bytes.Buffer{}, // ignored when --host set
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

	// The LLM must have been called with remote content.
	if len(llmClient.captured) == 0 {
		t.Fatal("LLM was never called — remote content not forwarded")
	}

	// Verify the redactor was applied.
	if atomic.LoadInt64(&red.calls) == 0 {
		t.Fatal("redactor was never called — TRUST BOUNDARY VIOLATION")
	}

	// Verify the remote syslog content reached the LLM.
	found := false
	for _, req := range llmClient.captured {
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "Failed password") {
				found = true
			}
		}
	}
	if !found {
		t.Error("remote syslog content not found in LLM messages")
	}
}

func TestParseSyslog_AcceptsBSDFormat(t *testing.T) {
	body := []byte("May 13 10:00:00 web01 sshd: connection from 10.0.0.1\n")
	out, err := parseSyslog(body)
	if err != nil {
		t.Fatalf("parseSyslog: %v", err)
	}
	// BSD without PRI defaults to info (6), so it's dropped under filter.
	if !strings.Contains(out, "1 info-level dropped") {
		t.Errorf("expected info-level drop count, got: %s", out)
	}
}
