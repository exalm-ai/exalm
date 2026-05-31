package eventlog

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
	if p.Name() != "eventlog" {
		t.Errorf("Name() = %q, want eventlog", p.Name())
	}
	if p.Mutates() {
		t.Error("eventlog plugin must be read-only")
	}
	if len(p.Subcommands()) == 0 {
		t.Error("expected at least one subcommand")
	}
}

func TestSummarize_RedactorIsCalled(t *testing.T) {
	p := New()
	llm := &fakeLLM{}
	red := &trackingRedactor{inner: redact.New()}

	body := `[
	  {"TimeCreated":"2026-05-13T10:00:00","Id":4625,"Level":2,"LevelDisplayName":"Error","ProviderName":"Microsoft-Windows-Security-Auditing","LogName":"Security","MachineName":"DC01","Message":"Failed logon from CORP\\jdoe SID S-1-5-21-1111-2222-3333-1001 with key AKIAIOSFODNN7EXAMPLE","RecordId":42}
	]`
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
			if strings.Contains(m.Content, "S-1-5-21-1111-2222-3333-1001") {
				t.Fatalf("RAW SID LEAKED TO LLM: %q", m.Content)
			}
		}
	}
}

func TestSummarize_RejectsEvtxBinary(t *testing.T) {
	p := New()
	args := plugin.RunArgs{
		Stdin:    strings.NewReader(""),
		Flags:    map[string]string{"file": "C:/path/to/Security.evtx"},
		LLM:      &fakeLLM{},
		Redactor: redact.New(),
	}
	_, err := p.Subcommands()[0].Run(context.Background(), args)
	if err == nil {
		t.Fatal("expected error for .evtx binary input")
	}
	if !strings.Contains(err.Error(), "evtx") {
		t.Errorf("error should mention evtx, got: %v", err)
	}
}

// TestSummarize_SSHRemoteCollection verifies that --host routes collection over
// SSH, fetching Windows Event Log JSON, and the content reaches the LLM via
// the redactor. Uses an embedded sshtest server — no real SSH daemon needed.
func TestSummarize_SSHRemoteCollection(t *testing.T) {
	const eventJSON = `[{"Id":4625,"Level":2,"LevelDisplayName":"Error","Message":"An account failed to log on","TimeCreated":"2026-01-01T00:00:00","ProviderName":"Security-Auditing","LogName":"Security","MachineName":"WIN-DC01","RecordId":1}]`
	cmd := exassh.EventLogCmd("Security", 1000) // matches default log-lines for eventlog

	srv := sshtest.NewServer(t, map[string]string{cmd: eventJSON + "\n"})
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
			"log-name": "Security",
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
			if strings.Contains(m.Content, "failed to log on") {
				found = true
			}
		}
	}
	if !found {
		t.Error("remote Event Log content not found in LLM messages")
	}
}

func TestParseEvents_FiltersInfoLevel(t *testing.T) {
	body := []byte(`[
	  {"TimeCreated":"t1","Id":4624,"Level":4,"LevelDisplayName":"Information","Message":"OK"},
	  {"TimeCreated":"t2","Id":4625,"Level":2,"LevelDisplayName":"Error","Message":"BAD"}
	]`)
	out, err := parseEvents(body)
	if err != nil {
		t.Fatalf("parseEvents: %v", err)
	}
	if strings.Contains(out, "OK") {
		t.Errorf("information-level event should be filtered out, got: %s", out)
	}
	if !strings.Contains(out, "BAD") {
		t.Errorf("error-level event should be kept, got: %s", out)
	}
}

func TestParseEvents_HandlesSingleObject(t *testing.T) {
	body := []byte(`{"TimeCreated":"t","Id":1102,"Level":1,"LevelDisplayName":"Critical","Message":"audit log cleared"}`)
	out, err := parseEvents(body)
	if err != nil {
		t.Fatalf("parseEvents: %v", err)
	}
	if !strings.Contains(out, "audit log cleared") {
		t.Errorf("expected message in output, got: %s", out)
	}
}
