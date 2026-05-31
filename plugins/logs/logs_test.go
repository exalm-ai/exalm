package logs

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/internal/redact"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// fakeLLM is a test double that records what it was asked to complete
// and returns a canned response.
type fakeLLM struct {
	lastSystem  string
	lastUserMsg string
	resp        string
}

func (f *fakeLLM) Name() string { return "fake" }

func (f *fakeLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	f.lastSystem = req.System
	if len(req.Messages) > 0 {
		f.lastUserMsg = req.Messages[0].Content
	}
	return plugin.CompleteResponse{Content: f.resp}, nil
}

func TestSummarize_RedactsBeforeLLM(t *testing.T) {
	p := New()

	llm := &fakeLLM{resp: "ok"}
	r := redact.New()

	args := plugin.RunArgs{
		Stdin:    strings.NewReader("login attempt: AKIAIOSFODNN7EXAMPLE failed for user=admin password=hunter2"),
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		LLM:      llm,
		Redactor: r,
	}

	_, err := p.Subcommands()[0].Run(context.Background(), args)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if strings.Contains(llm.lastUserMsg, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("AWS key reached the LLM unredacted: %q", llm.lastUserMsg)
	}
	if strings.Contains(llm.lastUserMsg, "hunter2") {
		t.Fatalf("password reached the LLM unredacted: %q", llm.lastUserMsg)
	}
	if !strings.Contains(llm.lastUserMsg, "[REDACTED:") {
		t.Fatalf("expected redaction marker in LLM input, got %q", llm.lastUserMsg)
	}
}

func TestSummarize_EmptyInput(t *testing.T) {
	p := New()
	args := plugin.RunArgs{
		Stdin:    strings.NewReader(""),
		LLM:      &fakeLLM{},
		Redactor: redact.New(),
	}
	_, err := p.Subcommands()[0].Run(context.Background(), args)
	if err == nil {
		t.Fatalf("expected error on empty input")
	}
	if !strings.Contains(err.Error(), "no input") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestPlugin_Metadata(t *testing.T) {
	p := New()
	if p.Name() != "logs" {
		t.Errorf("Name() = %q, want logs", p.Name())
	}
	if p.Mutates() {
		t.Errorf("logs plugin should be read-only (Mutates() = false)")
	}
	if len(p.Subcommands()) == 0 {
		t.Errorf("expected at least one subcommand")
	}
}
