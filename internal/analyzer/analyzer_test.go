package analyzer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// fakeLLM is a stand-in for plugin.LLMClient used in every test in this file.
type fakeLLM struct {
	mu        sync.Mutex
	calls     int64
	failFirst int32 // fail this many times with a retryable error
	failErr   error
	captured  []plugin.CompleteRequest
	respFn    func(req plugin.CompleteRequest, n int64) string
}

func (f *fakeLLM) Name() string { return "fake" }

func (f *fakeLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	n := atomic.AddInt64(&f.calls, 1)
	f.mu.Lock()
	f.captured = append(f.captured, req)
	f.mu.Unlock()

	if f.failFirst > 0 {
		f.failFirst--
		err := f.failErr
		if err == nil {
			err = errors.New("429 rate limit exceeded")
		}
		return plugin.CompleteResponse{}, err
	}
	body := "ok"
	if f.respFn != nil {
		body = f.respFn(req, n)
	}
	return plugin.CompleteResponse{Content: body, InputTokens: 10, OutputTokens: 5}, nil
}

// trackingRedactor wraps another redactor and records each call.
type trackingRedactor struct {
	calls int64
	mu    sync.Mutex
	seen  []string
}

func (t *trackingRedactor) Redact(input string) string {
	atomic.AddInt64(&t.calls, 1)
	out := strings.ReplaceAll(input, "AKIAIOSFODNN7EXAMPLE", "[REDACTED:AWS_ACCESS_KEY]")
	t.mu.Lock()
	t.seen = append(t.seen, out)
	t.mu.Unlock()
	return out
}

func TestAnalyze_SingleChunkSkipsReduce(t *testing.T) {
	llm := &fakeLLM{respFn: func(req plugin.CompleteRequest, _ int64) string { return "verdict" }}
	red := &trackingRedactor{}
	tmp := writeTemp(t, "small.log", "line a\nline b\n")

	rep, err := Analyze(context.Background(), Spec{
		Sources:      []string{tmp},
		ChunkBytes:   4096,
		SystemPrompt: "sys",
		LLM:          llm,
		Redactor:     red,
		Title:        "T",
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.Title != "T" {
		t.Errorf("Title = %q, want T", rep.Title)
	}
	if !strings.Contains(rep.Raw, "verdict") {
		t.Errorf("Raw = %q, want to contain verdict", rep.Raw)
	}
	if atomic.LoadInt64(&llm.calls) != 1 {
		t.Errorf("expected 1 LLM call (no reduce), got %d", llm.calls)
	}
}

func TestAnalyze_MultiChunkUsesReduce(t *testing.T) {
	llm := &fakeLLM{respFn: func(req plugin.CompleteRequest, n int64) string {
		return fmt.Sprintf("chunk-answer-%d", n)
	}}
	red := &trackingRedactor{}

	// Generate a body large enough to require 3 chunks at 32-byte chunks.
	var b strings.Builder
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "line%02d-data-data-data-data\n", i)
	}
	tmp := writeTemp(t, "big.log", b.String())

	_, err := Analyze(context.Background(), Spec{
		Sources:      []string{tmp},
		ChunkBytes:   200,
		Concurrency:  2,
		SystemPrompt: "sys",
		ReducePrompt: "reduce",
		LLM:          llm,
		Redactor:     red,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if atomic.LoadInt64(&llm.calls) < 3 { // at least 2 map + 1 reduce
		t.Errorf("expected ≥3 LLM calls, got %d", llm.calls)
	}
	// The reduce call should mention the reduce prompt as System.
	foundReduce := false
	for _, req := range llm.captured {
		if req.System == "reduce" {
			foundReduce = true
		}
	}
	if !foundReduce {
		t.Errorf("expected at least one call with reduce prompt")
	}
}

func TestAnalyze_RedactorIsCalled(t *testing.T) {
	llm := &fakeLLM{}
	red := &trackingRedactor{}
	tmp := writeTemp(t, "secret.log",
		"first line\nAccess key AKIAIOSFODNN7EXAMPLE in logs\nlast line\n")

	_, err := Analyze(context.Background(), Spec{
		Sources:      []string{tmp},
		SystemPrompt: "sys",
		LLM:          llm,
		Redactor:     red,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if atomic.LoadInt64(&red.calls) == 0 {
		t.Fatalf("redactor was never called — TRUST BOUNDARY VIOLATION")
	}
	// Verify the captured LLM request contains the redacted marker, NOT the raw secret.
	for _, req := range llm.captured {
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "AKIAIOSFODNN7EXAMPLE") {
				t.Fatalf("RAW SECRET LEAKED TO LLM: %q", m.Content)
			}
		}
	}
}

func TestAnalyze_ChunkBoundariesArePerLine(t *testing.T) {
	llm := &fakeLLM{respFn: func(req plugin.CompleteRequest, _ int64) string { return "ok" }}
	red := &trackingRedactor{}
	body := strings.Repeat("0123456789ABCDEF\n", 50) // 17 bytes per line
	tmp := writeTemp(t, "lines.log", body)

	_, err := Analyze(context.Background(), Spec{
		Sources:    []string{tmp},
		ChunkBytes: 64,
		LLM:        llm,
		Redactor:   red,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// Inspect map-step user messages only. Reduce-step messages contain LLM
	// responses, not raw lines.
	for _, req := range llm.captured {
		isMap := false
		for _, m := range req.Messages {
			if strings.Contains(m.Content, "Source:") {
				isMap = true
			}
		}
		if !isMap {
			continue
		}
		for _, m := range req.Messages {
			for _, line := range strings.Split(m.Content, "\n") {
				if !strings.HasPrefix(line, "0123456789ABCDEF") &&
					!strings.HasPrefix(line, "Source:") &&
					!strings.HasPrefix(line, "```") &&
					line != "" {
					t.Errorf("found split or unexpected line in map step: %q", line)
				}
			}
		}
	}
}

func TestAnalyze_RetriesOn429(t *testing.T) {
	llm := &fakeLLM{
		failFirst: 2,
		failErr:   errors.New("429 too many requests"),
		respFn:    func(req plugin.CompleteRequest, _ int64) string { return "eventually" },
	}
	red := &trackingRedactor{}
	tmp := writeTemp(t, "retry.log", "one line\n")

	rep, err := Analyze(context.Background(), Spec{
		Sources:    []string{tmp},
		LLM:        llm,
		Redactor:   red,
		MaxRetries: 5,
	})
	if err != nil {
		t.Fatalf("Analyze should have succeeded after retries: %v", err)
	}
	if !strings.Contains(rep.Raw, "eventually") {
		t.Errorf("expected eventual success body, got %q", rep.Raw)
	}
	if atomic.LoadInt64(&llm.calls) < 3 {
		t.Errorf("expected ≥3 calls (2 fails + 1 success), got %d", llm.calls)
	}
}

func TestAnalyze_FailsFastOnNonRetryable(t *testing.T) {
	llm := &fakeLLM{
		failFirst: 99,
		failErr:   errors.New("invalid api key"),
	}
	red := &trackingRedactor{}
	tmp := writeTemp(t, "bad.log", "one line\n")

	_, err := Analyze(context.Background(), Spec{
		Sources:    []string{tmp},
		LLM:        llm,
		Redactor:   red,
		MaxRetries: 5,
	})
	if err == nil {
		t.Fatalf("expected error for non-retryable failure")
	}
	if atomic.LoadInt64(&llm.calls) != 1 {
		t.Errorf("expected exactly 1 call (no retries on non-retryable), got %d", llm.calls)
	}
}

func TestAnalyze_CancellationPropagates(t *testing.T) {
	llm := &fakeLLM{respFn: func(req plugin.CompleteRequest, _ int64) string {
		time.Sleep(20 * time.Millisecond)
		return "ok"
	}}
	red := &trackingRedactor{}

	var b strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "row%03d\n", i)
	}
	tmp := writeTemp(t, "cancel.log", b.String())

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()

	_, _ = Analyze(ctx, Spec{
		Sources:     []string{tmp},
		ChunkBytes:  20,
		Concurrency: 2,
		LLM:         llm,
		Redactor:    red,
	})
	// The point of this test is that it terminates promptly and -race finds
	// no data races, not whether it returns a specific error.
}

func TestAnalyze_GlobExpansion(t *testing.T) {
	llm := &fakeLLM{}
	red := &trackingRedactor{}
	dir := t.TempDir()
	for _, name := range []string{"a.log", "b.log", "c.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("body\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	_, err := Analyze(context.Background(), Spec{
		Sources:  []string{filepath.Join(dir, "*.log")},
		LLM:      llm,
		Redactor: red,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if atomic.LoadInt64(&llm.calls) < 3 {
		t.Errorf("expected ≥3 calls for 3 files, got %d", llm.calls)
	}
}

func TestAnalyze_EmptyInputErrors(t *testing.T) {
	llm := &fakeLLM{}
	red := &trackingRedactor{}
	_, err := Analyze(context.Background(), Spec{
		Stdin:    bytes.NewReader(nil),
		LLM:      llm,
		Redactor: red,
	})
	if err == nil {
		t.Fatalf("expected error for empty input")
	}
}

func TestAnalyze_ProgressWritesToWriter(t *testing.T) {
	llm := &fakeLLM{}
	red := &trackingRedactor{}
	var buf bytes.Buffer
	tmp := writeTemp(t, "prog.log", "one\ntwo\nthree\n")

	_, err := Analyze(context.Background(), Spec{
		Sources:    []string{tmp},
		ChunkBytes: 5,
		LLM:        llm,
		Redactor:   red,
		Progress:   &buf,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if buf.Len() == 0 {
		t.Errorf("expected progress output to be written")
	}
	if !strings.Contains(buf.String(), "prog.log") {
		t.Errorf("expected progress to mention source filename: %q", buf.String())
	}
}

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Compile-time sanity: io.Discard is a Writer (referenced in production code).
var _ io.Writer = io.Discard
