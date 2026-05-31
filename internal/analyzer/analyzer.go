// Package analyzer is the shared map-reduce engine used by every
// log-shaped plugin (logs, eventlog, iis, syslog, httplog).
//
// Responsibilities, in order:
//
//  1. Expand --file globs and concatenate --file values from RunArgs.
//  2. Stream each source through the chunker at line boundaries.
//  3. Apply the plugin-supplied Parse function to normalize each chunk.
//  4. Run user data through the redactor BEFORE it reaches the LLM. This
//     is the central guarantee — plugins literally cannot forget.
//  5. Fan out to a bounded worker pool that calls the LLM in parallel.
//  6. Reduce chunk-level outputs into a single Report via a final LLM call.
//
// The package is provider-agnostic: it talks to plugin.LLMClient and
// plugin.Redactor, both of which live in pkg/plugin.
package analyzer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Spec configures one Analyze run.
type Spec struct {
	// Sources is a list of file paths or globs. Empty means read Stdin.
	Sources []string
	Stdin   io.Reader

	// ChunkBytes is the soft cap on the size of each chunk handed to the LLM.
	// Chunks split at line boundaries; a single oversized line is allowed.
	// Default: 200 * 1024.
	ChunkBytes int

	// Concurrency is the maximum number of in-flight LLM calls. Default: 4.
	Concurrency int

	// MaxInputBytes is a hard ceiling per file (truncate, never split). 0 = unlimited.
	MaxInputBytes int64

	// SystemPrompt is sent with every map-step (per-chunk) call.
	// ReducePrompt is sent with the final synthesis call. If ReducePrompt is
	// empty and there is more than one chunk, SystemPrompt is reused.
	SystemPrompt string
	ReducePrompt string

	// Title is the Report.Title for the final output.
	Title string

	// LLM and Redactor are injected from the plugin.RunArgs.
	LLM      plugin.LLMClient
	Redactor plugin.Redactor

	// Progress receives one line per completed chunk. Typically os.Stderr.
	// Set to io.Discard to suppress.
	Progress io.Writer

	// Parse normalizes a chunk into the string the LLM should see. Plugins
	// can use this to filter event-log levels, drop noise lines, or convert
	// IIS W3C into a more readable form. If nil, raw text is used.
	Parse func(chunk []byte) (string, error)

	// MaxRetries caps the number of LLM retries per chunk on retryable errors.
	// Default: 5.
	MaxRetries int
}

const (
	defaultChunkBytes  = 200 * 1024
	defaultConcurrency = 4
	defaultRetries     = 5
	mapMaxTokens       = 1024
	reduceMaxTokens    = 2048
)

// Analyze runs the spec and returns a single, merged Report.
func Analyze(ctx context.Context, s Spec) (plugin.Report, error) {
	if s.LLM == nil {
		return plugin.Report{}, errors.New("analyzer: LLM is nil")
	}
	if s.Redactor == nil {
		return plugin.Report{}, errors.New("analyzer: Redactor is nil")
	}
	if s.ChunkBytes <= 0 {
		s.ChunkBytes = defaultChunkBytes
	}
	if s.Concurrency <= 0 {
		s.Concurrency = defaultConcurrency
	}
	if s.MaxRetries <= 0 {
		s.MaxRetries = defaultRetries
	}
	if s.Progress == nil {
		s.Progress = io.Discard
	}
	if s.Title == "" {
		s.Title = "Log analysis"
	}

	chunks, err := collectChunks(s)
	if err != nil {
		return plugin.Report{}, err
	}
	if len(chunks) == 0 {
		return plugin.Report{}, errors.New("no input: pass --file <path> or pipe data to stdin")
	}

	results, err := mapChunks(ctx, s, chunks)
	if err != nil {
		return plugin.Report{}, err
	}

	if len(results) == 1 {
		return plugin.Report{
			Title:   s.Title,
			Summary: fmt.Sprintf("Analyzed 1 chunk (%d bytes) using %s.", chunks[0].Bytes, s.LLM.Name()),
			Raw:     results[0],
		}, nil
	}

	reduced, err := reduceResults(ctx, s, results)
	if err != nil {
		// Fall open: hand the user concatenated map outputs rather than nothing.
		var b strings.Builder
		for i, r := range results {
			fmt.Fprintf(&b, "## Chunk %d\n\n%s\n\n", i+1, r)
		}
		return plugin.Report{
			Title:   s.Title,
			Summary: fmt.Sprintf("Analyzed %d chunks using %s. Reduce step failed: %v. Returning per-chunk findings.", len(results), s.LLM.Name(), err),
			Raw:     b.String(),
		}, nil
	}

	totalBytes := 0
	for _, c := range chunks {
		totalBytes += c.Bytes
	}
	return plugin.Report{
		Title:   s.Title,
		Summary: fmt.Sprintf("Analyzed %d chunks across %d source(s) — %d bytes total, using %s.", len(chunks), countDistinctSources(chunks), totalBytes, s.LLM.Name()),
		Raw:     reduced,
	}, nil
}

// mapChunks runs the per-chunk LLM call in parallel with bounded concurrency.
// Results are returned in chunk order so the reduce step is deterministic.
func mapChunks(ctx context.Context, s Spec, chunks []Chunk) ([]string, error) {
	results := make([]string, len(chunks))
	errs := make([]error, len(chunks))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sem := make(chan struct{}, s.Concurrency)
	var wg sync.WaitGroup
	total := len(chunks)
	progress := newProgress(s.Progress, total)

	for i, ch := range chunks {
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			errs[i] = ctx.Err()
			continue
		}
		go func(idx int, c Chunk) {
			defer wg.Done()
			defer func() { <-sem }()

			body, err := analyzeChunk(ctx, s, c)
			if err != nil {
				errs[idx] = fmt.Errorf("chunk %d (%s): %w", idx+1, c.Source, err)
				cancel()
				return
			}
			results[idx] = body
			progress.tick(c.Source)
		}(i, ch)
	}
	wg.Wait()

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return results, nil
}

// analyzeChunk runs Parse → Redact → LLM, with retry on retryable errors.
func analyzeChunk(ctx context.Context, s Spec, c Chunk) (string, error) {
	parsed := string(c.Data)
	if s.Parse != nil {
		v, err := s.Parse(c.Data)
		if err != nil {
			return "", fmt.Errorf("parse: %w", err)
		}
		parsed = v
	}

	// CRITICAL: redaction MUST happen before any data reaches the LLM.
	redacted := s.Redactor.Redact(parsed)

	header := fmt.Sprintf("Source: %s (chunk %d/%d)\n\n", c.Source, c.Index+1, c.TotalInSource)
	user := header + "```\n" + redacted + "\n```"

	req := plugin.CompleteRequest{
		System:    s.SystemPrompt,
		MaxTokens: mapMaxTokens,
		Messages:  []plugin.Message{{Role: "user", Content: user}},
	}

	resp, err := callWithBackoff(ctx, s.LLM, req, s.MaxRetries)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

// reduceResults asks the LLM to synthesize per-chunk findings into one report.
func reduceResults(ctx context.Context, s Spec, results []string) (string, error) {
	var b strings.Builder
	for i, r := range results {
		fmt.Fprintf(&b, "[chunk %d]\n%s\n\n", i+1, r)
	}
	prompt := s.ReducePrompt
	if prompt == "" {
		prompt = s.SystemPrompt
	}
	req := plugin.CompleteRequest{
		System:    prompt,
		MaxTokens: reduceMaxTokens,
		Messages:  []plugin.Message{{Role: "user", Content: "Synthesize a single, deduplicated report from these per-chunk analyses:\n\n" + b.String()}},
	}
	resp, err := callWithBackoff(ctx, s.LLM, req, s.MaxRetries)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

func countDistinctSources(chunks []Chunk) int {
	seen := map[string]struct{}{}
	for _, c := range chunks {
		seen[c.Source] = struct{}{}
	}
	return len(seen)
}

// AssertStderrWriter is a placeholder hook used by tests to verify the
// progress stream is wired. Production code never relies on this.
var AssertStderrWriter = func(w io.Writer) bool { return w == os.Stderr }
