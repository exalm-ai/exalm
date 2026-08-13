// Package logs implements `exalm logs ...` subcommands.
//
// MVP scope: a single subcommand `summarize` that reads logs from stdin
// or --file, redacts secrets, sends the content to the configured LLM,
// and returns a root-cause-oriented summary.
//
// Adding more subcommands here (e.g. `tail`, `pattern`) follows the same
// pattern: implement a function with the (ctx, RunArgs) signature and
// register it in Subcommands().
package logs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxInputBytes caps how much log data we send to the LLM in one request.
// 200 KB ≈ 50k tokens which fits comfortably in current context windows
// and keeps API costs predictable.
const MaxInputBytes = 200 * 1024

// Plugin implements plugin.Plugin for the logs domain.
type Plugin struct {
	mu          sync.Mutex
	lastSession *investigate.LogSession
}

// New returns a new logs plugin.
func New() *Plugin { return &Plugin{} }

// Name returns "logs".
func (p *Plugin) Name() string { return "logs" }

// Description is shown in the top-level --help.
func (p *Plugin) Description() string {
	return "Summarize log files and identify likely root causes"
}

// Mutates returns false: this plugin only reads.
func (p *Plugin) Mutates() bool { return false }

// Subcommands lists the actions this plugin supports.
func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "summarize",
			Description: "Summarize logs from stdin or --file and return likely causes",
			Run:         p.summarize,
		},
	}
}

// summarize is the runner for `exalm logs summarize`.
func (p *Plugin) summarize(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	raw, err := readInput(args)
	if err != nil {
		return plugin.Report{}, err
	}
	if len(raw) == 0 {
		return plugin.Report{}, errors.New("no input: pipe a log file to stdin or pass --file <path>")
	}

	// Build the investigation session from the same buffer, independent of
	// the LLM call. It is published only after the analysis succeeds.
	session := investigate.NewLogSession("logs")
	srcPath := args.Flags["file"]
	if srcPath == "" {
		srcPath = "<stdin>"
	}
	idx := session.AddSource(investigate.SourceDesc{Path: srcPath})
	session.Append(parseEvents(idx, raw)...)
	stats := buildStats(session)
	session.Stats = stats

	// CRITICAL: redact before any data leaves the process.
	redacted := args.Redactor.Redact(string(raw))

	resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
		System:    systemPrompt,
		MaxTokens: 2048,
		Messages: []plugin.Message{
			{
				Role:    "user",
				Content: fmt.Sprintf("```\n%s\n```", redacted),
			},
		},
	})
	if err != nil {
		return plugin.Report{}, fmt.Errorf("llm: %w", err)
	}

	p.setSession(session)

	source := investigate.FindingSource("logs", "", session)
	findings := investigate.FindingsFrom(logsProfile(), session, investigate.Target{}, source)
	// Candidate findings from the timeline: a bucket far outside its own recent
	// baseline. These say something moved, not why — the investigation engine is
	// what establishes cause.
	findings = append(findings, investigate.DetectAnomalies(session, stats.ErrorTimeline, plugin.Entity{}, source)...)

	return plugin.Report{
		Title:    "Log analysis",
		Summary:  fmt.Sprintf("Analyzed %d bytes of log content using %s.", len(raw), args.LLM.Name()),
		Raw:      resp.Content,
		Findings: findings,
	}, nil
}

// readInput resolves the source of log data: --file flag or stdin.
func readInput(args plugin.RunArgs) ([]byte, error) {
	if path, ok := args.Flags["file"]; ok && path != "" {
		f, err := os.Open(path) //nolint:gosec // G304: path comes from user-supplied --file flag
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, MaxInputBytes))
	}
	if args.Stdin == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(args.Stdin, MaxInputBytes))
}
