// Package httplog implements `exalm httplog ...` subcommands for analyzing
// Apache and nginx access and error logs.
//
// Named httplog rather than "web" to avoid colliding with the internal/web
// package that backs `--output web`.
package httplog

import (
	"context"

	"github.com/exalm-ai/exalm/internal/analyzer"
	exassh "github.com/exalm-ai/exalm/internal/ssh"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

const MaxInputBytes = 1024 * 1024

type Plugin struct{}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return "httplog" }

func (p *Plugin) Description() string {
	return "Analyze Apache or nginx access/error logs"
}

func (p *Plugin) Mutates() bool { return false }

func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "analyze",
			Description: "Analyze Apache/nginx access or error logs from --file (repeatable, supports globs), --host (SSH), or stdin",
			Run:         analyze,
		},
	}
}

func analyze(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	// Phase 2: SSH remote collection.
	// Fetch both access log and error log when a remote host is given.
	if rem, err := exassh.CollectIfNeeded(ctx, args,
		exassh.HTTPLogCmd(args.Flags["log-path"], exassh.LogLinesFromArgs(args, 10000))); err != nil {
		return plugin.Report{}, err
	} else if rem != nil {
		args.Stdin = rem.Reader
		args.FlagsMulti = map[string][]string{}
		if args.Flags == nil {
			args.Flags = map[string]string{}
		}
		args.Flags["file"] = ""
	}

	title := "HTTP log analysis"
	if h := args.Flags["host"]; h != "" {
		title = "HTTP log analysis — " + h
	}

	spec := analyzer.Spec{
		Sources:       analyzer.SourcesFromArgs(args),
		Stdin:         args.Stdin,
		ChunkBytes:    analyzer.ParseChunkSize(args, MaxInputBytes/2),
		Concurrency:   analyzer.ParseConcurrency(args, 4),
		MaxInputBytes: int64(MaxInputBytes),
		SystemPrompt:  systemPrompt,
		ReducePrompt:  reducePrompt,
		Title:         title,
		LLM:           args.LLM,
		Redactor:      args.Redactor,
		Progress:      args.Stderr,
		Parse:         parseHTTP,
	}
	return analyzer.Analyze(ctx, spec)
}
