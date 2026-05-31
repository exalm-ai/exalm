// Package syslog implements `exalm syslog ...` subcommands for analyzing
// Linux syslog (RFC 3164 / 5424) and journalctl JSON output.
package syslog

import (
	"context"

	"github.com/exalm-ai/exalm/internal/analyzer"
	exassh "github.com/exalm-ai/exalm/internal/ssh"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxInputBytes caps the per-file slice we examine.
const MaxInputBytes = 512 * 1024

type Plugin struct{}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return "syslog" }

func (p *Plugin) Description() string {
	return "Analyze Linux syslog (RFC 3164/5424) or journalctl -o json output"
}

func (p *Plugin) Mutates() bool { return false }

func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "analyze",
			Description: "Analyze syslog or journalctl output from --file (repeatable, supports globs) or stdin",
			Run:         analyze,
		},
	}
}

func analyze(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	// Phase 2: SSH remote collection.
	if rem, err := exassh.CollectIfNeeded(ctx, args,
		exassh.SyslogCmd(true, exassh.LogLinesFromArgs(args, 5000))); err != nil {
		return plugin.Report{}, err
	} else if rem != nil {
		args.Stdin = rem.Reader
		args.FlagsMulti = map[string][]string{} // clear --file; use stdin only
		if args.Flags == nil {
			args.Flags = map[string]string{}
		}
		args.Flags["file"] = "" // suppress SourcesFromArgs
		if args.Flags["title"] == "" {
			args.Flags["title"] = "syslog analysis — " + rem.Host
		}
	}

	title := "syslog analysis"
	if h := args.Flags["host"]; h != "" {
		title = "syslog analysis — " + h
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
		Parse:         parseSyslog,
	}
	return analyzer.Analyze(ctx, spec)
}
