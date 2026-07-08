// Package syslog implements `exalm syslog ...` subcommands for analyzing
// Linux syslog (RFC 3164 / 5424) and journalctl JSON output.
package syslog

import (
	"context"
	"sync"

	"github.com/exalm-ai/exalm/internal/analyzer"
	"github.com/exalm-ai/exalm/internal/investigate"
	exassh "github.com/exalm-ai/exalm/internal/ssh"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxInputBytes caps the per-file slice we examine.
const MaxInputBytes = 512 * 1024

type Plugin struct {
	mu          sync.Mutex
	lastSession *investigate.LogSession
}

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
			Run:         p.analyze,
		},
	}
}

func (p *Plugin) analyze(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	session := investigate.NewLogSession("syslog")

	// Phase 2: SSH remote collection.
	remoteHost := ""
	if rem, err := exassh.CollectIfNeeded(ctx, args,
		exassh.SyslogCmd(true, exassh.LogLinesFromArgs(args, 5000))); err != nil {
		return plugin.Report{}, err
	} else if rem != nil {
		remoteHost = rem.Host
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

	if rp := sessionRemoteParams(args); rp != nil {
		session.SSH = rp
		session.DiagTier = args.Flags["remote-diag"]
	}

	title := "syslog analysis"
	if h := args.Flags["host"]; h != "" {
		title = "syslog analysis — " + h
	}

	srcIdx := map[string]int{}
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
		OnChunk: func(source string, data []byte) {
			idx, ok := srcIdx[source]
			if !ok {
				d := investigate.SourceDesc{Path: source}
				if remoteHost != "" {
					d = investigate.SourceDesc{Host: remoteHost, Channel: "syslog"}
				}
				idx = session.AddSource(d)
				srcIdx[source] = idx
			}
			session.Append(parseEvents(idx, data)...)
		},
	}
	rep, err := analyzer.Analyze(ctx, spec)
	if err != nil {
		return plugin.Report{}, err
	}
	session.Stats = buildStats(session)
	p.setSession(session)
	return rep, nil
}
