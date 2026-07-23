// Package iis implements `exalm iis ...` subcommands for analyzing IIS
// W3C Extended access logs.
package iis

import (
	"context"
	"sync"

	"github.com/exalm-ai/exalm/internal/analyzer"
	"github.com/exalm-ai/exalm/internal/investigate"
	exassh "github.com/exalm-ai/exalm/internal/ssh"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxInputBytes is the per-file ceiling. W3C records are short; 1 MB covers
// a busy site for several hours.
const MaxInputBytes = 1024 * 1024

type Plugin struct {
	mu          sync.Mutex
	lastSession *investigate.LogSession
}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return "iis" }

func (p *Plugin) Description() string {
	return "Analyze IIS W3C access logs for error bursts, slow requests, and suspicious URIs"
}

func (p *Plugin) Mutates() bool { return false }

func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "analyze",
			Description: "Analyze IIS W3C access logs from --file (repeatable, supports globs) or stdin",
			Run:         p.analyze,
		},
	}
}

func (p *Plugin) analyze(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	session := investigate.NewLogSession("iis")

	// Phase 2: SSH remote collection.
	// Connects to a Windows IIS host via SSH and tails the latest W3C log file.
	logDir := args.Flags["log-dir"]
	remoteHost := ""
	if rem, err := exassh.CollectIfNeeded(ctx, args,
		exassh.IISLogCmd(logDir, exassh.LogLinesFromArgs(args, 5000))); err != nil {
		return plugin.Report{}, err
	} else if rem != nil {
		remoteHost = rem.Host
		args.Stdin = rem.Reader
		args.FlagsMulti = map[string][]string{} // clear --file; use stdin only
		if args.Flags == nil {
			args.Flags = map[string]string{}
		}
		args.Flags["file"] = "" // suppress SourcesFromArgs
	}

	if rp := sessionRemoteParams(args, logDir); rp != nil {
		session.SSH = rp
		session.DiagTier = args.Flags["remote-diag"]
	}

	title := "IIS access log analysis"
	if h := args.Flags["host"]; h != "" {
		title = "IIS access log analysis — " + h
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
		Parse:         parseW3C,
		OnChunk: func(source string, data []byte) {
			idx, ok := srcIdx[source]
			if !ok {
				d := investigate.SourceDesc{Path: source}
				if remoteHost != "" {
					d = investigate.SourceDesc{Host: remoteHost, Channel: logDir}
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
	rep.Findings = investigate.FindingsFrom(iisProfile(), session, investigate.Target{},
		investigate.FindingSource("iis", remoteHost, session))
	return rep, nil
}
