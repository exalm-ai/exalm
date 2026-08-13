// Package httplog implements `exalm httplog ...` subcommands for analyzing
// Apache and nginx access and error logs.
//
// Named httplog rather than "web" to avoid colliding with the internal/web
// package that backs `--output web`.
package httplog

import (
	"context"
	"sync"

	"github.com/exalm-ai/exalm/internal/analyzer"
	"github.com/exalm-ai/exalm/internal/investigate"
	exassh "github.com/exalm-ai/exalm/internal/ssh"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

const MaxInputBytes = 1024 * 1024

type Plugin struct {
	mu          sync.Mutex
	lastSession *investigate.LogSession
}

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
			Run:         p.analyze,
		},
	}
}

func (p *Plugin) analyze(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	session := investigate.NewLogSession("httplog")

	// SSH remote collection.
	// Fetch both access log and error log when a remote host is given.
	remoteHost := ""
	if rem, err := exassh.CollectIfNeeded(ctx, args,
		exassh.HTTPLogCmd(args.Flags["log-path"], exassh.LogLinesFromArgs(args, 10000))); err != nil {
		return plugin.Report{}, err
	} else if rem != nil {
		remoteHost = rem.Host
		args.Stdin = rem.Reader
		args.FlagsMulti = map[string][]string{}
		if args.Flags == nil {
			args.Flags = map[string]string{}
		}
		args.Flags["file"] = ""
	}

	if rp := sessionRemoteParams(args); rp != nil {
		session.SSH = rp
		session.DiagTier = args.Flags["remote-diag"]
	}

	title := "HTTP log analysis"
	if h := args.Flags["host"]; h != "" {
		title = "HTTP log analysis — " + h
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
		Parse:         parseHTTP,
		OnChunk: func(source string, data []byte) {
			idx, ok := srcIdx[source]
			if !ok {
				d := investigate.SourceDesc{Path: source}
				if remoteHost != "" {
					d = investigate.SourceDesc{Host: remoteHost, Channel: args.Flags["log-path"]}
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
	stats := buildStats(session)
	session.Stats = stats
	p.setSession(session)
	rep.Findings = investigate.FindingsFrom(httplogProfile(), session, investigate.Target{},
		investigate.FindingSource("httplog", remoteHost, session))
	// Candidate findings from the timeline: a bucket far outside its own
	// recent baseline. These say something moved, not why — the investigation
	// engine is what establishes cause.
	rep.Findings = append(rep.Findings, investigate.DetectAnomalies(session,
		stats.RequestTimeline, plugin.Entity{}, investigate.FindingSource("httplog", remoteHost, session))...)
	return rep, nil
}
