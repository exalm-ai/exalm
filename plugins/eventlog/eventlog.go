// Package eventlog implements `exalm eventlog ...` subcommands for analyzing
// Windows Event Log exports.
//
// Input format: JSON produced by `Get-WinEvent ... | ConvertTo-Json`.
// Binary .evtx files are NOT parsed natively — we ask the user to pipe through
// PowerShell first. Avoids pulling in a binary-XML parser that hasn't been
// security-audited.
package eventlog

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/exalm-ai/exalm/internal/analyzer"
	"github.com/exalm-ai/exalm/internal/investigate"
	exassh "github.com/exalm-ai/exalm/internal/ssh"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxInputBytes caps the bytes we ever look at per file. Event logs in JSON
// form are verbose; 512 KB is roughly 1k–2k events.
const MaxInputBytes = 512 * 1024

type Plugin struct {
	mu          sync.Mutex
	lastSession *investigate.LogSession
}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return "eventlog" }

func (p *Plugin) Description() string {
	return "Summarize Windows Event Log exports (PowerShell JSON)"
}

func (p *Plugin) Mutates() bool { return false }

func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "summarize",
			Description: "Summarize Windows Event Log JSON and highlight critical events",
			Run:         p.summarize,
		},
		{
			Name:        "fix",
			Description: "Summarize, then apply proposed Windows service-restart fixes over SSH (needs --host; --apply to execute)",
			Run:         p.fix,
		},
	}
}

// fix summarizes to surface findings, then drives the shared interactive fix
// flow: it lists the auto-applicable Restart-Service fixes and, with --apply,
// prompts and executes each confirmed one over SSH (PowerShell) against --host.
func (p *Plugin) fix(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	logName := args.Flags["log-name"]
	if logName == "" {
		logName = "Security"
	}
	rp := sessionRemoteParams(args, logName)
	rep, err := p.summarize(ctx, args)
	if err != nil {
		return plugin.Report{}, err
	}
	return investigate.RunFixSubcommand(ctx, args, rep, "eventlog fix", rp)
}

func (p *Plugin) summarize(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	if err := rejectEvtxBinary(args); err != nil {
		return plugin.Report{}, err
	}

	session := investigate.NewLogSession("eventlog")

	// SSH remote collection.
	// Connect to a Windows host via SSH (requires OpenSSH for Windows on the target)
	// and run Get-WinEvent | ConvertTo-Json remotely.
	logName := args.Flags["log-name"]
	if logName == "" {
		logName = "Security"
	}
	remoteHost := ""
	if rem, err := exassh.CollectIfNeeded(ctx, args,
		exassh.EventLogCmd(logName, exassh.LogLinesFromArgs(args, 1000))); err != nil {
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

	if rp := sessionRemoteParams(args, logName); rp != nil {
		session.SSH = rp
		session.DiagTier = args.Flags["remote-diag"]
	}

	title := "Windows Event Log analysis"
	if h := args.Flags["host"]; h != "" {
		title = "Windows Event Log analysis — " + h
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
		Parse:         parseEvents,
		OnChunk: func(source string, data []byte) {
			idx, ok := srcIdx[source]
			if !ok {
				d := investigate.SourceDesc{Path: source}
				if remoteHost != "" {
					d = investigate.SourceDesc{Host: remoteHost, Channel: logName}
				}
				idx = session.AddSource(d)
				srcIdx[source] = idx
			}
			session.Append(parseSessionEvents(idx, data)...)
		},
	}
	rep, err := analyzer.Analyze(ctx, spec)
	if err != nil {
		return plugin.Report{}, err
	}
	session.Stats = buildStats(session)
	p.setSession(session)
	rep.Findings = investigate.FindingsFrom(p.InvestigationProfile(), session, investigate.Target{},
		investigate.FindingSource("eventlog", remoteHost, session))
	return rep, nil
}

// rejectEvtxBinary returns a friendly error if the user pointed at a .evtx file.
// We don't parse the binary format on purpose — see package doc.
func rejectEvtxBinary(args plugin.RunArgs) error {
	for _, src := range analyzer.SourcesFromArgs(args) {
		if strings.HasSuffix(strings.ToLower(src), ".evtx") {
			return errors.New(evtxHelp)
		}
	}
	return nil
}

const evtxHelp = `binary .evtx files are not supported directly.
Export to JSON via PowerShell first, then pipe into exalm:

    Get-WinEvent -Path C:\path\to\Security.evtx |
        Where-Object { $_.Level -le 3 } |
        ConvertTo-Json -Depth 3 |
        exalm eventlog summarize

Or live from a channel:

    Get-WinEvent -LogName Security -MaxEvents 500 |
        ConvertTo-Json -Depth 3 |
        exalm eventlog summarize`
