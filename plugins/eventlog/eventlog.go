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

	"github.com/exalm-ai/exalm/internal/analyzer"
	exassh "github.com/exalm-ai/exalm/internal/ssh"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxInputBytes caps the bytes we ever look at per file. Event logs in JSON
// form are verbose; 512 KB is roughly 1k–2k events.
const MaxInputBytes = 512 * 1024

type Plugin struct{}

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
			Run:         summarize,
		},
	}
}

func summarize(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	if err := rejectEvtxBinary(args); err != nil {
		return plugin.Report{}, err
	}

	// Phase 2: SSH remote collection.
	// Connect to a Windows host via SSH (requires OpenSSH for Windows on the target)
	// and run Get-WinEvent | ConvertTo-Json remotely.
	logName := args.Flags["log-name"]
	if logName == "" {
		logName = "Security"
	}
	if rem, err := exassh.CollectIfNeeded(ctx, args,
		exassh.EventLogCmd(logName, exassh.LogLinesFromArgs(args, 1000))); err != nil {
		return plugin.Report{}, err
	} else if rem != nil {
		args.Stdin = rem.Reader
		args.FlagsMulti = map[string][]string{} // clear --file; use stdin only
		if args.Flags == nil {
			args.Flags = map[string]string{}
		}
		args.Flags["file"] = "" // suppress SourcesFromArgs
	}

	title := "Windows Event Log analysis"
	if h := args.Flags["host"]; h != "" {
		title = "Windows Event Log analysis — " + h
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
		Parse:         parseEvents,
	}
	return analyzer.Analyze(ctx, spec)
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
