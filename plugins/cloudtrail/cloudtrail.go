// Package cloudtrail implements `exalm cloudtrail ...` subcommands for
// analyzing AWS CloudTrail activity.
//
// Input format: newline-delimited JSON, one CloudTrail record per line (not
// the raw {"Records":[...]} array AWS delivers to S3). NDJSON keeps every
// record on its own line, which is safe for the shared chunker (it only
// ever splits at line boundaries) and for MaxInputBytes truncation — a
// dropped trailing line just loses one record instead of corrupting the
// whole file. Convert a raw export first: jq -c '.Records[]' trail.json.
package cloudtrail

import (
	"context"
	"sync"

	"github.com/exalm-ai/exalm/internal/analyzer"
	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxInputBytes caps the per-file slice we examine.
const MaxInputBytes = 512 * 1024

type Plugin struct {
	mu          sync.Mutex
	lastSession *investigate.LogSession
}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return "cloudtrail" }

func (p *Plugin) Description() string {
	return "Analyze AWS CloudTrail activity (NDJSON) for risky or anomalous API calls"
}

func (p *Plugin) Mutates() bool { return false }

func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "analyze",
			Description: "Analyze CloudTrail NDJSON from --file (repeatable, supports globs) or stdin",
			Run:         p.analyze,
		},
	}
}

func (p *Plugin) analyze(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	session := investigate.NewLogSession("cloudtrail")

	srcIdx := map[string]int{}
	spec := analyzer.Spec{
		Sources:       analyzer.SourcesFromArgs(args),
		Stdin:         args.Stdin,
		ChunkBytes:    analyzer.ParseChunkSize(args, MaxInputBytes/2),
		Concurrency:   analyzer.ParseConcurrency(args, 4),
		MaxInputBytes: int64(MaxInputBytes),
		SystemPrompt:  systemPrompt,
		ReducePrompt:  reducePrompt,
		Title:         "cloudtrail analysis",
		LLM:           args.LLM,
		Redactor:      args.Redactor,
		Progress:      args.Stderr,
		Parse:         parseCloudTrail,
		OnChunk: func(source string, data []byte) {
			idx, ok := srcIdx[source]
			if !ok {
				idx = session.AddSource(investigate.SourceDesc{Path: source})
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
	rep.Findings = investigate.FindingsFrom(cloudtrailProfile(), session, investigate.Target{},
		investigate.FindingSource("cloudtrail", "", session))
	// Candidate findings from the timeline: a bucket far outside its own recent
	// baseline. These say something moved, not why — the investigation engine is
	// what establishes cause.
	rep.Findings = append(rep.Findings, investigate.DetectAnomalies(session,
		stats.EventTimeline, plugin.Entity{}, investigate.FindingSource("cloudtrail", "", session))...)
	return rep, nil
}
