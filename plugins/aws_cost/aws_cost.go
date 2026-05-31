// Package aws_cost implements `exalm aws cost`.
//
// It reads the JSON output of `aws ce get-cost-and-usage` from a file or stdin,
// detects cost anomalies month-over-month, and asks the configured LLM for a
// prioritised cost report.
//
// Typical workflow:
//
//	aws ce get-cost-and-usage \
//	  --time-period Start=2024-03-01,End=2024-05-01 \
//	  --granularity MONTHLY \
//	  --metrics BlendedCost \
//	  --group-by Type=DIMENSION,Key=SERVICE \
//	  > cost.json
//	exalm aws cost analyze --file cost.json
package aws_cost

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Plugin implements plugin.Plugin for AWS cost analysis.
type Plugin struct{}

// New returns a configured aws_cost plugin.
func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string        { return "aws" }
func (p *Plugin) Description() string { return "Analyse AWS cost data and detect spending anomalies" }
func (p *Plugin) Mutates() bool       { return false }

func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "cost",
			Description: "Read AWS Cost Explorer output and return an LLM-powered cost report",
			Run:         p.analyze,
		},
	}
}

// analyze is the runner for `exalm aws cost`.
func (p *Plugin) analyze(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	data, source, err := readInput(args)
	if err != nil {
		return plugin.Report{}, err
	}
	if len(data) > MaxInputBytes {
		data = data[:MaxInputBytes]
	}

	report, err := parseCostReport(data)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("aws cost: %w", err)
	}

	summaries := summarise(report)
	anomalies := detectAnomalies(summaries)

	formatted := formatReport(summaries, anomalies)
	redacted := args.Redactor.Redact(formatted)

	resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
		System:    systemPrompt,
		MaxTokens: 2048,
		Messages:  []plugin.Message{{Role: "user", Content: redacted}},
	})
	if err != nil {
		return plugin.Report{}, fmt.Errorf("llm: %w", err)
	}

	periods := len(summaries)
	findings := BuildFindings(summaries, anomalies)
	return plugin.Report{
		Title:    "AWS cost analysis",
		Summary:  fmt.Sprintf("Analysed %d billing period(s) from %s using %s.", periods, source, args.LLM.Name()),
		Findings: findings,
		Raw:      resp.Content,
	}, nil
}

func readInput(args plugin.RunArgs) ([]byte, string, error) {
	if f := args.Flags["file"]; f != "" {
		data, err := os.ReadFile(f) //nolint:gosec // G304: file path is from user-provided --file flag, intentional
		if err != nil {
			return nil, "", fmt.Errorf("read cost file: %w", err)
		}
		return data, f, nil
	}
	data, err := io.ReadAll(io.LimitReader(args.Stdin, MaxInputBytes))
	if err != nil {
		return nil, "", fmt.Errorf("read stdin: %w", err)
	}
	return data, "stdin", nil
}
