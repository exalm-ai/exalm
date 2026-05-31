// Package tf implements `exalm tf review`.
//
// It reads a Terraform plan JSON (produced by `terraform show -json`) from a
// file or stdin, assesses the risk of each resource change, and asks the
// configured LLM for a prioritised review.
package tf

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Plugin implements plugin.Plugin for Terraform plan review.
type Plugin struct{}

// New returns a configured tf plugin.
func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string        { return "tf" }
func (p *Plugin) Description() string { return "Review a Terraform plan for risky changes" }
func (p *Plugin) Mutates() bool       { return false }

func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "review",
			Description: "Analyse a terraform plan JSON and return a risk-ranked review",
			Run:         p.review,
		},
	}
}

// review is the runner for `exalm tf review`.
func (p *Plugin) review(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	data, source, err := readInput(args)
	if err != nil {
		return plugin.Report{}, err
	}
	if len(data) > MaxInputBytes {
		data = data[:MaxInputBytes]
	}

	plan, err := parsePlan(data)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("tf review: %w", err)
	}

	formatted := formatPlan(plan)
	redacted := args.Redactor.Redact(formatted)

	resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
		System:    systemPrompt,
		MaxTokens: 2048,
		Messages:  []plugin.Message{{Role: "user", Content: redacted}},
	})
	if err != nil {
		return plugin.Report{}, fmt.Errorf("llm: %w", err)
	}

	total := len(plan.ResourceChanges)
	findings := BuildFindings(plan)
	return plugin.Report{
		Title:    "Terraform plan review",
		Summary:  fmt.Sprintf("Reviewed %d resource change(s) from %s using %s.", total, source, args.LLM.Name()),
		Findings: findings,
		Raw:      resp.Content,
	}, nil
}

// readInput reads from --file flag or stdin.
func readInput(args plugin.RunArgs) ([]byte, string, error) {
	if f := args.Flags["file"]; f != "" {
		data, err := os.ReadFile(f) //nolint:gosec // G304: path comes from user-supplied --file flag
		if err != nil {
			return nil, "", fmt.Errorf("read plan file: %w", err)
		}
		return data, f, nil
	}
	data, err := io.ReadAll(io.LimitReader(args.Stdin, MaxInputBytes))
	if err != nil {
		return nil, "", fmt.Errorf("read stdin: %w", err)
	}
	return data, "stdin", nil
}
