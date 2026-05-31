// Package main — exalm tui subcommand.
//
// tui launches the interactive Bubble Tea UI that lets users browse plugins,
// fill flag forms, and run analyses without remembering subcommand names.
//
// Example:
//
//	exalm tui
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/exalm-ai/exalm/internal/config"
	"github.com/exalm-ai/exalm/internal/llm"
	"github.com/exalm-ai/exalm/internal/redact"
	"github.com/exalm-ai/exalm/internal/registry"
	internaltui "github.com/exalm-ai/exalm/internal/tui"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// newTUICmd returns the `exalm tui` cobra command.
func newTUICmd(flags *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Interactive TUI — browse plugins, fill flags, and run analyses",
		Long: `tui launches the Exalm interactive terminal UI powered by Bubble Tea.

Use the arrow keys to select a plugin and subcommand, fill in the flag form,
and press Enter to run. Results are shown inline. Press q or Ctrl+C to quit.

Examples:
  exalm tui
  exalm --provider openai tui`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTUI(cmd.Context(), flags)
		},
	}
}

// runTUI wires the LLM / redactor from rootFlags and starts the TUI program.
func runTUI(ctx context.Context, flags *rootFlags) error {
	cfg := config.Load()
	if flags.provider != "" {
		cfg.LLMProvider = flags.provider
	}
	if flags.model != "" {
		cfg.LLMModel = flags.model
	}
	cfg.ShowRedactions = flags.showRedactions

	llmClient, err := llm.NewFromConfig(cfg)
	if err != nil {
		if errors.Is(err, llm.ErrNoProvider) {
			return errors.New(noProviderHelp) //nolint:staticcheck // ST1005: user-facing help text, intentionally capitalized
		}
		return fmt.Errorf("init LLM: %w", err)
	}

	redactor := redact.New(cfg.OptionalRedactions...)

	runner := func(
		ctx context.Context,
		p plugin.Plugin,
		sc plugin.Subcommand,
		pluginFlags map[string]string,
	) (plugin.Report, error) {
		return sc.Run(ctx, plugin.RunArgs{
			Stdin:      os.Stdin,
			Stdout:     os.Stdout,
			Stderr:     os.Stderr,
			Flags:      pluginFlags,
			FlagsMulti: map[string][]string{},
			LLM:        llmClient,
			Redactor:   redactor,
		})
	}

	return internaltui.Run(ctx, registry.All(), runner, os.Stdout)
}
