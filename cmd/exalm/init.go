package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/exalm-ai/exalm/internal/cliui"
	"github.com/exalm-ai/exalm/internal/config"
	"github.com/exalm-ai/exalm/internal/preflight"
)

// newInitCmd returns the `exalm init` cobra command.
//
// init performs a one-time setup check:
//  1. Detects the configured (or default) LLM provider and validates its API key.
//  2. Checks for a reachable kubeconfig context.
//  3. Creates ~/.exalm/ with correct permissions if it does not exist.
//  4. Prints a ready-summary so the user knows what is working and what to fix.
//
// It is intentionally near-non-mutating: the only change it ever makes is
// creating ~/.exalm/ if it is absent. The actual checks live in
// internal/preflight so `init`, `serve`, and `--dry-run` share one implementation.
func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Check Exalm prerequisites and print a readiness summary",
		Long: `init validates that your environment is correctly configured for Exalm.

It checks:
  • LLM provider and API key presence
  • KUBECONFIG / active kube context
  • ~/.exalm/ data directory (creates it if missing)
  • Dashboard auth token (warns if unset)

No changes are made to your system beyond creating ~/.exalm/ if it is absent.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit()
		},
	}
}

// runInit runs every readiness check and prints a coloured summary with
// actionable next steps. Returns an error only when a critical check fails.
func runInit() error {
	cfg := config.Load()
	results := preflight.RunAll(cfg)

	// ── Summary table ────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("  " + cliui.Bold("Exalm readiness check"))
	fmt.Println("  ─────────────────────")
	for _, r := range results {
		fmt.Printf("  %s  %-16s %s\n", statusIcon(r), r.Name, r.Message)
	}
	fmt.Println()

	// ── Provider/model sanity line ───────────────────────────────────────────
	model := cfg.LLMModel
	if model == "" {
		model = "provider default"
	}
	fmt.Println("  " + cliui.Dim(fmt.Sprintf("provider=%s · model=%s", cfg.LLMProvider, model)))

	// ── N/M summary ──────────────────────────────────────────────────────────
	passed, total := preflight.CountOK(results), len(results)
	summary := fmt.Sprintf("%d/%d checks passed", passed, total)
	if passed == total {
		fmt.Println("  " + cliui.Success(summary))
	} else {
		fmt.Println("  " + cliui.Warn(summary))
	}
	fmt.Println()

	// ── Next steps for any failing check ─────────────────────────────────────
	printNextSteps(results)

	if preflight.AllCriticalOK(results) {
		if passed == total {
			fmt.Println("  " + cliui.Success("Ready. Run 'exalm k8s analyze' to start."))
		} else {
			fmt.Println("  " + cliui.Success("Core checks passed.") + " The optional items above are safe to skip.")
		}
		fmt.Println()
		return nil
	}

	return errors.New("one or more critical checks failed — see the next steps above")
}

// statusIcon returns the coloured status glyph for a check result: a green ✓
// for pass, a red ✗ for a failed critical check, and a yellow ! otherwise.
func statusIcon(r preflight.Result) string {
	switch {
	case r.OK:
		return cliui.Success("✓")
	case r.Critical:
		return cliui.Errorf("✗")
	default:
		return cliui.Warn("!")
	}
}

// printNextSteps lists the actionable hint for every failing check, if any.
func printNextSteps(results []preflight.Result) {
	var printedHeader bool
	for _, r := range results {
		if r.OK || r.Hint == "" {
			continue
		}
		if !printedHeader {
			fmt.Println("  Next steps:")
			printedHeader = true
		}
		fmt.Printf("    • %-16s %s\n", r.Name+":", cliui.Hint(r.Hint))
	}
	if printedHeader {
		fmt.Println()
	}
}
