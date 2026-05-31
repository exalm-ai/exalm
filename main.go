// Command exalm is the entry point for the Exalm CLI.
//
// Plugin registration happens in registerPlugins(). Adding a new plugin
// = importing the package and calling registry.Register there.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/exalm-ai/exalm/internal/config"
	"github.com/exalm-ai/exalm/internal/llm"
	"github.com/exalm-ai/exalm/internal/output"
	"github.com/exalm-ai/exalm/internal/redact"
	"github.com/exalm-ai/exalm/internal/registry"
	"github.com/exalm-ai/exalm/internal/version"
	"github.com/exalm-ai/exalm/pkg/plugin"

	// Plugins. Adding a new plugin: import its package and call registry.Register
	// in registerPlugins() below.
	logsplugin "github.com/exalm-ai/exalm/plugins/logs"
)

func main() {
	registerPlugins()

	rootCmd := newRootCmd()

	// signal.NotifyContext was added in Go 1.16. This achieves the same
	// thing: cancel the context on Ctrl-C or SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err) //nolint:errcheck // fatal error to stderr before exit
		os.Exit(1)
	}
}

// registerPlugins is the single source of truth for which plugins are
// compiled into this binary.
func registerPlugins() {
	registry.Register(logsplugin.New())
	// Future:
	// registry.Register(k8splugin.New())
	// registry.Register(awscostplugin.New())
	// registry.Register(tfreviewplugin.New())
}

// rootFlags holds top-level persistent flags. Subcommands read from this
// after Cobra has parsed them.
type rootFlags struct {
	output         string
	apply          bool
	showRedactions bool
	provider       string
	model          string
}

func newRootCmd() *cobra.Command {
	flags := &rootFlags{}

	root := &cobra.Command{
		Use:   "exalm",
		Short: "Exalm — open-source AI ops assistant",
		Long: `Exalm is an open-source AI ops assistant for engineers managing
hybrid environments: Linux, Kubernetes, cloud, Windows, and on-prem.

Read-only by default. Bring your own LLM. Local-first.

Quickstart:
  export ANTHROPIC_API_KEY=sk-ant-...
  cat /var/log/syslog | exalm logs summarize

Run "exalm <plugin> --help" for plugin-specific commands.`,
		Version:       buildVersionString(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&flags.output, "output", "markdown", `output format: "markdown" or "json"`)
	root.PersistentFlags().BoolVar(&flags.apply, "apply", false, "allow mutating actions (required for non-read-only plugins)")
	root.PersistentFlags().BoolVar(&flags.showRedactions, "show-redactions", false, "print redaction summary to stderr before sending to LLM")
	root.PersistentFlags().StringVar(&flags.provider, "provider", "", `LLM provider: "claude", "openai", "ollama" (overrides env)`)
	root.PersistentFlags().StringVar(&flags.model, "model", "", "model name (overrides provider default)")

	for _, p := range registry.All() {
		root.AddCommand(buildPluginCmd(p, flags))
	}

	return root
}

// buildPluginCmd returns a Cobra command for a plugin, with one subcommand
// per Subcommand the plugin exposes.
func buildPluginCmd(p plugin.Plugin, flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   p.Name(),
		Short: p.Description(),
	}
	for _, sc := range p.Subcommands() {
		sc := sc // capture
		sub := &cobra.Command{
			Use:   sc.Name,
			Short: sc.Description,
			RunE: func(cmd *cobra.Command, args []string) error {
				file, _ := cmd.Flags().GetString("file")
				return runSubcommand(cmd.Context(), p, sc, args, flags, file)
			},
		}
		sub.Flags().String("file", "", "read input from this file instead of stdin")
		cmd.AddCommand(sub)
	}
	return cmd
}

// runSubcommand resolves config, builds the LLM client and redactor,
// invokes the plugin, and renders the output.
func runSubcommand(ctx context.Context, p plugin.Plugin, sc plugin.Subcommand, args []string, flags *rootFlags, file string) error {
	cfg := config.Load()

	// CLI flags override env.
	if flags.provider != "" {
		cfg.LLMProvider = flags.provider
	}
	if flags.model != "" {
		cfg.LLMModel = flags.model
	}
	cfg.OutputFormat = flags.output
	cfg.Apply = flags.apply
	cfg.ShowRedactions = flags.showRedactions

	// Safety gate: mutating plugins require --apply.
	if p.Mutates() && !cfg.Apply {
		return fmt.Errorf("plugin %q can mutate state; pass --apply to allow", p.Name())
	}

	llmClient, err := llm.NewFromConfig(cfg)
	if err != nil {
		if errors.Is(err, llm.ErrNoProvider) {
			return errors.New(noProviderHelp) //nolint:staticcheck // ST1005: user-facing help text, intentionally capitalized
		}
		return fmt.Errorf("init LLM: %w", err)
	}

	redactor := redact.New(cfg.OptionalRedactions...)

	pluginFlags := map[string]string{}
	if file != "" {
		pluginFlags["file"] = file
	}

	report, err := sc.Run(ctx, plugin.RunArgs{
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		Flags:    pluginFlags,
		Args:     args,
		LLM:      llmClient,
		Redactor: redactor,
	})
	if err != nil {
		return err
	}

	switch cfg.OutputFormat {
	case "json":
		return output.JSON(os.Stdout, report)
	default:
		return output.Markdown(os.Stdout, report)
	}
}

func buildVersionString() string {
	return fmt.Sprintf("%s (commit %s, built %s)", version.Version, version.Commit, version.BuildDate)
}

const noProviderHelp = `No LLM provider configured.

Set up Claude (recommended for MVP):
  export ANTHROPIC_API_KEY=sk-ant-...
  export EXALM_LLM_PROVIDER=claude

Or pass --provider claude on the command line.

Other providers (OpenAI, Ollama) are stubbed and will be implemented in Phase 2`
