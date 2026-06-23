// Command exalm is the entry point for the Exalm CLI.
//
// Plugin registration happens in registerPlugins(). Adding a new plugin
// = importing the package and calling registry.Register there.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/exalm-ai/exalm/internal/cliui"
	"github.com/exalm-ai/exalm/internal/config"
	"github.com/exalm-ai/exalm/internal/gitprovider"
	"github.com/exalm-ai/exalm/internal/llm"
	"github.com/exalm-ai/exalm/internal/mcp"
	"github.com/exalm-ai/exalm/internal/output"
	"github.com/exalm-ai/exalm/internal/preflight"
	"github.com/exalm-ai/exalm/internal/redact"
	"github.com/exalm-ai/exalm/internal/registry"
	exalmstore "github.com/exalm-ai/exalm/internal/store"
	"github.com/exalm-ai/exalm/internal/version"
	"github.com/exalm-ai/exalm/internal/web"
	webhookpkg "github.com/exalm-ai/exalm/internal/webhook"
	"github.com/exalm-ai/exalm/pkg/plugin"
	k8splugin "github.com/exalm-ai/exalm/plugins/k8s"

	// Plugins. Adding a new plugin: import its package and call registry.Register
	// in registerPlugins() below.
	awscostplugin "github.com/exalm-ai/exalm/plugins/aws_cost"
	chaosplugin "github.com/exalm-ai/exalm/plugins/chaos"
	doraplugin "github.com/exalm-ai/exalm/plugins/dora"
	eventlogplugin "github.com/exalm-ai/exalm/plugins/eventlog"
	httplogplugin "github.com/exalm-ai/exalm/plugins/httplog"
	iisplugin "github.com/exalm-ai/exalm/plugins/iis"
	incidentplugin "github.com/exalm-ai/exalm/plugins/incident"
	logsplugin "github.com/exalm-ai/exalm/plugins/logs"
	notifyplugin "github.com/exalm-ai/exalm/plugins/notify"
	sloplugin "github.com/exalm-ai/exalm/plugins/slo"
	sysloplugin "github.com/exalm-ai/exalm/plugins/syslog"
	tfplugin "github.com/exalm-ai/exalm/plugins/tf"
)

func main() {
	// Open the SQLite database and wire deployment + incident stores before
	// plugins are registered. Errors are non-fatal: the tool falls back to
	// the legacy file-based stores automatically. db.Close() checkpoints the
	// SQLite WAL so the database file is up to date on every clean exit.
	db := initStore()
	if db != nil {
		defer db.Close()
	}
	registerPlugins()

	rootCmd := newRootCmd()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, cliui.FriendlyError(err)) //nolint:errcheck // fatal error to stderr before exit
		os.Exit(1)
	}
}

// initStore opens the SQLite database and wires the dora and incident packages
// to use it. Errors are printed as warnings and the tool falls back to the
// legacy JSONL/JSON file stores — no functionality is lost.
// Returns the opened *sql.DB so the caller can defer db.Close() for a clean WAL
// checkpoint; returns nil when the DB could not be opened.
func initStore() *sql.DB {
	path, err := exalmstore.DefaultPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠  store: %v (using file stores)\n", err) //nolint:errcheck // warning to stderr; fallback is safe
		return nil
	}
	db, err := exalmstore.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠  store: %v (using file stores)\n", err) //nolint:errcheck // warning to stderr; fallback is safe
		return nil
	}
	doraplugin.SetDeployDB(db)
	incidentplugin.SetIncidentDB(db)
	globalDB = db

	// Best-effort one-time migration from legacy file stores.
	// Errors are silently ignored — existing data is preserved in the files.
	home, err := os.UserHomeDir()
	if err == nil {
		exalmstore.MigrateDeployments(db, filepath.Join(home, ".exalm", "deployments.jsonl")) //nolint:errcheck
		exalmstore.MigrateIncidents(db, filepath.Join(home, ".exalm", "incidents"))           //nolint:errcheck
	}
	return db
}

// registerPlugins is the single source of truth for which plugins are
// compiled into this binary.
func registerPlugins() {
	registry.Register(logsplugin.New())
	registry.Register(k8splugin.New())
	registry.Register(tfplugin.New())
	registry.Register(awscostplugin.New())
	registry.Register(eventlogplugin.New())
	registry.Register(iisplugin.New())
	registry.Register(sysloplugin.New())
	registry.Register(httplogplugin.New())
	registry.Register(sloplugin.New())
	registry.Register(incidentplugin.New())
	registry.Register(doraplugin.New())
	registry.Register(chaosplugin.New())
	registry.Register(notifyplugin.New())
}

// concurrentPlugins lists plugins that accept the shared analyzer flags
// (--file repeatable, --concurrency, --chunk-size).
var concurrentPlugins = map[string]bool{
	"eventlog": true,
	"iis":      true,
	"syslog":   true,
	"httplog":  true,
}

// rootFlags holds top-level persistent flags. Subcommands read from this
// after Cobra has parsed them.
type rootFlags struct {
	output         string
	apply          bool
	showRedactions bool
	provider       string
	model          string
	notifyURL      string // POST the report to this webhook after every analysis
	dryRun         bool   // validate + preview without calling the LLM or mutating
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

	root.PersistentFlags().StringVar(&flags.output, "output", "markdown", `output format: "markdown", "json", or "web"`)
	root.PersistentFlags().BoolVar(&flags.apply, "apply", false, "allow mutating actions (required for non-read-only plugins)")
	root.PersistentFlags().BoolVar(&flags.showRedactions, "show-redactions", false, "print redaction summary to stderr before sending to LLM")
	root.PersistentFlags().StringVar(&flags.provider, "provider", "", `LLM provider: "claude", "openai", "ollama" (overrides env)`)
	root.PersistentFlags().StringVar(&flags.model, "model", "", "model name (overrides provider default)")
	root.PersistentFlags().StringVar(&flags.notifyURL, "notify-url", "", "POST every analysis report to this webhook URL after completion (Slack auto-detected)")
	root.PersistentFlags().BoolVar(&flags.dryRun, "dry-run", false, "validate config and preview the run without calling the LLM or mutating anything (k8s fix: compute fixes without applying)")

	for _, p := range registry.All() {
		root.AddCommand(buildPluginCmd(p, flags))
	}

	root.AddCommand(newInitCmd())
	root.AddCommand(newMCPCmd(flags))
	root.AddCommand(newServeCmd(flags))
	root.AddCommand(newTUICmd(flags))
	root.AddCommand(newWebhookCmd())
	root.AddCommand(newUsageCmd())

	return root
}

// newMCPCmd registers the `exalm mcp` subtree. Today it has one action
// (`serve`), with stdio default and --sse for HTTP transport.
func newMCPCmd(_ *rootFlags) *cobra.Command {
	mcpRoot := &cobra.Command{
		Use:   "mcp",
		Short: "Model Context Protocol server — expose findings & remediation as LLM-agent tools",
	}
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server (stdio by default, --sse for HTTP)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			sse, _ := cmd.Flags().GetString("sse")
			allowWrite, _ := cmd.Flags().GetBool("write")
			tok, _ := cmd.Flags().GetString("token")
			if tok == "" {
				tok = os.Getenv("EXALM_TOKEN")
			}
			return runMCPServe(cmd.Context(), sse, allowWrite, tok)
		},
	}
	serve.Flags().String("sse", "", "if non-empty, serve over SSE on this address (e.g. :7434); otherwise stdio")
	serve.Flags().Bool("write", false, "enable mutating tools (apply_remediation, open_incident)")
	serve.Flags().String("token", "", "Bearer token required on every SSE request (default: $EXALM_TOKEN)")
	mcpRoot.AddCommand(serve)
	return mcpRoot
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
			RunE: func(cmd *cobra.Command, _ []string) error {
				pluginFlags, pluginFlagsMulti := extractFlags(cmd, p.Name(), sc.Name)
				return runSubcommand(cmd.Context(), p, sc, flags, pluginFlags, pluginFlagsMulti)
			},
		}
		if concurrentPlugins[p.Name()] {
			sub.Flags().StringSlice("file", nil, "read input from this file (repeatable, supports globs)")
			sub.Flags().String("concurrency", "4", "maximum in-flight LLM calls")
			sub.Flags().String("chunk-size", "", "soft cap per chunk (e.g. 200KB, 1MB)")
			// SSH remote collection (Phase 2).
			sub.Flags().String("host", "", "SSH hostname — collect logs directly from this remote host")
			sub.Flags().String("ssh-user", "", "SSH username (default: current OS user)")
			sub.Flags().String("ssh-key", "", "path to SSH private key (default: ~/.ssh/id_rsa)")
			sub.Flags().String("ssh-port", "22", "SSH port (default: 22)")
			sub.Flags().String("ssh-password", "", "SSH password (prefer EXALM_SSH_PASSWORD env var)")
			sub.Flags().String("log-lines", "5000", "number of log lines to fetch from remote host")
		} else {
			sub.Flags().String("file", "", "read input from this file instead of stdin")
		}
		if p.Name() == "httplog" {
			sub.Flags().String("log-path", "", "custom log path on the remote host (default: /var/log/nginx/access.log)")
		}
		if p.Name() == "eventlog" {
			sub.Flags().String("log-name", "Security", `Windows event log channel (e.g. "Security", "System", "Application")`)
		}
		if p.Name() == "iis" {
			sub.Flags().String("log-dir", "", `IIS log directory on the remote host (default: C:\inetpub\logs\LogFiles\W3SVC1)`)
		}
		if p.Name() == "incident" {
			switch sc.Name {
			case "open":
				sub.Flags().String("title", "", "incident title (required)")
				sub.Flags().String("severity", "medium", "severity: critical, high, medium, low")
				sub.Flags().String("from-deploy", "", "deployment ID to link as likely cause (from: exalm dora log-deploy)")
			case "list":
				sub.Flags().String("status", "", "filter by status: open, closed, mitigated")
			case "close", "postmortem":
				sub.Flags().String("incident-id", "", "incident ID (required, e.g. INC-20260101-120000-001)")
			}
		}
		if p.Name() == "dora" {
			switch sc.Name {
			case "report":
				sub.Flags().String("days", "30", "analysis window in days")
				sub.Flags().Bool("ai", false, "add LLM narrative analysis to the report")
			case "log-deploy":
				sub.Flags().String("service", "", "service/workload name (required)")
				sub.Flags().String("version", "", "deployed version (image tag, chart version, git SHA)")
				sub.Flags().String("namespace", "", "Kubernetes namespace")
				sub.Flags().String("deployed-by", "", "who/what triggered the deployment (e.g. github-actions)")
				sub.Flags().Bool("failed", false, "mark the deployment as failed")
				sub.Flags().String("commit", "", "git commit SHA that triggered this deployment")
				sub.Flags().String("commit-time", "", "when the commit was authored (RFC3339, e.g. 2026-01-15T10:30:00Z)")
			}
		}
		if p.Name() == "slo" {
			sub.Flags().String("samples", "", "JSON file of per-SLO Sample arrays (omit for synthesized healthy stream)")
			if sc.Name == "check" {
				sub.Flags().String("prometheus-url", "", "Prometheus base URL for live error budgets (overrides EXALM_PROMETHEUS_URL)")
			}
		}
		if p.Name() == "chaos" {
			sub.Flags().String("snapshot-file", "", "path to k8s snapshot JSON (from: exalm k8s analyze --output json > snap.json)")
			sub.Flags().String("namespace", "", "filter to this namespace (default: all)")
		}
		if p.Name() == "notify" && sc.Name == "webhook" {
			sub.Flags().String("url", "", "webhook URL to POST the report to (required)")
		}
		if p.Name() == "k8s" {
			sub.Flags().StringP("namespace", "n", "", "Kubernetes namespace (default: all namespaces)")
			sub.Flags().String("kubeconfig", "", "path to kubeconfig file (default: standard discovery)")
			sub.Flags().String("context", "", "kubeconfig context to use (default: current-context)")
			sub.Flags().String("max-pods", "25", "maximum unhealthy pods to include in the report")
			sub.Flags().String("since", "1h", "time window for warning events (e.g. 30m, 2h)")
			sub.Flags().String("log-lines", "100", "lines of log tail per failing container")
			sub.Flags().String("include-nodes", "false", "also collect unhealthy node conditions")
			sub.Flags().String("github-token", "", "git provider token for PR creation (or set GITHUB_TOKEN)")
			sub.Flags().String("github-repo", "", "git repo for fix PR: owner/repo (or set GITHUB_REPO)")
			sub.Flags().String("github-base-branch", "main", "base branch for the fix PR")
			sub.Flags().String("git-provider", "github", `git hosting provider: "github", "gitlab", "bitbucket", "azuredevops"`)
			if sc.Name == "watch" {
				sub.Flags().String("interval", "60s", "how often to refresh cluster state")
			}
		}
		cmd.AddCommand(sub)
	}
	return cmd
}

// extractFlags collects non-empty flag values from cmd into the single-valued
// and multi-valued maps that get passed to the plugin via RunArgs.
func extractFlags(cmd *cobra.Command, pluginName, subName string) (map[string]string, map[string][]string) {
	out := map[string]string{}
	multi := map[string][]string{}

	if concurrentPlugins[pluginName] {
		if vs, err := cmd.Flags().GetStringSlice("file"); err == nil && len(vs) > 0 {
			multi["file"] = vs
			out["file"] = vs[len(vs)-1]
		}
		for _, name := range []string{"concurrency", "chunk-size", "host", "ssh-user", "ssh-key", "ssh-port", "ssh-password", "log-lines"} {
			if v, err := cmd.Flags().GetString(name); err == nil && v != "" {
				out[name] = v
			}
		}
	} else {
		if v, err := cmd.Flags().GetString("file"); err == nil && v != "" {
			out["file"] = v
		}
	}

	if pluginName == "httplog" {
		if v, err := cmd.Flags().GetString("log-path"); err == nil && v != "" {
			out["log-path"] = v
		}
	}
	if pluginName == "eventlog" {
		if v, err := cmd.Flags().GetString("log-name"); err == nil && v != "" {
			out["log-name"] = v
		}
	}
	if pluginName == "iis" {
		if v, err := cmd.Flags().GetString("log-dir"); err == nil && v != "" {
			out["log-dir"] = v
		}
	}
	if pluginName == "incident" {
		for _, name := range []string{"title", "severity", "status", "incident-id", "from-deploy"} {
			if v, err := cmd.Flags().GetString(name); err == nil && v != "" {
				out[name] = v
			}
		}
	}
	if pluginName == "dora" {
		for _, name := range []string{"days", "service", "version", "namespace", "deployed-by", "commit", "commit-time"} {
			if v, err := cmd.Flags().GetString(name); err == nil && v != "" {
				out[name] = v
			}
		}
		if v, _ := cmd.Flags().GetBool("ai"); v {
			out["ai"] = "true"
		}
		if v, _ := cmd.Flags().GetBool("failed"); v {
			out["failed"] = "true"
		}
	}
	if pluginName == "slo" {
		if v, err := cmd.Flags().GetString("samples"); err == nil && v != "" {
			out["samples"] = v
		}
		if v, err := cmd.Flags().GetString("prometheus-url"); err == nil && v != "" {
			out["prometheus-url"] = v
		}
	}
	if pluginName == "chaos" {
		for _, name := range []string{"snapshot-file", "namespace"} {
			if v, err := cmd.Flags().GetString(name); err == nil && v != "" {
				out[name] = v
			}
		}
	}
	if pluginName == "notify" {
		if v, err := cmd.Flags().GetString("url"); err == nil && v != "" {
			out["url"] = v
		}
	}
	if pluginName == "k8s" {
		for _, name := range []string{"namespace", "kubeconfig", "context", "max-pods", "since", "log-lines", "include-nodes", "github-token", "github-repo", "github-base-branch", "git-provider"} {
			if v, err := cmd.Flags().GetString(name); err == nil && v != "" {
				out[name] = v
			}
		}
		if subName == "watch" {
			if v, err := cmd.Flags().GetString("interval"); err == nil && v != "" {
				out["interval"] = v
			}
		}
	}
	return out, multi
}

// runSubcommand resolves config, builds the LLM client and redactor,
// invokes the plugin, and renders the output.
func runSubcommand(ctx context.Context, p plugin.Plugin, sc plugin.Subcommand, flags *rootFlags, pluginFlags map[string]string, pluginFlagsMulti map[string][]string) error {
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

	// ── Unified --dry-run ─────────────────────────────────────────────────────
	// k8s fix has a native dry-run (compute concrete fixes, show them, don't
	// apply): pass it through and fall through to normal execution. For every
	// other subcommand, --dry-run is a safe preview — validate the environment,
	// print what WOULD run, and return before any LLM call, store write, or
	// mutation, so even mutating subcommands like `incident open` preview safely.
	isK8sFix := p.Name() == "k8s" && sc.Name == "fix"
	if flags.dryRun {
		if isK8sFix {
			pluginFlags["dry-run"] = "true"
		} else {
			return dryRunPreview(cfg, p, sc)
		}
	}

	// Safety gate: mutating subcommands require --apply.
	// We check sc.Mutates (subcommand-level) so that read-only subcommands on
	// a plugin where Mutates() == true (e.g. "incident list") are not blocked.
	if sc.Mutates && !cfg.Apply {
		return fmt.Errorf("subcommand %q of plugin %q can mutate state; pass --apply to allow", sc.Name, p.Name())
	}

	// Pass --apply state through to the plugin via flags so fix subcommand can read it.
	if cfg.Apply {
		pluginFlags["apply"] = "true"
	}

	llmClient, err := llm.NewFromConfig(cfg)
	if err != nil {
		if errors.Is(err, llm.ErrNoProvider) {
			return errors.New(noProviderHelp) //nolint:staticcheck // ST1005: user-facing help text, intentionally capitalized
		}
		return fmt.Errorf("init LLM: %w", err)
	}

	// Wrap the LLM client to record per-call token usage in SQLite.
	trackedLLM := wrapWithUsageTracking(llmClient, p.Name(), sc.Name)

	redactor := redact.New(cfg.OptionalRedactions...)

	// Progress spinner on stderr for slow, single-shot markdown runs. Skipped for
	// JSON/web output, the concurrent log plugins (which print their own
	// progress), and the interactive `k8s fix` flow. NewSpinner self-disables when
	// stderr is not a TTY or NO_COLOR is set, so piped/CI output stays clean.
	showSpinner := cfg.OutputFormat == "markdown" && !concurrentPlugins[p.Name()] && !isK8sFix
	spinner := cliui.NewSpinner(os.Stderr)
	if showSpinner {
		spinner.Start(fmt.Sprintf("Analyzing with %s…", cfg.LLMProvider))
	}

	report, err := sc.Run(ctx, plugin.RunArgs{
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Flags:      pluginFlags,
		FlagsMulti: pluginFlagsMulti,
		LLM:        trackedLLM,
		Redactor:   redactor,
	})
	spinner.Stop()
	if err != nil {
		return err
	}

	// Post the report to the --notify-url webhook if configured.
	if flags.notifyURL != "" {
		if err := notifyplugin.Send(ctx, flags.notifyURL, report); err != nil {
			fmt.Fprintf(os.Stderr, "⚠  notify: %v\n", err) //nolint:errcheck // warning to stderr; non-fatal
		}
	}

	// k8s fix: always print to markdown (interactive CLI flow).
	if p.Name() == "k8s" && sc.Name == "fix" {
		return output.Markdown(os.Stdout, report)
	}

	// k8s analyze/watch: open the web dashboard only when stdout is an
	// interactive terminal. In CI / pipes / automated runs (no TTY), fall
	// through to plain markdown output and exit cleanly.
	stdoutStat, _ := os.Stdout.Stat()
	openWeb := p.Name() == "k8s" && (sc.Name == "analyze" || sc.Name == "watch") &&
		cfg.OutputFormat == "markdown" &&
		stdoutStat != nil && (stdoutStat.Mode()&os.ModeCharDevice) != 0

	switch {
	case cfg.OutputFormat == "json":
		return output.JSON(os.Stdout, report)
	case cfg.OutputFormat == "web" || openWeb:
		serveOpts := web.ServeOpts{Port: 7433, OpenBrowser: true}

		// Inject ApplyFix closure using the k8s client stored on the plugin.
		if k8sPlug, ok := p.(*k8splugin.Plugin); ok {
			if cs := k8sPlug.LastClient(); cs != nil {
				serveOpts.ApplyFix = func(ctx context.Context, action plugin.RemediationAction) error {
					return k8splugin.ApplyRemediation(ctx, cs, action)
				}
			}
			// Inject watch mode report channel.
			if sc.Name == "watch" {
				serveOpts.ReportUpdates = k8sPlug.WatchReportCh()
			}
			// Inject the findings re-collector so the dashboard auto-refreshes
			// (analyze mode) and reflects post-fix state immediately. Nil when
			// no cluster connection was made (e.g. --from-file), which keeps the
			// dashboard footer honest ("static snapshot").
			serveOpts.RefreshFindings = k8sPlug.RefreshFunc()
		}

		// Inject CreatePR closure if a git provider token and repo are configured.
		gpToken := pluginFlags["github-token"]
		if gpToken == "" {
			gpToken = os.Getenv("GITHUB_TOKEN")
		}
		gpRepo := pluginFlags["github-repo"]
		if gpRepo == "" {
			gpRepo = os.Getenv("GITHUB_REPO")
		}
		if gpToken != "" && gpRepo != "" {
			parts := strings.SplitN(gpRepo, "/", 2)
			if len(parts) == 2 {
				baseBranch := pluginFlags["github-base-branch"]
				if baseBranch == "" {
					baseBranch = "main"
				}
				gpOpts := gitprovider.Options{
					Token:      gpToken,
					Owner:      parts[0],
					Repo:       parts[1],
					BaseBranch: baseBranch,
				}
				gp, err := gitprovider.NewFromFlags(pluginFlags["git-provider"], gpOpts)
				if err != nil {
					return fmt.Errorf("git provider: %w", err)
				}
				serveOpts.CreatePR = func(ctx context.Context, r plugin.Report) (string, error) {
					return gp.CreateFixPR(ctx, r)
				}
			}
		}

		return web.Serve(ctx, report, serveOpts)
	default:
		return output.Markdown(os.Stdout, report)
	}
}

// dryRunPreview validates the environment and prints what the command WOULD do
// without calling the LLM, writing to any store, or mutating anything. It backs
// the global --dry-run flag for every subcommand except `k8s fix`, which has its
// own native dry-run that computes and displays concrete fixes.
func dryRunPreview(cfg config.Config, p plugin.Plugin, sc plugin.Subcommand) error {
	results := preflight.RunAll(cfg)

	var b strings.Builder
	b.WriteString("\n  " + cliui.Bold("Dry run — no LLM call, nothing mutated") + "\n")
	b.WriteString("  ─────────────────────────────────────\n")
	for _, r := range results {
		fmt.Fprintf(&b, "  %s  %-16s %s\n", statusIcon(r), r.Name, r.Message)
	}

	model := cfg.LLMModel
	if model == "" {
		model = "provider default"
	}
	b.WriteString("\n  Would run: " + cliui.Bold(p.Name()+" "+sc.Name) + "\n")
	b.WriteString("  " + cliui.Dim(fmt.Sprintf("provider=%s · model=%s · output=%s", cfg.LLMProvider, model, cfg.OutputFormat)) + "\n")

	passed, total := preflight.CountOK(results), len(results)
	summary := fmt.Sprintf("%d/%d checks passed", passed, total)
	if preflight.AllCriticalOK(results) {
		b.WriteString("  " + cliui.Success(summary) + "\n")
		b.WriteString("  " + cliui.Dim("Re-run without --dry-run to execute.") + "\n")
	} else {
		b.WriteString("  " + cliui.Warn(summary) + "\n")
		b.WriteString("  " + cliui.Warn("A real run would fail until the critical checks above pass.") + "\n")
	}
	b.WriteString("\n")

	fmt.Fprint(os.Stderr, b.String()) //nolint:errcheck // diagnostic to stderr
	return nil
}

func buildVersionString() string {
	return fmt.Sprintf("%s (commit %s, built %s)", version.Version, version.Commit, version.BuildDate)
}

// runMCPServe boots the MCP server. Stdio is the MCP-spec default transport
// used when an LLM client (e.g. Claude Desktop) launches Exalm as a child
// process. SSE mode is useful when running Exalm as a long-lived sidecar.
func runMCPServe(ctx context.Context, sseAddr string, allowWrite bool, token string) error {
	// Empty report; in production this would be wired to a watch loop that
	// keeps the MCP server's view fresh. For now we expose an empty surface
	// that tests + manual handshakes can exercise.
	srv := mcp.NewServer(plugin.Report{Title: "exalm-mcp", Summary: "MCP server (empty report)"}, allowWrite)

	if sseAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/mcp", mcp.SSEHandler(srv))

		if token == "" {
			fmt.Fprintln(os.Stderr, "  ⚠️  MCP SSE endpoint is running WITHOUT authentication.")  //nolint:errcheck // startup warning to stderr
			fmt.Fprintln(os.Stderr, "     Set --token or EXALM_TOKEN to require a Bearer token.") //nolint:errcheck // startup warning to stderr
		}
		fmt.Fprintf(os.Stderr, "exalm mcp: SSE listening on %s (POST /mcp)\n", sseAddr) //nolint:errcheck // startup info to stderr

		s := &http.Server{
			Addr:              sseAddr,
			Handler:           web.RequireToken(mux, token),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			<-ctx.Done()
			_ = s.Close()
		}()
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}

	fmt.Fprintln(os.Stderr, "exalm mcp: stdio mode (one JSON-RPC request per line)") //nolint:errcheck // startup info to stderr
	return mcp.ServeStdio(srv, os.Stdin, os.Stdout)
}

// newWebhookCmd returns the `exalm webhook` command group, which currently
// hosts `exalm webhook terraform` — an HTTP server that receives Terraform
// Cloud run notifications and persists them to a local JSONL store.
func newWebhookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhook",
		Short: "Receive infrastructure change webhooks (Terraform Cloud, etc.)",
	}
	tf := &cobra.Command{
		Use:   "terraform",
		Short: "Start a Terraform Cloud webhook receiver on --listen (default :8765)",
		RunE:  runTerraformWebhook,
	}
	tf.Flags().String("listen", ":8765", "address to listen on")
	tf.Flags().String("hmac-secret", "", "Terraform notification HMAC-SHA512 secret (or set TF_WEBHOOK_SECRET env var)")
	tf.Flags().String("store", "", "path to events JSONL file (default: ~/.exalm/tf-events.jsonl)")
	cmd.AddCommand(tf)
	return cmd
}

func runTerraformWebhook(cmd *cobra.Command, _ []string) error {
	listen, _ := cmd.Flags().GetString("listen")
	secret, _ := cmd.Flags().GetString("hmac-secret")
	if secret == "" {
		secret = os.Getenv("TF_WEBHOOK_SECRET")
	}
	store, _ := cmd.Flags().GetString("store")
	if store == "" {
		home, _ := os.UserHomeDir()
		store = filepath.Join(home, ".exalm", "tf-events.jsonl")
	}

	h := webhookpkg.NewHandler(store, secret)
	fmt.Fprintf(os.Stderr, "  Exalm webhook: listening on %s\n", listen)                             //nolint:errcheck // startup info to stderr
	fmt.Fprintf(os.Stderr, "  Configure Terraform Cloud to POST to: http://<your-host>%s\n", listen) //nolint:errcheck // startup info to stderr

	srv := &http.Server{
		Addr:              listen,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second, // webhooks may send large payloads slowly
	}
	go func() {
		<-cmd.Context().Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("webhook: %w", err)
	}
	return nil
}

const noProviderHelp = `No LLM provider configured.

Set up Claude (recommended):
  export ANTHROPIC_API_KEY=sk-ant-...
  export EXALM_LLM_PROVIDER=claude

Or use OpenAI:
  export OPENAI_API_KEY=sk-...
  export EXALM_LLM_PROVIDER=openai

Or use a local model with Ollama (no API key needed):
  export EXALM_LLM_PROVIDER=ollama   # defaults to http://localhost:11434

Or pass --provider <claude|openai|ollama|openrouter> on the command line`
