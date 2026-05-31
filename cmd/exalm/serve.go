// Package main — exalm serve subcommand.
//
// serve is the Phase 1 "single-tenant local control plane" entry point.
// It runs the k8s watch loop (and optionally an SLO check) and serves the
// live web dashboard without having to pick a plugin-scoped subcommand.
//
// Examples:
//
//	exalm serve                                          # K8s only
//	exalm serve --slo-file specs.json                    # K8s + SLO
//	exalm serve --prometheus-url http://prom:9090        # SLO from Prometheus
//	exalm serve --port 8080 --open-browser=false         # headless CI mode
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/exalm-ai/exalm/internal/config"
	"github.com/exalm-ai/exalm/internal/gitprovider"
	"github.com/exalm-ai/exalm/internal/llm"
	"github.com/exalm-ai/exalm/internal/redact"
	"github.com/exalm-ai/exalm/internal/web"
	"github.com/exalm-ai/exalm/pkg/plugin"
	k8splugin "github.com/exalm-ai/exalm/plugins/k8s"
	sloplugin "github.com/exalm-ai/exalm/plugins/slo"
)

// serveCLIFlags captures all flags registered on the serve command.
type serveCLIFlags struct {
	port        int
	interval    string
	namespace   string
	kubeconfig  string
	kubeContext string

	// SLO integration
	sloFile string
	promURL string

	// Dashboard behaviour
	openBrowser bool

	// Security: Bearer token for the dashboard (or EXALM_TOKEN env var).
	token string

	// Network: bind address for the HTTP listener.
	// Default "localhost" keeps the dashboard off the network.
	// Set to "" or "0.0.0.0" (with --token) to expose on all interfaces.
	bind string

	// Git provider for PR creation
	githubToken      string
	githubRepo       string
	githubBaseBranch string
	gitProvider      string
}

// newServeCmd returns the top-level `exalm serve` cobra command.
func newServeCmd(root *rootFlags) *cobra.Command {
	f := &serveCLIFlags{}

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the live Exalm dashboard (K8s watch + optional SLO)",
		Long: `serve is the single-tenant control plane entry point for Phase 1.

It connects to your Kubernetes cluster, runs a continuous health-check loop,
and serves the live findings dashboard on localhost:7433 (overridable with --port).

If --slo-file is supplied, SLO burn-rate findings are merged into the dashboard.
If EXALM_PROMETHEUS_URL (or --prometheus-url) is set, live error-budget data is
pulled from Prometheus instead of the file-based --samples fallback.

Examples:
  # Basic K8s watch
  exalm serve

  # Namespace-scoped with 30 s refresh
  exalm serve --namespace prod --interval 30s

  # K8s + SLO with Prometheus backend
  exalm serve --slo-file specs.json --prometheus-url http://prometheus:9090

  # Headless (no auto-browser) on custom port
  exalm serve --port 8080 --open-browser=false`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), root, f)
		},
	}

	cmd.Flags().IntVar(&f.port, "port", 7433, "TCP port for the web dashboard")
	cmd.Flags().StringVar(&f.interval, "interval", "60s", "K8s cluster-state refresh interval (e.g. 30s, 2m)")
	cmd.Flags().StringVarP(&f.namespace, "namespace", "n", "", "Kubernetes namespace to watch (default: all namespaces)")
	cmd.Flags().StringVar(&f.kubeconfig, "kubeconfig", "", "path to kubeconfig file (default: standard discovery)")
	cmd.Flags().StringVar(&f.kubeContext, "context", "", "kubeconfig context to use (default: current-context)")
	cmd.Flags().StringVar(&f.sloFile, "slo-file", "", "SLO spec JSON file; enables SLO findings in the dashboard")
	cmd.Flags().StringVar(&f.promURL, "prometheus-url", "", "Prometheus base URL for live error budgets (overrides EXALM_PROMETHEUS_URL)")
	cmd.Flags().BoolVar(&f.openBrowser, "open-browser", true, "open the dashboard in the default browser on start")
	cmd.Flags().StringVar(&f.token, "token", "", "bearer token for dashboard auth (or EXALM_TOKEN env var); omit to serve without auth")
	cmd.Flags().StringVar(&f.bind, "bind", "localhost", `host/IP to bind the dashboard on (default "localhost"; use "0.0.0.0" with --token to expose on all interfaces)`)
	cmd.Flags().StringVar(&f.githubToken, "github-token", "", "git provider token for PR creation (or GITHUB_TOKEN env var)")
	cmd.Flags().StringVar(&f.githubRepo, "github-repo", "", "git repo for fix PR: owner/repo (or GITHUB_REPO env var)")
	cmd.Flags().StringVar(&f.githubBaseBranch, "github-base-branch", "main", "base branch for the fix PR")
	cmd.Flags().StringVar(&f.gitProvider, "git-provider", "github", `git hosting provider: "github", "gitlab", "bitbucket", "azuredevops"`)

	return cmd
}

// runServe is the implementation of `exalm serve`.
// It wires together the K8s watch loop, optional SLO check, and the web
// dashboard, then blocks until ctx is cancelled (Ctrl-C / SIGTERM).
func runServe(ctx context.Context, root *rootFlags, f *serveCLIFlags) error {
	// --- Build shared dependencies ----------------------------------------
	cfg := config.Load()
	if root.provider != "" {
		cfg.LLMProvider = root.provider
	}
	if root.model != "" {
		cfg.LLMModel = root.model
	}
	cfg.Apply = root.apply
	cfg.ShowRedactions = root.showRedactions

	llmClient, err := llm.NewFromConfig(cfg)
	if err != nil {
		if errors.Is(err, llm.ErrNoProvider) {
			return errors.New(noProviderHelp) //nolint:staticcheck // ST1005: user-facing help text, intentionally capitalized
		}
		return fmt.Errorf("init LLM: %w", err)
	}

	redactor := redact.New(cfg.OptionalRedactions...)

	// --- K8s watch --------------------------------------------------------
	// We use k8splugin directly (not the registry) so we can access
	// LastClient() and WatchReportCh() after the watch subcommand returns.
	k8sPlug := k8splugin.New()
	watchSC, ok := findSubcommand(k8sPlug, "watch")
	if !ok {
		return fmt.Errorf("serve: k8s plugin is missing the 'watch' subcommand (internal error)")
	}

	k8sFlags := map[string]string{"interval": f.interval}
	if f.namespace != "" {
		k8sFlags["namespace"] = f.namespace
	}
	if f.kubeconfig != "" {
		k8sFlags["kubeconfig"] = f.kubeconfig
	}
	if f.kubeContext != "" {
		k8sFlags["context"] = f.kubeContext
	}

	fmt.Fprintln(os.Stderr, "exalm serve: connecting to Kubernetes cluster…") //nolint:errcheck // startup info to stderr
	initialReport, err := watchSC.Run(ctx, plugin.RunArgs{
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		Flags:    k8sFlags,
		LLM:      llmClient,
		Redactor: redactor,
	})
	if err != nil {
		return fmt.Errorf("k8s watch: %w", err)
	}

	// --- Optional SLO check (once at startup) -----------------------------
	sloFindings, sloErr := runSLOCheck(ctx, f, llmClient, redactor)
	if sloErr != nil {
		// Non-fatal: warn and continue with K8s-only dashboard.
		fmt.Fprintf(os.Stderr, "exalm serve: SLO check failed (continuing without SLO findings): %v\n", sloErr) //nolint:errcheck // warning to stderr; non-fatal
	}

	// Merge SLO findings into the initial report.
	initialReport = mergeReports(initialReport, sloFindings)

	// --- Live update channel: re-attach SLO findings on every K8s refresh -
	// Only set ReportUpdates when there is an actual producer; an empty channel
	// with no goroutine writing to it would leave the web server goroutine
	// blocked forever.
	// Resolve dashboard auth token: flag > env var > empty (warn-only mode).
	dashToken := f.token
	if dashToken == "" {
		dashToken = os.Getenv("EXALM_TOKEN")
	}

	serveOpts := web.ServeOpts{
		Port:        f.port,
		BindAddr:    f.bind,
		OpenBrowser: f.openBrowser,
		Token:       dashToken,
	}
	if k8sCh := k8sPlug.WatchReportCh(); k8sCh != nil {
		mergedCh := make(chan plugin.Report, 1)
		go mergeLiveUpdates(ctx, k8sCh, mergedCh, sloFindings)
		serveOpts.ReportUpdates = mergedCh
	}

	// Inject ApplyFix closure using the kubernetes client that was established
	// during the watch run.
	if cs := k8sPlug.LastClient(); cs != nil {
		serveOpts.ApplyFix = func(ctx context.Context, action plugin.RemediationAction) error {
			return k8splugin.ApplyRemediation(ctx, cs, action)
		}
	}

	// Inject CreatePR closure if a git provider token and repo are configured.
	serveOpts.CreatePR = buildCreatePRFn(f)

	fmt.Fprintf(os.Stderr, "exalm serve: dashboard starting on http://localhost:%d\n", f.port) //nolint:errcheck // startup info to stderr
	return web.Serve(ctx, initialReport, serveOpts)
}

// runSLOCheck executes `slo check` once and returns the resulting findings.
// Returns nil, nil when f.sloFile is empty (SLO not configured for this run).
func runSLOCheck(ctx context.Context, f *serveCLIFlags, llmClient plugin.LLMClient, redactor plugin.Redactor) ([]plugin.Finding, error) {
	if f.sloFile == "" {
		return nil, nil
	}

	sloPlug := sloplugin.New()
	checkSC, ok := findSubcommand(sloPlug, "check")
	if !ok {
		return nil, fmt.Errorf("slo plugin is missing the 'check' subcommand (internal error)")
	}

	sloFlags := map[string]string{"file": f.sloFile}

	// Prefer flag; fall back to env var (same precedence as slo.go itself).
	promURL := f.promURL
	if promURL == "" {
		promURL = os.Getenv("EXALM_PROMETHEUS_URL")
	}
	if promURL != "" {
		sloFlags["prometheus-url"] = promURL
	}

	report, err := checkSC.Run(ctx, plugin.RunArgs{
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		Flags:    sloFlags,
		LLM:      llmClient,
		Redactor: redactor,
	})
	if err != nil {
		return nil, fmt.Errorf("slo check: %w", err)
	}
	return report.Findings, nil
}

// mergeReports merges extraFindings into r.Findings and updates the title/
// summary to reflect the combined dataset. Returns a new Report; the caller's
// slice is never modified (we copy into a fresh backing array).
func mergeReports(r plugin.Report, extraFindings []plugin.Finding) plugin.Report {
	if len(extraFindings) == 0 {
		return r
	}
	// Allocate a fresh slice so we never write into the caller's backing array,
	// regardless of whether r.Findings has spare capacity.
	merged := make([]plugin.Finding, len(r.Findings)+len(extraFindings))
	copy(merged, r.Findings)
	copy(merged[len(r.Findings):], extraFindings)
	r.Findings = merged
	r.Title = "Exalm live dashboard"
	r.Summary = fmt.Sprintf("%s | %d SLO finding(s) merged.", r.Summary, len(extraFindings))
	return r
}

// mergeLiveUpdates re-attaches sloFindings into every incoming K8s report
// and pushes the result to dst. Runs until ctx is cancelled or src is closed.
func mergeLiveUpdates(ctx context.Context, src <-chan plugin.Report, dst chan<- plugin.Report, sloFindings []plugin.Finding) {
	for {
		select {
		case <-ctx.Done():
			return
		case r, ok := <-src:
			if !ok {
				return
			}
			merged := mergeReports(r, sloFindings)
			select {
			case dst <- merged:
			default: // drop if the web server's consumer is not ready
			}
		}
	}
}

// findSubcommand returns the Subcommand with the given name from p.
func findSubcommand(p plugin.Plugin, name string) (plugin.Subcommand, bool) {
	for _, sc := range p.Subcommands() {
		if sc.Name == name {
			return sc, true
		}
	}
	return plugin.Subcommand{}, false
}

// buildCreatePRFn constructs the CreatePR closure for ServeOpts.
// Returns nil when the git provider is not fully configured.
func buildCreatePRFn(f *serveCLIFlags) func(context.Context, plugin.Report) (string, error) {
	token := f.githubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	repo := f.githubRepo
	if repo == "" {
		repo = os.Getenv("GITHUB_REPO")
	}
	if token == "" || repo == "" {
		return nil
	}
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return nil
	}
	baseBranch := f.githubBaseBranch
	if baseBranch == "" {
		baseBranch = "main"
	}
	gp, err := gitprovider.NewFromFlags(f.gitProvider, gitprovider.Options{
		Token:      token,
		Owner:      parts[0],
		Repo:       parts[1],
		BaseBranch: baseBranch,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "exalm serve: git provider setup failed: %v\n", err) //nolint:errcheck // warning to stderr; returns nil
		return nil
	}
	return func(ctx context.Context, r plugin.Report) (string, error) {
		return gp.CreateFixPR(ctx, r)
	}
}

// Compile-time checks: both plugin types must satisfy plugin.Plugin.
var (
	_ plugin.Plugin = (*k8splugin.Plugin)(nil)
	_ plugin.Plugin = (*sloplugin.Plugin)(nil)
)
