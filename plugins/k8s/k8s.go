package k8s

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxInputBytes caps the LLM payload — same constant as the logs plugin.
const MaxInputBytes = 200 * 1024

// Plugin implements plugin.Plugin for the k8s domain.
type Plugin struct {
	// clientFactory is overridden in tests to inject a fake kubernetes.Interface.
	clientFactory func(kubeconfigPath, contextName string) (kubernetes.Interface, error)
	// dynamicClientFactory builds the dynamic client for CRD queries (ArgoCD etc.).
	// Overridden in tests to inject a fake dynamic.Interface.
	dynamicClientFactory func(kubeconfigPath, contextName string) (dynamic.Interface, error)
	// newLogFetcher is overridden in tests to avoid the fake clientset's broken Stream().
	newLogFetcher func(kubernetes.Interface) logFetcher

	// lastCS is set after every successful cluster connection so that cmd/exalm/main.go
	// can retrieve it (via LastClient) to build the ApplyFix closure for the web server.
	mu      sync.Mutex
	lastCS  kubernetes.Interface
	watchCh chan plugin.Report // non-nil during watch subcommand
}

// New returns a production-configured k8s plugin.
func New() *Plugin {
	return &Plugin{
		clientFactory:        newKubeClient,
		dynamicClientFactory: newDynamicClient,
		newLogFetcher: func(cs kubernetes.Interface) logFetcher {
			return &restLogFetcher{clientset: cs}
		},
	}
}

func (p *Plugin) Name() string { return "k8s" }
func (p *Plugin) Description() string {
	return "Analyse Kubernetes cluster health and diagnose pod failures"
}
func (p *Plugin) Mutates() bool { return false }

// LastClient returns the most recent kubernetes client created by this plugin.
// Returns nil if no cluster connection has been made yet.
// Used by cmd/exalm/main.go to build the ApplyFix closure for the web server.
func (p *Plugin) LastClient() kubernetes.Interface {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastCS
}

func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "analyze",
			Description: "Collect cluster state and return an LLM-powered diagnostic report",
			Run:         p.analyze,
		},
		{
			Name:        "fix",
			Description: "Show fixable findings and optionally apply them (requires --apply)",
			Run:         p.fix,
		},
		{
			Name:        "watch",
			Description: "Continuously monitor cluster health with a live web dashboard",
			Run:         p.watch,
		},
	}
}

// analyze is the runner for `exalm k8s analyze`.
func (p *Plugin) analyze(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	// --from-file short-circuits cluster connection for local testing.
	if f := args.Flags["file"]; f != "" {
		return p.analyzeFile(ctx, f, args)
	}

	opts := parseOpts(args.Flags)

	cs, err := p.clientFactory(args.Flags["kubeconfig"], args.Flags["context"])
	if err != nil {
		return plugin.Report{}, fmt.Errorf("connect to cluster: %w", err)
	}
	p.setLastClient(cs)

	// Best-effort: dynamic client for IaC change detection; nil is safe.
	opts.DynamicClient, _ = p.buildDynamicClient(args.Flags["kubeconfig"], args.Flags["context"])

	lf := p.newLogFetcher(cs)

	snapshot, err := Collect(ctx, cs, lf, opts)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("collect cluster state: %w", err)
	}

	// CRITICAL: redact before any data leaves the process.
	formatted := Format(snapshot, MaxInputBytes)
	redacted := args.Redactor.Redact(formatted)

	resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
		System:    systemPrompt,
		MaxTokens: 2048,
		Messages:  []plugin.Message{{Role: "user", Content: redacted}},
	})
	if err != nil {
		return plugin.Report{}, fmt.Errorf("llm: %w", err)
	}

	ns := opts.Namespace
	if ns == "" {
		ns = "all namespaces"
	}
	return plugin.Report{
		Title:    "Kubernetes analysis",
		Summary:  fmt.Sprintf("Analysed %d pods (%d unhealthy) in %s using %s.", snapshot.TotalPods, len(snapshot.UnhealthyPods), ns, args.LLM.Name()),
		Findings: BuildAndEnrichFindings(snapshot),
		Raw:      resp.Content,
	}, nil
}

// fix is the runner for `exalm k8s fix`.
// It collects cluster state, shows fixable findings, and applies remediations
// with per-finding y/n prompts when --apply is set.
func (p *Plugin) fix(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	opts := parseOpts(args.Flags)
	dryRun := args.Flags["dry-run"] == "true"
	applyAll := args.Flags["apply"] == "true"

	cs, err := p.clientFactory(args.Flags["kubeconfig"], args.Flags["context"])
	if err != nil {
		return plugin.Report{}, fmt.Errorf("connect to cluster: %w", err)
	}
	p.setLastClient(cs)

	opts.DynamicClient, _ = p.buildDynamicClient(args.Flags["kubeconfig"], args.Flags["context"])

	lf := p.newLogFetcher(cs)
	snapshot, err := Collect(ctx, cs, lf, opts)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("collect cluster state: %w", err)
	}

	findings := BuildAndEnrichFindings(snapshot)

	// Filter to actionable findings only.
	var fixable []plugin.Finding
	for _, f := range findings {
		if f.Remediation != nil {
			fixable = append(fixable, f)
		}
	}

	if len(fixable) == 0 {
		fmt.Fprintln(args.Stdout, "No auto-fixable findings found.") //nolint:errcheck // plugin stdout; error is harmless
		return plugin.Report{
			Title:    "Kubernetes fix",
			Summary:  "No auto-fixable findings.",
			Findings: findings,
		}, nil
	}

	fmt.Fprintf(args.Stdout, "\n%d auto-fixable finding(s):\n\n", len(fixable)) //nolint:errcheck // plugin stdout; error is harmless
	for i, f := range fixable {
		fmt.Fprintf(args.Stdout, "  [%d] [%s] %s\n      %s\n\n", i+1, strings.ToUpper(string(f.Severity)), f.Title, f.Remediation.KubectlCmd) //nolint:errcheck // plugin stdout; error is harmless
	}

	if dryRun {
		fmt.Fprintln(args.Stdout, "Dry-run: no changes applied.") //nolint:errcheck // plugin stdout; error is harmless
		return plugin.Report{Title: "Kubernetes fix (dry-run)", Findings: findings}, nil
	}

	if !applyAll {
		fmt.Fprintln(args.Stderr, "\nPass --apply to execute remediations.") //nolint:errcheck // plugin stderr; error is harmless
		return plugin.Report{Title: "Kubernetes fix", Findings: findings}, nil
	}

	scanner := bufio.NewScanner(args.Stdin)
	var applied, skipped int
	for _, f := range fixable {
		fmt.Fprintf(args.Stdout, "Apply fix for [%s] %s? [y/N] ", strings.ToUpper(string(f.Severity)), f.Title) //nolint:errcheck // plugin stdout; error is harmless
		scanner.Scan()
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer != "y" && answer != "yes" {
			skipped++
			continue
		}
		if err := ApplyRemediation(ctx, cs, *f.Remediation); err != nil {
			fmt.Fprintf(args.Stderr, "  Error: %v\n", err) //nolint:errcheck // plugin stderr; error is harmless
		} else {
			fmt.Fprintf(args.Stdout, "  ✓ Applied: %s\n", f.Remediation.Description) //nolint:errcheck // plugin stdout; error is harmless
			applied++
		}
	}

	return plugin.Report{
		Title:    "Kubernetes fix",
		Summary:  fmt.Sprintf("Applied %d fix(es), skipped %d.", applied, skipped),
		Findings: findings,
	}, nil
}

// watch is the runner for `exalm k8s watch`.
// It opens the web dashboard and continuously refreshes cluster data.
// The LLM analysis runs once initially; subsequent ticks update findings only.
func (p *Plugin) watch(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	opts := parseOpts(args.Flags)

	interval := 60 * time.Second
	if v := args.Flags["interval"]; v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 10*time.Second {
			interval = d
		}
	}

	cs, err := p.clientFactory(args.Flags["kubeconfig"], args.Flags["context"])
	if err != nil {
		return plugin.Report{}, fmt.Errorf("connect to cluster: %w", err)
	}
	p.setLastClient(cs)

	opts.DynamicClient, _ = p.buildDynamicClient(args.Flags["kubeconfig"], args.Flags["context"])

	lf := p.newLogFetcher(cs)
	snapshot, err := Collect(ctx, cs, lf, opts)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("collect cluster state: %w", err)
	}

	// Run LLM once for the initial narrative.
	formatted := Format(snapshot, MaxInputBytes)
	redacted := args.Redactor.Redact(formatted)
	resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
		System:    systemPrompt,
		MaxTokens: 2048,
		Messages:  []plugin.Message{{Role: "user", Content: redacted}},
	})
	if err != nil {
		return plugin.Report{}, fmt.Errorf("llm: %w", err)
	}

	ns := opts.Namespace
	if ns == "" {
		ns = "all namespaces"
	}
	initialReport := plugin.Report{
		Title:    "Kubernetes watch",
		Summary:  fmt.Sprintf("Watching %s — refreshing every %s.", ns, interval),
		Findings: BuildAndEnrichFindings(snapshot),
		Raw:      resp.Content,
	}

	// Start background loop — pushes refreshed findings to watchCh every interval.
	p.startWatchLoop(cs, lf, opts, interval)

	return initialReport, nil
}

// WatchReportCh returns the channel used to push live report updates from watch mode.
// Non-nil only while a watch subcommand is active.
func (p *Plugin) WatchReportCh() <-chan plugin.Report {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.watchCh
}

// setLastClient stores cs safely under the plugin mutex.
func (p *Plugin) setLastClient(cs kubernetes.Interface) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastCS = cs
}

// buildDynamicClient calls dynamicClientFactory when set. Returns nil without
// error when the factory is not configured (e.g. in tests that only set the
// core clientFactory).
func (p *Plugin) buildDynamicClient(kubeconfigPath, contextName string) (dynamic.Interface, error) {
	if p.dynamicClientFactory == nil {
		return nil, nil
	}
	return p.dynamicClientFactory(kubeconfigPath, contextName)
}

// startWatchLoop starts a background goroutine that re-collects cluster state every
// interval and pushes updated reports to the plugin's watchCh.
func (p *Plugin) startWatchLoop(cs kubernetes.Interface, lf logFetcher, opts CollectOpts, interval time.Duration) {
	p.mu.Lock()
	p.watchCh = make(chan plugin.Report, 1)
	p.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			snap, err := Collect(context.Background(), cs, lf, opts)
			if err != nil {
				continue
			}
			report := plugin.Report{
				Title:    "Kubernetes watch",
				Summary:  fmt.Sprintf("Watching %s — live refresh.", opts.Namespace),
				Findings: BuildAndEnrichFindings(snap),
			}
			p.mu.Lock()
			ch := p.watchCh
			p.mu.Unlock()
			select {
			case ch <- report:
			default: // drop if consumer is not ready
			}
		}
	}()
}

// analyzeFile reads a pre-formatted snapshot file and sends it straight to the
// LLM, bypassing cluster connection. Used for local testing with example files.
func (p *Plugin) analyzeFile(ctx context.Context, path string, args plugin.RunArgs) (plugin.Report, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path comes from user-supplied --file flag, intentional
	if err != nil {
		return plugin.Report{}, fmt.Errorf("read snapshot file: %w", err)
	}
	redacted := args.Redactor.Redact(string(raw))
	resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
		System:    systemPrompt,
		MaxTokens: 2048,
		Messages:  []plugin.Message{{Role: "user", Content: redacted}},
	})
	if err != nil {
		return plugin.Report{}, fmt.Errorf("llm: %w", err)
	}
	return plugin.Report{
		Title:   "Kubernetes analysis",
		Summary: fmt.Sprintf("Analysed snapshot file %q using %s.", path, args.LLM.Name()),
		Raw:     resp.Content,
	}, nil
}

// parseOpts extracts CollectOpts from the string flag map passed by the CLI.
func parseOpts(flags map[string]string) CollectOpts {
	opts := CollectOpts{
		Namespace: flags["namespace"],
		MaxPods:   25,
		Since:     time.Hour,
		LogLines:  100,
	}
	if v := flags["max-pods"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			opts.MaxPods = n
		}
	}
	if v := flags["since"]; v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			opts.Since = d
		}
	}
	if v := flags["log-lines"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			opts.LogLines = n
		}
	}
	if flags["include-nodes"] == "true" {
		opts.IncludeNodes = true
	}
	return opts
}
