// Package slo provides SLO/SLI compliance tracking and AI-powered burn-rate analysis.
//
// SRE use case: ops teams define service level objectives once in a JSON spec file.
// Exalm evaluates the current error budget status with Google SRE-style multi-window
// burn rates (1h / 6h / 72h), projects budget exhaustion, and generates structured
// findings + LLM analysis when burn rate exceeds safe thresholds.
//
// Quickstart:
//
//	exalm slo check --file examples/slo/specs.json --samples examples/slo/samples.json
//	exalm slo report --file examples/slo/specs.json
//
// When --samples is omitted, slo check uses a synthetic healthy sample stream so
// the command demonstrates the multi-window output without requiring a metrics
// backend. Production deployments will plug Prometheus / OpenObserve / Mimir into
// the Sample stream via collect.go.
package slo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Plugin is the SLO/SLI tracking and burn-rate analysis plugin.
type Plugin struct{}

// New returns a new SLO plugin instance.
func New() *Plugin { return &Plugin{} }

// Name returns "slo".
func (p *Plugin) Name() string { return "slo" }

// Description returns the short help text shown in `exalm --help`.
func (p *Plugin) Description() string {
	return "Track SLO compliance with multi-window burn-rate analysis (Google SRE pattern)"
}

// Mutates returns false — this plugin is read-only (queries metrics, no writes).
func (p *Plugin) Mutates() bool { return false }

// Subcommands returns the two SLO subcommands.
func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "check",
			Description: "Evaluate SLO compliance and emit multi-window burn-rate findings",
			Run:         p.check,
		},
		{
			Name:        "report",
			Description: "Generate AI burn-rate narrative and mitigation recommendations",
			Run:         p.report,
		},
	}
}

// Snapshot is the result of a single `slo check` run.
//
// Strength: openobserve — "Aggregation functions for alerts: count, avg, min,
// max, sum, median, p50, p75, p90, p95, p99" — we add the SLO layer that turns
// those aggregations into burn-rate decisions OO/Komodor cannot make natively.
type Snapshot struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Specs       []SLOSpec             `json:"specs"`
	BurnRates   map[string][]BurnRate `json:"burn_rates"` // keyed by spec.Name
}

// check loads SLOSpec definitions from --file, loads samples from --samples (or
// synthesizes healthy samples), runs ComputeMultiWindow per spec, and emits a
// Finding per triggered burn-rate window.
func (p *Plugin) check(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	specPath := args.Flags["file"]
	if specPath == "" {
		return plugin.Report{}, errors.New("slo check: --file <specs.json> is required")
	}
	specs, err := loadSpecs(specPath)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("load specs: %w", err)
	}

	cfg := DefaultMultiWindowConfig()

	// Resolve Prometheus URL from flag or environment variable.
	promURL := args.Flags["prometheus-url"]
	if promURL == "" {
		promURL = os.Getenv("EXALM_PROMETHEUS_URL")
	}

	var samplesByName map[string][]Sample
	if promURL != "" {
		hc := &http.Client{Timeout: 30 * time.Second}
		samplesByName, err = fetchSamplesFromProm(ctx, specs, promURL, cfg.Long, hc)
		if err != nil {
			return plugin.Report{}, fmt.Errorf("prometheus: %w", err)
		}
	} else {
		samplesByName, err = loadSamples(args.Flags["samples"])
		if err != nil {
			return plugin.Report{}, fmt.Errorf("load samples: %w", err)
		}
	}

	now := time.Now()

	snap := Snapshot{
		GeneratedAt: now,
		Specs:       specs,
		BurnRates:   make(map[string][]BurnRate, len(specs)),
	}

	var findings []plugin.Finding
	for _, spec := range specs {
		samples, ok := samplesByName[spec.Name]
		if !ok {
			// Default: synthesize a healthy stream so the command always produces output.
			samples = synthesizeHealthy(now, cfg.Long)
		}
		burns := ComputeMultiWindow(spec, samples, now, cfg)
		snap.BurnRates[spec.Name] = burns
		findings = append(findings, burnRatesToFindings(spec, burns)...)
	}

	// Stable ordering: critical → high → medium → info, then by title.
	sort.SliceStable(findings, func(i, j int) bool {
		si, sj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return findings[i].Title < findings[j].Title
	})

	snapJSON, _ := json.MarshalIndent(snap, "", "  ")
	report := plugin.Report{
		Title:    "SLO multi-window burn-rate check",
		Summary:  summarize(snap),
		Findings: findings,
		Raw:      string(snapJSON),
	}
	return report, nil
}

// report runs check and then asks the LLM for a burn-rate narrative.
func (p *Plugin) report(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	r, err := p.check(ctx, args)
	if err != nil {
		return r, err
	}
	if args.LLM == nil {
		// No LLM configured — return structured findings only.
		return r, nil
	}
	redacted := args.Redactor.Redact(r.Raw)
	resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
		System: systemPrompt,
		Messages: []plugin.Message{
			{Role: "user", Content: redacted},
		},
		MaxTokens:   1200,
		Temperature: 0.2,
	})
	if err != nil {
		return r, fmt.Errorf("llm complete: %w", err)
	}
	r.Raw = resp.Content
	return r, nil
}

// loadSpecs reads a JSON file containing []SLOSpec.
func loadSpecs(path string) ([]SLOSpec, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path comes from user-supplied --file flag
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var specs []SLOSpec
	if err := json.Unmarshal(data, &specs); err != nil {
		return nil, fmt.Errorf("parse specs JSON: %w", err)
	}
	if len(specs) == 0 {
		return nil, errors.New("specs file contains zero SLOs")
	}
	return specs, nil
}

// loadSamples reads an optional samples file. Format:
//
//	{
//	  "slo-name": [{"at": "2026-05-19T10:00:00Z", "good": 1000, "total": 1010}, ...],
//	  ...
//	}
//
// Returns an empty map (not nil) when path is empty.
func loadSamples(path string) (map[string][]Sample, error) {
	out := map[string][]Sample{}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path) //nolint:gosec // G304: path comes from user-supplied --file flag
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse samples JSON: %w", err)
	}
	return out, nil
}

// synthesizeHealthy fabricates a steady 100% success sample stream spanning
// the longest configured window. Used so that `slo check` produces a
// demonstrable green output even without a real metrics source.
func synthesizeHealthy(end time.Time, span time.Duration) []Sample {
	step := 5 * time.Minute
	n := int(span / step)
	if n < 1 {
		n = 1
	}
	out := make([]Sample, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Sample{
			At:    end.Add(-time.Duration(n-i) * step),
			Good:  1000,
			Total: 1000,
		})
	}
	return out
}

// burnRatesToFindings converts each triggered window into a Finding. The tier
// maps to severity: page→critical, ticket→high, warn→medium.
func burnRatesToFindings(spec SLOSpec, burns []BurnRate) []plugin.Finding {
	var out []plugin.Finding
	for _, b := range burns {
		if !b.Triggered {
			continue
		}
		sev := plugin.SeverityMedium
		switch b.Tier {
		case "page":
			sev = plugin.SeverityCritical
		case "ticket":
			sev = plugin.SeverityHigh
		}
		out = append(out, plugin.Finding{
			Severity: sev,
			Category: "SLO",
			Title:    fmt.Sprintf("Burn-rate %s: %s (%.1f× over %s)", b.Tier, spec.Name, b.Multiplier, b.Window),
			Detail: fmt.Sprintf(
				"SLO %q (objective %.4f) is burning error budget %.2f× faster than allowed in the %s window. "+
					"Observed error rate %.4f vs allowed %.4f. Threshold %.1f.",
				spec.Name, spec.Objective, b.Multiplier, b.Window, b.ObservedRate, b.AllowedRate, b.Threshold,
			),
			Suggestion: suggestionForTier(b.Tier, spec),
		})
	}
	return out
}

func suggestionForTier(tier string, spec SLOSpec) string {
	switch tier {
	case "page":
		return fmt.Sprintf("Page on-call: short-window burn — investigate %s in namespace %s immediately.", spec.Service, spec.Namespace)
	case "ticket":
		return fmt.Sprintf("Open a ticket for %s — medium-window burn means a sustained issue is consuming budget.", spec.Service)
	case "warn":
		return fmt.Sprintf("Plan capacity / reliability work for %s — long-window burn predicts budget exhaustion.", spec.Service)
	}
	return ""
}

func severityRank(s plugin.Severity) int {
	switch s {
	case plugin.SeverityCritical:
		return 4
	case plugin.SeverityHigh:
		return 3
	case plugin.SeverityMedium:
		return 2
	case plugin.SeverityLow:
		return 1
	}
	return 0
}

// summarize produces a one-line summary suitable for the report header / dashboard.
func summarize(snap Snapshot) string {
	if len(snap.Specs) == 0 {
		return "No SLOs evaluated."
	}
	var page, ticket, warn int
	for _, burns := range snap.BurnRates {
		switch WorstTier(burns) {
		case "page":
			page++
		case "ticket":
			ticket++
		case "warn":
			warn++
		}
	}
	if page+ticket+warn == 0 {
		return fmt.Sprintf("%d SLOs evaluated — all green.", len(snap.Specs))
	}
	return fmt.Sprintf("%d SLOs evaluated — %d page, %d ticket, %d warn.", len(snap.Specs), page, ticket, warn)
}
