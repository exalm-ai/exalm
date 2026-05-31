// Package dora provides DORA engineering-health metrics (Deployment Frequency,
// Lead Time for Changes, Change Failure Rate, and MTTR) sourced from local
// deployment logs and the incident store.
//
// Quickstart:
//
//	# Record a deployment
//	exalm dora log-deploy --service payments-api --version v1.4.2
//
//	# View DORA metrics for the last 30 days
//	exalm dora report
//
//	# View metrics with LLM analysis
//	exalm dora report --ai
//
// Deployment events are stored in ~/.exalm/deployments.jsonl (one JSON object
// per line). They can also be written automatically by `exalm k8s watch`.
//
// Incident MTTR and CFR data are sourced from the incident plugin store at
// ~/.exalm/incidents/.
package dora

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
	incidentpkg "github.com/exalm-ai/exalm/plugins/incident"
)

// Plugin is the DORA metrics plugin.
type Plugin struct{}

// New returns a new DORA plugin instance.
func New() *Plugin { return &Plugin{} }

// Name returns "dora".
func (p *Plugin) Name() string { return "dora" }

// Description returns the short help text shown in `exalm --help`.
func (p *Plugin) Description() string {
	return "Compute DORA engineering-health metrics: Deployment Frequency, Lead Time, CFR, MTTR"
}

// Mutates returns false — log-deploy writes local data but does not mutate
// any external system.
//
// NOTE: log-deploy does write to ~/.exalm/deployments.jsonl, but this is
// treated as append-only local telemetry rather than a mutation that requires
// --apply confirmation. Phase 4 may revisit if we add delete/edit capabilities.
func (p *Plugin) Mutates() bool { return false }

// Subcommands returns the DORA plugin actions.
func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "report",
			Description: "Display DORA metrics for the past N days (default: 30). Add --ai for LLM analysis.",
			Run:         p.report,
		},
		{
			Name:        "log-deploy",
			Description: "Record a deployment event (--service required, --version optional, --failed flag)",
			Run:         p.logDeploy,
		},
	}
}

// report computes and renders DORA metrics.
func (p *Plugin) report(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	days := 30
	if v := args.Flags["days"]; v != "" {
		if _, err := fmt.Sscanf(v, "%d", &days); err != nil || days <= 0 {
			return plugin.Report{}, fmt.Errorf("dora report: --days must be a positive integer")
		}
	}
	window := time.Duration(days) * 24 * time.Hour

	// Load deployments.
	deployments, err := loadDeploymentsInWindow(window)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("dora report: load deployments: %w", err)
	}

	// Load incidents via the incident store.
	incidents, err := loadIncidentsInWindow(ctx, window)
	if err != nil {
		// Non-fatal: DORA metrics degrade gracefully without incident data.
		incidents = nil
	}

	m := calculateDORA(window, deployments, incidents)

	// Format the metrics table.
	summary := formatMetricsTable(m)

	findings := metricsToFindings(m)

	// Optional LLM analysis.
	if args.Flags["ai"] == "true" || args.Flags["ai"] == "1" || args.Flags["ai"] == "yes" {
		llmInput := formatMetricsForLLM(m)
		redacted := args.Redactor.Redact(llmInput)
		resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
			System:    doraPrompt,
			MaxTokens: 1024,
			Messages: []plugin.Message{
				{Role: "user", Content: redacted},
			},
		})
		if err == nil && resp.Content != "" {
			findings = append(findings, plugin.Finding{
				Severity: plugin.SeverityInfo,
				Category: "DORA Analysis",
				Title:    "AI Engineering Health Assessment",
				Detail:   resp.Content,
			})
		}
	}

	return plugin.Report{
		Title:    fmt.Sprintf("DORA Metrics — last %d days", days),
		Summary:  summary,
		Findings: findings,
	}, nil
}

// logDeploy records a deployment event to ~/.exalm/deployments.jsonl.
func (p *Plugin) logDeploy(_ context.Context, args plugin.RunArgs) (plugin.Report, error) {
	service := strings.TrimSpace(args.Flags["service"])
	if service == "" {
		return plugin.Report{}, fmt.Errorf("dora log-deploy: --service is required")
	}

	now := time.Now().UTC()
	success := args.Flags["failed"] != "true" && args.Flags["failed"] != "1"

	ev := DeploymentEvent{
		ID:         newDeploymentID(now),
		Service:    service,
		Namespace:  args.Flags["namespace"],
		Version:    args.Flags["version"],
		DeployedAt: now,
		DeployedBy: args.Flags["deployed-by"],
		Success:    success,
		CommitSHA:  args.Flags["commit"],
	}
	if ct := args.Flags["commit-time"]; ct != "" {
		if t, err := time.Parse(time.RFC3339, ct); err == nil {
			ev.CommitTime = t.UTC()
		}
	}

	if err := appendDeployment(ev); err != nil {
		return plugin.Report{}, fmt.Errorf("dora log-deploy: %w", err)
	}

	status := "successful"
	severity := plugin.SeverityInfo
	if !success {
		status = "failed"
		severity = plugin.SeverityHigh
	}

	return plugin.Report{
		Title:   "Deployment logged",
		Summary: fmt.Sprintf("Recorded %s deployment of %s (ID: %s)", status, service, ev.ID),
		Findings: []plugin.Finding{
			{
				Severity: severity,
				Category: "Deployment",
				Title:    fmt.Sprintf("%s — %s", service, status),
				Detail:   fmt.Sprintf("ID: %s | Version: %s | Time: %s", ev.ID, ev.Version, now.Format(time.RFC3339)),
			},
		},
	}, nil
}

// ─── public API for the web dashboard ────────────────────────────────────────

// PublicMetrics is the JSON-serialisable DORA summary for the web dashboard.
type PublicMetrics struct {
	Window                  string            `json:"window"`
	DeploymentFrequency     float64           `json:"deployment_frequency"`
	DeploymentFrequencyBand string            `json:"deployment_frequency_band"`
	CFR                     float64           `json:"cfr"`
	CFRBand                 string            `json:"cfr_band"`
	MTTRHours               float64           `json:"mttr_hours"`
	MTTRBand                string            `json:"mttr_band"`
	LeadTimeBand            string            `json:"lead_time_band"`
	TotalDeployments        int               `json:"total_deployments"`
	TotalIncidents          int               `json:"total_incidents"`
	OverallBand             string            `json:"overall_band"`
	RecentDeployments       []DeploymentEvent `json:"recent_deployments"`
}

// ComputePublicMetrics computes DORA metrics over the given number of days and
// returns a JSON-friendly summary for the web dashboard.
func ComputePublicMetrics(days int) (PublicMetrics, error) {
	if days <= 0 {
		days = 30
	}
	window := time.Duration(days) * 24 * time.Hour

	deployments, err := loadDeploymentsInWindow(window)
	if err != nil {
		return PublicMetrics{}, fmt.Errorf("dora: load deployments: %w", err)
	}

	incidents, _ := loadIncidentsInWindow(context.Background(), window)

	m := calculateDORA(window, deployments, incidents)

	// Take the 10 most recent deployments for the table (slice is already
	// filtered to the window; loadDeployments returns chronological order).
	recent := deployments
	if len(recent) > 10 {
		recent = recent[len(recent)-10:]
	}
	// Reverse so newest is first.
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}

	return PublicMetrics{
		Window:                  fmt.Sprintf("%d days", days),
		DeploymentFrequency:     m.DeploymentFrequency,
		DeploymentFrequencyBand: string(m.DeploymentFrequencyRating),
		CFR:                     m.ChangeFailureRate,
		CFRBand:                 string(m.ChangeFailureRateRating),
		MTTRHours:               m.MTTRHours,
		MTTRBand:                string(m.MTTRRating),
		LeadTimeBand:            string(m.LeadTimeRating),
		TotalDeployments:        m.TotalDeployments,
		TotalIncidents:          m.TotalIncidents,
		OverallBand:             string(m.OverallRating),
		RecentDeployments:       recent,
	}, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// loadIncidentsInWindow uses the incident store to get incidents in the window.
func loadIncidentsInWindow(ctx context.Context, window time.Duration) ([]incidentpkg.Incident, error) {
	store := incidentpkg.NewFileStore()
	to := time.Now().UTC()
	from := to.Add(-window)
	return store.QueryByDateRange(ctx, from, to)
}

// formatMetricsTable renders the four DORA metrics as a readable markdown table.
func formatMetricsTable(m DORAMetrics) string {
	var sb strings.Builder
	days := int(m.Window.Hours() / 24)
	sb.WriteString(fmt.Sprintf("**DORA Engineering Health — last %d days**\n\n", days)) //nolint:staticcheck // QF1012: fmt.Fprintf alternative would need errcheck suppression too

	sb.WriteString("| Metric | Value | Band |\n")
	sb.WriteString("|--------|-------|------|\n")

	// Deployment Frequency
	dfStr := fmt.Sprintf("%.2f/day (%d deployments)", m.DeploymentFrequency, m.SuccessfulDeployments)
	if m.SuccessfulDeployments == 0 {
		dfStr = "no data"
	}
	sb.WriteString(fmt.Sprintf("| Deployment Frequency | %s | %s |\n", dfStr, bandEmoji(m.DeploymentFrequencyRating))) //nolint:staticcheck // QF1012

	// Lead Time
	ltStr := "N/A (pass --commit to log-deploy)"
	if m.LeadTimeRating != BandNA {
		ltStr = formatHours(m.LeadTimeHours)
	}
	sb.WriteString(fmt.Sprintf("| Lead Time for Changes | %s | %s |\n", ltStr, bandEmoji(m.LeadTimeRating))) //nolint:staticcheck // QF1012

	// Change Failure Rate
	cfrStr := fmt.Sprintf("%.1f%% (%d failures / %d deployments)", m.ChangeFailureRate*100, m.CriticalHighIncidents, m.TotalDeployments)
	if m.TotalDeployments == 0 {
		cfrStr = "no data"
	}
	sb.WriteString(fmt.Sprintf("| Change Failure Rate | %s | %s |\n", cfrStr, bandEmoji(m.ChangeFailureRateRating))) //nolint:staticcheck // QF1012

	// MTTR
	mttrStr := formatHours(m.MTTRHours)
	if m.TotalIncidents == 0 {
		mttrStr = "no incidents"
	}
	sb.WriteString(fmt.Sprintf("| MTTR | %s | %s |\n", mttrStr, bandEmoji(m.MTTRRating))) //nolint:staticcheck // QF1012

	sb.WriteString(fmt.Sprintf("\n**Overall:** %s\n", bandEmoji(m.OverallRating)))                                   //nolint:staticcheck // QF1012
	sb.WriteString(fmt.Sprintf("Analysed %d deployments and %d incidents.\n", m.TotalDeployments, m.TotalIncidents)) //nolint:staticcheck // QF1012
	sb.WriteString("\n_Record deployments with: `exalm dora log-deploy --service <name>`_\n")
	return sb.String()
}

// metricsToFindings converts DORAMetrics into structured plugin.Findings.
func metricsToFindings(m DORAMetrics) []plugin.Finding {
	var findings []plugin.Finding

	if m.DeploymentFrequencyRating == BandLow || m.DeploymentFrequencyRating == BandMedium {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityMedium,
			Category:   "DORA",
			Title:      "Low Deployment Frequency",
			Detail:     fmt.Sprintf("%.2f deployments/day over the analysis window. DORA Elite threshold: ≥1/day.", m.DeploymentFrequency),
			Suggestion: "Invest in CI/CD pipeline improvements and break changes into smaller, independently deployable units.",
		})
	}

	if m.ChangeFailureRateRating == BandLow || m.ChangeFailureRateRating == BandMedium {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityHigh,
			Category:   "DORA",
			Title:      "Elevated Change Failure Rate",
			Detail:     fmt.Sprintf("%.1f%% of deployments correlate with high/critical incidents. DORA Elite threshold: <5%%.", m.ChangeFailureRate*100),
			Suggestion: "Add automated smoke tests post-deploy, improve rollback automation, and review release readiness criteria.",
		})
	}

	if m.MTTRRating == BandLow || m.MTTRRating == BandMedium {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityHigh,
			Category:   "DORA",
			Title:      "High Mean Time to Restore",
			Detail:     fmt.Sprintf("Average incident duration: %s. DORA Elite threshold: <1 hour.", formatHours(m.MTTRHours)),
			Suggestion: "Improve runbook coverage, on-call alerting latency, and invest in automated remediation for common failure modes.",
		})
	}

	// Positive reinforcements for elite/high performers.
	if m.DeploymentFrequencyRating == BandElite || m.DeploymentFrequencyRating == BandHigh {
		findings = append(findings, plugin.Finding{
			Severity: plugin.SeverityInfo,
			Category: "DORA",
			Title:    "Strong Deployment Frequency",
			Detail:   fmt.Sprintf("%.2f deployments/day — %s band. Good CI/CD velocity.", m.DeploymentFrequency, m.DeploymentFrequencyRating),
		})
	}

	if m.MTTRRating == BandElite || m.MTTRRating == BandHigh {
		findings = append(findings, plugin.Finding{
			Severity: plugin.SeverityInfo,
			Category: "DORA",
			Title:    "Excellent MTTR",
			Detail:   fmt.Sprintf("Average restore time: %s — %s band.", formatHours(m.MTTRHours), m.MTTRRating),
		})
	}

	return findings
}

// formatMetricsForLLM serialises metrics into a text block for the LLM prompt.
func formatMetricsForLLM(m DORAMetrics) string {
	days := int(m.Window.Hours() / 24)
	ltStr := "N/A (pass --commit to log-deploy)"
	if m.LeadTimeRating != BandNA {
		ltStr = formatHours(m.LeadTimeHours)
	}
	return fmt.Sprintf(
		"Analysis window: %d days\n\n"+
			"Deployment Frequency: %.2f/day (%d successful / %d total) — Band: %s\n"+
			"Lead Time for Changes: %s — Band: %s\n"+
			"Change Failure Rate: %.1f%% (%d high/critical incidents / %d deployments) — Band: %s\n"+
			"MTTR: %s (%d closed incidents) — Band: %s\n"+
			"Overall DORA Band: %s\n",
		days,
		m.DeploymentFrequency, m.SuccessfulDeployments, m.TotalDeployments, m.DeploymentFrequencyRating,
		ltStr, m.LeadTimeRating,
		m.ChangeFailureRate*100, m.CriticalHighIncidents, m.TotalDeployments, m.ChangeFailureRateRating,
		formatHours(m.MTTRHours), m.TotalIncidents, m.MTTRRating,
		m.OverallRating,
	)
}

// formatHours formats a duration in hours as a human-readable string.
func formatHours(h float64) string {
	if h == 0 {
		return "0m"
	}
	d := time.Duration(h * float64(time.Hour))
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", h)
	}
	return fmt.Sprintf("%.1fd", h/24)
}
