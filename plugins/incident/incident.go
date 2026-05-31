// Package incident manages the full production incident lifecycle: open, track,
// close, and generate AI-powered blameless postmortems.
//
// SRE use case workflow:
//  1. Alert fires or `exalm k8s analyze` returns critical findings.
//  2. Run `exalm incident open --title "Payment service down" --severity critical`
//     to create a local incident record.
//  3. Throughout the incident, `exalm k8s analyze` findings are appended to the
//     timeline (automatically in watch mode once implemented).
//  4. After mitigation: `exalm incident close --incident-id INC-001`.
//  5. Post-incident: `exalm incident postmortem --incident-id INC-001` generates
//     a structured blameless postmortem using the configured LLM.
//
// Incident records are stored locally in ~/.exalm/incidents/ (one JSON file each).
// This keeps them close to the cluster context and avoids requiring a central
// database for the single-operator use case.
package incident

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Plugin is the incident lifecycle management plugin.
type Plugin struct {
	store Store
}

// New returns a new incident plugin instance.
func New() *Plugin { return &Plugin{store: newFileStore()} }

// Name returns "incident".
func (p *Plugin) Name() string { return "incident" }

// Description returns the short help text shown in `exalm --help`.
func (p *Plugin) Description() string {
	return "Open, track, close, and postmortem production incidents"
}

// Mutates returns true because open and close write incident records to disk.
func (p *Plugin) Mutates() bool { return true }

// Subcommands returns the four incident lifecycle operations.
func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "open",
			Description: "Open a new incident record (requires --title, optional --severity)",
			Mutates:     true, // writes a new incident record to the local store
			Run:         p.open,
		},
		{
			Name:        "list",
			Description: "List all incidents (optionally filter by status with --status open|closed|mitigated)",
			Mutates:     false, // read-only: no store writes
			Run:         p.list,
		},
		{
			Name:        "close",
			Description: "Mark an incident as resolved (requires --incident-id)",
			Mutates:     true, // updates the incident record in the local store
			Run:         p.close,
		},
		{
			Name:        "postmortem",
			Description: "Generate an AI blameless postmortem for a closed incident (requires --incident-id)",
			Mutates:     true, // persists the generated postmortem back to the incident record
			Run:         p.postmortem,
		},
	}
}

// open creates a new incident record from --title and optional --severity flags.
func (p *Plugin) open(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	title := strings.TrimSpace(args.Flags["title"])
	if title == "" {
		return plugin.Report{}, fmt.Errorf("incident open: --title is required")
	}

	severity := plugin.Severity(strings.TrimSpace(args.Flags["severity"]))
	if severity == "" {
		severity = plugin.SeverityMedium
	}

	relatedDeploy := strings.TrimSpace(args.Flags["from-deploy"])

	now := time.Now().UTC()
	inc := Incident{
		ID:                  newIncidentID(now),
		Title:               title,
		Status:              IncidentOpen,
		Severity:            severity,
		OpenedAt:            now,
		RelatedDeploymentID: relatedDeploy,
	}

	if err := p.store.Create(ctx, inc); err != nil {
		return plugin.Report{}, fmt.Errorf("incident open: %w", err)
	}

	detail := fmt.Sprintf("ID: %s | Status: %s | Severity: %s | Opened: %s", inc.ID, inc.Status, inc.Severity, inc.OpenedAt.Format(time.RFC3339))
	if relatedDeploy != "" {
		detail += " | Deploy: " + relatedDeploy
	}

	return plugin.Report{
		Title:   "Incident opened",
		Summary: fmt.Sprintf("Incident %s opened", inc.ID),
		Findings: []plugin.Finding{
			{
				Severity: severity,
				Category: "Incident",
				Title:    inc.Title,
				Detail:   detail,
			},
		},
	}, nil
}

// list shows all incidents stored locally, optionally filtered by --status.
func (p *Plugin) list(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	incidents, err := p.store.List(ctx)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("incident list: %w", err)
	}

	statusFilter := strings.TrimSpace(args.Flags["status"])
	if statusFilter != "" {
		filtered := incidents[:0]
		for _, inc := range incidents {
			if string(inc.Status) == statusFilter {
				filtered = append(filtered, inc)
			}
		}
		incidents = filtered
	}

	if len(incidents) == 0 {
		msg := "No incidents found."
		if statusFilter != "" {
			msg = fmt.Sprintf("No incidents found with status %q.", statusFilter)
		}
		return plugin.Report{
			Title:   "Incidents",
			Summary: msg,
		}, nil
	}

	var sb strings.Builder
	sb.WriteString("| ID | Status | Severity | Title | Opened | Duration |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")

	for _, inc := range incidents {
		duration := incidentDuration(inc)
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n", //nolint:staticcheck // QF1012: fmt.Fprintf alternative would need errcheck suppression too
			inc.ID,
			inc.Status,
			inc.Severity,
			escapeMarkdown(inc.Title),
			inc.OpenedAt.Format("2006-01-02 15:04"),
			duration,
		))
	}

	return plugin.Report{
		Title:   "Incidents",
		Summary: fmt.Sprintf("%d incident(s) found.", len(incidents)),
		Raw:     sb.String(),
	}, nil
}

// close marks an incident as resolved.
func (p *Plugin) close(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	id := strings.TrimSpace(args.Flags["incident-id"])
	if id == "" {
		return plugin.Report{}, fmt.Errorf("incident close: --incident-id is required")
	}

	inc, err := p.store.Get(ctx, id)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("incident close: %w", err)
	}

	now := time.Now().UTC()
	inc.Status = IncidentClosed
	inc.ClosedAt = &now

	if err := p.store.Update(ctx, inc); err != nil {
		return plugin.Report{}, fmt.Errorf("incident close: %w", err)
	}

	mttr := now.Sub(inc.OpenedAt)
	return plugin.Report{
		Title:   "Incident closed",
		Summary: fmt.Sprintf("Incident %s closed. MTTR: %s", inc.ID, formatDuration(mttr)),
		Findings: []plugin.Finding{
			{
				Severity: plugin.SeverityInfo,
				Category: "Incident",
				Title:    fmt.Sprintf("%s resolved", inc.ID),
				Detail:   fmt.Sprintf("Closed at %s. MTTR: %s.", now.Format(time.RFC3339), formatDuration(mttr)),
			},
		},
	}, nil
}

// postmortem generates an AI blameless postmortem for a closed incident.
func (p *Plugin) postmortem(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	id := strings.TrimSpace(args.Flags["incident-id"])
	if id == "" {
		return plugin.Report{}, fmt.Errorf("incident postmortem: --incident-id is required")
	}

	inc, err := p.store.Get(ctx, id)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("incident postmortem: %w", err)
	}

	pm, err := generatePostmortem(ctx, args.LLM, args.Redactor, inc)
	if err != nil {
		return plugin.Report{}, fmt.Errorf("incident postmortem: %w", err)
	}

	inc.Postmortem = &pm
	if err := p.store.Update(ctx, inc); err != nil {
		return plugin.Report{}, fmt.Errorf("incident postmortem: persist: %w", err)
	}

	findings := []plugin.Finding{
		{
			Severity: plugin.SeverityInfo,
			Category: "Postmortem",
			Title:    "Summary",
			Detail:   pm.Summary,
		},
	}
	if len(pm.RootCauses) > 0 {
		findings = append(findings, plugin.Finding{
			Severity: plugin.SeverityHigh,
			Category: "Postmortem",
			Title:    "Root Causes",
			Detail:   strings.Join(pm.RootCauses, "\n"),
		})
	}
	if len(pm.ActionItems) > 0 {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityMedium,
			Category:   "Postmortem",
			Title:      "Action Items",
			Detail:     strings.Join(pm.ActionItems, "\n"),
			Suggestion: "Assign owners and track in your task management system.",
		})
	}

	mttrStr := "N/A"
	if pm.MTTR > 0 {
		mttrStr = formatDuration(pm.MTTR)
	}

	return plugin.Report{
		Title:    fmt.Sprintf("Postmortem: %s", inc.ID),
		Summary:  fmt.Sprintf("Postmortem generated for %s. MTTR: %s", inc.ID, mttrStr),
		Findings: findings,
	}, nil
}

// incidentDuration returns the elapsed time for an incident as a human string.
func incidentDuration(inc Incident) string {
	end := time.Now().UTC()
	if inc.ClosedAt != nil {
		end = *inc.ClosedAt
	}
	return formatDuration(end.Sub(inc.OpenedAt))
}

// formatDuration renders a duration as "Xh Ym" or "Ym Zs" for readability.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < 0 {
		d = 0
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// escapeMarkdown replaces pipe characters in titles to avoid breaking tables.
func escapeMarkdown(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
