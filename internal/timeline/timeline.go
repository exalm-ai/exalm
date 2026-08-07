// Package timeline aggregates the cross-signal correlation timeline served
// at /api/timeline: current findings, historical snapshot findings,
// incidents, and IaC changes, merged into one chronological event list.
// Transport-independent — takes a Report + snapshot history, returns Data.
//
// Extracted from internal/web/server.go's handleTimelineJSON as part of the
// platform service-layer consolidation: this is the reusable core a future
// TimelineService (CLI/REST/MCP) wraps, not a web-specific handler detail.
// It keeps handleTimelineJSON's existing behavior of opening the incident
// and change stores directly (the same pattern plugins/dora's
// ComputePublicMetrics already uses) rather than requiring every caller to
// inject them.
package timeline

import (
	"context"
	"fmt"
	"time"

	"github.com/exalm-ai/exalm/internal/changestore"
	"github.com/exalm-ai/exalm/pkg/plugin"
	incidentpkg "github.com/exalm-ai/exalm/plugins/incident"
)

// Event is a single coloured event on the cross-signal SVG timeline.
type Event struct {
	At       string `json:"at"` // ISO8601
	Label    string `json:"label"`
	Severity string `json:"severity"` // "critical","high","medium","low","info","iac"
	Source   string `json:"source"`   // "finding","iac","incident"
	Detail   string `json:"detail"`
}

// Data is the JSON payload served by /api/timeline.
type Data struct {
	StartISO string  `json:"start"` // earliest event ISO8601
	EndISO   string  `json:"end"`   // now ISO8601
	Events   []Event `json:"events"`
}

// Snapshot is a single historical report snapshot used to widen the
// timeline window and contribute past findings.
type Snapshot struct {
	CollectedAt time.Time
	Report      plugin.Report
}

// findingSeverity folds IaC-sourced findings into the "iac" lane so they
// render distinctly from ordinary severity-ranked findings.
func findingSeverity(f plugin.Finding) string {
	if f.Category == "IaC" || f.Source == "iac" {
		return "iac"
	}
	return string(f.Severity)
}

// Aggregate merges the four timeline sources — current report findings,
// snapshot-history findings, incidents, and IaC changes — into one
// chronological Data payload spanning at least the last 7 days (widened to
// the oldest snapshot when history reaches further back).
func Aggregate(ctx context.Context, report plugin.Report, snapshots []Snapshot, now time.Time) Data {
	start := now.Add(-7 * 24 * time.Hour)
	var events []Event

	// ── 1. Findings from the current report ──
	for _, f := range report.Findings {
		events = append(events, Event{
			At: now.Format(time.RFC3339), Label: f.Title,
			Severity: findingSeverity(f), Source: "finding", Detail: f.Detail,
		})
	}

	// ── 2. Findings from snapshot history ──
	for _, snap := range snapshots {
		ts := snap.CollectedAt
		if ts.Before(start) {
			start = ts
		}
		for _, f := range snap.Report.Findings {
			events = append(events, Event{
				At: ts.Format(time.RFC3339), Label: f.Title,
				Severity: findingSeverity(f), Source: "finding", Detail: f.Detail,
			})
		}
	}

	// ── 3. Incidents from the incident store ──
	store := incidentpkg.NewFileStore()
	if incidents, err := store.QueryByDateRange(ctx, start, now); err == nil {
		for _, inc := range incidents {
			sev := string(inc.Severity)
			if sev == "" {
				sev = "info"
			}
			events = append(events, Event{
				At:       inc.OpenedAt.Format(time.RFC3339),
				Label:    fmt.Sprintf("[%s] %s", inc.ID, inc.Title),
				Severity: sev, Source: "incident",
				Detail: fmt.Sprintf("Status: %s | Opened: %s", inc.Status, inc.OpenedAt.Format(time.RFC3339)),
			})
		}
	}

	// ── 4. IaC changes from the changestore ──
	if cs, err := changestore.Open(""); err == nil {
		if changes, err := cs.All(start); err == nil {
			for _, c := range changes {
				events = append(events, Event{
					At:       c.Timestamp.Format(time.RFC3339),
					Label:    fmt.Sprintf("%s %s/%s", c.Kind, c.Namespace, c.Name),
					Severity: "iac", Source: "iac",
					Detail: fmt.Sprintf("Action: %s | Actor: %s", c.Action, c.Actor),
				})
			}
		}
	}

	data := Data{StartISO: start.Format(time.RFC3339), EndISO: now.Format(time.RFC3339), Events: events}
	if data.Events == nil {
		data.Events = []Event{}
	}
	return data
}
