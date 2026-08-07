package investigate

// history.go answers "has this happened before?" from what Exalm already
// stores: prior conversations about the same focus, incident records (via a
// decoupled closure), and change frequency (via a closure so this package
// never imports internal/changestore). Moved from plugins/k8s.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/internal/convo"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// historyWindow is how far back the copilot looks for recurrence.
const historyWindow = 30 * 24 * time.Hour

// PastIncident is a decoupled view of one historical incident record.
type PastIncident struct {
	Title      string
	Namespace  string // scope (namespace/host/site) the incident concerned
	Service    string
	Status     string
	OpenedAt   time.Time
	Resolution string
}

// IncidentHistoryFn fetches incidents opened in [from, to].
type IncidentHistoryFn func(ctx context.Context, from, to time.Time) ([]PastIncident, error)

// ChangeSummary is one recorded change to the focus resource.
type ChangeSummary struct {
	Kind      string
	Name      string
	Action    string
	Actor     string
	Timestamp time.Time
}

// ChangeFrequencyFn returns recent changes for a resource, newest first.
type ChangeFrequencyFn func(scope, name string, window time.Duration, now time.Time) []ChangeSummary

// HistorySources are the optional recurrence inputs wired at startup.
type HistorySources struct {
	Convo     convo.Store
	Incidents IncidentHistoryFn
	Changes   ChangeFrequencyFn
}

// HistoryDeps carries what the history collector needs from the current turn.
type HistoryDeps struct {
	Sources     HistorySources
	SelfID      string // current conversation — excluded from "prior" matches
	Focus       string
	Fingerprint string
}

// GatherHistory assembles Kind:"history" evidence: prior investigations of
// the same focus (with their conclusions), matching incidents (with what
// fixed them), and change frequency for the resource. Exported so profiles
// can register it directly as their "history" collector.
func GatherHistory(ctx context.Context, h HistoryDeps, scope, name string, now time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	var evid []plugin.EvidenceItem

	// 1. Prior conversations about the same focus resource.
	if h.Sources.Convo != nil && h.Focus != "" {
		if prior, err := h.Sources.Convo.ListByFocus(ctx, h.Focus, scope); err == nil {
			var others []plugin.Conversation
			for _, c := range prior {
				if c.ID != h.SelfID && len(c.Messages) > 0 {
					others = append(others, c)
				}
			}
			if len(others) > 0 {
				latest := others[0] // ListByFocus is newest-first
				excerpt := fmt.Sprintf("this resource was investigated %d time(s) before; last on %s",
					len(others), latest.UpdatedAt.Format("2006-01-02 15:04"))
				if conclusion := lastAssistantLine(latest); conclusion != "" {
					excerpt += " — concluded: " + truncate(conclusion, 160)
				}
				if h.Fingerprint != "" && latest.Fingerprint == h.Fingerprint {
					excerpt += " (SAME symptom — a recurring incident, not a new one)"
				}
				evid = append(evid, plugin.EvidenceItem{
					Kind: "history", Source: "conversations/" + h.Focus, Edge: "resource→history",
					Excerpt: excerpt, At: latest.UpdatedAt,
				})
			}
		}
	}

	// 2. Incident records for the same scope/service.
	if h.Sources.Incidents != nil {
		if incidents, err := h.Sources.Incidents(ctx, now.Add(-historyWindow), now); err == nil {
			matches := 0
			var lastFix string
			var lastAt time.Time
			for _, inc := range incidents {
				if !incidentMatches(inc, scope, name) {
					continue
				}
				matches++
				if inc.Resolution != "" && inc.OpenedAt.After(lastAt) {
					lastFix, lastAt = inc.Resolution, inc.OpenedAt
				}
			}
			if matches > 0 {
				excerpt := fmt.Sprintf("%d incident(s) recorded for this service in the last 30 days", matches)
				if lastFix != "" {
					excerpt += " — last resolution: " + truncate(lastFix, 160)
				}
				evid = append(evid, plugin.EvidenceItem{
					Kind: "history", Source: "incidents/" + scope, Edge: "resource→history",
					Excerpt: excerpt, At: lastAt,
				})
			}
		}
	}

	// 3. Change frequency: how often has this resource changed recently?
	if h.Sources.Changes != nil && name != "" {
		if changes := h.Sources.Changes(scope, name, historyWindow, now); len(changes) > 0 {
			evid = append(evid, plugin.EvidenceItem{
				Kind: "history", Source: "changes/" + name, Edge: "resource→history",
				Excerpt: fmt.Sprintf("%d change(s) to this resource in the last 30 days — most recent %s ago",
					len(changes), humanAgo(now.Sub(changes[0].Timestamp))),
				At: changes[0].Timestamp,
			})
		}
	}

	if len(evid) == 0 {
		return []plugin.InvestigationStep{{Label: "Historical recurrence checked", Status: "done",
			Detail: "no prior investigations, incidents, or changes recorded for this resource"}}, nil
	}
	return []plugin.InvestigationStep{{Label: "Historical recurrence checked", Status: "done",
		Detail: fmt.Sprintf("%d historical signal(s) found", len(evid))}}, evid
}

// incidentMatches reports whether a past incident concerns the scope/name
// focus (service names rarely match instance names exactly — prefix matching
// covers "payment-api" vs pod "payment-api-7d8-xkp").
func incidentMatches(inc PastIncident, scope, name string) bool {
	if scope != "" && inc.Namespace != "" && inc.Namespace != scope {
		return false
	}
	if name == "" || inc.Service == "" {
		return inc.Namespace == scope && scope != ""
	}
	return strings.HasPrefix(name, inc.Service) || strings.HasPrefix(inc.Service, name)
}

// lastAssistantLine returns the first line of the most recent assistant
// message — the conversation's latest conclusion.
func lastAssistantLine(c plugin.Conversation) string {
	for i := len(c.Messages) - 1; i >= 0; i-- {
		if c.Messages[i].Role == "assistant" {
			line := strings.SplitN(strings.TrimSpace(c.Messages[i].Content), "\n", 2)[0]
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// truncate shortens s to at most n runes, appending "…" when cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// humanAgo renders a duration compactly ("3h", "2d").
func humanAgo(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
