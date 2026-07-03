package k8s

// history.go answers "has this happened before?" from what Exalm already
// stores: prior conversations about the same focus resource, incident records
// (via a decoupled closure so plugins/k8s never imports plugins/incident),
// and change-frequency over the last 30 days. Fingerprint matching surfaces
// "similar past incident + what fixed it".

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

// PastIncident is a decoupled view of one historical incident record —
// populated by cmd/exalm/main.go from the incident store so plugins stay
// independent of each other.
type PastIncident struct {
	Title      string
	Namespace  string
	Service    string
	Status     string
	OpenedAt   time.Time
	Resolution string // postmortem action items / mitigation, when recorded
}

// IncidentHistoryFn fetches incidents opened in [from, to].
type IncidentHistoryFn func(ctx context.Context, from, to time.Time) ([]PastIncident, error)

// SetHistorySources wires the optional historical sources into the copilot.
// Safe to call once at startup; nil disables incident history gracefully.
func (p *Plugin) SetHistorySources(incidents IncidentHistoryFn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.incidentHistory = incidents
}

// historyDeps carries what gatherHistory needs from the current turn.
type historyDeps struct {
	convoStore  convo.Store
	incidents   IncidentHistoryFn
	selfID      string // current conversation — excluded from "prior" matches
	focus       string
	fingerprint string
}

// gatherHistory assembles Kind:"history" evidence: prior investigations of
// the same focus (with their conclusions), matching incidents (with what
// fixed them), and change frequency for the resource.
func gatherHistory(ctx context.Context, h historyDeps, ns, name string, now time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	var evid []plugin.EvidenceItem

	// 1. Prior conversations about the same focus resource.
	if h.convoStore != nil && h.focus != "" {
		if prior, err := h.convoStore.ListByFocus(ctx, h.focus, ns); err == nil {
			var others []plugin.Conversation
			for _, c := range prior {
				if c.ID != h.selfID && len(c.Messages) > 0 {
					others = append(others, c)
				}
			}
			if len(others) > 0 {
				latest := others[0] // ListByFocus is newest-first
				excerpt := fmt.Sprintf("this resource was investigated %d time(s) before; last on %s",
					len(others), latest.UpdatedAt.Format("2006-01-02 15:04"))
				if conclusion := lastAssistantLine(latest); conclusion != "" {
					excerpt += " — concluded: " + truncateString(conclusion, 160)
				}
				if h.fingerprint != "" && latest.Fingerprint == h.fingerprint {
					excerpt += " (SAME symptom — a recurring incident, not a new one)"
				}
				evid = append(evid, plugin.EvidenceItem{
					Kind: "history", Source: "conversations/" + h.focus, Edge: "resource→history",
					Excerpt: excerpt, At: latest.UpdatedAt,
				})
			}
		}
	}

	// 2. Incident records for the same namespace/service.
	if h.incidents != nil {
		if incidents, err := h.incidents(ctx, now.Add(-historyWindow), now); err == nil {
			matches := 0
			var lastFix string
			var lastAt time.Time
			for _, inc := range incidents {
				if !incidentMatches(inc, ns, name) {
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
					excerpt += " — last resolution: " + truncateString(lastFix, 160)
				}
				evid = append(evid, plugin.EvidenceItem{
					Kind: "history", Source: "incidents/" + ns, Edge: "resource→history",
					Excerpt: excerpt, At: lastAt,
				})
			}
		}
	}

	// 3. Change frequency: how often has this resource changed recently?
	if cstore := defaultStore(); cstore != nil && name != "" {
		if changes, err := cstore.RecentForResource(ns, name, correlationKinds, historyWindow, now); err == nil && len(changes) > 0 {
			evid = append(evid, plugin.EvidenceItem{
				Kind: "history", Source: "changes/" + name, Edge: "resource→history",
				Excerpt: fmt.Sprintf("%d change(s) to this resource in the last 30 days — most recent %s ago",
					len(changes), humanizeAge(changes[0].Timestamp, now)),
				At: changes[0].Timestamp,
			})
		}
	}

	if len(evid) == 0 {
		return []plugin.InvestigationStep{step("Historical recurrence checked", "done", "no prior investigations, incidents, or changes recorded for this resource", "")}, nil
	}
	return []plugin.InvestigationStep{step("Historical recurrence checked", "done", fmt.Sprintf("%d historical signal(s) found", len(evid)), "")}, evid
}

// incidentMatches reports whether a past incident concerns the ns/name focus
// (service names rarely match pod names exactly — prefix matching covers
// "payment-api" vs pod "payment-api-7d8-xkp").
func incidentMatches(inc PastIncident, ns, name string) bool {
	if ns != "" && inc.Namespace != "" && inc.Namespace != ns {
		return false
	}
	if name == "" || inc.Service == "" {
		return inc.Namespace == ns && ns != ""
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
