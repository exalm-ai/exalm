package main

// serve_investigate.go wires any log analyzer that exposes an investigation
// session + profile into the web dashboard — the same conversational
// copilot, chat persistence, per-line analysis, stats, and chart-to-log
// drilldown the Kubernetes dashboard has, with zero per-plugin web code.

import (
	"context"
	"strings"
	"time"

	convopkg "github.com/exalm-ai/exalm/internal/convo"
	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/internal/registry"
	"github.com/exalm-ai/exalm/internal/web"
	"github.com/exalm-ai/exalm/pkg/plugin"
	incidentplugin "github.com/exalm-ai/exalm/plugins/incident"
)

// investigable is satisfied structurally by every analyzer plugin that built
// an investigation session (syslog, httplog, eventlog, iis, logs).
type investigable interface {
	InvestigationSession() *investigate.LogSession
	InvestigationProfile() investigate.Profile
}

// dashboardRegistry builds the full dashboard descriptor list: platform
// built-ins plus one entry per registered analyzer plugin that can host an
// investigation. hasK8s controls the k8s findings dashboard entry.
func dashboardRegistry(hasK8s bool) []web.DashboardDesc {
	out := web.BuiltinDashboards(hasK8s)
	var analyzerIDs []string
	for _, p := range registry.All() {
		if _, ok := p.(investigable); ok {
			analyzerIDs = append(analyzerIDs, p.Name())
		}
	}
	return append(out, web.AnalyzerDashboards(analyzerIDs)...)
}

// incidentsStatsFn returns the incidents-dashboard stats provider: a
// read-only summary of the local incident store, newest first.
func incidentsStatsFn() func() any {
	store := incidentplugin.NewFileStore()
	return func() any {
		incidents, err := store.List(context.Background())
		if err != nil {
			return map[string]any{"error": "incident store unavailable"}
		}
		type row struct {
			ID       string `json:"id"`
			Title    string `json:"title"`
			Status   string `json:"status"`
			Severity string `json:"severity"`
			OpenedAt string `json:"openedAt"`
			Service  string `json:"service,omitempty"`
		}
		open := 0
		rows := make([]row, 0, len(incidents))
		for _, inc := range incidents {
			if string(inc.Status) == "open" {
				open++
			}
			rows = append(rows, row{
				ID: inc.ID, Title: inc.Title, Status: string(inc.Status),
				Severity: string(inc.Severity), OpenedAt: inc.OpenedAt.UTC().Format(time.RFC3339),
				Service: inc.Service,
			})
		}
		if len(rows) > 50 {
			rows = rows[:50]
		}
		return map[string]any{"open": open, "total": len(incidents), "incidents": rows}
	}
}

// incidentHistorySources builds the shared history sources (prior
// conversations + incident records) for an investigation engine.
func incidentHistorySources(convoStore convopkg.Store) investigate.HistorySources {
	incStore := incidentplugin.NewFileStore()
	return investigate.HistorySources{
		Convo: convoStore,
		Incidents: func(ctx context.Context, from, to time.Time) ([]investigate.PastIncident, error) {
			incidents, err := incStore.QueryByDateRange(ctx, from, to)
			if err != nil {
				return nil, err
			}
			out := make([]investigate.PastIncident, 0, len(incidents))
			for _, inc := range incidents {
				past := investigate.PastIncident{
					Title: inc.Title, Namespace: inc.Namespace, Service: inc.Service,
					Status: string(inc.Status), OpenedAt: inc.OpenedAt,
				}
				if pm := inc.Postmortem; pm != nil {
					past.Resolution = pm.Mitigation
					if past.Resolution == "" && len(pm.ActionItems) > 0 {
						past.Resolution = strings.Join(pm.ActionItems, "; ")
					}
				}
				out = append(out, past)
			}
			return out, nil
		},
	}
}

// buildAnalyzerHandlers constructs the per-session web closures (chat,
// conversation resume, line analysis, log query) for one analyzer session +
// engine. Shared by the legacy single-analyzer path and the hub's ingest.
func buildAnalyzerHandlers(session *investigate.LogSession, engine *investigate.Engine, llm plugin.LLMClient, red plugin.Redactor) web.SessionHandlers {
	convoStore := convopkg.NewStore()
	history := incidentHistorySources(convoStore)
	return web.SessionHandlers{
		Converse: func(ctx context.Context, req web.ConverseRequest) (*plugin.Conversation, error) {
			return engine.Converse(ctx, investigate.ConverseReq{
				ConvoID: req.ConversationID, AnchorID: req.FindingID,
				Scope: req.Namespace, Message: req.Message,
			}, investigate.Deps{
				LLM: llm, Red: red, Store: convoStore,
				Facts: session, History: history,
			})
		},
		GetConversation: func(ctx context.Context, id string) (*plugin.Conversation, error) {
			c, err := convoStore.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			return &c, nil
		},
		AnalyzeLine: func(ctx context.Context, req web.LogAnalyzeRequest) (string, error) {
			return engine.AnalyzeLine(ctx, investigate.LineRequest{
				Fields: []investigate.KV{
					{Key: "Analyzer", Value: session.Analyzer},
					{Key: "Scope", Value: req.Namespace},
					{Key: "Unit", Value: req.Pod},
					{Key: "Severity", Value: req.Severity},
					{Key: "Source", Value: req.Source},
				},
				Message: req.Message,
				Context: req.Context,
			}, llm, red)
		},
		LogQuery: func(_ context.Context, req web.LogQueryRequest) (web.LogQueryResponse, error) {
			events, total := session.Query(investigate.LogQuery{
				From: req.From, To: req.To,
				Severity: req.Severity, Unit: req.Unit, Scope: req.Scope,
				Code: req.Code, Contains: req.Contains,
				Limit: req.Limit, Offset: req.Offset,
			})
			out := web.LogQueryResponse{Total: total, Truncated: session.Truncated()}
			for _, e := range events {
				ev := web.LogQueryEvent{
					Severity: e.Severity, Scope: e.Scope, Unit: e.Unit,
					Code: e.Code, Message: e.Message, Raw: e.Raw,
				}
				if !e.At.IsZero() {
					ev.At = e.At.UTC().Format(time.RFC3339)
				}
				out.Events = append(out.Events, ev)
			}
			return out, nil
		},
	}
}

// applyAnalyzerServeOpts fills the investigation-related ServeOpts for an
// analyzer plugin. Returns false when the plugin has no session to serve.
func applyAnalyzerServeOpts(opts *web.ServeOpts, inv investigable, llm plugin.LLMClient, red plugin.Redactor) (bool, error) {
	session := inv.InvestigationSession()
	if session == nil {
		return false, nil
	}
	engine, err := investigate.NewEngine(inv.InvestigationProfile())
	if err != nil {
		return false, err
	}
	h := buildAnalyzerHandlers(session, engine, llm, red)
	opts.Analyzer = session.Analyzer
	opts.AnalyzerStats = func() any { return session.Stats }
	opts.Converse = h.Converse
	opts.GetConversation = h.GetConversation
	opts.AnalyzeLogLine = h.AnalyzeLine
	opts.LogQuery = h.LogQuery
	return true, nil
}
