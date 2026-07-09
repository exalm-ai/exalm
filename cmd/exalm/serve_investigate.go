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
	convoStore := convopkg.NewStore()
	incStore := incidentplugin.NewFileStore()
	history := investigate.HistorySources{
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

	opts.Analyzer = session.Analyzer
	opts.AnalyzerStats = func() any { return session.Stats }
	opts.Converse = func(ctx context.Context, req web.ConverseRequest) (*plugin.Conversation, error) {
		return engine.Converse(ctx, investigate.ConverseReq{
			ConvoID: req.ConversationID, AnchorID: req.FindingID,
			Scope: req.Namespace, Message: req.Message,
		}, investigate.Deps{
			LLM: llm, Red: red, Store: convoStore,
			Facts: session, History: history,
		})
	}
	opts.GetConversation = func(ctx context.Context, id string) (*plugin.Conversation, error) {
		c, err := convoStore.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		return &c, nil
	}
	opts.AnalyzeLogLine = func(ctx context.Context, req web.LogAnalyzeRequest) (string, error) {
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
	}
	opts.LogQuery = func(_ context.Context, req web.LogQueryRequest) (web.LogQueryResponse, error) {
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
	}
	return true, nil
}
