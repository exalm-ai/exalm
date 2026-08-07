package web

// dashroutes.go — per-dashboard scoped API routes:
//
//	GET  /api/dashboards/{id}/stats
//	GET  /api/dashboards/{id}/logs
//	POST /api/dashboards/{id}/chat
//	POST /api/dashboards/{id}/logs/analyze
//	POST /api/dashboards/incidents/action
//
// The legacy unscoped aliases (/api/analyzer/stats, /api/analyzer/logs,
// /api/chat) keep working unchanged. Until the multi-session hub lands,
// scoped routes resolve against the single wired analyzer session (or the
// k8s conversation engine for id "k8s"); a disabled dashboard 404s and a
// known-but-unattached dashboard 503s.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// dashKnown reports whether the id exists in the (unfiltered) registry.
// With no registry (legacy mode) any id matching the wired analyzer counts.
func (s *liveServer) dashKnown(id string) bool {
	for _, d := range s.dashboards {
		if d.ID == id {
			return true
		}
	}
	return len(s.dashboards) == 0 && (id == s.analyzer || (id == "k8s" && s.analyzer == ""))
}

// dashEnabled reports whether the id survives the settings filter.
func (s *liveServer) dashEnabled(id string) bool {
	if len(s.dashboards) == 0 {
		return true
	}
	for _, d := range s.enabledDashboards() {
		if d.ID == id {
			return true
		}
	}
	return false
}

// gateDashboard writes the appropriate error for an unusable dashboard id
// and reports whether the caller should return. 404 for unknown/disabled.
func (s *liveServer) gateDashboard(w http.ResponseWriter, id string) bool {
	if id == "" || !s.dashKnown(id) || !s.dashEnabled(id) {
		http.Error(w, "unknown or disabled dashboard", http.StatusNotFound)
		return false
	}
	return true
}

// dashSession resolves the live session for a dashboard id: the hub's
// session registry first, then the legacy single-session fields.
func (s *liveServer) dashSession(id string) (*DashSession, bool) {
	if s.sessions != nil {
		if ds, ok := s.sessions.Get(id); ok {
			return ds, true
		}
	}
	return nil, false
}

// handleDashStats serves GET /api/dashboards/{id}/stats.
func (s *liveServer) handleDashStats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.gateDashboard(w, id) {
		return
	}
	if id == "incidents" {
		if s.incidentsFn == nil {
			http.Error(w, "incidents store not wired", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"analyzer": "incidents", "stats": s.incidentsFn()}) //nolint:errcheck
		return
	}
	if ds, ok := s.dashSession(id); ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"analyzer": id, "stats": ds.Stats}) //nolint:errcheck
		return
	}
	if id != s.analyzer || s.analyzerStatsFn == nil {
		http.Error(w, "no session attached to this dashboard", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"analyzer": id, "stats": s.analyzerStatsFn()}) //nolint:errcheck
}

// handleDashLogs serves GET /api/dashboards/{id}/logs.
func (s *liveServer) handleDashLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.gateDashboard(w, id) {
		return
	}
	if ds, ok := s.dashSession(id); ok && ds.Handlers.LogQuery != nil {
		s.serveLogQuery(w, r, ds.Handlers.LogQuery)
		return
	}
	if id != s.analyzer || s.logQueryFn == nil {
		http.Error(w, "no session attached to this dashboard", http.StatusServiceUnavailable)
		return
	}
	s.serveLogQuery(w, r, s.logQueryFn)
}

// handleDashChat serves POST /api/dashboards/{id}/chat.
func (s *liveServer) handleDashChat(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.gateDashboard(w, id) {
		return
	}
	if !s.currentSettings().SupportsAI {
		http.Error(w, "AI features are disabled in settings", http.StatusServiceUnavailable)
		return
	}
	if ds, ok := s.dashSession(id); ok && ds.Handlers.Converse != nil {
		s.serveChat(w, r, ds.Handlers.Converse)
		return
	}
	// The k8s conversation engine and a legacy analyzer engine share
	// converseFn; only the dashboard the session belongs to may use it.
	if id != s.analyzer && !(id == "k8s" && s.analyzer == "") {
		http.Error(w, "no session attached to this dashboard", http.StatusServiceUnavailable)
		return
	}
	s.handleChat(w, r)
}

// handleDashLogAnalyze serves POST /api/dashboards/{id}/logs/analyze.
func (s *liveServer) handleDashLogAnalyze(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.gateDashboard(w, id) {
		return
	}
	if !s.currentSettings().SupportsAI {
		http.Error(w, "AI features are disabled in settings", http.StatusServiceUnavailable)
		return
	}
	if ds, ok := s.dashSession(id); ok && ds.Handlers.AnalyzeLine != nil {
		s.serveLogAnalyze(w, r, ds.Handlers.AnalyzeLine)
		return
	}
	if id != s.analyzer && !(id == "k8s" && s.analyzer == "") {
		http.Error(w, "no session attached to this dashboard", http.StatusServiceUnavailable)
		return
	}
	s.handleLogAnalyze(w, r)
}

// IncidentActionRequest is the body of POST /api/dashboards/incidents/action.
// Action selects the operation; the other fields are per-action inputs.
type IncidentActionRequest struct {
	Action    string `json:"action"`              // "open" | "close" | "reopen"
	ID        string `json:"id,omitempty"`        // close/reopen target
	Title     string `json:"title,omitempty"`     // open: required
	Severity  string `json:"severity,omitempty"`  // open: default "medium"
	Namespace string `json:"namespace,omitempty"` // open: optional scope
	Service   string `json:"service,omitempty"`   // open: optional scope
}

// handleIncidentAction serves POST /api/dashboards/incidents/action. The
// operation itself runs in the injected closure (cmd/exalm wires it to the
// incident store); this handler owns gating, decoding, and shape validation.
// CSRF protection comes from the server-wide requireCSRF middleware.
func (s *liveServer) handleIncidentAction(w http.ResponseWriter, r *http.Request) {
	if !s.gateDashboard(w, "incidents") {
		return
	}
	if s.incidentActFn == nil {
		http.Error(w, "incident actions not wired", http.StatusServiceUnavailable)
		return
	}
	var req IncidentActionRequest
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024) // titles and IDs are small
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	switch req.Action {
	case "open":
		if strings.TrimSpace(req.Title) == "" {
			http.Error(w, "title is required", http.StatusBadRequest)
			return
		}
	case "close", "reopen":
		if strings.TrimSpace(req.ID) == "" {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "unknown action (use open, close, or reopen)", http.StatusBadRequest)
		return
	}
	res, err := s.incidentActFn(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "incident": res}) //nolint:errcheck
}

// serveLogQuery parses the drilldown query parameters and writes the result.
// Shared by the legacy /api/analyzer/logs handler and the scoped route.
func (s *liveServer) serveLogQuery(w http.ResponseWriter, r *http.Request, fn func(ctx context.Context, req LogQueryRequest) (LogQueryResponse, error)) {
	q := r.URL.Query()
	req := LogQueryRequest{
		Severity:  q.Get("severity"),
		Unit:      q.Get("unit"),
		Scope:     q.Get("scope"),
		Code:      q.Get("code"),
		Contains:  q.Get("contains"),
		AroundIdx: -1,
	}
	// around accepts a corpus index (preferred, exact) or an RFC3339
	// timestamp (fallback when indices were invalidated by a re-ingest).
	if v := q.Get("around"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			req.AroundIdx = n
		} else if ts, err := time.Parse(time.RFC3339, v); err == nil {
			req.AroundTime = ts
		}
	}
	if v := q.Get("context"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			req.Context = n
		}
	}
	if v := q.Get("from"); v != "" {
		if ts, err := time.Parse(time.RFC3339, v); err == nil {
			req.From = ts
		}
	}
	if v := q.Get("to"); v != "" {
		if ts, err := time.Parse(time.RFC3339, v); err == nil {
			req.To = ts
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			req.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			req.Offset = n
		}
	}
	resp, err := fn(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}
