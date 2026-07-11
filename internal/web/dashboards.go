package web

// dashboards.go — the dashboard registry. Every dashboard the SPA can show
// is described by a DashboardDesc; the frontend builds its navigation and
// widget layout from this list instead of hardcoding pages. Built-ins cover
// the k8s findings dashboard and the platform pages (DORA, timeline,
// incidents); analyzer dashboards are registered per log-analyzer plugin.
//
// Widget tables live here rather than on the plugins because the mapping
// from widget ID to stats-struct field is a frontend contract — the plugin
// SDK (pkg/plugin, a zero-dependency module) stays untouched.

import (
	"encoding/json"
	"net/http"
	"sort"
)

// WidgetDesc describes one chart/panel a dashboard renders.
type WidgetDesc struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Kind selects the shared chart primitive: "timeline", "barlist",
	// "counters", "donut", or "table".
	Kind string `json:"kind"`
	// Drill marks widgets whose elements open the matching log lines.
	Drill bool `json:"drill,omitempty"`
}

// DashboardDesc is one registry entry, served at /api/dashboards and
// embedded in the dashboard payload's `dashboards` array.
type DashboardDesc struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Icon        string `json:"icon"` // key into the frontend icon set
	Description string `json:"description,omitempty"`
	// Category groups navigation: "platform" (k8s, dora, timeline,
	// incidents) or "analyzer" (log analyzers).
	Category            string `json:"category"`
	SupportsAI          bool   `json:"supportsAI"`
	SupportsTimeline    bool   `json:"supportsTimeline"`
	SupportsRemediation bool   `json:"supportsRemediation"`
	// Standalone dashboards render as navigation links to their own page
	// (/dora, /timeline) instead of an in-SPA view.
	Standalone bool `json:"standalone,omitempty"`
	// Live reports whether a data session/report is attached right now.
	Live    bool         `json:"live"`
	Widgets []WidgetDesc `json:"widgets,omitempty"`
}

// builtinDashboards returns the platform dashboards. hasK8s controls whether
// the k8s findings dashboard is present (false under `serve --no-k8s`).
func builtinDashboards(hasK8s bool) []DashboardDesc {
	var out []DashboardDesc
	if hasK8s {
		out = append(out, DashboardDesc{
			ID: "k8s", Name: "Kubernetes", Icon: "dashboard", Category: "platform",
			Description: "Cluster findings, health, and AI investigation",
			SupportsAI:  true, SupportsTimeline: true, SupportsRemediation: true,
			Live: true,
		})
	}
	out = append(out,
		DashboardDesc{
			ID: "dora", Name: "DORA Metrics", Icon: "dora", Category: "platform",
			Description: "Deployment frequency, lead time, CFR, MTTR",
			Standalone:  true, Live: true,
		},
		DashboardDesc{
			ID: "timeline", Name: "Timeline", Icon: "timeline", Category: "platform",
			Description:      "Cross-signal correlation timeline",
			SupportsTimeline: true, Standalone: true, Live: true,
		},
		DashboardDesc{
			ID: "incidents", Name: "Incidents", Icon: "alerts", Category: "platform",
			Description: "Open and recent incident records",
			Live:        true,
		},
	)
	return out
}

// analyzerWidgets maps each log analyzer to the widgets its stats struct
// supports today (data-backed only — no placeholders).
var analyzerWidgets = map[string][]WidgetDesc{
	"syslog": {
		{ID: "severityTimeline", Title: "Severity timeline", Kind: "timeline", Drill: true},
		{ID: "topUnits", Title: "Top units", Kind: "barlist", Drill: true},
		{ID: "topHosts", Title: "Top hosts", Kind: "barlist", Drill: true},
		{ID: "signals", Title: "Auth / OOM / disk signals", Kind: "counters", Drill: true},
	},
	"httplog": {
		{ID: "requestTimeline", Title: "Requests over time", Kind: "timeline", Drill: true},
		{ID: "codeHistogram", Title: "Status codes", Kind: "barlist", Drill: true},
		{ID: "topUris", Title: "Top URLs", Kind: "barlist", Drill: true},
		{ID: "topClients", Title: "Top clients", Kind: "barlist", Drill: true},
		{ID: "bursts5xx", Title: "5xx bursts", Kind: "timeline", Drill: true},
		{ID: "slowRequests", Title: "Slow requests", Kind: "counters", Drill: true},
	},
	"eventlog": {
		{ID: "levelTimeline", Title: "Event level timeline", Kind: "timeline", Drill: true},
		{ID: "topEventIds", Title: "Top event IDs", Kind: "barlist", Drill: true},
		{ID: "topProviders", Title: "Top providers", Kind: "barlist", Drill: true},
		{ID: "signals", Title: "Services / reboots / auth", Kind: "counters", Drill: true},
	},
	"iis": {
		{ID: "requestTimeline", Title: "Requests over time", Kind: "timeline", Drill: true},
		{ID: "codeHistogram", Title: "Status codes", Kind: "barlist", Drill: true},
		{ID: "topUris", Title: "Top URLs", Kind: "barlist", Drill: true},
		{ID: "topSites", Title: "Top sites", Kind: "barlist", Drill: true},
		{ID: "slowRequests", Title: "Slow requests", Kind: "counters", Drill: true},
	},
	"logs": {
		{ID: "errorTimeline", Title: "Error timeline", Kind: "timeline", Drill: true},
		{ID: "severityCounts", Title: "Severity mix", Kind: "barlist", Drill: true},
	},
}

// analyzerNames maps analyzer IDs to display metadata.
var analyzerNames = map[string][2]string{
	"syslog":   {"Linux Syslog", "System, kernel, auth, and service logs"},
	"httplog":  {"HTTP Logs", "Apache / Nginx access and error logs"},
	"eventlog": {"Windows Events", "Windows Event Log channels"},
	"iis":      {"IIS Logs", "IIS W3C site logs and app pools"},
	"logs":     {"App Logs", "Any application log via stdin or file"},
}

// analyzerDashboard builds the descriptor for one analyzer id.
func analyzerDashboard(id string) (DashboardDesc, bool) {
	widgets, ok := analyzerWidgets[id]
	if !ok {
		return DashboardDesc{}, false
	}
	meta := analyzerNames[id]
	return DashboardDesc{
		ID: id, Name: meta[0], Icon: "explorer", Category: "analyzer",
		Description: meta[1],
		SupportsAI:  true, SupportsTimeline: true,
		Widgets: widgets,
	}, true
}

// AnalyzerDashboards returns descriptors for the given analyzer IDs, in
// sorted order. Unknown IDs are skipped. Exported for cmd/exalm wiring.
func AnalyzerDashboards(ids []string) []DashboardDesc {
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	out := make([]DashboardDesc, 0, len(sorted))
	for _, id := range sorted {
		if d, ok := analyzerDashboard(id); ok {
			out = append(out, d)
		}
	}
	return out
}

// BuiltinDashboards exposes the platform descriptors for cmd/exalm wiring.
func BuiltinDashboards(hasK8s bool) []DashboardDesc { return builtinDashboards(hasK8s) }

// enabledDashboards filters the registry by the effective settings and
// stamps liveness from the session registry (when present).
func (s *liveServer) enabledDashboards() []DashboardDesc {
	if len(s.dashboards) == 0 {
		return nil
	}
	cur := s.currentSettings()
	out := make([]DashboardDesc, 0, len(s.dashboards))
	for _, d := range s.dashboards {
		if !cur.DashboardEnabled(d.ID) {
			continue
		}
		if !cur.SupportsAI {
			d.SupportsAI = false
		}
		// Hub mode: an analyzer dashboard is live when a session is attached.
		if s.sessions != nil && d.Category == "analyzer" {
			_, d.Live = s.sessions.Get(d.ID)
		}
		out = append(out, d)
	}
	// Safety net: a settings file that disabled every registered dashboard
	// would brick the UI — treat it as enable-all instead.
	if len(out) == 0 {
		out = append(out, s.dashboards...)
	}
	return out
}

// handleDashboardsJSON serves GET /api/dashboards.
func (s *liveServer) handleDashboardsJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	list := s.enabledDashboards()
	if list == nil {
		list = []DashboardDesc{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"dashboards": list}) //nolint:errcheck
}
