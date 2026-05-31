// Package web serves an Exalm analysis report as a localhost HTML dashboard.
// Start it with Serve(); it blocks until ctx is cancelled (Ctrl+C).
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/exalm-ai/exalm/internal/changestore"
	"github.com/exalm-ai/exalm/pkg/plugin"
	dorapkg "github.com/exalm-ai/exalm/plugins/dora"
	incidentpkg "github.com/exalm-ai/exalm/plugins/incident"
)

//go:embed templates static
var assets embed.FS

// SnapshotEntry is a single historical report snapshot used to build the
// cross-signal correlation timeline.
type SnapshotEntry struct {
	CollectedAt time.Time
	Report      plugin.Report
}

// ServeOpts configures the web server.
type ServeOpts struct {
	Port        int    // defaults to 7433
	BindAddr    string // host/IP to bind on; defaults to "localhost" (safe default — do not expose to 0.0.0.0 without auth)
	OpenBrowser bool   // attempt to open the system browser on start

	// Token is the Bearer token required on every request.
	// When empty, the dashboard is served without authentication and a
	// warning is printed to stderr. Always set this in production.
	Token string

	// ApplyFix is called when the user clicks "Apply Fix" in the dashboard.
	// Nil means the fix button is not shown.
	ApplyFix func(ctx context.Context, action plugin.RemediationAction) error

	// CreatePR is called when the user clicks "Create PR" in the dashboard.
	// Returns the HTML URL of the created pull request. Nil means button not shown.
	CreatePR func(ctx context.Context, report plugin.Report) (string, error)

	// ReportUpdates delivers live report refreshes for watch mode.
	// Nil means the report is static (analyze mode).
	ReportUpdates <-chan plugin.Report

	// CollectedAt is the timestamp of the initial report collection.
	// Used as the anchor point for the cross-signal correlation timeline.
	CollectedAt time.Time

	// SnapshotHistory is an ordered list of historical report snapshots.
	// When non-nil, the timeline page renders findings across all snapshots.
	SnapshotHistory []SnapshotEntry
}

// RequireToken returns an HTTP middleware that enforces Bearer-token
// authentication on every request.
//
// If token is empty the original handler is returned unchanged.
// Clients may supply the token as:
//
//	Authorization: Bearer <token>
//	?token=<token>   (query parameter — convenient for opening links in browsers)
//
// The variadic publicPaths argument lists exact paths that bypass authentication
// (e.g. "/healthz", "/metrics").
func RequireToken(h http.Handler, token string, publicPaths ...string) http.Handler {
	if token == "" {
		return h
	}
	exempt := make(map[string]struct{}, len(publicPaths))
	for _, p := range publicPaths {
		exempt[p] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := exempt[r.URL.Path]; ok {
			h.ServeHTTP(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if got != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// requireToken is the dashboard-specific wrapper: /healthz and /metrics are
// always public so Kubernetes probes and Prometheus scraping work without auth.
func requireToken(h http.Handler, token string) http.Handler {
	return RequireToken(h, token, "/healthz", "/metrics")
}

// requireCSRF returns an HTTP middleware that rejects mutating requests (POST,
// PUT, DELETE) that do not carry the custom X-Exalm-Request: true header.
//
// Browsers cannot add custom headers to cross-origin requests without
// triggering a CORS preflight. A malicious webpage therefore cannot forge a
// valid POST to /api/fix or /api/fix-all — it would need to include
// X-Exalm-Request: true, but the server never responds with a permissive
// Access-Control-Allow-Origin header, so the browser blocks the preflight.
//
// Safe HTTP methods (GET, HEAD, OPTIONS) pass through unchanged.
// When the Origin header is present and does not reference localhost, the
// request is also rejected as a defence-in-depth measure.
func requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		// Mutating method: require the custom header.
		if r.Header.Get("X-Exalm-Request") != "true" {
			http.Error(w, "csrf: missing X-Exalm-Request header", http.StatusForbidden)
			return
		}
		// Defence-in-depth: when Origin is present it must reference localhost.
		if origin := r.Header.Get("Origin"); origin != "" {
			if !isLocalhostOrigin(origin) {
				http.Error(w, "csrf: origin not allowed", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isLocalhostOrigin reports whether an Origin header value refers to localhost.
// Accepts http://localhost[:port] and http://127.0.0.1[:port] (and the https
// variants for when TLS is terminated at the process level in future).
func isLocalhostOrigin(origin string) bool {
	return strings.HasPrefix(origin, "http://localhost") ||
		strings.HasPrefix(origin, "http://127.0.0.1") ||
		strings.HasPrefix(origin, "https://localhost") ||
		strings.HasPrefix(origin, "https://127.0.0.1")
}

// maxConcurrentFixes is the maximum number of /api/fix or /api/fix-all
// requests that may execute simultaneously. Each fix call proxies an LLM
// request; without this gate a single unauthenticated (or authenticated)
// client could pile up goroutines and exhaust the LLM API quota.
const maxConcurrentFixes = 3

// liveServer holds runtime state for a running dashboard.
type liveServer struct {
	mu              sync.RWMutex
	report          plugin.Report
	snapshotHistory []SnapshotEntry
	applyFix        func(ctx context.Context, action plugin.RemediationAction) error
	createPR        func(ctx context.Context, report plugin.Report) (string, error)
	tmpl            *template.Template
	startTime       time.Time
	reportCount     int64         // accessed atomically
	fixSem          chan struct{} // concurrency gate for /api/fix and /api/fix-all
}

func (s *liveServer) getReport() plugin.Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.report
}

func (s *liveServer) setReport(r plugin.Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.report = r
	atomic.AddInt64(&s.reportCount, 1)
}

// Serve starts an HTTP server on localhost and blocks until ctx is cancelled.
// It prints the URL to stderr immediately on binding.
func Serve(ctx context.Context, report plugin.Report, opts ServeOpts) error {
	if opts.Port == 0 {
		opts.Port = 7433
	}

	tmpl := template.Must(template.New("index.html").Funcs(template.FuncMap{
		"catIcon":         categoryIcon,
		"remediationJSON": remediationJSON,
		"sourceHost":      sourceHost,
		"sourcePlatform":  sourcePlatform,
	}).ParseFS(assets, "templates/index.html", "templates/timeline.html", "templates/dora.html"))

	srv := &liveServer{
		report:          report,
		snapshotHistory: opts.SnapshotHistory,
		applyFix:        opts.ApplyFix,
		createPR:        opts.CreatePR,
		tmpl:            tmpl,
		startTime:       time.Now(),
		fixSem:          make(chan struct{}, maxConcurrentFixes),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleDashboard)
	mux.HandleFunc("/timeline", srv.handleTimeline)
	mux.HandleFunc("/dora", srv.handleDORAPage)
	mux.HandleFunc("/api/report", srv.handleReportJSON)
	mux.HandleFunc("/api/fix", srv.handleFix)
	mux.HandleFunc("/api/fix-all", srv.handleFixAll)
	mux.HandleFunc("/api/create-pr", srv.handleCreatePR)
	mux.HandleFunc("/api/changes", srv.handleChangesJSON)
	mux.HandleFunc("/api/timeline", srv.handleTimelineJSON)
	mux.HandleFunc("/api/dora", srv.handleDORAJSON)
	mux.HandleFunc("/healthz", srv.handleHealthz)
	mux.HandleFunc("/metrics", srv.handleMetrics)

	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return fmt.Errorf("web: embed static: %w", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	bindHost := opts.BindAddr
	if bindHost == "" {
		bindHost = "localhost"
	}
	addr := fmt.Sprintf("%s:%d", bindHost, opts.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("web: bind %s: %w", addr, err)
	}

	// Warn when the dashboard is exposed beyond localhost without a token.
	if opts.Token == "" {
		fmt.Fprintln(os.Stderr, "  ⚠️  Dashboard is running WITHOUT authentication.")         //nolint:errcheck // startup warning to stderr
		fmt.Fprintln(os.Stderr, "     Set --token or EXALM_TOKEN to require a Bearer token.") //nolint:errcheck // startup warning to stderr
		fmt.Fprintln(os.Stderr, "     Do NOT expose this port outside localhost.")             //nolint:errcheck // startup warning to stderr
	} else if bindHost != "localhost" && bindHost != "127.0.0.1" {
		fmt.Fprintf(os.Stderr, "  ⚠️  Dashboard is bound to %s — ensure a token is set and TLS is terminated upstream.\n", bindHost) //nolint:errcheck // startup warning to stderr
	}

	displayAddr := fmt.Sprintf("localhost:%d", opts.Port) // always show as localhost in browser link
	if bindHost != "localhost" && bindHost != "127.0.0.1" {
		displayAddr = addr
	}
	url := fmt.Sprintf("http://%s", displayAddr)
	fmt.Fprintf(os.Stderr, "\n  ⬡ Exalm dashboard: %s\n  Press Ctrl+C to stop.\n\n", url) //nolint:errcheck // startup info to stderr

	if opts.OpenBrowser {
		openBrowser(url)
	}

	// Watch mode: consume report updates in background.
	if opts.ReportUpdates != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case r, ok := <-opts.ReportUpdates:
					if !ok {
						return
					}
					srv.setReport(r)
				}
			}
		}()
	}

	httpSrv := &http.Server{
		Handler:           requireToken(requireCSRF(mux), opts.Token),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() { //nolint:gosec // G118: context.Background is correct here — shutdown must outlive the request context
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	if err := httpSrv.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("web server: %w", err)
	}
	return nil
}

// templateData is injected into index.html.
type templateData struct {
	Title           string
	Summary         string
	RawEscaped      string // report.Raw with quotes escaped for data-raw attribute
	Findings        []plugin.Finding
	GroupedFindings map[string][]plugin.Finding
	Timestamp       string
	SeverityCounts  map[string]int
	CategoryCounts  map[string]int
	HasApplyFix     bool
	HasCreatePR     bool
	FixableCount    int
}

func buildTemplateData(r plugin.Report, hasApplyFix, hasCreatePR bool) templateData {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, f := range r.Findings {
		counts[string(f.Severity)]++
	}

	rawGroups := map[string][]plugin.Finding{}
	catCounts := map[string]int{}
	fixable := 0
	for _, f := range r.Findings {
		cat := f.Category
		if cat == "" {
			cat = "Other"
		}
		rawGroups[cat] = append(rawGroups[cat], f)
		catCounts[cat]++
		if f.Remediation != nil {
			fixable++
		}
	}

	escaped := strings.ReplaceAll(r.Raw, `"`, `&quot;`)
	escaped = strings.ReplaceAll(escaped, `'`, `&#39;`)

	return templateData{
		Title:           r.Title,
		Summary:         r.Summary,
		RawEscaped:      escaped,
		Findings:        r.Findings,
		GroupedFindings: rawGroups,
		Timestamp:       time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		SeverityCounts:  counts,
		CategoryCounts:  catCounts,
		HasApplyFix:     hasApplyFix,
		HasCreatePR:     hasCreatePR,
		FixableCount:    fixable,
	}
}

func (s *liveServer) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	report := s.getReport()
	data := buildTemplateData(report, s.applyFix != nil, s.createPR != nil)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *liveServer) handleReportJSON(w http.ResponseWriter, _ *http.Request) {
	report := s.getReport()
	payload, _ := json.Marshal(report)
	w.Header().Set("Content-Type", "application/json")
	w.Write(payload) //nolint:errcheck
}

// handleChangesJSON returns recent cluster change events for the
// Komodor-style change timeline. Reads directly from the default changestore;
// if the store is missing or empty, returns []. Bounded to ~500 events for
// payload sanity.
//
// Query param: since=1h|24h|7d (default: 24h)
func (s *liveServer) handleChangesJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	since := parseSinceDuration(r.URL.Query().Get("since"), 24*time.Hour)

	store, err := changestore.Open("")
	if err != nil {
		w.Write([]byte("[]")) //nolint:errcheck
		return
	}
	events, err := store.All(time.Now().Add(-since))
	if err != nil {
		w.Write([]byte("[]")) //nolint:errcheck
		return
	}
	if len(events) > 500 {
		events = events[len(events)-500:]
	}
	payload, _ := json.Marshal(events)
	w.Write(payload) //nolint:errcheck
}

// ── Timeline types ────────────────────────────────────────────────────────────

// TimelineEvent is a single coloured event on the cross-signal SVG timeline.
type TimelineEvent struct {
	At       string `json:"at"` // ISO8601
	Label    string `json:"label"`
	Severity string `json:"severity"` // "critical","high","medium","low","info","iac"
	Source   string `json:"source"`   // "finding","iac","incident"
	Detail   string `json:"detail"`
}

// TimelineData is the JSON payload served by /api/timeline.
type TimelineData struct {
	StartISO string          `json:"start"` // earliest event ISO8601
	EndISO   string          `json:"end"`   // now ISO8601
	Events   []TimelineEvent `json:"events"`
}

// handleTimeline renders the timeline.html template.
func (s *liveServer) handleTimeline(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := s.tmpl.Lookup("timeline.html")
	if tmpl == nil {
		http.Error(w, "timeline template not found", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleTimelineJSON builds and serves the TimelineData JSON payload.
func (s *liveServer) handleTimelineJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	now := time.Now().UTC()
	start := now.Add(-7 * 24 * time.Hour)

	var events []TimelineEvent

	// ── 1. Findings from the current report ──────────────────────────────────
	report := s.getReport()
	for _, f := range report.Findings {
		sev := string(f.Severity)
		if f.Category == "IaC" || f.Source == "iac" {
			sev = "iac"
		}
		ev := TimelineEvent{
			At:       now.Format(time.RFC3339),
			Label:    f.Title,
			Severity: sev,
			Source:   "finding",
			Detail:   f.Detail,
		}
		events = append(events, ev)
	}

	// ── 2. Findings from snapshot history ────────────────────────────────────
	s.mu.RLock()
	snapshots := s.snapshotHistory
	s.mu.RUnlock()
	for _, snap := range snapshots {
		ts := snap.CollectedAt
		if ts.Before(start) {
			start = ts
		}
		for _, f := range snap.Report.Findings {
			sev := string(f.Severity)
			if f.Category == "IaC" || f.Source == "iac" {
				sev = "iac"
			}
			ev := TimelineEvent{
				At:       ts.Format(time.RFC3339),
				Label:    f.Title,
				Severity: sev,
				Source:   "finding",
				Detail:   f.Detail,
			}
			events = append(events, ev)
		}
	}

	// ── 3. Incidents from the incident store ─────────────────────────────────
	store := incidentpkg.NewFileStore()
	incidents, err := store.QueryByDateRange(context.Background(), start, now)
	if err == nil {
		for _, inc := range incidents {
			sev := string(inc.Severity)
			if sev == "" {
				sev = "info"
			}
			label := fmt.Sprintf("[%s] %s", inc.ID, inc.Title)
			detail := fmt.Sprintf("Status: %s | Opened: %s", inc.Status, inc.OpenedAt.Format(time.RFC3339))
			events = append(events, TimelineEvent{
				At:       inc.OpenedAt.Format(time.RFC3339),
				Label:    label,
				Severity: sev,
				Source:   "incident",
				Detail:   detail,
			})
		}
	}

	// ── 4. IaC changes from the changestore ──────────────────────────────────
	cs, err := changestore.Open("")
	if err == nil {
		changes, err := cs.All(start)
		if err == nil {
			for _, c := range changes {
				events = append(events, TimelineEvent{
					At:       c.Timestamp.Format(time.RFC3339),
					Label:    fmt.Sprintf("%s %s/%s", c.Kind, c.Namespace, c.Name),
					Severity: "iac",
					Source:   "iac",
					Detail:   fmt.Sprintf("Action: %s | Actor: %s", c.Action, c.Actor),
				})
			}
		}
	}

	data := TimelineData{
		StartISO: start.Format(time.RFC3339),
		EndISO:   now.Format(time.RFC3339),
		Events:   events,
	}
	if data.Events == nil {
		data.Events = []TimelineEvent{}
	}
	payload, _ := json.Marshal(data)
	w.Write(payload) //nolint:errcheck
}

// ── DORA page handlers ────────────────────────────────────────────────────────

// handleDORAPage renders the dora.html template.
func (s *liveServer) handleDORAPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := s.tmpl.Lookup("dora.html")
	if tmpl == nil {
		http.Error(w, "dora template not found", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleDORAJSON computes DORA metrics and returns them as JSON.
func (s *liveServer) handleDORAJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	metrics, err := dorapkg.ComputePublicMetrics(30)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
		return
	}
	payload, _ := json.Marshal(metrics)
	w.Write(payload) //nolint:errcheck
}

// parseSinceDuration maps the ?since= query param to a time.Duration.
// Accepted values: "1h", "24h", "7d". Falls back to defaultDur for
// unrecognised or empty values.
func parseSinceDuration(s string, defaultDur time.Duration) time.Duration {
	switch s {
	case "1h":
		return 1 * time.Hour
	case "24h":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	default:
		return defaultDur
	}
}

// handleFix applies a RemediationAction sent as JSON in the POST body.
// At most maxConcurrentFixes requests execute simultaneously; excess requests
// receive 429 Too Many Requests immediately rather than queueing.
func (s *liveServer) handleFix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.applyFix == nil {
		http.Error(w, "fix not available", http.StatusServiceUnavailable)
		return
	}

	// Acquire a slot in the concurrency semaphore or reject immediately.
	select {
	case s.fixSem <- struct{}{}:
		defer func() { <-s.fixSem }()
	default:
		http.Error(w, "too many concurrent fix requests", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KB is ample for a RemediationAction
	var action plugin.RemediationAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.applyFix(r.Context(), action); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// handleCreatePR creates a GitHub PR with fix suggestions.
func (s *liveServer) handleCreatePR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.createPR == nil {
		http.Error(w, "GitHub PR not configured", http.StatusServiceUnavailable)
		return
	}

	report := s.getReport()
	url, err := s.createPR(r.Context(), report)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": url}) //nolint:errcheck
}

// categoryIcon maps a finding category to a display icon.
func categoryIcon(cat string) string {
	switch cat {
	case "Pods":
		return "⬡"
	case "Nodes", "Node":
		return "◈"
	case "Resources":
		return "📊"
	case "Security":
		return "🔒"
	case "Networking":
		return "🌐"
	case "Services":
		return "⚙"
	case "Workloads":
		return "⚙"
	case "Storage":
		return "💾"
	case "Scaling":
		return "↕"
	case "Jobs":
		return "⏱"
	case "SLO":
		return "📈"
	// Windows log categories
	case "EventLog":
		return "🪟"
	case "IIS":
		return "🌐"
	case "Auth":
		return "🔑"
	// Linux log categories
	case "Syslog":
		return "🐧"
	case "HTTPLog":
		return "🔗"
	case "System":
		return "💻"
	default:
		return "•"
	}
}

// sourceHost extracts the hostname portion of a finding source string.
// "eventlog/win-dc-01" → "win-dc-01", "k8s/prod-cluster" → "prod-cluster".
func sourceHost(source string) string {
	if source == "" {
		return ""
	}
	if i := strings.LastIndex(source, "/"); i >= 0 {
		return source[i+1:]
	}
	return source
}

// sourcePlatform returns a short platform key based on the source prefix.
// Used for platform badge CSS classes: "windows", "linux", "k8s", or "".
func sourcePlatform(source string) string {
	switch {
	case strings.HasPrefix(source, "eventlog/") || strings.HasPrefix(source, "iis/"):
		return "windows"
	case strings.HasPrefix(source, "syslog/") || strings.HasPrefix(source, "httplog/"):
		return "linux"
	case strings.HasPrefix(source, "k8s/"):
		return "k8s"
	default:
		return ""
	}
}

// remediationJSON serialises a RemediationAction pointer for use in an HTML
// data attribute (single-quoted). Returns template.HTMLAttr so Go's
// html/template does not double-escape the JSON's double-quotes.
func remediationJSON(r *plugin.RemediationAction) template.HTMLAttr {
	if r == nil {
		return "{}"
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "{}"
	}
	// Only single-quotes need escaping inside a single-quoted attribute.
	// json.Marshal already escapes <, >, & as \uXXXX so no further HTML
	// escaping is required.
	return template.HTMLAttr(strings.ReplaceAll(string(b), "'", "&#39;"))
}

// fixAllResult is one entry in the /api/fix-all response array.
type fixAllResult struct {
	Title string `json:"title"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// handleFixAll applies all remediable findings from the current report.
// Safe order: rollout-restart → resume-cronjob → delete-pod.
// Shares the same fixSem semaphore as handleFix — fix-all counts as one slot.
func (s *liveServer) handleFixAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.applyFix == nil {
		http.Error(w, "fix not available", http.StatusServiceUnavailable)
		return
	}

	select {
	case s.fixSem <- struct{}{}:
		defer func() { <-s.fixSem }()
	default:
		http.Error(w, "too many concurrent fix requests", http.StatusTooManyRequests)
		return
	}

	report := s.getReport()
	kindOrder := map[string]int{"rollout-restart": 0, "resume-cronjob": 1, "delete-pod": 2}
	order := func(k string) int {
		if v, ok := kindOrder[k]; ok {
			return v
		}
		return 99
	}

	type fixable struct {
		title  string
		action plugin.RemediationAction
	}
	var items []fixable
	for _, f := range report.Findings {
		if f.Remediation != nil {
			items = append(items, fixable{title: f.Title, action: *f.Remediation})
		}
	}
	// Sort by kind order (restarts before deletes).
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && order(items[j].action.Kind) < order(items[j-1].action.Kind); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}

	results := make([]fixAllResult, 0, len(items))
	for _, item := range items {
		res := fixAllResult{Title: item.title}
		if err := s.applyFix(r.Context(), item.action); err != nil {
			res.Error = err.Error()
		} else {
			res.OK = true
		}
		results = append(results, res)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results) //nolint:errcheck
}

// handleHealthz returns a simple JSON health check with uptime.
func (s *liveServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	uptime := int64(time.Since(s.startTime).Seconds()) //nolint:gosec // G115: uptime in seconds; truncation is intentional
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","uptime_seconds":%d}`, uptime) //nolint:errcheck // health response; client disconnect is harmless
}

// handleMetrics returns Prometheus text format metrics.
func (s *liveServer) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	uptime := time.Since(s.startTime).Seconds()
	refreshes := atomic.LoadInt64(&s.reportCount)
	report := s.getReport()
	findings := int64(len(report.Findings))     //nolint:gosec // G115: len() is always non-negative
	goroutines := int64(runtime.NumGoroutine()) //nolint:gosec // G115: NumGoroutine() is always non-negative

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	// Prometheus text-format writes to http.ResponseWriter; client disconnect errors are harmless.
	fmt.Fprintf(w, "# HELP exalm_uptime_seconds Seconds since the dashboard started.\n")                //nolint:errcheck
	fmt.Fprintf(w, "# TYPE exalm_uptime_seconds gauge\n")                                               //nolint:errcheck
	fmt.Fprintf(w, "exalm_uptime_seconds %g\n", uptime)                                                 //nolint:errcheck
	fmt.Fprintf(w, "# HELP exalm_findings_total Number of findings in the current report.\n")           //nolint:errcheck
	fmt.Fprintf(w, "# TYPE exalm_findings_total gauge\n")                                               //nolint:errcheck
	fmt.Fprintf(w, "exalm_findings_total %d\n", findings)                                               //nolint:errcheck
	fmt.Fprintf(w, "# HELP exalm_report_refreshes_total Total number of report refreshes delivered.\n") //nolint:errcheck
	fmt.Fprintf(w, "# TYPE exalm_report_refreshes_total counter\n")                                     //nolint:errcheck
	fmt.Fprintf(w, "exalm_report_refreshes_total %d\n", refreshes)                                      //nolint:errcheck
	fmt.Fprintf(w, "# HELP go_goroutines Number of goroutines.\n")                                      //nolint:errcheck
	fmt.Fprintf(w, "# TYPE go_goroutines gauge\n")                                                      //nolint:errcheck
	fmt.Fprintf(w, "go_goroutines %d\n", goroutines)                                                    //nolint:errcheck
}

// openBrowser attempts to open url in the system browser. Best-effort only.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url) //nolint:gosec // fixed args, url is user-provided flag
	case "darwin":
		cmd = exec.Command("open", url) //nolint:gosec // fixed command, url is user-provided flag
	default:
		cmd = exec.Command("xdg-open", url) //nolint:gosec // fixed command, url is user-provided flag
	}
	_ = cmd.Start()
}
