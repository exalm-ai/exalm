package web

// analyzer.go — the web surface for log-analyzer investigation sessions:
// per-analyzer dashboard stats and the chart-to-log drilldown query. Both
// read-only over the in-memory session; both 503 when no analyzer session
// is wired (the k8s dashboard doesn't use them).

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// LogQueryRequest filters the analyzer session's parsed corpus. Zero values
// mean "no filter".
type LogQueryRequest struct {
	From     time.Time `json:"from,omitempty"`
	To       time.Time `json:"to,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Unit     string    `json:"unit,omitempty"`
	Scope    string    `json:"scope,omitempty"`
	Code     string    `json:"code,omitempty"`
	Contains string    `json:"contains,omitempty"`
	Limit    int       `json:"limit,omitempty"`
	Offset   int       `json:"offset,omitempty"`
}

// LogQueryEvent is one matched corpus event in the front-end shape.
type LogQueryEvent struct {
	At       string `json:"at,omitempty"` // RFC3339; "" when untimestamped
	Severity string `json:"severity,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Unit     string `json:"unit,omitempty"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	Raw      string `json:"raw"`
}

// LogQueryResponse carries one page of matches plus the honest total.
type LogQueryResponse struct {
	Events    []LogQueryEvent `json:"events"`
	Total     int             `json:"total"`
	Truncated int             `json:"truncated,omitempty"` // corpus events dropped to caps
}

// handleAnalyzerStats serves the analyzer-specific dashboard stats:
// GET /api/analyzer/stats.
func (s *liveServer) handleAnalyzerStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.analyzerStatsFn == nil {
		http.Error(w, "no analyzer session", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"analyzer": s.analyzer,
		"stats":    s.analyzerStatsFn(),
	})
}

// handleAnalyzerLogs serves the chart-to-log drilldown:
// GET /api/analyzer/logs?from=&to=&severity=&unit=&scope=&code=&contains=&limit=&offset=
func (s *liveServer) handleAnalyzerLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.logQueryFn == nil {
		http.Error(w, "no analyzer session", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	req := LogQueryRequest{
		Severity: q.Get("severity"),
		Unit:     q.Get("unit"),
		Scope:    q.Get("scope"),
		Code:     q.Get("code"),
		Contains: q.Get("contains"),
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
	resp, err := s.logQueryFn(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}
