package iis

// session.go — structured event parsing for the in-memory investigation
// session. parseEvents is the structured sibling of parseW3C in parser.go:
// parser.go produces the LLM-facing text summary (the byte-identical oracle
// covered by existing tests) while this file derives normalized
// investigate.LogEvent records from the same W3C lines, honoring #Fields:
// headers the same way (fields can change mid-file when IIS rolls config).

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// InvestigationSession returns the session built by the most recent
// successful analyze run, or nil before the first analysis.
func (p *Plugin) InvestigationSession() *investigate.LogSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastSession
}

func (p *Plugin) setSession(s *investigate.LogSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastSession = s
}

// sessionRemoteParams builds the SSH params for --host runs; nil otherwise.
func sessionRemoteParams(args plugin.RunArgs, logDir string) *investigate.RemoteParams {
	host := args.Flags["host"]
	if host == "" {
		return nil
	}
	port := 0
	if n, err := strconv.Atoi(args.Flags["ssh-port"]); err == nil {
		port = n
	}
	pw := os.Getenv("EXALM_SSH_PASSWORD")
	if pw == "" {
		pw = args.Flags["ssh-password"]
	}
	return &investigate.RemoteParams{
		Host:     host,
		User:     args.Flags["ssh-user"],
		KeyPath:  args.Flags["ssh-key"],
		Port:     port,
		Password: pw,
		OSFamily: "windows",
		LogDir:   logDir,
	}
}

// latencyMsRe extracts the "(NNNms)" suffix parseEvents appends to request
// messages, so buildStats can count slow requests from the corpus alone.
var latencyMsRe = regexp.MustCompile(`\((\d+)ms\)$`)

// parseEvents derives structured LogEvents from a raw chunk of W3C lines,
// honoring the #Fields: header like parseW3C does. Unlike parseW3C it keeps
// every request — the corpus needs 2xx context, not just failures. W3C
// date/time fields are UTC per the spec.
func parseEvents(source int, chunk []byte) []investigate.LogEvent {
	lines := strings.Split(string(chunk), "\n")
	var fields []string
	events := make([]investigate.LogEvent, 0, len(lines))
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#Fields:") {
				fields = strings.Fields(strings.TrimPrefix(line, "#Fields:"))
			}
			continue
		}
		parts := strings.Fields(line)
		if len(fields) == 0 || len(parts) < len(fields) {
			continue
		}
		rec := map[string]string{}
		for i, f := range fields {
			rec[f] = parts[i]
		}
		status := rec["sc-status"]
		uri := rec["cs-uri-stem"]
		msg := fmt.Sprintf("%s %s → %s", rec["cs-method"], uri, status)
		if ms, err := strconv.Atoi(rec["time-taken"]); err == nil {
			msg += fmt.Sprintf(" (%dms)", ms)
		}
		var at time.Time
		if rec["date"] != "" && rec["time"] != "" {
			at, _ = time.Parse("2006-01-02 15:04:05", rec["date"]+" "+rec["time"])
		}
		events = append(events, investigate.LogEvent{
			At:       at,
			Severity: statusClass(status),
			Scope:    rec["s-sitename"],
			Unit:     firstPathSegment(uri),
			Code:     status,
			Message:  msg,
			Raw:      line,
			Source:   source,
		})
	}
	return events
}

// statusClass normalizes a 3-digit HTTP status to its class ("2xx".."5xx");
// anything else passes through raw.
func statusClass(status string) string {
	if len(status) == 3 && status[0] >= '1' && status[0] <= '5' {
		return status[:1] + "xx"
	}
	return status
}

// firstPathSegment maps "/api/users/1" to "/api" and "/" to "/".
func firstPathSegment(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	uri = strings.TrimPrefix(uri, "/")
	if i := strings.IndexByte(uri, '/'); i >= 0 {
		uri = uri[:i]
	}
	return "/" + uri
}

// NameCount is one named counter in the stats payload.
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// TimeBucket is one per-minute ("15:04") bucket in a stats timeline.
// TimeBucket is the shared timeline bucket. Aliased rather than redeclared:
// all six analyzers had byte-identical copies, and the chart drilldown needs
// the bucket instant that the local copies did not carry.
type TimeBucket = investigate.TimeBucket

// IISStats is the dashboard stats payload for an IIS session.
type IISStats struct {
	RequestTimeline []TimeBucket `json:"requestTimeline"`
	CodeHistogram   []NameCount  `json:"codeHistogram"`
	SlowRequests    int          `json:"slowRequests"`
	TopURIs         []NameCount  `json:"topUris"`
	TopSites        []NameCount  `json:"topSites"`
}

// slowRequestMs is the latency threshold counted as slow. Pairs with slowMs
// in parser.go (unexported const inside parseW3C).
const slowRequestMs = 5000

// buildStats computes IISStats from the session corpus.
func buildStats(s *investigate.LogSession) IISStats {
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	var st IISStats
	codeHist := map[string]int{}
	uriHist := map[string]int{}
	siteHist := map[string]int{}
	perMinute := map[time.Time]int{}
	for _, e := range events {
		if e.Code != "" {
			codeHist[e.Code]++
		}
		if fields := strings.Fields(e.Message); len(fields) >= 2 {
			uriHist[fields[1]]++
		}
		if e.Scope != "" {
			siteHist[e.Scope]++
		}
		if m := latencyMsRe.FindStringSubmatch(e.Message); m != nil {
			if ms, err := strconv.Atoi(m[1]); err == nil && ms >= slowRequestMs {
				st.SlowRequests++
			}
		}
		if !e.At.IsZero() {
			perMinute[investigate.BucketMinute(e.At)]++
		}
	}
	for t, n := range perMinute {
		st.RequestTimeline = append(st.RequestTimeline, TimeBucket{T: t.Format("15:04"), At: t, Width: time.Minute, Count: n})
	}
	sort.Slice(st.RequestTimeline, func(i, j int) bool { return st.RequestTimeline[i].At.Before(st.RequestTimeline[j].At) })
	st.CodeHistogram = topCounts(codeHist, 10)
	st.TopURIs = topCounts(uriHist, 10)
	st.TopSites = topCounts(siteHist, 10)
	return st
}

// topCounts returns the top-n counters, sorted by count desc then name asc.
func topCounts(m map[string]int, n int) []NameCount {
	out := make([]NameCount, 0, len(m))
	for k, v := range m {
		out = append(out, NameCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
