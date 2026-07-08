package httplog

// session.go — structured event parsing for the in-memory investigation
// session. parseEvents is the structured sibling of parseHTTP in parser.go:
// parser.go produces the LLM-facing text summary (the byte-identical oracle
// covered by existing tests) while this file derives normalized
// investigate.LogEvent records from the same line formats, reusing the
// combinedRe / apacheErrRe / nginxErrRe regexes declared in parser.go.

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
func sessionRemoteParams(args plugin.RunArgs) *investigate.RemoteParams {
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
		OSFamily: "linux",
		LogPath:  args.Flags["log-path"],
	}
}

// accessTimeLayout matches the combined-log timestamp inside [...].
const accessTimeLayout = "02/Jan/2006:15:04:05 -0700"

// latencyMsRe extracts the "(NNNms)" suffix parseEvents appends to access
// messages, so buildStats can count slow requests from the corpus alone.
var latencyMsRe = regexp.MustCompile(`\((\d+)ms\)$`)

// parseEvents derives structured LogEvents from a raw chunk of access
// and/or error log lines. Unlike parseHTTP it keeps every request — the
// investigation corpus needs 2xx context, not just failures.
func parseEvents(source int, chunk []byte) []investigate.LogEvent {
	lines := strings.Split(string(chunk), "\n")
	events := make([]investigate.LogEvent, 0, len(lines))
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if m := combinedRe.FindStringSubmatch(line); m != nil {
			ts, method, uri, status := m[3], m[4], m[5], m[7]
			msg := fmt.Sprintf("%s %s → %s", method, uri, status)
			if rt := m[11]; rt != "" {
				if sec, err := strconv.ParseFloat(rt, 64); err == nil {
					msg += fmt.Sprintf(" (%.0fms)", sec*1000)
				}
			}
			at, _ := time.Parse(accessTimeLayout, ts)
			events = append(events, investigate.LogEvent{
				At:       at,
				Severity: statusClass(status),
				Scope:    "",
				Unit:     firstPathSegment(uri),
				Code:     status,
				Message:  msg,
				Raw:      line,
				Source:   source,
			})
			continue
		}
		if m := apacheErrRe.FindStringSubmatch(line); m != nil {
			events = append(events, investigate.LogEvent{
				At:       parseApacheErrTime(m[1]),
				Severity: strings.ToLower(m[2]),
				Message:  m[4],
				Raw:      line,
				Source:   source,
			})
			continue
		}
		if m := nginxErrRe.FindStringSubmatch(line); m != nil {
			at, _ := time.Parse("2006/01/02 15:04:05", m[1])
			events = append(events, investigate.LogEvent{
				At:       at,
				Severity: strings.ToLower(m[2]),
				Message:  m[3],
				Raw:      line,
				Source:   source,
			})
			continue
		}
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

// firstPathSegment maps "/api/users/1?x=1" to "/api" and "/" to "/".
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

// parseApacheErrTime handles both modern ("Wed Oct 11 14:32:52.123456 2023")
// and legacy ("Wed Oct 11 14:32:52 2023") apache error-log timestamps.
func parseApacheErrTime(ts string) time.Time {
	for _, layout := range []string{"Mon Jan 02 15:04:05.000000 2006", "Mon Jan _2 15:04:05.000000 2006", "Mon Jan 02 15:04:05 2006", "Mon Jan _2 15:04:05 2006"} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t
		}
	}
	return time.Time{}
}

// NameCount is one named counter in the stats payload.
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// TimeBucket is one per-minute ("15:04") bucket in a stats timeline.
type TimeBucket struct {
	T     string `json:"t"`
	Count int    `json:"count"`
	Sev   string `json:"sev,omitempty"`
}

// HTTPStats is the dashboard stats payload for an httplog session.
type HTTPStats struct {
	RequestTimeline []TimeBucket `json:"requestTimeline"`
	CodeHistogram   []NameCount  `json:"codeHistogram"`
	SlowRequests    int          `json:"slowRequests"`
	TopURIs         []NameCount  `json:"topUris"`
	TopClients      []NameCount  `json:"topClients"`
	Bursts5xx       []TimeBucket `json:"bursts5xx"`
}

// slowRequestMs is the latency threshold counted as slow. Pairs with slowMs
// in parser.go (unexported const inside parseHTTP).
const slowRequestMs = 5000

// buildStats computes HTTPStats from the session corpus.
func buildStats(s *investigate.LogSession) HTTPStats {
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	var st HTTPStats
	codeHist := map[string]int{}
	uriHist := map[string]int{}
	clientHist := map[string]int{}
	perMinute := map[string]int{}
	perMinute5xx := map[string]int{}
	for _, e := range events {
		if e.Code == "" {
			continue // error-log line, not an access record
		}
		codeHist[e.Code]++
		if fields := strings.Fields(e.Message); len(fields) >= 2 {
			uriHist[fields[1]]++
		}
		if m := combinedRe.FindStringSubmatch(e.Raw); m != nil && m[1] != "" {
			clientHist[m[1]]++
		}
		if m := latencyMsRe.FindStringSubmatch(e.Message); m != nil {
			if ms, err := strconv.Atoi(m[1]); err == nil && ms >= slowRequestMs {
				st.SlowRequests++
			}
		}
		if e.At.IsZero() {
			continue
		}
		bucket := e.At.Format("15:04")
		perMinute[bucket]++
		if e.Severity == "5xx" {
			perMinute5xx[bucket]++
		}
	}
	st.RequestTimeline = minuteTimeline(perMinute)
	st.CodeHistogram = topCounts(codeHist, 10)
	st.TopURIs = topCounts(uriHist, 10)
	st.TopClients = topCounts(clientHist, 10)
	st.Bursts5xx = burstBuckets(perMinute5xx, 10)
	return st
}

// minuteTimeline converts per-minute counts into a time-ordered timeline.
func minuteTimeline(m map[string]int) []TimeBucket {
	out := make([]TimeBucket, 0, len(m))
	for t, n := range m {
		out = append(out, TimeBucket{T: t, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out
}

// burstBuckets returns the n busiest minutes, worst first.
func burstBuckets(m map[string]int, n int) []TimeBucket {
	out := make([]TimeBucket, 0, len(m))
	for t, c := range m {
		out = append(out, TimeBucket{T: t, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].T < out[j].T
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
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
