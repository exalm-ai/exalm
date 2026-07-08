package logs

// session.go — structured event parsing for the in-memory investigation
// session. The logs plugin has no format-specific parser (summarize sends
// the raw buffer to the LLM), so parseEvents is a best-effort generic line
// parser: an optional ISO / syslog-style timestamp prefix plus a severity
// token; everything else defaults to "info".

import (
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
)

// InvestigationSession returns the session built by the most recent
// successful summarize run, or nil before the first analysis.
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

// severityTokenRe finds the first conventional level token in a line.
var severityTokenRe = regexp.MustCompile(`(?i)\b(PANIC|FATAL|ERROR|WARNING|WARN|INFO|DEBUG)\b`)

// parseEvents derives structured LogEvents from generic log lines. Scope,
// Unit and Code are unknowable for arbitrary formats and stay empty.
func parseEvents(source int, chunk []byte) []investigate.LogEvent {
	lines := strings.Split(string(chunk), "\n")
	events := make([]investigate.LogEvent, 0, len(lines))
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		events = append(events, investigate.LogEvent{
			At:       parseGenericTime(line),
			Severity: severityToken(line),
			Message:  line,
			Raw:      line,
			Source:   source,
		})
	}
	return events
}

// severityToken maps the first level token in the line to the normalized
// vocabulary (panic|fatal|error|warn|info|debug); default "info".
func severityToken(line string) string {
	m := severityTokenRe.FindString(line)
	if m == "" {
		return "info"
	}
	sev := strings.ToLower(m)
	if sev == "warning" {
		sev = "warn"
	}
	return sev
}

// genericTimeLayouts are tried against the leading tokens of a line, most
// specific first. Syslog-style stamps carry no year — current year is
// assumed (see below).
var genericTimeLayouts = []struct {
	layout string
	tokens int // how many space-separated tokens the layout spans
	noYear bool
}{
	{time.RFC3339Nano, 1, false},
	{time.RFC3339, 1, false},
	{"2006-01-02T15:04:05", 1, false},
	{"2006-01-02 15:04:05.000", 2, false},
	{"2006-01-02 15:04:05,000", 2, false},
	{"2006-01-02 15:04:05", 2, false},
	{"2006/01/02 15:04:05", 2, false},
	{"Jan _2 15:04:05", 3, true},
}

// parseGenericTime best-effort parses a leading timestamp; zero when none.
func parseGenericTime(line string) time.Time {
	fields := strings.Fields(line)
	for _, cand := range genericTimeLayouts {
		if len(fields) < cand.tokens {
			continue
		}
		prefix := strings.Join(fields[:cand.tokens], " ")
		t, err := time.Parse(cand.layout, prefix)
		if err != nil {
			continue
		}
		if cand.noYear {
			return time.Date(time.Now().Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		}
		return t
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

// LogsStats is the dashboard stats payload for a generic logs session.
type LogsStats struct {
	ErrorTimeline  []TimeBucket `json:"errorTimeline"`
	SeverityCounts []NameCount  `json:"severityCounts"`
}

// errorRank orders error-class severities worst-first; -1 means "not an error".
func errorRank(sev string) int {
	switch sev {
	case "panic":
		return 0
	case "fatal":
		return 1
	case "error":
		return 2
	default:
		return -1
	}
}

// buildStats computes LogsStats from the session corpus.
func buildStats(s *investigate.LogSession) LogsStats {
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	var st LogsStats
	sevHist := map[string]int{}
	minuteCount := map[string]int{}
	minuteWorst := map[string]int{}
	for _, e := range events {
		sevHist[e.Severity]++
		rank := errorRank(e.Severity)
		if rank < 0 || e.At.IsZero() {
			continue
		}
		bucket := e.At.Format("15:04")
		minuteCount[bucket]++
		if cur, ok := minuteWorst[bucket]; !ok || rank < cur {
			minuteWorst[bucket] = rank
		}
	}
	errNames := []string{"panic", "fatal", "error"}
	for bucket, n := range minuteCount {
		st.ErrorTimeline = append(st.ErrorTimeline, TimeBucket{T: bucket, Count: n, Sev: errNames[minuteWorst[bucket]]})
	}
	sort.Slice(st.ErrorTimeline, func(i, j int) bool { return st.ErrorTimeline[i].T < st.ErrorTimeline[j].T })
	st.SeverityCounts = topCounts(sevHist, 10)
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
