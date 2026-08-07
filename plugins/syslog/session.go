package syslog

// session.go — structured event parsing for the in-memory investigation
// session. parseEvents is the structured sibling of parseSyslog in parser.go:
// parser.go produces the LLM-facing text summary (the byte-identical oracle
// covered by existing tests) while this file derives normalized
// investigate.LogEvent records from the same line formats. It reuses
// parseLine from parser.go for format detection; severity naming is
// duplicated here (sevName) because the session vocabulary uses "warn"
// where the LLM view uses "warning".

import (
	"os"
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
	}
}

// parseEvents derives structured LogEvents from a raw chunk. Unlike
// parseSyslog it keeps every priority level — the investigation corpus needs
// informational context lines, not just severe events.
func parseEvents(source int, chunk []byte) []investigate.LogEvent {
	lines := strings.Split(string(chunk), "\n")
	events := make([]investigate.LogEvent, 0, len(lines))
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		ev, ok := parseLine(line)
		if !ok {
			continue
		}
		events = append(events, investigate.LogEvent{
			At:       parseSyslogTime(ev.timestamp),
			Severity: sevName(ev.priority),
			Scope:    ev.host,
			Unit:     unitFromTag(ev.tag),
			Code:     "",
			Message:  ev.message,
			Raw:      line,
			Source:   source,
		})
	}
	return events
}

// unitFromTag strips the "[pid]" suffix from an RFC3164 tag. Journalctl
// units (already ending in ".service" etc.) pass through unchanged — we
// never invent a unit suffix.
func unitFromTag(tag string) string {
	if i := strings.IndexByte(tag, '['); i > 0 {
		return tag[:i]
	}
	return tag
}

// sevName maps a syslog priority to the normalized session severity
// vocabulary. Pairs with prioName in parser.go, which uses "warning" for the
// LLM view; the session uses "warn". Unknown priorities default to "info".
func sevName(p int) string {
	switch p {
	case 0:
		return "emerg"
	case 1:
		return "alert"
	case 2:
		return "crit"
	case 3:
		return "err"
	case 4:
		return "warn"
	case 5:
		return "notice"
	case 6:
		return "info"
	case 7:
		return "debug"
	default:
		return "info"
	}
}

// parseSyslogTime handles the three timestamp shapes parseLine emits:
// RFC5424 (RFC 3339), RFC3164/BSD ("Jan _2 15:04:05", no year — current year
// is assumed), and journalctl __REALTIME_TIMESTAMP (microseconds since
// epoch). Returns the zero time when unparseable.
func parseSyslogTime(ts string) time.Time {
	ts = strings.TrimSpace(ts)
	if ts == "" || ts == "-" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t
	}
	if t, err := time.Parse("Jan _2 15:04:05", ts); err == nil {
		return time.Date(time.Now().Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	}
	if n, err := strconv.ParseInt(ts, 10, 64); err == nil && n > 0 {
		return time.UnixMicro(n).UTC()
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

// SyslogStats is the dashboard stats payload for a syslog session.
type SyslogStats struct {
	SeverityTimeline []TimeBucket `json:"severityTimeline"`
	TopUnits         []NameCount  `json:"topUnits"`
	TopHosts         []NameCount  `json:"topHosts"`
	AuthFailures     int          `json:"authFailures"`
	OOMEvents        int          `json:"oomEvents"`
	DiskErrors       int          `json:"diskErrors"`
}

// severeRank orders session severities worst-first; -1 means "not severe".
func severeRank(sev string) int {
	switch sev {
	case "emerg":
		return 0
	case "alert":
		return 1
	case "crit":
		return 2
	case "err":
		return 3
	case "warn":
		return 4
	default:
		return -1
	}
}

// buildStats computes SyslogStats from the session corpus.
func buildStats(s *investigate.LogSession) SyslogStats {
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	var st SyslogStats
	unitHist := map[string]int{}
	hostHist := map[string]int{}
	minuteCount := map[string]int{}
	minuteWorst := map[string]int{}
	for _, e := range events {
		if e.Unit != "" {
			unitHist[e.Unit]++
		}
		if e.Scope != "" {
			hostHist[e.Scope]++
		}
		lower := strings.ToLower(e.Message)
		if strings.Contains(lower, "failed password") || strings.Contains(lower, "authentication failure") || strings.Contains(lower, "invalid user") {
			st.AuthFailures++
		}
		if strings.Contains(lower, "out of memory") || strings.Contains(lower, "oom-killer") || strings.Contains(lower, "oom_kill") {
			st.OOMEvents++
		}
		if strings.Contains(lower, "i/o error") || strings.Contains(lower, "disk error") || strings.Contains(lower, "read-only file system") || strings.Contains(lower, "no space left") {
			st.DiskErrors++
		}
		rank := severeRank(e.Severity)
		if rank < 0 || e.At.IsZero() {
			continue
		}
		bucket := e.At.Format("15:04")
		minuteCount[bucket]++
		if cur, ok := minuteWorst[bucket]; !ok || rank < cur {
			minuteWorst[bucket] = rank
		}
	}
	sevNames := []string{"emerg", "alert", "crit", "err", "warn"}
	for bucket, n := range minuteCount {
		st.SeverityTimeline = append(st.SeverityTimeline, TimeBucket{T: bucket, Count: n, Sev: sevNames[minuteWorst[bucket]]})
	}
	sort.Slice(st.SeverityTimeline, func(i, j int) bool { return st.SeverityTimeline[i].T < st.SeverityTimeline[j].T })
	st.TopUnits = topCounts(unitHist, 10)
	st.TopHosts = topCounts(hostHist, 10)
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
