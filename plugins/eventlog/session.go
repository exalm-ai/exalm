package eventlog

// session.go — structured event parsing for the in-memory investigation
// session. parseSessionEvents is the structured sibling of parseEvents in
// parser.go (which owns that name for the LLM-facing text summary — the
// byte-identical oracle covered by existing tests). This parser decodes the
// same Get-WinEvent | ConvertTo-Json shapes (array, single object, or
// concatenated documents) into normalized investigate.LogEvent records,
// skipping anything unparseable rather than erroring.

import (
	"bytes"
	"encoding/json"
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

// sessionRemoteParams builds the SSH params for --host runs; nil otherwise.
func sessionRemoteParams(args plugin.RunArgs, logName string) *investigate.RemoteParams {
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
		LogName:  logName,
	}
}

// psDateRe matches the PowerShell JSON date form "/Date(1620900000000)/".
var psDateRe = regexp.MustCompile(`^/Date\((\d+)\)/$`)

// parseSessionEvents derives structured LogEvents from a chunk of
// Get-WinEvent JSON. Unlike parseEvents it keeps every level — the
// investigation corpus needs informational context, not just errors. It
// never returns an error: undecodable input yields no events.
func parseSessionEvents(source int, chunk []byte) []investigate.LogEvent {
	chunk = bytes.TrimSpace(chunk)
	if len(chunk) == 0 {
		return nil
	}
	var events []investigate.LogEvent
	dec := json.NewDecoder(bytes.NewReader(chunk))
	for {
		var v any
		if err := dec.Decode(&v); err != nil {
			break // stop at the first undecodable document
		}
		switch doc := v.(type) {
		case []any:
			for _, item := range doc {
				if rec, ok := item.(map[string]any); ok {
					if e, ok := recordToEvent(rec, source); ok {
						events = append(events, e)
					}
				}
			}
		case map[string]any:
			if e, ok := recordToEvent(doc, source); ok {
				events = append(events, e)
			}
		}
	}
	return events
}

// recordToEvent maps one decoded Get-WinEvent record to a LogEvent. Records
// without any recognizable field are skipped.
func recordToEvent(rec map[string]any, source int) (investigate.LogEvent, bool) {
	id, hasID := jsonInt(rec["Id"])
	provider, _ := rec["ProviderName"].(string)
	machine, _ := rec["MachineName"].(string)
	msg, _ := rec["Message"].(string)
	if !hasID && provider == "" && msg == "" {
		return investigate.LogEvent{}, false
	}
	severity, _ := rec["LevelDisplayName"].(string)
	if severity == "" {
		if lvl, ok := jsonInt(rec["Level"]); ok {
			severity = sessionLevelName(lvl)
		}
	}
	if severity == "" {
		severity = "Information"
	}
	code := ""
	if hasID {
		code = strconv.Itoa(id)
	}
	msg = strings.TrimSpace(msg)
	at := parseEventTime(rec["TimeCreated"])
	raw := fmt.Sprintf("%s | EventID=%s | Level=%s | Provider=%s | Host=%s | %s",
		at.Format(time.RFC3339), code, severity, provider, machine, firstLine(msg))
	return investigate.LogEvent{
		At:       at,
		Severity: severity,
		Scope:    machine,
		Unit:     provider,
		Code:     code,
		Message:  msg,
		Raw:      raw,
		Source:   source,
	}, true
}

// jsonInt coerces a decoded JSON number (or numeric string) to int.
func jsonInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case string:
		if i, err := strconv.Atoi(n); err == nil {
			return i, true
		}
	}
	return 0, false
}

// sessionLevelName maps a numeric Level to its display name. Pairs with
// levelName in parser.go but defaults to "Information" (the session never
// labels an event "Unknown").
func sessionLevelName(n int) string {
	switch n {
	case 1:
		return "Critical"
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 4:
		return "Information"
	default:
		return "Information"
	}
}

// parseEventTime handles both TimeCreated encodings ConvertTo-Json emits:
// "/Date(ms)/" and ISO strings (with or without zone). Zero when absent or
// unparseable.
func parseEventTime(v any) time.Time {
	s, ok := v.(string)
	if !ok || s == "" {
		return time.Time{}
	}
	if m := psDateRe.FindStringSubmatch(s); m != nil {
		if ms, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			return time.UnixMilli(ms).UTC()
		}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
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

// EventLogStats is the dashboard stats payload for an eventlog session.
type EventLogStats struct {
	LevelTimeline []TimeBucket `json:"levelTimeline"`
	TopEventIDs   []NameCount  `json:"topEventIds"`
	TopProviders  []NameCount  `json:"topProviders"`
	ServiceEvents int          `json:"serviceEvents"`
	Reboots       int          `json:"reboots"`
	AuthFailures  int          `json:"authFailures"`
}

// levelRank orders event levels worst-first for the timeline Sev marker.
func levelRank(sev string) int {
	switch sev {
	case "Critical":
		return 0
	case "Error":
		return 1
	case "Warning":
		return 2
	default:
		return 3
	}
}

// rebootEventIDs are the classic boot/shutdown event IDs (EventLog 6005/6006/
// 6008, User32 1074, Kernel-Power 41).
var rebootEventIDs = map[string]bool{"6005": true, "6006": true, "6008": true, "1074": true, "41": true}

// buildStats computes EventLogStats from the session corpus.
func buildStats(s *investigate.LogSession) EventLogStats {
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	var st EventLogStats
	idHist := map[string]int{}
	provHist := map[string]int{}
	minuteCount := map[time.Time]int{}
	minuteWorst := map[time.Time]int{}
	for _, e := range events {
		if e.Code != "" {
			idHist[e.Code]++
		}
		if e.Unit != "" {
			provHist[e.Unit]++
		}
		if e.Unit == "Service Control Manager" {
			st.ServiceEvents++
		}
		if rebootEventIDs[e.Code] {
			st.Reboots++
		}
		lower := strings.ToLower(e.Message)
		if e.Code == "4625" || strings.Contains(lower, "failed to log on") || strings.Contains(lower, "logon failure") {
			st.AuthFailures++
		}
		if e.At.IsZero() {
			continue
		}
		bucket := investigate.BucketMinute(e.At)
		minuteCount[bucket]++
		rank := levelRank(e.Severity)
		if cur, ok := minuteWorst[bucket]; !ok || rank < cur {
			minuteWorst[bucket] = rank
		}
	}
	levelNames := []string{"Critical", "Error", "Warning", "Information"}
	for bucket, n := range minuteCount {
		st.LevelTimeline = append(st.LevelTimeline, TimeBucket{T: bucket.Format("15:04"), At: bucket, Width: time.Minute, Count: n, Sev: levelNames[minuteWorst[bucket]]})
	}
	sort.Slice(st.LevelTimeline, func(i, j int) bool { return st.LevelTimeline[i].T < st.LevelTimeline[j].T })
	st.TopEventIDs = topCounts(idHist, 10)
	st.TopProviders = topCounts(provHist, 10)
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
