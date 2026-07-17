package cloudtrail

// session.go — structured event parsing for the in-memory investigation
// session. parseEvents is the structured sibling of parseCloudTrail in
// parser.go: parser.go produces the LLM-facing filtered summary while this
// file derives normalized investigate.LogEvent records from every record,
// including routine ones — the investigation corpus needs the full picture,
// not just what's worth showing the LLM.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
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

// severityFor classifies a record the way the dashboard/timeline expects:
// root usage is always critical regardless of outcome, an explicit AWS
// error/denial is "err", a destructive or privilege-escalation call that
// nonetheless succeeded is "warn", everything else is routine "info".
func severityFor(r *ctRecord) string {
	switch {
	case r.isRoot():
		return "crit"
	case r.ErrorCode != "":
		return "err"
	case deletionRe.MatchString(r.EventName), privEscRe.MatchString(r.EventName):
		return "warn"
	default:
		return "info"
	}
}

// parseEvents derives structured LogEvents from a raw NDJSON chunk. Lines
// that aren't valid JSON are skipped, never fail the chunk.
func parseEvents(source int, chunk []byte) []investigate.LogEvent {
	lines := strings.Split(string(chunk), "\n")
	events := make([]investigate.LogEvent, 0, len(lines))
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var r ctRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		msg := fmt.Sprintf("%s called %s from %s", r.principal(), r.EventName, r.SourceIPAddress)
		if r.ErrorCode != "" {
			msg += fmt.Sprintf(" — %s: %s", r.ErrorCode, r.ErrorMessage)
		}
		at, _ := time.Parse(time.RFC3339, r.EventTime)
		events = append(events, investigate.LogEvent{
			At:       at,
			Severity: severityFor(&r),
			Scope:    r.AWSRegion,
			Unit:     r.EventName,
			Code:     r.ErrorCode,
			Message:  msg,
			Raw:      line,
			Source:   source,
		})
	}
	return events
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

// CloudTrailStats is the dashboard stats payload for a cloudtrail session.
type CloudTrailStats struct {
	EventTimeline        []TimeBucket `json:"eventTimeline"`
	TopEventNames        []NameCount  `json:"topEventNames"`
	TopPrincipals        []NameCount  `json:"topPrincipals"`
	TopSourceIPs         []NameCount  `json:"topSourceIps"`
	AccessDenied         int          `json:"accessDenied"`
	RootUsage            int          `json:"rootUsage"`
	ConsoleLoginFailures int          `json:"consoleLoginFailures"`
	ResourceDeletions    int          `json:"resourceDeletions"`
}

// buildStats computes CloudTrailStats from the session corpus. Principal and
// source-IP histograms are re-derived from Raw at stats-build time — the
// same pattern plugins/httplog uses for TopClients/TopUserAgents — rather
// than adding AWS-specific fields to the generic LogEvent type.
func buildStats(s *investigate.LogSession) CloudTrailStats {
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	var st CloudTrailStats
	eventHist := map[string]int{}
	principalHist := map[string]int{}
	ipHist := map[string]int{}
	perMinute := map[string]int{}

	for _, e := range events {
		eventHist[e.Unit]++
		var r ctRecord
		if err := json.Unmarshal([]byte(e.Raw), &r); err == nil {
			principalHist[r.principal()]++
			if r.SourceIPAddress != "" {
				ipHist[r.SourceIPAddress]++
			}
			if r.isRoot() {
				st.RootUsage++
			}
			if r.ErrorCode != "" {
				st.AccessDenied++
			}
			if r.loginFailed() {
				st.ConsoleLoginFailures++
			}
			if deletionRe.MatchString(r.EventName) {
				st.ResourceDeletions++
			}
		}
		if e.At.IsZero() {
			continue
		}
		perMinute[e.At.Format("15:04")]++
	}

	st.EventTimeline = minuteTimeline(perMinute)
	st.TopEventNames = topCounts(eventHist, 10)
	st.TopPrincipals = topCounts(principalHist, 10)
	st.TopSourceIPs = topCounts(ipHist, 10)
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
