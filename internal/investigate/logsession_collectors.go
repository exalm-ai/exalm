package investigate

// logsession_collectors.go — the shared collectors every corpus-based
// analyzer profile composes: search/window/frequency over the parsed
// LogSession, a stats summary, and the wrapper for allowlisted remote
// diagnostics. All deterministic and read-only; anything user-authored in
// the emitted excerpts passes the redactor.

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// sessionFrom unwraps the corpus session from the opaque Facts.
func sessionFrom(f Facts) *LogSession {
	if s, ok := f.(*LogSession); ok {
		return s
	}
	return nil
}

func redactWith(red plugin.Redactor, s string) string {
	if red == nil {
		return s
	}
	return red.Redact(s)
}

const (
	maxSearchHits   = 5
	maxExcerptBytes = 600
)

// CorpusSearchCollector emits the first lines matching pattern (scoped to
// the focus unit when set) as log evidence, with the reproduce anchor.
func CorpusSearchCollector(label string, pattern *regexp.Regexp, anchor string) Collector {
	return func(_ context.Context, cc CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		s := sessionFrom(cc.Facts)
		if s == nil {
			return []plugin.InvestigationStep{{Label: label, Status: "unavailable", Detail: "no analysis session loaded"}}, nil
		}
		var evid []plugin.EvidenceItem
		events, total := s.Query(LogQuery{Unit: cc.Target.Name, Limit: MaxSessionEvents})
		if cc.Target.Name == "" {
			events, total = s.Query(LogQuery{Limit: MaxSessionEvents})
		}
		hits := 0
		for _, e := range events {
			if !pattern.MatchString(e.Message) && !pattern.MatchString(e.Raw) {
				continue
			}
			hits++
			if len(evid) < maxSearchHits {
				evid = append(evid, plugin.EvidenceItem{
					Kind: "log", Source: eventSource(e),
					Excerpt: truncate(redactWith(cc.Red, e.Raw), maxExcerptBytes),
					At:      e.At, Anchor: anchor,
				})
			}
		}
		_ = total
		if hits == 0 {
			return []plugin.InvestigationStep{{Label: label, Status: "done", Detail: "no matching lines in the analyzed corpus"}}, nil
		}
		return []plugin.InvestigationStep{{Label: label, Status: "done",
			Detail: fmt.Sprintf("%d matching line(s), showing %d", hits, len(evid)), Anchor: anchor}}, evid
	}
}

// CorpusWindowCollector emits the lines around the focus's worst recent
// event — the "what happened before/after it failed?" primitive.
func CorpusWindowCollector(label string, before, after time.Duration) Collector {
	return func(_ context.Context, cc CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		s := sessionFrom(cc.Facts)
		if s == nil {
			return []plugin.InvestigationStep{{Label: label, Status: "unavailable", Detail: "no analysis session loaded"}}, nil
		}
		center, centerEvent := worstEventTime(s, cc.Target.Name)
		if center.IsZero() {
			return []plugin.InvestigationStep{{Label: label, Status: "done", Detail: "no timestamped error events for this focus"}}, nil
		}
		win := s.Window(center, before, after, 40)
		var b strings.Builder
		for _, e := range win {
			b.WriteString(e.Raw)
			b.WriteString("\n")
		}
		evid := []plugin.EvidenceItem{{
			Kind: "log", Source: eventSource(centerEvent),
			Excerpt: truncate(redactWith(cc.Red, b.String()), 2*maxExcerptBytes),
			At:      center,
		}}
		return []plugin.InvestigationStep{{Label: label, Status: "done",
			Detail: fmt.Sprintf("%d line(s) around %s", len(win), center.Format("15:04:05"))}}, evid
	}
}

// CorpusFrequencyCollector emits per-minute burst detection for error-class
// events (metric evidence): when did the rate spike, and how hard.
func CorpusFrequencyCollector(label string) Collector {
	return func(_ context.Context, cc CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		s := sessionFrom(cc.Facts)
		if s == nil {
			return []plugin.InvestigationStep{{Label: label, Status: "unavailable", Detail: "no analysis session loaded"}}, nil
		}
		buckets := map[string]int{}
		events, _ := s.Query(LogQuery{Unit: cc.Target.Name, Limit: MaxSessionEvents})
		if cc.Target.Name == "" {
			events, _ = s.Query(LogQuery{Limit: MaxSessionEvents})
		}
		total := 0
		for _, e := range events {
			if !isErrorClass(e.Severity) || e.At.IsZero() {
				continue
			}
			total++
			buckets[e.At.Format("15:04")] += 1
		}
		if total == 0 {
			return []plugin.InvestigationStep{{Label: label, Status: "done", Detail: "no error-class events to profile"}}, nil
		}
		type kv struct {
			k string
			v int
		}
		var top []kv
		for k, v := range buckets {
			top = append(top, kv{k, v})
		}
		sort.Slice(top, func(i, j int) bool {
			if top[i].v != top[j].v {
				return top[i].v > top[j].v
			}
			return top[i].k < top[j].k
		})
		if len(top) > 3 {
			top = top[:3]
		}
		var parts []string
		for _, t := range top {
			parts = append(parts, fmt.Sprintf("%s → %d/min", t.k, t.v))
		}
		evid := []plugin.EvidenceItem{{
			Kind: "metric", Source: "corpus-frequency",
			Excerpt: fmt.Sprintf("%d error-class events; busiest minutes: %s", total, strings.Join(parts, ", ")),
		}}
		return []plugin.InvestigationStep{{Label: label, Status: "done",
			Detail: fmt.Sprintf("%d error-class events profiled", total)}}, evid
	}
}

// StatsSummaryCollector emits the analyzer's computed stats through a
// profile-supplied renderer (Stats is analyzer-typed).
func StatsSummaryCollector(label string, render func(stats any) string) Collector {
	return func(_ context.Context, cc CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		s := sessionFrom(cc.Facts)
		if s == nil || s.Stats == nil {
			return []plugin.InvestigationStep{{Label: label, Status: "unavailable", Detail: "no stats computed for this analysis"}}, nil
		}
		text := strings.TrimSpace(render(s.Stats))
		if text == "" {
			return []plugin.InvestigationStep{{Label: label, Status: "done", Detail: "stats empty"}}, nil
		}
		evid := []plugin.EvidenceItem{{
			Kind: "metric", Source: "analysis-stats",
			Excerpt: truncate(redactWith(cc.Red, text), 2*maxExcerptBytes),
		}}
		return []plugin.InvestigationStep{{Label: label, Status: "done", Detail: "computed statistics summarized"}}, evid
	}
}

// DiagFn runs one allowlisted remote diagnostic against the session's host.
// Wired at serve time to internal/ssh's RunDiag; injected fakes in tests.
// It must be read-only and must only accept allowlist keys — never command
// strings.
type DiagFn func(ctx context.Context, s *LogSession, name, param string) (output, describe string, err error)

// DiagCollector wraps one allowlisted remote diagnostic. paramFrom derives
// the single validated parameter (e.g. the focus unit) — nil for fixed
// commands. Reports "unavailable" (never an error) when diagnostics are
// disabled, no host is attached, or the tier refuses the command.
func DiagCollector(label, name string, paramFrom func(CollectCtx) string, run DiagFn) Collector {
	return func(ctx context.Context, cc CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		s := sessionFrom(cc.Facts)
		if s == nil || s.SSH == nil {
			return []plugin.InvestigationStep{{Label: label, Status: "unavailable", Detail: "no remote host attached to this analysis"}}, nil
		}
		if s.DiagTier == "" || s.DiagTier == "off" {
			return []plugin.InvestigationStep{{Label: label, Status: "unavailable", Detail: "remote diagnostics disabled (--remote-diag off)"}}, nil
		}
		if run == nil {
			return []plugin.InvestigationStep{{Label: label, Status: "unavailable", Detail: "diagnostics runner not wired"}}, nil
		}
		param := ""
		if paramFrom != nil {
			param = paramFrom(cc)
		}
		out, describe, err := run(ctx, s, name, param)
		if err != nil {
			return []plugin.InvestigationStep{{Label: label, Status: "unavailable", Detail: err.Error()}}, nil
		}
		evid := []plugin.EvidenceItem{{
			Kind: "metric", Source: "diag/" + name,
			Excerpt: truncate(redactWith(cc.Red, out), 2*maxExcerptBytes),
			Anchor:  describe,
		}}
		return []plugin.InvestigationStep{{Label: label, Status: "done", Detail: describe}}, evid
	}
}

// eventSource renders a stable source label for one event.
func eventSource(e LogEvent) string {
	switch {
	case e.Unit != "" && e.Scope != "":
		return e.Scope + "/" + e.Unit
	case e.Unit != "":
		return e.Unit
	case e.Scope != "":
		return e.Scope
	default:
		return "corpus"
	}
}

// isErrorClass reports whether a normalized severity is error-or-worse.
func isErrorClass(severity string) bool {
	switch strings.ToLower(severity) {
	case "emerg", "alert", "crit", "err", "error", "critical", "fatal", "5xx":
		return true
	}
	return strings.HasPrefix(severity, "5")
}

// worstEventTime finds the most severe (then most recent) timestamped event
// for the focus unit ("" = whole corpus).
func worstEventTime(s *LogSession, unit string) (time.Time, LogEvent) {
	events, _ := s.Query(LogQuery{Unit: unit, Limit: MaxSessionEvents})
	if unit == "" {
		events, _ = s.Query(LogQuery{Limit: MaxSessionEvents})
	}
	var best LogEvent
	bestRank := -1
	for _, e := range events {
		if e.At.IsZero() {
			continue
		}
		r := severityRank(e.Severity)
		if r > bestRank || (r == bestRank && e.At.After(best.At)) {
			best, bestRank = e, r
		}
	}
	return best.At, best
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "emerg", "alert", "crit", "critical", "fatal":
		return 4
	case "err", "error", "5xx":
		return 3
	case "warn", "warning":
		return 2
	case "notice", "info", "information":
		return 1
	default:
		if strings.HasPrefix(severity, "5") {
			return 3
		}
		if strings.HasPrefix(severity, "4") {
			return 2
		}
		return 0
	}
}
