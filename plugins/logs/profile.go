package logs

// profile.go assembles the generic application-log investigation Profile for
// internal/investigate. The logs plugin is corpus-only: every collector reads
// the in-memory LogSession built by the last summarize run — there are no
// remote diagnostics. Facts is always *investigate.LogSession (possibly nil
// before the first analysis).

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// maxTimelineEvents caps the chronological view at the worst error-class
// entries so the UI stays readable.
const maxTimelineEvents = 12

// Corpus search patterns — case-insensitive, shared by collectors, symptom
// matchers, and cause matchers so they never drift apart.
var (
	errorSearchRe   = investigate.Re(`error|exception|panic|fatal|fail`)
	timeoutSearchRe = investigate.Re(`timeout|timed out|deadline exceeded`)
	exceptionRe     = investigate.Re(`exception|panic|stack ?trace`)
)

// logsSessionOf unwraps the corpus session from the opaque Facts, tolerating
// any other type (nil session = "run an analysis first").
func logsSessionOf(f investigate.Facts) *investigate.LogSession {
	s, _ := f.(*investigate.LogSession)
	return s
}

// isErrorClassSeverity reports whether a normalized severity is
// error-or-worse for the generic parser's vocabulary.
func isErrorClassSeverity(severity string) bool {
	switch strings.ToLower(severity) {
	case "emerg", "alert", "crit", "err", "error", "critical", "fatal", "panic":
		return true
	}
	return strings.HasPrefix(severity, "5")
}

// countErrorClass counts error-class events in the whole corpus.
func countErrorClass(s *investigate.LogSession) int {
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	n := 0
	for _, e := range events {
		if isErrorClassSeverity(e.Severity) {
			n++
		}
	}
	return n
}

// countMatching counts corpus events whose Message or Raw matches re.
func countMatching(s *investigate.LogSession, re *regexp.Regexp) int {
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	n := 0
	for _, e := range events {
		if re.MatchString(e.Message) || re.MatchString(e.Raw) {
			n++
		}
	}
	return n
}

// logsSymptomCatalog is what an experienced engineer checks FIRST for each
// application-log failure mode, and the candidate causes to rank.
var logsSymptomCatalog = []investigate.Symptom{
	{
		Key:      "error-burst",
		Title:    "Error burst",
		Category: "Reliability",
		Severity: plugin.SeverityHigh,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d error-class log line(s) in the corpus.", countErrorClass(logsSessionOf(f)))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			s := logsSessionOf(f)
			return s != nil && countErrorClass(s) >= 5
		},
		Checks: []investigate.Check{
			{Collector: "corpus-errors", Reason: "a burst of error-class lines — read the signatures first", Priority: 1},
			{Collector: "corpus-frequency", Reason: "when did the error rate spike, and how hard", Priority: 2},
			{Collector: "corpus-window", Reason: "the lines around the worst error show what led into it", Priority: 3},
			{Collector: "history", Reason: "recurring bursts point at a chronic fault, not a one-off", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Application fault repeating under load",
				Base:  45,
				For:   []investigate.EvidenceMatcher{{Kind: "log", Pattern: investigate.Re(`error|exception`), Weight: 15}},
			},
			{
				Title: "Recent change introduced the errors",
				Base:  40,
				For:   []investigate.EvidenceMatcher{{Kind: "history", Pattern: investigate.Re(`change`), Weight: 20}},
			},
		},
	},
	{
		Key:      "exception-cluster",
		Title:    "Exception cluster",
		Category: "Reliability",
		Severity: plugin.SeverityHigh,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d exception/stack-trace line(s) in the corpus.", countMatching(logsSessionOf(f), exceptionRe))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			s := logsSessionOf(f)
			return s != nil && countMatching(s, exceptionRe) >= 3
		},
		Checks: []investigate.Check{
			{Collector: "corpus-errors", Reason: "repeated exceptions — quote the exact signatures", Priority: 1},
			{Collector: "corpus-window", Reason: "what the application logged just before the exceptions", Priority: 2},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Unhandled exception in a specific code path",
				Base:  50,
				For:   []investigate.EvidenceMatcher{{Kind: "log", Pattern: investigate.Re(`exception|panic`), Weight: 20}},
			},
		},
	},
	{
		Key:      "timeout-cluster",
		Title:    "Timeout cluster",
		Category: "Performance",
		Severity: plugin.SeverityMedium,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d timeout/deadline-exceeded line(s) in the corpus.", countMatching(logsSessionOf(f), timeoutSearchRe))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			s := logsSessionOf(f)
			return s != nil && countMatching(s, timeoutSearchRe) >= 3
		},
		Checks: []investigate.Check{
			{Collector: "corpus-timeouts", Reason: "repeated timeouts — identify which operation is stalling", Priority: 1},
			{Collector: "corpus-frequency", Reason: "timeout bursts correlate with load or dependency incidents", Priority: 2},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Dependency slow or unreachable",
				Base:  50,
				For:   []investigate.EvidenceMatcher{{Kind: "log", Pattern: investigate.Re(`timeout|deadline`), Weight: 20}},
			},
			{Title: "Resource starvation in the application", Base: 35},
		},
	},
	{
		Key:      "log-anomaly",
		Title:    "Log anomaly",
		Category: "Reliability",
		Severity: plugin.SeverityLow,
		Fallback: true,
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return logsSessionOf(f) != nil
		},
		Checks: []investigate.Check{
			{Collector: "stats-summary", Reason: "no specific failure signature — start from the computed statistics", Priority: 1},
			{Collector: "corpus-frequency", Reason: "the error-rate shape narrows down when things changed", Priority: 2},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Log volume/pattern anomaly — needs a baseline comparison", Base: 30},
		},
	},
}

// logsEdgeRegistry documents the corpus relationships the planner follows.
var logsEdgeRegistry = []investigate.Edge{
	{Name: "corpus→errors", Collector: "corpus-errors", Why: "error-class lines are the primary failure signal in a log corpus"},
	{Name: "corpus→window", Collector: "corpus-window", Why: "the lines around the worst event show cause, not just effect"},
	{Name: "corpus→frequency", Collector: "corpus-frequency", Why: "the error-rate shape distinguishes bursts from steady faults"},
	{Name: "corpus→timeouts", Collector: "corpus-timeouts", Why: "timeout lines expose slow or unreachable dependencies"},
	{Name: "resource→history", Collector: "history", Why: "prior investigations and incidents cover 'has this happened before'"},
}

// logsIntentPatterns extend the framework's common intents with the
// error/timeout questions operators actually ask about app logs.
var logsIntentPatterns = append(investigate.CommonIntentPatterns(),
	investigate.IntentPattern{Intent: "errors", Re: investigate.Re(`error|exception|panic|fatal`)},
	investigate.IntentPattern{Intent: "timeouts", Re: investigate.Re(`timeout|deadline|hang`)},
)

// logsIntentChecks maps question intents to collector requests.
var logsIntentChecks = map[string][]investigate.Check{
	"errors": {
		{Collector: "corpus-errors", Reason: "you asked about errors — quoting the matching lines", Priority: 1},
		{Collector: "corpus-frequency", Reason: "the error-rate profile shows when they clustered", Priority: 2},
	},
	"timeouts": {
		{Collector: "corpus-timeouts", Reason: "you asked about timeouts — quoting the matching lines", Priority: 1},
		{Collector: "corpus-frequency", Reason: "timeout bursts correlate with load spikes", Priority: 2},
	},
	"previous-logs": {
		{Collector: "corpus-window", Reason: "you asked what happened before — showing the surrounding lines", Priority: 1},
	},
	"comparison": {
		{Collector: "history", Reason: "comparing with the past needs prior investigations and incidents", Priority: 1},
		{Collector: "corpus-frequency", Reason: "the rate profile is the corpus-side comparison baseline", Priority: 2},
	},
	"history": {
		{Collector: "history", Reason: "you asked whether this happened before", Priority: 1},
		{Collector: "corpus-frequency", Reason: "recurrence shows up as repeated rate spikes", Priority: 2},
	},
	"rca": {
		{Collector: "history", Reason: "an RCA should note recurrence", Priority: 1},
		{Collector: "corpus-frequency", Reason: "an RCA needs the failure's time profile", Priority: 2},
	},
}

// logsCollectorTTL keeps corpus evidence fresh for the whole conversation —
// the corpus never changes between analyses, so 10 minutes is safe.
var logsCollectorTTL = map[string]time.Duration{
	"corpus-window":    10 * time.Minute,
	"corpus-frequency": 10 * time.Minute,
	"stats-summary":    10 * time.Minute,
	"corpus-errors":    10 * time.Minute,
	"corpus-timeouts":  10 * time.Minute,
	"history":          10 * time.Minute,
}

// renderLogsStats renders the analyzer-typed stats payload for evidence.
func renderLogsStats(stats any) string {
	st, ok := stats.(LogsStats)
	if !ok {
		return ""
	}
	var b strings.Builder
	if len(st.SeverityCounts) > 0 {
		var parts []string
		for _, c := range st.SeverityCounts {
			parts = append(parts, fmt.Sprintf("%s=%d", c.Name, c.Count))
		}
		b.WriteString("severity counts: " + strings.Join(parts, ", "))
	}
	if len(st.ErrorTimeline) > 0 {
		worst := st.ErrorTimeline[0]
		for _, tb := range st.ErrorTimeline {
			if tb.Count > worst.Count {
				worst = tb
			}
		}
		fmt.Fprintf(&b, "; error timeline: %d minute bucket(s), busiest %s → %d (%s)",
			len(st.ErrorTimeline), worst.T, worst.Count, worst.Sev)
	}
	return b.String()
}

// logsCollectors is the dispatch table — corpus-only, no remote diagnostics.
func logsCollectors() map[string]investigate.Collector {
	return map[string]investigate.Collector{
		"corpus-window":    investigate.CorpusWindowCollector("Lines around the worst error inspected", 5*time.Minute, 2*time.Minute),
		"corpus-frequency": investigate.CorpusFrequencyCollector("Error-rate profile computed"),
		"stats-summary":    investigate.StatsSummaryCollector("Analysis statistics summarized", renderLogsStats),
		"corpus-errors":    investigate.CorpusSearchCollector("Error lines searched", errorSearchRe, "grep -iE 'error|exception|panic|fatal|fail' <logfile>"),
		"corpus-timeouts":  investigate.CorpusSearchCollector("Timeout lines searched", timeoutSearchRe, "grep -iE 'timeout|timed out|deadline exceeded' <logfile>"),
		"history": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			return investigate.GatherHistory(ctx, cc.History, cc.Target.Scope, cc.Target.Name, cc.Now)
		},
	}
}

// logsConfidenceRules score evidence QUALITY for the corpus domain.
var logsConfidenceRules = []investigate.ConfidenceRule{
	{
		Score:  70,
		Reason: "a repeating error signature was isolated in the corpus and its rate profile corroborates it",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			if !investigate.EvidenceMatching(ev, "log", errorSearchRe) {
				return false
			}
			for _, e := range ev {
				if e.Kind == "metric" {
					return true
				}
			}
			return false
		},
	},
	{
		Score:  60,
		Reason: "log-pattern evidence only — signature found but not yet corroborated",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			for _, e := range ev {
				if e.Kind == "log" {
					return true
				}
			}
			return false
		},
	},
	{
		Score:  30,
		Reason: "weak signal — some evidence gathered but no clear failure signature",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return len(ev) > 0
		},
	},
}

// logsPreventionCatalog maps matched symptoms to long-term prevention advice.
var logsPreventionCatalog = map[string][]plugin.RemediationAction{
	"error-burst": {{
		Kind: "prevention", FixType: "prevention", Risk: "low",
		Description: "Add structured logging with error-rate alerts per component.",
	}},
	"exception-cluster": {{
		Kind: "prevention", FixType: "prevention", Risk: "low",
		Description: "Ship stack traces to an error tracker and gate deploys on new-exception detection.",
	}},
	"timeout-cluster": {{
		Kind: "prevention", FixType: "prevention", Risk: "low",
		Description: "Set explicit timeouts with retries + circuit breakers, and monitor dependency latency.",
	}},
	"log-anomaly": {{
		Kind: "prevention", FixType: "prevention", Risk: "low",
		Description: "Establish log-volume baselines and alert on anomalies.",
	}},
}

// logsTimelineSeverity maps a normalized corpus severity to the timeline tier.
func logsTimelineSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "crit", "emerg", "alert", "critical", "fatal", "panic":
		return "critical"
	case "err", "error", "5xx":
		return "high"
	case "warn", "warning":
		return "medium"
	}
	if strings.HasPrefix(severity, "5") {
		return "high"
	}
	return "info"
}

// logsTimeline returns the worst error-class events (focus unit when set,
// corpus-wide otherwise), chronologically ascending, capped.
func logsTimeline(f investigate.Facts, t investigate.Target, _ time.Time) []plugin.TimelineEvent {
	s := logsSessionOf(f)
	if s == nil {
		return nil
	}
	q := investigate.LogQuery{Limit: investigate.MaxSessionEvents}
	if t.Name != "" {
		q.Unit = t.Name
	}
	events, _ := s.Query(q)
	var errs []investigate.LogEvent
	for _, e := range events {
		if e.At.IsZero() || !isErrorClassSeverity(e.Severity) {
			continue
		}
		errs = append(errs, e)
	}
	if len(errs) > maxTimelineEvents {
		errs = errs[len(errs)-maxTimelineEvents:]
	}
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].At.Before(errs[j].At) })
	out := make([]plugin.TimelineEvent, 0, len(errs))
	for _, e := range errs {
		detail := e.Message
		if len(detail) > 200 {
			detail = detail[:200] + "…"
		}
		out = append(out, plugin.TimelineEvent{
			At:       e.At,
			Label:    strings.ToUpper(e.Severity) + " log entry",
			Severity: logsTimelineSeverity(e.Severity),
			Source:   "event",
			Detail:   detail,
		})
	}
	return out
}

// logsSuggestFollowUps proposes what to ask next, skipping intents already
// covered this turn. Purely rule-based.
func logsSuggestFollowUps(intents []string, _ investigate.Facts, _ []plugin.InvestigationStep) []string {
	has := func(intent string) bool {
		for _, i := range intents {
			if i == intent {
				return true
			}
		}
		return false
	}
	var out []string
	add := func(s string) {
		if len(out) < 5 {
			out = append(out, s)
		}
	}
	if !has("errors") {
		add("Show the error lines")
	}
	if !has("timeouts") {
		add("Check for timeouts")
	}
	if !has("previous-logs") {
		add("Show the lines before the worst error")
	}
	if !has("comparison") && !has("history") {
		add("Has this happened before?")
	}
	if !has("rca") {
		add("Generate an RCA")
	}
	return out
}

// Prompt wording — the trust-rule skeleton is framework-owned.
const logsPromptRole = "a senior systems engineer investigating application log output"

var (
	logsConversationPrompt = investigate.ConversationPromptFor(logsPromptRole,
		`- Quote error signatures exactly as they appear in the corpus — never paraphrase a log line you cite.
- The corpus is a bounded snapshot from one analysis run; say so plainly when asked about data outside it.`)
	logsLineAnalysisPrompt = investigate.LineAnalysisPromptFor(logsPromptRole,
		`- Quote error signatures exactly as they appear in the log entry.`)
)

// logsBaseline contributes the free corpus summary every turn starts from.
func logsBaseline(_ context.Context, f investigate.Facts, _ investigate.Target, _ time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	s := logsSessionOf(f)
	if s == nil || s.Len() == 0 {
		return []plugin.InvestigationStep{{
			Label: "Corpus loaded", Status: "unavailable",
			Detail: "no log corpus available — run an analysis first",
		}}, nil
	}
	from, to := s.TimeRange()
	rangeText := "no parseable timestamps"
	if !from.IsZero() {
		rangeText = from.Format(time.RFC3339) + " → " + to.Format(time.RFC3339)
	}
	summary := fmt.Sprintf("%d event(s) from %d source(s); time range %s; %d event(s) dropped to caps",
		s.Len(), len(s.Sources), rangeText, s.Truncated())
	step := plugin.InvestigationStep{
		Label: "Corpus loaded", Status: "done",
		Detail: fmt.Sprintf("%d event(s) from %d source(s)", s.Len(), len(s.Sources)),
	}
	evid := plugin.EvidenceItem{Kind: "metric", Source: "corpus-summary", Excerpt: summary, At: s.CollectedAt}
	return []plugin.InvestigationStep{step}, []plugin.EvidenceItem{evid}
}

// logsProfile builds the logs investigation profile from the package-level
// catalogs. Stateless — per-turn state arrives via Facts.
func logsProfile() investigate.Profile {
	return investigate.Profile{
		Name:            "logs",
		Symptoms:        logsSymptomCatalog,
		Edges:           logsEdgeRegistry,
		IntentPatterns:  logsIntentPatterns,
		IntentChecks:    logsIntentChecks,
		Collectors:      logsCollectors(),
		ConfidenceRules: logsConfidenceRules,
		Prevention:      logsPreventionCatalog,
		TTLs:            logsCollectorTTL,

		ConversationPrompt: logsConversationPrompt,
		LogLinePrompt:      logsLineAnalysisPrompt,

		ResolveFocus: func(prev, _, message string, f investigate.Facts) string {
			return investigate.ResolveFocusFromVocabulary(prev, message, logsSessionOf(f))
		},
		Baseline:         logsBaseline,
		Timeline:         logsTimeline,
		SuggestFollowUps: logsSuggestFollowUps,
	}
}

// InvestigationProfile exposes the logs profile for engine construction.
func (p *Plugin) InvestigationProfile() investigate.Profile {
	return logsProfile()
}
