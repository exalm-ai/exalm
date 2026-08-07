package iis

// profile.go assembles the IIS investigation Profile for the generic
// framework (internal/investigate). The domain Facts is the parsed W3C
// corpus (*investigate.LogSession) built by session.go; everything here is
// deterministic catalogs — the per-turn pipeline is the framework engine's.

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

// diagRun executes one allowlisted remote diagnostic. Package-level so tests
// can inject a fake; production uses the SSH allowlist runner.
var diagRun investigate.DiagFn = investigate.SSHDiagRunner

// runDiag defers to the current diagRun so registrations built before a test
// swaps the runner still honor the swap.
func runDiag(ctx context.Context, s *investigate.LogSession, name, param string) (string, string, error) {
	return diagRun(ctx, s, name, param)
}

// sessionOf unwraps the corpus session from the opaque Facts (nil-safe).
func sessionOf(f investigate.Facts) *investigate.LogSession {
	s, _ := f.(*investigate.LogSession)
	return s
}

// ── prompts ─────────────────────────────────────────────────────────────────

const iisDomainRole = "a senior Windows/IIS administrator investigating IIS W3C logs"

const iisDomainRules = `- Cite site names, URI stems, and HTTP status codes exactly as they appear in the corpus evidence — never normalize or invent them.
- W3C log timestamps are UTC; present times exactly as given.`

var (
	iisConversationPrompt = investigate.ConversationPromptFor(iisDomainRole, iisDomainRules)
	iisLogLinePrompt      = investigate.LineAnalysisPromptFor(iisDomainRole, iisDomainRules)
)

// ── query helpers (all nil-guarded) ─────────────────────────────────────────

// countCode returns how many corpus events carry the exact status code.
func countCode(s *investigate.LogSession, code string) int {
	if s == nil {
		return 0
	}
	_, n := s.Query(investigate.LogQuery{Code: code, Limit: 1})
	return n
}

// count5xx returns how many corpus events are 5xx-class.
func count5xx(s *investigate.LogSession) int {
	if s == nil {
		return 0
	}
	_, n := s.Query(investigate.LogQuery{Severity: "5xx", Limit: 1})
	return n
}

var slowEventRe = regexp.MustCompile(`\(\d{4,}ms\)`)

// countSlow returns how many corpus events carry a 4+ digit latency suffix.
func countSlow(s *investigate.LogSession) int {
	if s == nil {
		return 0
	}
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	n := 0
	for _, e := range events {
		if slowEventRe.MatchString(e.Message) || slowEventRe.MatchString(e.Raw) {
			n++
		}
	}
	return n
}

// poolNameRe / reW3SVC gate what a corpus-derived app-pool name may be: a
// single injection-safe token (subset of the SSH allowlist paramRe) that is NOT
// the numeric "W3SVCn" site-id form (a site id is not an app-pool name). W3C
// access logs carry the site (s-sitename), not the pool, so this only yields a
// candidate for friendly single-token site names — otherwise the finding stays
// advice-only rather than proposing a possibly-wrong recycle.
var (
	poolNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:\-]{0,127}$`)
	reW3SVC    = regexp.MustCompile(`(?i)^W3SVC\d+$`)
)

// poolCandidateFromCorpus returns a plausible, injection-safe app-pool name
// derived from the site scope of the 503 events, or "" when none qualifies.
func poolCandidateFromCorpus(s *investigate.LogSession) string {
	if s == nil {
		return ""
	}
	events, _ := s.Query(investigate.LogQuery{Code: "503", Limit: investigate.MaxSessionEvents})
	for _, e := range events {
		site := strings.TrimSpace(e.Scope)
		if site == "" || reW3SVC.MatchString(site) || !poolNameRe.MatchString(site) {
			continue
		}
		return site
	}
	return ""
}

// ── symptom catalog ─────────────────────────────────────────────────────────

var iisRe = investigate.Re

var iisSymptomCatalog = []investigate.Symptom{
	{
		Key:      "pool-failure",
		Title:    "IIS application pool failure (503)",
		Category: "Availability",
		Severity: plugin.SeverityHigh,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d Service Unavailable (503) response(s) — a stopped or rapid-fail-protected app pool.", countCode(sessionOf(f), "503"))
		},
		Remediate: func(f investigate.Facts, _ investigate.Target) *plugin.RemediationAction {
			pool := poolCandidateFromCorpus(sessionOf(f))
			if pool == "" {
				return nil // no safely-derivable pool name → advice-only
			}
			return &plugin.RemediationAction{
				Kind:            "iis-pool-recycle",
				Name:            pool,
				Shell:           "powershell",
				KubectlCmd:      "Import-Module WebAdministration; Restart-WebAppPool -Name " + pool,
				Description:     "Recycle the IIS application pool " + pool,
				FixType:         "temporary",
				Risk:            "medium",
				Rollback:        "None needed — a recycle restarts workers; no config change is made.",
				Warning:         "Assumes the app pool is named after site " + pool + "; verify with Get-IISAppPool before applying. Recycling drops in-flight requests and in-process session state.",
				ExpectedOutcome: "Workers restart and 503s clear; recurrence points at an app/config root cause.",
			}
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return countCode(sessionOf(f), "503") >= 3
		},
		Checks: []investigate.Check{
			{Collector: "corpus-503", Reason: "503s mean IIS accepted the request but no worker served it — see the exact failures", Priority: 1},
			{Collector: "iis-apppools", Reason: "a stopped or rapid-fail-protected app pool is the classic 503 cause", Priority: 2},
			{Collector: "sys-memory", Reason: "memory exhaustion recycles or kills worker processes", Priority: 3},
			{Collector: "corpus-window", Reason: "what happened around the worst failure narrows the trigger", Priority: 3},
			{Collector: "history", Reason: "recurring 503 bursts point at a chronic pool problem", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Application pool stopped or recycling under failure", Base: 55,
				For: []investigate.EvidenceMatcher{{Pattern: iisRe(`503`), Weight: 20}}},
			{Title: "Pool identity or configuration problem", Base: 40},
			{Title: "Worker process exhausting memory", Base: 30,
				For: []investigate.EvidenceMatcher{{Pattern: iisRe(`memory|9[0-9]%`), Weight: 20}}},
		},
	},
	{
		Key:      "burst-5xx",
		Title:    "5xx error burst",
		Category: "Availability",
		Severity: plugin.SeverityHigh,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d server-error (5xx) response(s) in the corpus.", count5xx(sessionOf(f)))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return count5xx(sessionOf(f)) >= 3
		},
		Checks: []investigate.Check{
			{Collector: "corpus-5xx", Reason: "the 5xx lines themselves show which URIs and sites are failing", Priority: 1},
			{Collector: "stats-summary", Reason: "the status-code histogram shows how widespread the errors are", Priority: 2},
			{Collector: "iis-apppools", Reason: "pool state distinguishes app errors from platform failures", Priority: 3},
			{Collector: "corpus-window", Reason: "the lines around the worst error show what changed at that moment", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Application errors in the site code", Base: 50,
				For: []investigate.EvidenceMatcher{{Pattern: iisRe(`500`), Weight: 15}}},
			{Title: "Backend dependency failing", Base: 40},
			{Title: "Recent deployment broke the site", Base: 35,
				For: []investigate.EvidenceMatcher{{Kind: "history", Pattern: iisRe(`change`), Weight: 20}}},
		},
	},
	{
		Key:      "slow-requests",
		Title:    "Slow requests",
		Category: "Performance",
		Severity: plugin.SeverityMedium,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d slow request(s) (≥1000ms time-taken) in the corpus.", countSlow(sessionOf(f)))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return countSlow(sessionOf(f)) >= 3
		},
		Checks: []investigate.Check{
			{Collector: "corpus-slow", Reason: "the slow lines show which URIs carry the high time-taken values", Priority: 1},
			{Collector: "stats-summary", Reason: "the slow-request count and top URIs bound the blast radius", Priority: 2},
			{Collector: "sys-disk", Reason: "a full or slow disk stalls IIS logging and content serving", Priority: 3},
			{Collector: "sys-memory", Reason: "memory pressure forces paging, which shows up as latency", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Slow database or downstream API behind the site", Base: 50},
			{Title: "Host resource saturation", Base: 35,
				For: []investigate.EvidenceMatcher{{Pattern: iisRe(`9[0-9]%`), Weight: 20}}},
		},
	},
	{
		Key:      "auth-4xx",
		Title:    "Authorization failures (401/403)",
		Category: "Security",
		Severity: plugin.SeverityMedium,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			s := sessionOf(f)
			return fmt.Sprintf("%d unauthorized/forbidden response(s) (401+403).", countCode(s, "401")+countCode(s, "403"))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			s := sessionOf(f)
			return countCode(s, "401")+countCode(s, "403") >= 5
		},
		Checks: []investigate.Check{
			{Collector: "corpus-frequency", Reason: "the per-minute burst profile separates a scan from a config break", Priority: 1},
			{Collector: "stats-summary", Reason: "which URIs and sites take the 401/403s shows what's being denied", Priority: 2},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Authentication misconfiguration after a change", Base: 45,
				For: []investigate.EvidenceMatcher{{Kind: "history", Pattern: iisRe(`change`), Weight: 20}}},
			{Title: "Unauthorized scanning traffic", Base: 40},
		},
	},
	{
		Key:      "site-anomaly",
		Title:    "Site anomaly",
		Category: "Reliability",
		Severity: plugin.SeverityLow,
		Fallback: true,
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return sessionOf(f) != nil
		},
		Checks: []investigate.Check{
			{Collector: "stats-summary", Reason: "the computed statistics are the fastest anomaly overview", Priority: 1},
			{Collector: "corpus-frequency", Reason: "error-rate bursts localize when the anomaly started", Priority: 2},
			{Collector: "history", Reason: "prior investigations reveal whether this is recurring", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Traffic anomaly — compare with a baseline window", Base: 35},
		},
	},
}

// ── resource graph ──────────────────────────────────────────────────────────

var iisEdgeRegistry = []investigate.Edge{
	{Name: "site→errors", Collector: "corpus-5xx", Why: "a site's 5xx lines are the direct failure record"},
	{Name: "server→apppools", Collector: "iis-apppools", Why: "sites run inside app pools — pool state explains 503s"},
	{Name: "host→memory", Collector: "sys-memory", Why: "worker processes die first when the host runs out of memory"},
	{Name: "host→disk", Collector: "sys-disk", Why: "a full disk stalls logging and content serving"},
	{Name: "server→service", Collector: "svc-status", Why: "the W3SVC service must be running for any site to serve"},
	{Name: "corpus→window", Collector: "corpus-window", Why: "the lines around the worst event show the trigger"},
	{Name: "corpus→frequency", Collector: "corpus-frequency", Why: "burst timing separates a spike from a steady failure"},
	{Name: "resource→history", Collector: "history", Why: "recurrence and past fixes shortcut the investigation"},
}

// ── intents ─────────────────────────────────────────────────────────────────

func iisIntentPatterns() []investigate.IntentPattern {
	return append(investigate.CommonIntentPatterns(),
		investigate.IntentPattern{Intent: "pools", Re: iisRe(`app(lication)? ?pool|w3wp|recycl`)},
		investigate.IntentPattern{Intent: "errors", Re: iisRe(`\b5\d\d\b|failed request`)},
		investigate.IntentPattern{Intent: "latency", Re: iisRe(`slow|latency|time-?taken`)},
		investigate.IntentPattern{Intent: "auth", Re: iisRe(`\b401\b|\b403\b|auth`)},
		investigate.IntentPattern{Intent: "sites", Re: iisRe(`site|w3svc`)},
	)
}

var iisIntentChecks = map[string][]investigate.Check{
	"pools": {
		{Collector: "iis-apppools", Reason: "you asked about application pools", Priority: 1},
		{Collector: "corpus-503", Reason: "503s are the log-side signature of a stopped pool", Priority: 2},
	},
	"errors": {
		{Collector: "corpus-5xx", Reason: "you asked about server errors", Priority: 1},
		{Collector: "corpus-frequency", Reason: "the burst profile shows when the errors spiked", Priority: 2},
	},
	"latency": {
		{Collector: "corpus-slow", Reason: "you asked about slow requests", Priority: 1},
		{Collector: "stats-summary", Reason: "the slow-request count bounds how widespread it is", Priority: 2},
	},
	"auth": {
		{Collector: "corpus-frequency", Reason: "you asked about authentication failures — profiling the 401/403 bursts", Priority: 1},
		{Collector: "stats-summary", Reason: "which URIs take the denials shows what's being probed", Priority: 2},
	},
	"sites": {
		{Collector: "stats-summary", Reason: "you asked about sites — per-site request stats first", Priority: 1},
		{Collector: "svc-status", Reason: "the W3SVC service state gates every site", Priority: 2},
	},
	"previous-logs": {
		{Collector: "corpus-window", Reason: "you asked what happened before — showing the lines around the worst event", Priority: 1},
	},
	"comparison": {{Collector: "history", Reason: "comparing with the past needs the historical record", Priority: 1}},
	"history":    {{Collector: "history", Reason: "you asked whether this happened before", Priority: 1}},
	"rca": {
		{Collector: "history", Reason: "an RCA should note recurrence", Priority: 1},
	},
}

// ── collectors ──────────────────────────────────────────────────────────────

var iisCollectorTTL = map[string]time.Duration{
	"corpus-window":    10 * time.Minute,
	"corpus-frequency": 10 * time.Minute,
	"corpus-5xx":       10 * time.Minute,
	"corpus-503":       10 * time.Minute,
	"corpus-slow":      10 * time.Minute,
	"stats-summary":    10 * time.Minute,
	"history":          10 * time.Minute,
	"iis-apppools":     90 * time.Second,
	"sys-memory":       90 * time.Second,
	"sys-disk":         90 * time.Second,
	"svc-status":       90 * time.Second,
}

// renderIISStats renders the analyzer-typed stats for the stats-summary
// evidence excerpt.
func renderIISStats(stats any) string {
	st, ok := stats.(IISStats)
	if !ok {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "slow requests (>=%dms): %d\n", slowRequestMs, st.SlowRequests)
	if len(st.CodeHistogram) > 0 {
		b.WriteString("status codes: ")
		b.WriteString(nameCountList(st.CodeHistogram))
		b.WriteString("\n")
	}
	if len(st.TopSites) > 0 {
		b.WriteString("top sites: ")
		b.WriteString(nameCountList(st.TopSites))
		b.WriteString("\n")
	}
	if len(st.TopURIs) > 0 {
		b.WriteString("top URIs: ")
		b.WriteString(nameCountList(st.TopURIs))
		b.WriteString("\n")
	}
	if len(st.RequestTimeline) > 0 {
		fmt.Fprintf(&b, "request timeline: %d minute bucket(s), %s → %s",
			len(st.RequestTimeline), st.RequestTimeline[0].T, st.RequestTimeline[len(st.RequestTimeline)-1].T)
	}
	return b.String()
}

func nameCountList(counts []NameCount) string {
	parts := make([]string, 0, len(counts))
	for _, c := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", c.Name, c.Count))
	}
	return strings.Join(parts, ", ")
}

func iisCollectors() map[string]investigate.Collector {
	return map[string]investigate.Collector{
		"corpus-window":    investigate.CorpusWindowCollector("Log window around the worst event inspected", 2*time.Minute, 2*time.Minute),
		"corpus-frequency": investigate.CorpusFrequencyCollector("Error-rate burst profile computed"),
		"stats-summary":    investigate.StatsSummaryCollector("Computed request statistics summarized", renderIISStats),
		"corpus-5xx":       investigate.CorpusSearchCollector("5xx responses searched", regexp.MustCompile(`→ 5\d\d| 5\d\d `), "corpus-5xx"),
		"corpus-503":       investigate.CorpusSearchCollector("503 responses searched", regexp.MustCompile(`\b503\b`), "corpus-503"),
		"corpus-slow":      investigate.CorpusSearchCollector("Slow requests searched", regexp.MustCompile(`\(\d{4,}ms\)|time-taken`), "corpus-slow"),
		"iis-apppools":     investigate.DiagCollector("Application pool states listed", "iis-apppools", nil, runDiag),
		"sys-memory":       investigate.DiagCollector("Host memory pressure checked", "sys-memory", nil, runDiag),
		"sys-disk":         investigate.DiagCollector("Host disk usage checked", "sys-disk", nil, runDiag),
		"svc-status": investigate.DiagCollector("W3SVC service status checked", "svc-status",
			func(investigate.CollectCtx) string { return "W3SVC" }, runDiag),
		"history": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			return investigate.GatherHistory(ctx, cc.History, cc.Target.Scope, cc.Target.Name, cc.Now)
		},
	}
}

// ── confidence rules ────────────────────────────────────────────────────────

var (
	iis503Re    = regexp.MustCompile(`503`)
	iisChangeRe = regexp.MustCompile(`(?i)change`)
	iisAnyRe    = regexp.MustCompile(`.`)
)

var iisConfidenceRules = []investigate.ConfidenceRule{
	{
		Score: 90, Reason: "app-pool state confirms the 503s — live diagnostics corroborate the log evidence",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			hasPoolDiag := false
			for _, e := range ev {
				if e.Source == "diag/iis-apppools" {
					hasPoolDiag = true
					break
				}
			}
			return hasPoolDiag && investigate.EvidenceMatching(ev, "log", iis503Re)
		},
	},
	{
		Score: 75, Reason: "the error burst matches a recorded change — strong temporal correlation",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "history", iisChangeRe)
		},
	},
	{
		Score: 60, Reason: "W3C-pattern evidence only — log lines match the failure signature but no live state corroborates it",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", iisAnyRe)
		},
	},
	{
		Score: 30, Reason: "weak signal — some evidence gathered but nothing matches a known failure signature",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return len(ev) > 0
		},
	},
}

// ── prevention catalog ──────────────────────────────────────────────────────

var iisPreventionCatalog = map[string][]plugin.RemediationAction{
	"pool-failure": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Set app-pool rapid-fail protection alerts and dedicated pools per site so one failure can't cascade."}},
	"burst-5xx": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Enable Failed Request Tracing for 5xx and health-gate deployments."}},
	"slow-requests": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Track time-taken percentiles per site and alert on regression."}},
	"auth-4xx": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Audit auth configuration changes and alert on 401/403 bursts."}},
	"site-anomaly": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Baseline per-site request rates and alert on deviation."}},
}

// ── hooks ───────────────────────────────────────────────────────────────────

// iisBaseline contributes the free corpus-overview evidence every turn.
func iisBaseline(_ context.Context, f investigate.Facts, _ investigate.Target, _ time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	s := sessionOf(f)
	if s == nil || s.Len() == 0 {
		return []plugin.InvestigationStep{{Label: "Corpus loaded", Status: "unavailable",
			Detail: "no IIS analysis session — run an analysis first"}}, nil
	}
	from, to := s.TimeRange()
	span := "no timestamped events"
	if !from.IsZero() {
		span = from.Format("2006-01-02 15:04:05") + " → " + to.Format("2006-01-02 15:04:05")
	}
	excerpt := fmt.Sprintf("%d W3C event(s) from %d source(s); time range %s", s.Len(), len(s.Sources), span)
	if s.Truncated() > 0 {
		excerpt += fmt.Sprintf("; %d oldest event(s) dropped to session caps", s.Truncated())
	}
	steps := []plugin.InvestigationStep{{Label: "Corpus loaded", Status: "done",
		Detail: fmt.Sprintf("%d event(s) from %d source(s)", s.Len(), len(s.Sources))}}
	evid := []plugin.EvidenceItem{{Kind: "metric", Source: "corpus", Excerpt: excerpt}}
	return steps, evid
}

// timelineSeverity maps a normalized event severity onto the UI tiers.
func timelineSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "crit", "emerg", "alert", "critical", "fatal":
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

// iisTimelineRank orders error-class events for "worst first" selection.
func iisTimelineRank(severity string) int {
	switch timelineSeverity(severity) {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	}
	return 0
}

// iisTimeline returns the worst ≤12 error-class events for the focus (or the
// whole corpus), in ascending time order.
func iisTimeline(f investigate.Facts, t investigate.Target, _ time.Time) []plugin.TimelineEvent {
	s := sessionOf(f)
	if s == nil {
		return nil
	}
	events, _ := s.Query(investigate.LogQuery{Unit: t.Name, Limit: investigate.MaxSessionEvents})
	if t.Name == "" {
		events, _ = s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	}
	var errs []investigate.LogEvent
	for _, e := range events {
		if e.At.IsZero() || iisTimelineRank(e.Severity) < 2 {
			continue
		}
		errs = append(errs, e)
	}
	// Worst first (severity, then most recent), keep 12, then ascending time.
	sort.SliceStable(errs, func(i, j int) bool {
		ri, rj := iisTimelineRank(errs[i].Severity), iisTimelineRank(errs[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return errs[i].At.After(errs[j].At)
	})
	if len(errs) > 12 {
		errs = errs[:12]
	}
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].At.Before(errs[j].At) })
	out := make([]plugin.TimelineEvent, 0, len(errs))
	for _, e := range errs {
		label := e.Message
		if label == "" {
			label = e.Raw
		}
		out = append(out, plugin.TimelineEvent{
			At: e.At, Label: label, Severity: timelineSeverity(e.Severity),
			Source: "event", Detail: e.Scope,
		})
	}
	return out
}

// iisSuggestFollowUps proposes next questions, skipping intents already asked.
func iisSuggestFollowUps(intents []string, f investigate.Facts, _ []plugin.InvestigationStep) []string {
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
	s := sessionOf(f)
	if s != nil && count5xx(s) > 0 && !has("errors") {
		add("Show the 5xx errors")
	}
	if !has("pools") {
		add("Check the application pool state")
	}
	if !has("latency") {
		add("Are any requests slow?")
	}
	if !has("history") && !has("comparison") {
		add("Has this happened before?")
	}
	if !has("rca") {
		add("Write an RCA summary")
	}
	return out
}

// iisProfile builds the IIS investigation profile from the package catalogs.
func iisProfile() investigate.Profile {
	return investigate.Profile{
		Name:            "iis",
		Symptoms:        iisSymptomCatalog,
		Edges:           iisEdgeRegistry,
		IntentPatterns:  iisIntentPatterns(),
		IntentChecks:    iisIntentChecks,
		Collectors:      iisCollectors(),
		ConfidenceRules: iisConfidenceRules,
		Prevention:      iisPreventionCatalog,
		TTLs:            iisCollectorTTL,

		ConversationPrompt: iisConversationPrompt,
		LogLinePrompt:      iisLogLinePrompt,

		ResolveFocus: func(prev, _, message string, f investigate.Facts) string {
			s := sessionOf(f)
			if s == nil {
				return prev
			}
			return investigate.ResolveFocusFromVocabulary(prev, message, s)
		},
		Baseline:         iisBaseline,
		Timeline:         iisTimeline,
		SuggestFollowUps: iisSuggestFollowUps,
	}
}

// InvestigationProfile exposes the IIS profile for the investigation engine.
func (p *Plugin) InvestigationProfile() investigate.Profile {
	return iisProfile()
}
