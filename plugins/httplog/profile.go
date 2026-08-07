package httplog

// profile.go assembles the HTTP access/error-log investigation Profile for
// the generic framework (internal/investigate). The domain Facts is the
// parsed corpus (*investigate.LogSession) built by session.go; everything
// here is deterministic catalogs — the per-turn pipeline is the framework
// engine's.

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

const httplogDomainRole = "a senior web infrastructure engineer investigating HTTP access and error logs"

const httplogDomainRules = `- Cite URIs, status codes, and client addresses exactly as they appear in the corpus evidence — never normalize or invent them.
- Status-code classes ("5xx", "4xx") describe a group of responses; do not present a class as a single status code.`

var (
	httplogConversationPrompt = investigate.ConversationPromptFor(httplogDomainRole, httplogDomainRules)
	httplogLogLinePrompt      = investigate.LineAnalysisPromptFor(httplogDomainRole, httplogDomainRules)
)

// ── query helpers (all nil-guarded) ─────────────────────────────────────────

// countSeverity returns how many corpus events carry the exact severity
// class ("5xx", "4xx", ...).
func countSeverity(s *investigate.LogSession, sev string) int {
	if s == nil {
		return 0
	}
	_, n := s.Query(investigate.LogQuery{Severity: sev, Limit: 1})
	return n
}

var slowEventRe2 = regexp.MustCompile(`\(\d{4,}ms\)`)

// countSlow returns how many corpus events carry a 4+ digit latency suffix.
func countSlow(s *investigate.LogSession) int {
	if s == nil {
		return 0
	}
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	n := 0
	for _, e := range events {
		if slowEventRe2.MatchString(e.Message) || slowEventRe2.MatchString(e.Raw) {
			n++
		}
	}
	return n
}

var (
	reUpstream = investigate.Re(`upstream timed out|connect\(\) failed|no live upstreams|upstream prematurely`)
	reTLS      = investigate.Re(`SSL_do_handshake|certificate|TLS handshake`)
)

// corpusHas reports whether any event in the corpus matches the pattern
// (Message or Raw).
func corpusHas(s *investigate.LogSession, re *regexp.Regexp) bool {
	if s == nil {
		return false
	}
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	for _, e := range events {
		if re.MatchString(e.Message) || re.MatchString(e.Raw) {
			return true
		}
	}
	return false
}

// ── symptom catalog ──────────────────────────────────────────────────────────

var httplogSymptomCatalog = []investigate.Symptom{
	{
		Key:      "burst-5xx",
		Title:    "5xx error burst",
		Category: "Availability",
		Severity: plugin.SeverityHigh,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d server-error (5xx) response(s) in the corpus.", countSeverity(sessionOf(f), "5xx"))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return countSeverity(sessionOf(f), "5xx") >= 3
		},
		Checks: []investigate.Check{
			{Collector: "corpus-5xx", Reason: "the 5xx lines themselves show which URIs and clients are failing", Priority: 1},
			{Collector: "http-error-log", Reason: "the live error log shows whether the failures are ongoing", Priority: 2},
			{Collector: "corpus-window", Reason: "the lines around the worst error show what changed at that moment", Priority: 2},
			{Collector: "stats-summary", Reason: "the status-code histogram shows how widespread the errors are", Priority: 3},
			{Collector: "history", Reason: "recurring 5xx bursts point at a chronic cause", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Backend/upstream failing behind the web server", Base: 55,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: investigate.Re(`upstream|connect\(\) failed|502|504`), Weight: 25}}},
			{Title: "Recent deploy broke request handling", Base: 40,
				For: []investigate.EvidenceMatcher{{Kind: "history", Pattern: investigate.Re(`change`), Weight: 20}}},
			{Title: "Web server resource exhaustion", Base: 30,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`worker|resource|memory`), Weight: 15}}},
		},
	},
	{
		Key:      "latency-degradation",
		Title:    "Latency degradation",
		Category: "Performance",
		Severity: plugin.SeverityMedium,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d slow request(s) (≥1000ms) in the corpus.", countSlow(sessionOf(f)))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return countSlow(sessionOf(f)) >= 3
		},
		Checks: []investigate.Check{
			{Collector: "corpus-slow", Reason: "the slow lines show which routes carry the high latency", Priority: 1},
			{Collector: "stats-summary", Reason: "the slow-request count bounds how widespread it is", Priority: 2},
			{Collector: "sys-memory", Reason: "memory pressure forces paging, which shows up as latency", Priority: 3},
			{Collector: "sys-disk", Reason: "a full or slow disk stalls logging and static serving", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Slow backend or database behind the affected routes", Base: 50},
			{Title: "Host resource saturation", Base: 35,
				For: []investigate.EvidenceMatcher{{Kind: "metric", Pattern: investigate.Re(`9[0-9]%`), Weight: 20}}},
		},
	},
	{
		Key:      "upstream-failure",
		Title:    "Upstream / backend failure",
		Category: "Availability",
		Severity: plugin.SeverityHigh,
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return corpusHas(sessionOf(f), reUpstream)
		},
		Checks: []investigate.Check{
			{Collector: "corpus-upstream", Reason: "upstream error lines name the failing backend", Priority: 1},
			{Collector: "http-error-log", Reason: "the live error log shows whether upstream failures are ongoing", Priority: 2},
			{Collector: "corpus-frequency", Reason: "the failure rate distinguishes an outage from a blip", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Upstream service down or unreachable", Base: 60,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`no live upstreams|connection refused`), Weight: 20}}},
			{Title: "Upstream too slow for the configured timeouts", Base: 40,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`timed out`), Weight: 20}}},
		},
	},
	{
		Key:      "tls-error",
		Title:    "TLS / certificate errors",
		Category: "Security",
		Severity: plugin.SeverityHigh,
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return corpusHas(sessionOf(f), reTLS)
		},
		Checks: []investigate.Check{
			{Collector: "corpus-tls", Reason: "the TLS/SSL error lines name the failing handshake stage", Priority: 1},
			{Collector: "http-error-log", Reason: "the live error log shows whether TLS failures are ongoing", Priority: 2},
			{Collector: "cert-expiry", Reason: "an expired or soon-to-expire certificate is the most common TLS cause", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Certificate expired or mismatched", Base: 55,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`certificate`), Weight: 20}}},
			{Title: "Client/protocol mismatch noise", Base: 30},
		},
	},
	{
		Key:      "client-4xx-spike",
		Title:    "Client 4xx spike",
		Category: "Security",
		Severity: plugin.SeverityMedium,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d client-error (4xx) response(s) — possible scanner or broken client.", countSeverity(sessionOf(f), "4xx"))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return countSeverity(sessionOf(f), "4xx") >= 10
		},
		Checks: []investigate.Check{
			{Collector: "corpus-frequency", Reason: "the per-minute burst profile separates a scan from a client bug", Priority: 1},
			{Collector: "stats-summary", Reason: "the top URIs and clients show what's being probed or broken", Priority: 2},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Scanner or misbehaving client probing the site", Base: 50},
			{Title: "Broken links or client integration after a change", Base: 35,
				For: []investigate.EvidenceMatcher{{Kind: "history", Pattern: investigate.Re(`change`), Weight: 20}}},
		},
	},
	{
		Key:      "traffic-anomaly",
		Title:    "Traffic anomaly",
		Category: "Reliability",
		Severity: plugin.SeverityLow,
		Fallback: true,
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return sessionOf(f) != nil
		},
		Checks: []investigate.Check{
			{Collector: "stats-summary", Reason: "the computed request statistics are the fastest anomaly overview", Priority: 1},
			{Collector: "corpus-frequency", Reason: "error-rate bursts localize when the anomaly started", Priority: 2},
			{Collector: "history", Reason: "prior investigations reveal whether this is recurring", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Traffic pattern shift — compare with a known-good window", Base: 35},
		},
	},
}

// ── resource graph ───────────────────────────────────────────────────────────

var httplogEdgeRegistry = []investigate.Edge{
	{Name: "route→errors", Collector: "corpus-5xx", Why: "a route's 5xx lines are the direct failure record"},
	{Name: "server→error-log", Collector: "http-error-log", Why: "the live error log shows whether failures are ongoing"},
	{Name: "server→service", Collector: "svc-status", Why: "the web server process must be running to serve anything"},
	{Name: "host→memory", Collector: "sys-memory", Why: "memory exhaustion degrades every route at once"},
	{Name: "host→disk", Collector: "sys-disk", Why: "a full disk stalls logging and static content serving"},
	{Name: "server→tls", Collector: "cert-expiry", Why: "certificate state explains TLS handshake failures"},
	{Name: "corpus→window", Collector: "corpus-window", Why: "the lines around the worst event show the trigger"},
	{Name: "corpus→frequency", Collector: "corpus-frequency", Why: "burst timing separates a spike from a steady failure"},
	{Name: "resource→history", Collector: "history", Why: "recurrence and past fixes shortcut the investigation"},
}

// ── intents ──────────────────────────────────────────────────────────────────

func httplogIntentPatterns() []investigate.IntentPattern {
	return append(investigate.CommonIntentPatterns(),
		investigate.IntentPattern{Intent: "latency", Re: investigate.Re(`slow|latency|response time`)},
		investigate.IntentPattern{Intent: "upstream", Re: investigate.Re(`upstream|backend|proxy`)},
		investigate.IntentPattern{Intent: "tls", Re: investigate.Re(`\btls\b|\bssl\b|certificate|handshake`)},
		investigate.IntentPattern{Intent: "clients", Re: investigate.Re(`client|user agent|\bip\b|source`)},
		investigate.IntentPattern{Intent: "errors", Re: investigate.Re(`\b5\d\d\b|\b4\d\d\b|error rate`)},
	)
}

var httplogIntentChecks = map[string][]investigate.Check{
	"latency": {
		{Collector: "corpus-slow", Reason: "you asked about latency — searching the corpus for slow requests", Priority: 1},
		{Collector: "stats-summary", Reason: "the slow-request count bounds how widespread it is", Priority: 2},
	},
	"upstream": {
		{Collector: "corpus-upstream", Reason: "you asked about the upstream — searching the corpus", Priority: 1},
		{Collector: "http-error-log", Reason: "the live error log shows current upstream failures", Priority: 2},
	},
	"tls": {
		{Collector: "corpus-tls", Reason: "you asked about TLS/SSL — searching the corpus", Priority: 1},
		{Collector: "cert-expiry", Reason: "checking whether the certificate is the cause", Priority: 2},
	},
	"clients": {
		{Collector: "stats-summary", Reason: "you asked about clients — the top-client breakdown", Priority: 1},
	},
	"errors": {
		{Collector: "corpus-5xx", Reason: "you asked about server errors", Priority: 1},
		{Collector: "corpus-frequency", Reason: "the burst profile shows when the errors spiked", Priority: 2},
	},
	"previous-logs": {
		{Collector: "corpus-window", Reason: "you asked what happened before — showing the lines around the worst event", Priority: 1},
	},
	"comparison": {{Collector: "history", Reason: "comparing with the past needs the historical record", Priority: 1}},
	"history":    {{Collector: "history", Reason: "you asked whether this happened before", Priority: 1}},
	"rca":        {{Collector: "history", Reason: "an RCA should note recurrence", Priority: 1}},
}

// ── collectors ───────────────────────────────────────────────────────────────

var httplogCollectorTTL = map[string]time.Duration{
	"corpus-window":    10 * time.Minute,
	"corpus-frequency": 10 * time.Minute,
	"corpus-5xx":       10 * time.Minute,
	"corpus-slow":      10 * time.Minute,
	"corpus-tls":       10 * time.Minute,
	"corpus-upstream":  10 * time.Minute,
	"stats-summary":    10 * time.Minute,
	"history":          10 * time.Minute,
	"http-error-log":   90 * time.Second,
	"svc-status":       90 * time.Second,
	"sys-memory":       90 * time.Second,
	"sys-disk":         90 * time.Second,
	"cert-expiry":      90 * time.Second,
}

// renderHTTPStats renders the analyzer-typed stats for the stats-summary
// evidence excerpt.
func renderHTTPStats(stats any) string {
	st, ok := stats.(HTTPStats)
	if !ok {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "slow requests (>=%dms): %d\n", slowRequestMs, st.SlowRequests)
	if len(st.CodeHistogram) > 0 {
		b.WriteString("status codes: ")
		b.WriteString(httpNameCountList(st.CodeHistogram))
		b.WriteString("\n")
	}
	if len(st.TopURIs) > 0 {
		b.WriteString("top URIs: ")
		b.WriteString(httpNameCountList(st.TopURIs))
		b.WriteString("\n")
	}
	if len(st.TopClients) > 0 {
		b.WriteString("top clients: ")
		b.WriteString(httpNameCountList(st.TopClients))
		b.WriteString("\n")
	}
	if len(st.Bursts5xx) > 0 {
		b.WriteString("busiest 5xx minute(s): ")
		b.WriteString(httpBucketList(st.Bursts5xx))
		b.WriteString("\n")
	}
	if len(st.RequestTimeline) > 0 {
		fmt.Fprintf(&b, "request timeline: %d minute bucket(s), %s → %s",
			len(st.RequestTimeline), st.RequestTimeline[0].T, st.RequestTimeline[len(st.RequestTimeline)-1].T)
	}
	return b.String()
}

func httpNameCountList(counts []NameCount) string {
	parts := make([]string, 0, len(counts))
	for _, c := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", c.Name, c.Count))
	}
	return strings.Join(parts, ", ")
}

func httpBucketList(buckets []TimeBucket) string {
	parts := make([]string, 0, len(buckets))
	for _, b := range buckets {
		parts = append(parts, fmt.Sprintf("%s=%d", b.T, b.Count))
	}
	return strings.Join(parts, ", ")
}

func httplogCollectors() map[string]investigate.Collector {
	return map[string]investigate.Collector{
		"corpus-window":    investigate.CorpusWindowCollector("Log window around the worst event inspected", 2*time.Minute, 2*time.Minute),
		"corpus-frequency": investigate.CorpusFrequencyCollector("Error-rate burst profile computed"),
		"stats-summary":    investigate.StatsSummaryCollector("Computed request statistics summarized", renderHTTPStats),
		"corpus-5xx":       investigate.CorpusSearchCollector("5xx responses searched", regexp.MustCompile(`→ 5\d\d| 5\d\d `), "corpus-5xx"),
		"corpus-slow":      investigate.CorpusSearchCollector("Slow requests searched", slowEventRe2, "corpus-slow"),
		"corpus-tls":       investigate.CorpusSearchCollector("TLS/SSL errors searched", reTLS, "corpus-tls"),
		"corpus-upstream":  investigate.CorpusSearchCollector("Upstream failures searched", reUpstream, "corpus-upstream"),
		"http-error-log":   investigate.DiagCollector("Live error log tailed", "http-error-log", nil, runDiag),
		"svc-status": investigate.DiagCollector("Web server service status checked", "svc-status",
			func(investigate.CollectCtx) string { return "nginx" }, runDiag),
		"sys-memory":  investigate.DiagCollector("Host memory pressure checked", "sys-memory", nil, runDiag),
		"sys-disk":    investigate.DiagCollector("Host disk usage checked", "sys-disk", nil, runDiag),
		"cert-expiry": investigate.DiagCollector("Certificate expiry checked", "cert-expiry", nil, runDiag),
		"history": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			return investigate.GatherHistory(ctx, cc.History, cc.Target.Scope, cc.Target.Name, cc.Now)
		},
	}
}

// ── confidence rules ─────────────────────────────────────────────────────────

var (
	httplogUpstreamLogRe = investigate.Re(`upstream|connect\(\) failed`)
	httplog5xxRe         = investigate.Re(`5\d\d`)
	httplogChangeRe      = investigate.Re(`(?i)change`)
	httplogAnyRe         = investigate.Re(`.`)
)

var httplogConfidenceRules = []investigate.ConfidenceRule{
	{
		Score: 90, Reason: "the error log confirms the upstream failure behind the 5xx responses",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", httplogUpstreamLogRe) &&
				investigate.EvidenceMatching(ev, "log", httplog5xxRe)
		},
	},
	{
		Score: 75, Reason: "the error burst timing matches a recorded change",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "history", httplogChangeRe)
		},
	},
	{
		Score: 60, Reason: "the conclusion rests on access-log pattern evidence only — no live state corroborates it",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", httplogAnyRe)
		},
	},
	{
		Score: 45, Reason: "only computed metrics are available — no matching log line was found",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "metric", httplogAnyRe) && !investigate.EvidenceMatching(ev, "log", httplogAnyRe)
		},
	},
	{
		Score: 30, Reason: "only weak, indirect correlation available",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return len(ev) > 0
		},
	},
}

// ── prevention catalog ───────────────────────────────────────────────────────

var httplogPreventionCatalog = map[string][]plugin.RemediationAction{
	"burst-5xx": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Add SLO burn-rate alerts on the error ratio and health-gate deploys so traffic never routes to a failing backend."}},
	"latency-degradation": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Track p95/p99 latency per route with alerts, and load-test before raising traffic."}},
	"upstream-failure": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Add upstream health checks with automatic failover and circuit breakers."}},
	"tls-error": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Automate certificate renewal (ACME) and alert 21 days before expiry."}},
	"client-4xx-spike": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Rate-limit abusive clients at the edge and monitor 404 hot-spots after releases."}},
	"traffic-anomaly": {{Kind: "advice", FixType: "prevention", Risk: "low",
		Description: "Baseline requests/sec per route and alert on deviation."}},
}

// ── hooks ────────────────────────────────────────────────────────────────────

// httplogBaseline contributes the free corpus-overview evidence every turn.
func httplogBaseline(_ context.Context, f investigate.Facts, _ investigate.Target, _ time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	s := sessionOf(f)
	if s == nil || s.Len() == 0 {
		return []plugin.InvestigationStep{{Label: "Corpus loaded", Status: "unavailable",
			Detail: "no HTTP log analysis session — run an analysis first"}}, nil
	}
	from, to := s.TimeRange()
	span := "no timestamped events"
	if !from.IsZero() {
		span = from.Format(time.RFC3339) + " → " + to.Format(time.RFC3339)
	}
	excerpt := fmt.Sprintf("%d event(s) from %d source(s); time range %s", s.Len(), len(s.Sources), span)
	if s.Truncated() > 0 {
		excerpt += fmt.Sprintf("; %d oldest event(s) dropped to session caps", s.Truncated())
	}
	steps := []plugin.InvestigationStep{{Label: "Corpus loaded", Status: "done",
		Detail: fmt.Sprintf("%d event(s) from %d source(s)", s.Len(), len(s.Sources))}}
	evid := []plugin.EvidenceItem{{Kind: "metric", Source: "corpus", Excerpt: excerpt}}
	return steps, evid
}

// httplogTimelineSeverity maps a normalized event severity onto the UI tiers.
func httplogTimelineSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "crit", "emerg", "alert", "critical", "fatal":
		return "critical"
	case "err", "error", "5xx":
		return "high"
	case "warn", "warning", "4xx":
		return "medium"
	}
	return "info"
}

// httplogTimelineRank orders error-class events for "worst first" selection.
func httplogTimelineRank(severity string) int {
	switch httplogTimelineSeverity(severity) {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	}
	return 0
}

// httplogTimeline returns the worst <=12 error-class events for the focus (or
// the whole corpus), in ascending time order.
func httplogTimeline(f investigate.Facts, t investigate.Target, _ time.Time) []plugin.TimelineEvent {
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
		if e.At.IsZero() || httplogTimelineRank(e.Severity) < 1 {
			continue
		}
		errs = append(errs, e)
	}
	sort.SliceStable(errs, func(i, j int) bool {
		ri, rj := httplogTimelineRank(errs[i].Severity), httplogTimelineRank(errs[j].Severity)
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
			At: e.At, Label: label, Severity: httplogTimelineSeverity(e.Severity),
			Source: "event", Detail: e.Unit,
		})
	}
	return out
}

// httplogSuggestFollowUps proposes up to five next questions, skipping
// intents already asked this turn.
func httplogSuggestFollowUps(intents []string, f investigate.Facts, _ []plugin.InvestigationStep) []string {
	var out []string
	add := func(intent, s string) {
		if len(out) < 5 && !investigate.HasIntent(intents, intent) {
			out = append(out, s)
		}
	}
	s := sessionOf(f)
	if s != nil && countSeverity(s, "5xx") > 0 {
		add("errors", "Show the 5xx errors")
	}
	add("latency", "Are any requests slow?")
	add("upstream", "Check the upstream/backend state")
	add("clients", "Who are the top clients?")
	add("rca", "Generate an RCA")
	return out
}

// httplogProfile builds the HTTP log investigation profile from the package
// catalogs.
func httplogProfile() investigate.Profile {
	return investigate.Profile{
		Name:            "httplog",
		Symptoms:        httplogSymptomCatalog,
		Edges:           httplogEdgeRegistry,
		IntentPatterns:  httplogIntentPatterns(),
		IntentChecks:    httplogIntentChecks,
		Collectors:      httplogCollectors(),
		ConfidenceRules: httplogConfidenceRules,
		Prevention:      httplogPreventionCatalog,
		TTLs:            httplogCollectorTTL,

		ConversationPrompt: httplogConversationPrompt,
		LogLinePrompt:      httplogLogLinePrompt,

		ResolveFocus: func(prev, _, message string, f investigate.Facts) string {
			s := sessionOf(f)
			if s == nil {
				return prev
			}
			return investigate.ResolveFocusFromVocabulary(prev, message, s)
		},
		Baseline:         httplogBaseline,
		Timeline:         httplogTimeline,
		SuggestFollowUps: httplogSuggestFollowUps,
	}
}

// InvestigationProfile exposes the httplog profile for the investigation
// engine.
func (p *Plugin) InvestigationProfile() investigate.Profile {
	return httplogProfile()
}
