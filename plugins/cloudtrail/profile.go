package cloudtrail

// profile.go assembles the CLOUDTRAIL investigation Profile for the generic
// framework (internal/investigate). The domain Facts are the parsed
// *investigate.LogSession corpus from the most recent analyze run; symptom
// matchers, collectors, confidence rules, and prevention advice all reason
// over that corpus. Unlike syslog/httplog there is no remote host to run
// allowlisted diagnostics against — AWS API activity is corpus-only, so
// every collector here is a Corpus* constructor or the framework's history
// gatherer. Per-turn pipeline is the framework engine's.

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

// Corpus signature patterns — shared by symptom matchers and corpus
// collectors. Regexes match against the raw NDJSON line, so field names are
// quoted the way encoding/json renders them.
var (
	reRoot         = investigate.Re(`"type"\s*:\s*"Root"`)
	reAccessDenied = investigate.Re(`"errorCode"\s*:\s*"(AccessDenied|UnauthorizedOperation|Client\.UnauthorizedAccess|AccessDeniedException)"`)
	reLoginFail    = investigate.Re(`"eventName"\s*:\s*"ConsoleLogin".*(failure|errorMessage)`)
	reDeletion     = investigate.Re(`"eventName"\s*:\s*"(Delete|Terminate|Remove)\w*"`)
	rePrivEsc      = investigate.Re(`"eventName"\s*:\s*"(PutUserPolicy|PutRolePolicy|AttachUserPolicy|AttachRolePolicy|CreateAccessKey|CreateLoginProfile|AddUserToGroup|UpdateAssumeRolePolicy)"`)
)

// sessionOf unwraps the corpus session from the framework's opaque Facts.
func sessionOf(f investigate.Facts) *investigate.LogSession {
	s, _ := f.(*investigate.LogSession)
	return s
}

// corpusHas reports whether any event in the corpus matches the pattern
// (Message or Raw).
func corpusHas(s *investigate.LogSession, re *regexp.Regexp) bool {
	return corpusCount(s, re) > 0
}

// corpusCount counts corpus events matching the pattern.
func corpusCount(s *investigate.LogSession, re *regexp.Regexp) int {
	if s == nil {
		return 0
	}
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	n := 0
	for _, e := range events {
		if re.MatchString(e.Message) || re.MatchString(e.Raw) {
			n++
		}
	}
	return n
}

// severeRank orders cloudtrail severities worst-first; -1 means "not
// notable enough for the timeline" (routine info-level activity).
func severeRank(sev string) int {
	switch sev {
	case "crit":
		return 0
	case "err":
		return 1
	case "warn":
		return 2
	default:
		return -1
	}
}

// hasNotableEvents reports whether the corpus contains at least one
// crit/err/warn event — the fallback symptom's trigger.
func hasNotableEvents(s *investigate.LogSession) bool {
	if s == nil {
		return false
	}
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	for _, e := range events {
		if severeRank(e.Severity) >= 0 {
			return true
		}
	}
	return false
}

// matchCorpus adapts a session-typed matcher into the framework signature,
// guarding the nil / wrong-type Facts case.
func matchCorpus(fn func(s *investigate.LogSession, t investigate.Target) bool) func(investigate.Facts, investigate.Target) bool {
	return func(f investigate.Facts, t investigate.Target) bool {
		s := sessionOf(f)
		if s == nil {
			return false
		}
		return fn(s, t)
	}
}

// cloudtrailSymptomCatalog is what an experienced cloud security engineer
// checks FIRST for each CloudTrail risk signature, and the candidate causes
// to rank.
var cloudtrailSymptomCatalog = []investigate.Symptom{
	{
		Key: "root-account-usage",
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return corpusHas(s, reRoot)
		}),
		Checks: []investigate.Check{
			{Collector: "corpus-root", Reason: "root-account API calls name exactly what was done and from where", Priority: 1},
			{Collector: "stats-summary", Reason: "the overall activity mix shows whether this is isolated or routine", Priority: 2},
			{Collector: "history", Reason: "a recurring root login points at a broken automation, not a one-off", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Root account credentials used directly for API calls", Base: 70,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: investigate.Re(`"type"\s*:\s*"Root"`), Weight: 20}},
			},
			{Title: "Break-glass procedure or emergency access, as intended", Base: 30},
		},
	},
	{
		Key: "access-denied-spike",
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return corpusCount(s, reAccessDenied) >= 3
		}),
		Checks: []investigate.Check{
			{Collector: "corpus-denied", Reason: "denied calls name the principal and the API they tried", Priority: 1},
			{Collector: "corpus-window", Reason: "calls immediately around a denial show what the principal tried next", Priority: 2},
			{Collector: "stats-summary", Reason: "the overall error rate distinguishes a spike from background noise", Priority: 3},
			{Collector: "history", Reason: "a principal denied before points at a chronic permissions gap", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Compromised or misconfigured credentials probing for access", Base: 55,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: reAccessDenied, Weight: 20}},
			},
			{Title: "A recent IAM policy change is more restrictive than the caller expects", Base: 40},
		},
	},
	{
		Key: "console-login-failure",
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return corpusHas(s, reLoginFail)
		}),
		Checks: []investigate.Check{
			{Collector: "corpus-login-fail", Reason: "failed console logins name the account and source IP targeted", Priority: 1},
			{Collector: "corpus-frequency", Reason: "the failure rate distinguishes a brute force from a forgotten password", Priority: 2},
			{Collector: "history", Reason: "repeated targeting of the same account is the clearest signal", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Brute-force or credential-stuffing attempt against the console", Base: 55,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: reLoginFail, Weight: 20}},
			},
			{Title: "Legitimate user mistyped a password or MFA code", Base: 35},
		},
	},
	{
		Key: "resource-deletion",
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return corpusHas(s, reDeletion)
		}),
		Checks: []investigate.Check{
			{Collector: "corpus-deletion", Reason: "deletion calls name exactly which resource and who removed it", Priority: 1},
			{Collector: "corpus-window", Reason: "calls around the deletion show whether it was part of a larger action", Priority: 2},
			{Collector: "history", Reason: "prior incidents or changes may explain a planned decommission", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Deliberate cleanup or decommission", Base: 40},
			{
				Title: "Accidental or malicious destructive action", Base: 45,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: reAccessDenied, Weight: 0}},
			},
		},
	},
	{
		Key: "privilege-escalation",
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return corpusHas(s, rePrivEsc)
		}),
		Checks: []investigate.Check{
			{Collector: "corpus-privesc", Reason: "IAM policy/key API calls name the principal granting itself access", Priority: 1},
			{Collector: "stats-summary", Reason: "the broader activity mix shows whether this fits routine IAM admin", Priority: 2},
			{Collector: "history", Reason: "a principal that has done this before is the strongest signal", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Legitimate IAM administration", Base: 35},
			{
				Title: "Privilege escalation via IAM policy or access-key manipulation", Base: 50,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: rePrivEsc, Weight: 20}},
			},
		},
	},
	{
		Key:      "unknown-activity",
		Fallback: true,
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return hasNotableEvents(s)
		}),
		Checks: []investigate.Check{
			{Collector: "stats-summary", Reason: "start from the overall shape of the activity", Priority: 1},
			{Collector: "corpus-frequency", Reason: "the rate of notable events over time frames every other check", Priority: 2},
			{Collector: "history", Reason: "whatever happened before is the first suspect", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Normal AWS API activity — no specific anomaly pattern matched", Base: 25},
		},
	},
}

// cloudtrailEdgeRegistry documents the resource-graph relationships the
// planner can follow and why they matter.
var cloudtrailEdgeRegistry = []investigate.Edge{
	{Name: "principal→history", Collector: "history", Why: "prior investigations and incidents cover recurrence for this principal or event type"},
	{Name: "corpus→window", Collector: "corpus-window", Why: "calls immediately around the worst event show the lead-up and follow-through"},
	{Name: "corpus→frequency", Collector: "corpus-frequency", Why: "the rate over time distinguishes an ongoing campaign from a one-off"},
}

// cloudtrailIntentPatterns extend the framework's common intents with
// CloudTrail domain vocabulary.
var cloudtrailIntentPatterns = append(investigate.CommonIntentPatterns(), []investigate.IntentPattern{
	{Intent: "access-denied", Re: investigate.Re(`denied|unauthorized|forbidden`)},
	{Intent: "root-usage", Re: investigate.Re(`\broot\b`)},
	{Intent: "deletion", Re: investigate.Re(`delete|terminat|remov`)},
	{Intent: "login", Re: investigate.Re(`login|console|sign.?in`)},
	{Intent: "privesc", Re: investigate.Re(`polic|privilege|escalat|access key`)},
}...)

// cloudtrailIntentChecks maps question intents to collector requests —
// asking about deletions schedules the deletion search even without a
// matching symptom. "refresh" is handled by the engine itself.
var cloudtrailIntentChecks = map[string][]investigate.Check{
	"access-denied": {
		{Collector: "corpus-denied", Reason: "you asked about denied calls — searching the corpus", Priority: 1},
		{Collector: "corpus-frequency", Reason: "the denial rate shows whether this is ongoing", Priority: 2},
	},
	"root-usage": {
		{Collector: "corpus-root", Reason: "you asked about root — searching for root-account activity", Priority: 1},
	},
	"deletion": {
		{Collector: "corpus-deletion", Reason: "you asked about deletions — searching the corpus", Priority: 1},
		{Collector: "corpus-window", Reason: "calls around a deletion show the broader context", Priority: 2},
	},
	"login": {
		{Collector: "corpus-login-fail", Reason: "you asked about console logins — searching for failures", Priority: 1},
	},
	"privesc": {
		{Collector: "corpus-privesc", Reason: "you asked about privilege/policy changes — searching the corpus", Priority: 1},
	},
	"previous-logs": {
		{Collector: "corpus-window", Reason: "you asked for the calls before the event", Priority: 1},
	},
	"comparison": {
		{Collector: "history", Reason: "comparing with the past needs prior investigations and incidents", Priority: 1},
		{Collector: "corpus-frequency", Reason: "the current rate is the comparison baseline", Priority: 2},
	},
	"history": {
		{Collector: "history", Reason: "you asked whether this happened before", Priority: 1},
		{Collector: "corpus-frequency", Reason: "the rate shows how the current episode compares", Priority: 2},
	},
	"rca": {
		{Collector: "history", Reason: "an RCA should note recurrence", Priority: 1},
		{Collector: "corpus-frequency", Reason: "an RCA needs the event's rate and timing", Priority: 2},
	},
}

// cloudtrailCollectorTTL is the per-collector evidence-cache freshness
// window. Every collector reads the immutable in-memory corpus snapshot, so
// all TTLs are the same, generous window.
var cloudtrailCollectorTTL = map[string]time.Duration{
	"corpus-window":     10 * time.Minute,
	"corpus-frequency":  10 * time.Minute,
	"stats-summary":     10 * time.Minute,
	"corpus-root":       10 * time.Minute,
	"corpus-denied":     10 * time.Minute,
	"corpus-login-fail": 10 * time.Minute,
	"corpus-deletion":   10 * time.Minute,
	"corpus-privesc":    10 * time.Minute,
	"history":           10 * time.Minute,
}

// renderCloudTrailStats renders the analyzer-typed stats payload for
// evidence.
func renderCloudTrailStats(stats any) string {
	st, ok := stats.(CloudTrailStats)
	if !ok {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "root usage: %d; access denied: %d; console login failures: %d; resource deletions: %d",
		st.RootUsage, st.AccessDenied, st.ConsoleLoginFailures, st.ResourceDeletions)
	if len(st.TopEventNames) > 0 {
		var parts []string
		for _, e := range st.TopEventNames {
			parts = append(parts, fmt.Sprintf("%s (%d)", e.Name, e.Count))
		}
		fmt.Fprintf(&b, "; top event names: %s", strings.Join(parts, ", "))
	}
	if len(st.TopPrincipals) > 0 {
		var parts []string
		for _, p := range st.TopPrincipals {
			parts = append(parts, fmt.Sprintf("%s (%d)", p.Name, p.Count))
		}
		fmt.Fprintf(&b, "; top principals: %s", strings.Join(parts, ", "))
	}
	return b.String()
}

// cloudtrailCollectors is the dispatch table: corpus queries and the
// framework's history gatherer. No remote diagnostics — AWS API activity has
// no host to SSH into.
func cloudtrailCollectors() map[string]investigate.Collector {
	return map[string]investigate.Collector{
		"corpus-window":    investigate.CorpusWindowCollector("Corpus window around worst event", 5*time.Minute, 2*time.Minute),
		"corpus-frequency": investigate.CorpusFrequencyCollector("Event frequency profiled"),
		"stats-summary":    investigate.StatsSummaryCollector("Analysis statistics summarized", renderCloudTrailStats),
		"corpus-root": investigate.CorpusSearchCollector("Root account usage searched", reRoot,
			`jq -c 'select(.userIdentity.type=="Root")' cloudtrail.ndjson`),
		"corpus-denied": investigate.CorpusSearchCollector("Access-denied calls searched", reAccessDenied,
			`jq -c 'select(.errorCode != null)' cloudtrail.ndjson`),
		"corpus-login-fail": investigate.CorpusSearchCollector("Console login failures searched", reLoginFail,
			`jq -c 'select(.eventName=="ConsoleLogin")' cloudtrail.ndjson`),
		"corpus-deletion": investigate.CorpusSearchCollector("Resource deletions searched", reDeletion,
			`jq -c 'select(.eventName | test("^(Delete|Terminate|Remove)"))' cloudtrail.ndjson`),
		"corpus-privesc": investigate.CorpusSearchCollector("Privilege-escalation API calls searched", rePrivEsc,
			`jq -c 'select(.eventName | test("PutUserPolicy|AttachUserPolicy|CreateAccessKey"))' cloudtrail.ndjson`),
		"history": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			return investigate.GatherHistory(ctx, cc.History, cc.Target.Scope, cc.Target.Name, cc.Now)
		},
	}
}

// cloudtrailConfidenceRules is the CloudTrail evidence-quality table: root
// usage observed directly beats an AWS-confirmed error code, which beats
// statistical corroboration, which beats a single matching line.
var cloudtrailConfidenceRules = []investigate.ConfidenceRule{
	{
		Score: 95, Reason: "root account credentials were directly observed in the matched event",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", investigate.Re(`"type"\s*:\s*"Root"`))
		},
	},
	{
		Score: 85, Reason: "AWS itself recorded an error/denial for the matched API calls",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", investigate.Re(`"errorCode"`))
		},
	},
	{
		Score: 70, Reason: "the pattern repeats across multiple events, not just one",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "metric", investigate.Re(`.`))
		},
	},
	{
		Score: 60, Reason: "the conclusion rests on a single matching event only",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", investigate.Re(`.`))
		},
	},
	{
		Score: 30, Reason: "only weak, indirect correlation available",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return len(ev) > 0
		},
	},
}

// cloudtrailPreventionCatalog maps symptom keys to preventive advice. Kind
// "advice" keeps them copy-only — prevention is a policy decision, never
// auto-applied.
var cloudtrailPreventionCatalog = map[string][]plugin.RemediationAction{
	"root-account-usage": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Enable MFA on the root account and stop using it for day-to-day API calls; create a named admin IAM role instead."},
	},
	"access-denied-spike": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Review the IAM policy attached to this principal and confirm whether the denials are expected tightening or a sign of probing."},
	},
	"console-login-failure": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Enforce MFA for console sign-in and alert on repeated failures against the same account."},
	},
	"resource-deletion": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Enable deletion/termination protection on production resources and require change approval for destructive calls."},
	},
	"privilege-escalation": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Restrict IAM policy and access-key management to a small break-glass role, and alert on any use outside it."},
	},
	"unknown-activity": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "No action needed — this reflects routine AWS API activity."},
	},
}

// cloudtrailRole is the domain persona for both prompt skeletons.
const cloudtrailRole = "a senior cloud security engineer investigating AWS CloudTrail activity with an operator"

// timelineSeverity maps a session severity onto the TimelineEvent scale.
func timelineSeverity(sev string) string {
	switch sev {
	case "crit":
		return "critical"
	case "err":
		return "high"
	case "warn":
		return "medium"
	default:
		return "info"
	}
}

// buildCloudTrailTimeline picks the worst ≤12 notable events for the focus
// event name (corpus-wide when no focus is set) and returns them oldest-first.
func buildCloudTrailTimeline(s *investigate.LogSession, t investigate.Target) []plugin.TimelineEvent {
	if s == nil {
		return nil
	}
	events, _ := s.Query(investigate.LogQuery{Unit: t.Name, Limit: investigate.MaxSessionEvents})
	if t.Name == "" {
		events, _ = s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	}
	var notable []investigate.LogEvent
	for _, e := range events {
		if e.At.IsZero() || severeRank(e.Severity) < 0 {
			continue
		}
		notable = append(notable, e)
	}
	sort.SliceStable(notable, func(i, j int) bool {
		ri, rj := severeRank(notable[i].Severity), severeRank(notable[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return notable[i].At.After(notable[j].At)
	})
	if len(notable) > 12 {
		notable = notable[:12]
	}
	sort.Slice(notable, func(i, j int) bool { return notable[i].At.Before(notable[j].At) })
	out := make([]plugin.TimelineEvent, 0, len(notable))
	for _, e := range notable {
		label := e.Unit
		if label == "" {
			label = e.Scope
		}
		if label == "" {
			label = "corpus"
		}
		out = append(out, plugin.TimelineEvent{
			At:       e.At,
			Label:    label,
			Severity: timelineSeverity(e.Severity),
			Source:   "event",
			Detail:   e.Message,
		})
	}
	return out
}

// suggestCloudTrailFollowUps proposes up to five next questions, skipping
// intents already asked this turn.
func suggestCloudTrailFollowUps(intents []string) []string {
	var out []string
	add := func(intent, s string) {
		if len(out) < 5 && !investigate.HasIntent(intents, intent) {
			out = append(out, s)
		}
	}
	add("access-denied", "Show me all AccessDenied events")
	add("root-usage", "Who used the root account?")
	add("deletion", "List every resource deletion")
	add("privesc", "Check for privilege escalation attempts")
	add("rca", "Generate an RCA")
	return out
}

// cloudtrailBaseline emits the free per-turn evidence: the corpus summary, or
// an honest "unavailable" step before the first analysis.
func cloudtrailBaseline(_ context.Context, f investigate.Facts, _ investigate.Target, _ time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	s := sessionOf(f)
	if s == nil || s.Len() == 0 {
		return []plugin.InvestigationStep{{Label: "Corpus loaded", Status: "unavailable",
			Detail: "no analysis session loaded — run an analysis first"}}, nil
	}
	from, to := s.TimeRange()
	rangeStr := "no timestamped events"
	if !from.IsZero() {
		rangeStr = from.Format(time.RFC3339) + " → " + to.Format(time.RFC3339)
	}
	summary := fmt.Sprintf("%d event(s) from %d source(s); time range %s; %d event(s) truncated by caps",
		s.Len(), len(s.Sources), rangeStr, s.Truncated())
	steps := []plugin.InvestigationStep{{Label: "Corpus loaded", Status: "done",
		Detail: fmt.Sprintf("%d event(s) from %d source(s)", s.Len(), len(s.Sources))}}
	evid := []plugin.EvidenceItem{{Kind: "metric", Source: "corpus-baseline", Excerpt: summary}}
	return steps, evid
}

// cloudtrailProfile builds the CloudTrail investigation profile from the
// package's catalogs. Package-level catalogs, per-turn state via Facts.
func cloudtrailProfile() investigate.Profile {
	return investigate.Profile{
		Name:            "cloudtrail",
		Symptoms:        cloudtrailSymptomCatalog,
		Edges:           cloudtrailEdgeRegistry,
		IntentPatterns:  cloudtrailIntentPatterns,
		IntentChecks:    cloudtrailIntentChecks,
		Collectors:      cloudtrailCollectors(),
		ConfidenceRules: cloudtrailConfidenceRules,
		Prevention:      cloudtrailPreventionCatalog,
		TTLs:            cloudtrailCollectorTTL,

		ConversationPrompt: investigate.ConversationPromptFor(cloudtrailRole,
			"- principal names and API call names must be quoted exactly as they appear in the corpus."),
		LogLinePrompt: investigate.LineAnalysisPromptFor(cloudtrailRole, ""),

		ResolveFocus: func(prev, _, message string, f investigate.Facts) string {
			s := sessionOf(f)
			if s == nil {
				return prev
			}
			return investigate.ResolveFocusFromVocabulary(prev, message, s)
		},
		Baseline: cloudtrailBaseline,
		Timeline: func(f investigate.Facts, t investigate.Target, _ time.Time) []plugin.TimelineEvent {
			return buildCloudTrailTimeline(sessionOf(f), t)
		},
		SuggestFollowUps: func(intents []string, _ investigate.Facts, _ []plugin.InvestigationStep) []string {
			return suggestCloudTrailFollowUps(intents)
		},
	}
}

// InvestigationProfile exposes the cloudtrail profile to the serve-time wiring.
func (p *Plugin) InvestigationProfile() investigate.Profile { return cloudtrailProfile() }
