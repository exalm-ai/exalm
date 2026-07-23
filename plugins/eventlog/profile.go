package eventlog

// profile.go assembles the Windows Event Log investigation Profile for the
// generic framework (internal/investigate). Everything domain-specific —
// symptom catalog, resource-graph edges, intent patterns, collectors,
// confidence rules, prevention advice, and prompt wording — lives here; the
// per-turn pipeline is the framework engine's.

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// diagRun is the remote diagnostics runner every DiagCollector registration
// uses. Package-level so tests can observe the wiring; the allowlist and
// tier gate live inside internal/ssh.
var diagRun investigate.DiagFn = investigate.SSHDiagRunner

// sess unwraps the corpus session from the framework's opaque Facts.
func sess(f investigate.Facts) *investigate.LogSession {
	s, _ := f.(*investigate.LogSession)
	return s
}

// Corpus search patterns shared by collectors and symptom matchers.
var (
	svcCrashRe = investigate.Re(`service.*(terminated|failed|stopped unexpectedly)|The .* service`)
	authFailRe = investigate.Re(`4625|4740|audit failure|logon failure`)
	updateRe   = investigate.Re(`WindowsUpdate|update.*fail|0x8\w{7}`)
	rebootRe   = investigate.Re(`unexpected(ly)? (shut ?down|reboot)|6008|Kernel-Power`)
)

// reWinServiceName captures a single-token Windows service short name from an
// SCM crash message ("The Spooler service terminated…"). It matches ONLY a
// space-free token, so a display name like "Print Spooler" yields no match
// (advice-only then) rather than an unusable `Restart-Service -Name` argument.
// The token shape is a subset of the SSH remediation allowlist's paramRe, so a
// name lifted from the corpus is injection-safe.
var reWinServiceName = regexp.MustCompile(`(?i)\bThe ([A-Za-z0-9_.\-]+) service\b`)

// crashedServiceFromCorpus returns the first single-token Windows service name
// named in an SCM crash line, or "" when none can be safely identified.
func crashedServiceFromCorpus(s *investigate.LogSession) string {
	if s == nil {
		return ""
	}
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	for _, e := range events {
		if !svcCrashRe.MatchString(e.Message) && !svcCrashRe.MatchString(e.Raw) {
			continue
		}
		if m := reWinServiceName.FindStringSubmatch(e.Message + " " + e.Raw); m != nil {
			return m[1]
		}
	}
	return ""
}

// countMatching counts corpus events whose Message or Raw matches re.
func countMatching(s *investigate.LogSession, re *regexp.Regexp) int {
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

// corpusMatches reports whether any event's Message or Raw matches re.
func corpusMatches(s *investigate.LogSession, re *regexp.Regexp) bool {
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

// codeCount returns how many events carry the given event ID.
func codeCount(s *investigate.LogSession, code string) int {
	if s == nil {
		return 0
	}
	_, total := s.Query(investigate.LogQuery{Code: code, Limit: 1})
	return total
}

// hasAnyCode reports whether any event carries one of the event IDs.
func hasAnyCode(s *investigate.LogSession, codes ...string) bool {
	for _, c := range codes {
		if codeCount(s, c) > 0 {
			return true
		}
	}
	return false
}

// hasProviderContaining reports whether any event's provider name contains
// one of the substrings (case-insensitive).
func hasProviderContaining(s *investigate.LogSession, substrings ...string) bool {
	if s == nil {
		return false
	}
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	for _, e := range events {
		unit := strings.ToLower(e.Unit)
		for _, sub := range substrings {
			if unit != "" && strings.Contains(unit, sub) {
				return true
			}
		}
	}
	return false
}

// errorClass reports whether a normalized severity is error-or-worse.
func errorClass(severity string) bool {
	switch strings.ToLower(severity) {
	case "emerg", "alert", "crit", "critical", "fatal", "err", "error":
		return true
	}
	return false
}

// hasErrorClassEvents reports whether the corpus holds at least one
// error-or-worse event.
func hasErrorClassEvents(s *investigate.LogSession) bool {
	if s == nil {
		return false
	}
	events, _ := s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	for _, e := range events {
		if errorClass(e.Severity) {
			return true
		}
	}
	return false
}

// timelineSeverity maps a normalized event severity to the timeline tier.
func timelineSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "crit", "emerg", "alert", "critical", "fatal":
		return "critical"
	case "err", "error", "5xx":
		return "high"
	case "warn", "warning":
		return "medium"
	}
	return "info"
}

// eventlogSymptoms is the Windows Event Log symptom catalog: what an
// experienced Windows administrator checks FIRST for each failure mode, and
// the candidate causes the hypothesis engine ranks against the evidence.
var eventlogSymptoms = []investigate.Symptom{
	{
		Key:      "service-crash",
		Title:    "Windows service crash",
		Category: "Availability",
		Severity: plugin.SeverityHigh,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			s := sess(f)
			if svc := crashedServiceFromCorpus(s); svc != "" {
				return fmt.Sprintf("Service Control Manager reported crashes; %s is among the failed services.", svc)
			}
			return fmt.Sprintf("%d service-crash event(s) from the Service Control Manager (7031/7034/7000).", countMatching(s, svcCrashRe))
		},
		Remediate: func(f investigate.Facts, _ investigate.Target) *plugin.RemediationAction {
			svc := crashedServiceFromCorpus(sess(f))
			if svc == "" {
				return nil // no single-token service name → advice-only
			}
			return &plugin.RemediationAction{
				Kind:            "svc-restart-windows",
				Name:            svc,
				Shell:           "powershell",
				KubectlCmd:      "Restart-Service -Name " + svc,
				Description:     "Restart the crashed Windows service " + svc,
				FixType:         "temporary",
				Risk:            "medium",
				Rollback:        "Stop-Service -Name " + svc + " if the restart destabilizes the host",
				Warning:         "Restarts the service; dependent services may briefly drop.",
				ExpectedOutcome: "The service returns to Running; recurrence indicates a config/dependency root cause.",
			}
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			s := sess(f)
			return hasAnyCode(s, "7031", "7034", "7000", "7009") || corpusMatches(s, svcCrashRe)
		},
		Checks: []investigate.Check{
			{Collector: "corpus-svc", Reason: "SCM events (7031/7034/7000) name the failing service and its exit behavior", Priority: 1},
			{Collector: "svc-status", Reason: "the service's live state shows whether it recovered or is still down", Priority: 2},
			{Collector: "corpus-window", Reason: "the events around the crash show what preceded it", Priority: 2},
			{Collector: "svc-failed", Reason: "other failed services point at a shared dependency", Priority: 3},
			{Collector: "history", Reason: "prior investigations show whether this service has crashed before", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Service crashing repeatedly (bad config, missing dependency, or bug)", Base: 55,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`7031|7034|terminated`), Weight: 20}},
			},
			{
				Title: "Crash triggered by an update or new deployment", Base: 40,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`update|install`), Weight: 15}},
			},
		},
	},
	{
		Key:      "auth-failure",
		Title:    "Repeated logon failures",
		Category: "Security",
		Severity: plugin.SeverityHigh,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d failed-logon event(s) (Event ID 4625/4740).", codeCount(sess(f), "4625"))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			s := sess(f)
			return codeCount(s, "4625") >= 3 || corpusMatches(s, authFailRe)
		},
		Checks: []investigate.Check{
			{Collector: "corpus-auth", Reason: "4625/4740 events identify the account, source, and failure reason", Priority: 1},
			{Collector: "corpus-frequency", Reason: "the failure rate distinguishes an attack burst from a stale credential", Priority: 2},
			{Collector: "login-history", Reason: "recent logon history shows who reached the host and when", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Brute-force or password-spray attempts", Base: 55,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`4625`), Weight: 20}},
			},
			{
				Title: "Expired service-account credential retrying", Base: 40,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`4740|locked`), Weight: 20}},
			},
		},
	},
	{
		Key:      "update-failure",
		Title:    "Windows Update failure",
		Category: "Maintenance",
		Severity: plugin.SeverityMedium,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return fmt.Sprintf("%d Windows Update failure event(s) (failing KB / 0x8… error code).", countMatching(sess(f), updateRe))
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			return corpusMatches(sess(f), updateRe)
		},
		Checks: []investigate.Check{
			{Collector: "corpus-update", Reason: "WindowsUpdate events carry the failing KB and 0x8… error code", Priority: 1},
			{Collector: "sys-disk", Reason: "exhausted disk space is the most common update failure", Priority: 2},
			{Collector: "corpus-window", Reason: "the events around the failure show what else was happening", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Windows Update failing (disk space or component store)", Base: 50,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`0x8|disk`), Weight: 20}},
			},
			{Title: "Update conflicts with installed software", Base: 35},
		},
	},
	{
		Key:      "unexpected-reboot",
		Title:    "Unexpected reboot / dirty shutdown",
		Category: "Reliability",
		Severity: plugin.SeverityHigh,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return "Dirty-shutdown / Kernel-Power (6008 / 41) events indicate the host went down unexpectedly."
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			s := sess(f)
			return hasAnyCode(s, "6008", "41") || corpusMatches(s, rebootRe)
		},
		Checks: []investigate.Check{
			{Collector: "corpus-reboot", Reason: "6008/Kernel-Power 41 events timestamp the dirty shutdown", Priority: 1},
			{Collector: "sys-uptime", Reason: "current uptime confirms when the host actually came back", Priority: 2},
			{Collector: "corpus-window", Reason: "the events before the reboot show what took the host down", Priority: 3},
			{Collector: "history", Reason: "recurrence distinguishes a one-off power cut from failing hardware", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Power loss or hardware fault", Base: 45,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`kernel-power|6008`), Weight: 20}},
			},
			{
				Title: "Bugcheck/BSOD crash", Base: 40,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`1001|bugcheck`), Weight: 25}},
			},
		},
	},
	{
		Key:      "disk-error",
		Title:    "Disk / NTFS errors",
		Category: "Storage",
		Severity: plugin.SeverityHigh,
		Describe: func(f investigate.Facts, _ investigate.Target) string {
			return "Disk/NTFS error events (Event ID 7/51/55/98 or a disk/ntfs provider) indicate storage trouble."
		},
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			s := sess(f)
			return hasAnyCode(s, "7", "51", "55", "98") || hasProviderContaining(s, "disk", "ntfs")
		},
		Checks: []investigate.Check{
			{Collector: "sys-disk", Reason: "live disk state shows free space and the volume reporting errors", Priority: 1},
			{Collector: "corpus-window", Reason: "the events around the disk error show the affected operations", Priority: 2},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Failing disk or controller", Base: 55,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`\b(7|51|55)\b|bad block`), Weight: 20}},
			},
			{
				Title: "Filesystem corruption", Base: 40,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`55|corrupt`), Weight: 20}},
			},
		},
	},
	{
		Key:      "unknown-events",
		Title:    "Elevated error events",
		Category: "Reliability",
		Severity: plugin.SeverityMedium,
		Fallback: true,
		Match: func(f investigate.Facts, _ investigate.Target) bool {
			s := sess(f)
			return s != nil && hasErrorClassEvents(s)
		},
		Checks: []investigate.Check{
			{Collector: "corpus-frequency", Reason: "when the errors clustered is the first framing question", Priority: 1},
			{Collector: "corpus-window", Reason: "the lines around the worst event carry the immediate context", Priority: 2},
			{Collector: "svc-failed", Reason: "a failed service is the most common silent culprit on Windows", Priority: 3},
			{Collector: "history", Reason: "whatever happened before frames whatever is happening now", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Recent change destabilized the host", Base: 40},
			{Title: "Transient errors — verify recurrence", Base: 30},
		},
	},
}

// eventlogEdges documents the resource-graph relationships the planner can
// follow across the corpus and the (optional) live host.
var eventlogEdges = []investigate.Edge{
	{Name: "provider→events", Collector: "corpus-window", Why: "the events around a provider's worst entry show what preceded the failure"},
	{Name: "host→services", Collector: "svc-failed", Why: "failed services on the host reveal the blast radius"},
	{Name: "service→state", Collector: "svc-status", Why: "the service's live state shows whether it recovered"},
	{Name: "host→disk", Collector: "sys-disk", Why: "disk exhaustion silently breaks services, updates, and logging"},
	{Name: "host→memory", Collector: "sys-memory", Why: "memory pressure destabilizes every process on the host"},
	{Name: "host→uptime", Collector: "sys-uptime", Why: "uptime confirms whether and when the host rebooted"},
	{Name: "host→logins", Collector: "login-history", Why: "recent logons show who touched the host before it broke"},
	{Name: "host→tasks", Collector: "scheduled-tasks", Why: "a scheduled task firing at the failure time is a classic trigger"},
	{Name: "resource→history", Collector: "history", Why: "prior investigations and incidents show whether this has happened before"},
	{Name: "corpus→frequency", Collector: "corpus-frequency", Why: "when the error rate spiked frames every other check"},
}

// eventlogIntentPatterns extends the framework's common intents with
// Windows-specific question routing.
func eventlogIntentPatterns() []investigate.IntentPattern {
	return append(investigate.CommonIntentPatterns(),
		investigate.IntentPattern{Intent: "services", Re: investigate.Re(`service|scm`)},
		investigate.IntentPattern{Intent: "auth", Re: investigate.Re(`auth|logon|login|4625|lockout`)},
		investigate.IntentPattern{Intent: "updates", Re: investigate.Re(`update|patch|kb\d+`)},
		investigate.IntentPattern{Intent: "reboot", Re: investigate.Re(`reboot|shutdown|boot|bsod|bugcheck`)},
		investigate.IntentPattern{Intent: "disk", Re: investigate.Re(`\bdisk\b|ntfs|volume`)},
		investigate.IntentPattern{Intent: "tasks", Re: investigate.Re(`scheduled task|task scheduler`)},
		investigate.IntentPattern{Intent: "firewall", Re: investigate.Re(`firewall`)},
	)
}

// eventlogIntentChecks maps question intents to collector requests.
var eventlogIntentChecks = map[string][]investigate.Check{
	"services": {
		{Collector: "corpus-svc", Reason: "you asked about services — searching SCM failure events", Priority: 1},
		{Collector: "svc-failed", Reason: "live failed-service state complements the event record", Priority: 2},
	},
	"auth": {
		{Collector: "corpus-auth", Reason: "you asked about logons — searching 4625/4740 audit events", Priority: 1},
		{Collector: "login-history", Reason: "live logon history shows who reached the host", Priority: 2},
	},
	"updates": {
		{Collector: "corpus-update", Reason: "you asked about updates — searching WindowsUpdate failures", Priority: 1},
	},
	"reboot": {
		{Collector: "corpus-reboot", Reason: "you asked about reboots — searching dirty-shutdown events", Priority: 1},
		{Collector: "sys-uptime", Reason: "current uptime confirms when the host came back", Priority: 2},
	},
	"disk": {
		{Collector: "sys-disk", Reason: "you asked about disk — checking live volume state", Priority: 1},
	},
	"tasks": {
		{Collector: "scheduled-tasks", Reason: "you asked about scheduled tasks — listing them", Priority: 1},
	},
	"firewall": {
		{Collector: "firewall-state", Reason: "you asked about the firewall — reading its profile state", Priority: 1},
	},
	"previous-logs": {
		{Collector: "corpus-window", Reason: "you asked for the events before the failure", Priority: 1},
	},
	"comparison": {
		{Collector: "history", Reason: "comparing with the past needs prior investigations", Priority: 1},
	},
	"history": {
		{Collector: "history", Reason: "you asked whether this happened before", Priority: 1},
	},
	"rca": {
		{Collector: "history", Reason: "an RCA should note recurrence", Priority: 1},
	},
}

// eventlogTTL is how long each collector class's evidence stays fresh in the
// per-conversation cache. Corpus reads are static per analysis; live
// diagnostics go stale fast.
var eventlogTTL = map[string]time.Duration{
	"corpus-window":    10 * time.Minute,
	"corpus-frequency": 10 * time.Minute,
	"corpus-svc":       10 * time.Minute,
	"corpus-auth":      10 * time.Minute,
	"corpus-update":    10 * time.Minute,
	"corpus-reboot":    10 * time.Minute,
	"stats-summary":    10 * time.Minute,
	"svc-failed":       90 * time.Second,
	"svc-status":       90 * time.Second,
	"sys-disk":         90 * time.Second,
	"sys-memory":       90 * time.Second,
	"sys-uptime":       90 * time.Second,
	"login-history":    90 * time.Second,
	"scheduled-tasks":  90 * time.Second,
	"firewall-state":   90 * time.Second,
	"history":          10 * time.Minute,
}

// renderEventLogStats renders the analyzer-typed stats payload for the
// stats-summary collector.
func renderEventLogStats(stats any) string {
	st, ok := stats.(EventLogStats)
	if !ok {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "serviceEvents=%d reboots=%d authFailures=%d\n", st.ServiceEvents, st.Reboots, st.AuthFailures)
	if len(st.TopEventIDs) > 0 {
		b.WriteString("top event IDs:")
		for _, c := range st.TopEventIDs {
			fmt.Fprintf(&b, " %s=%d", c.Name, c.Count)
		}
		b.WriteString("\n")
	}
	if len(st.TopProviders) > 0 {
		b.WriteString("top providers:")
		for _, c := range st.TopProviders {
			fmt.Fprintf(&b, " %s=%d", c.Name, c.Count)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// eventlogCollectors is the dispatch table: corpus reads over the parsed
// session plus allowlisted remote diagnostics through diagRun.
func eventlogCollectors() map[string]investigate.Collector {
	focusUnit := func(cc investigate.CollectCtx) string { return cc.Target.Name }
	return map[string]investigate.Collector{
		"corpus-window":    investigate.CorpusWindowCollector("Events around the failure inspected", 10*time.Minute, 5*time.Minute),
		"corpus-frequency": investigate.CorpusFrequencyCollector("Error frequency profiled"),
		"stats-summary":    investigate.StatsSummaryCollector("Event statistics summarized", renderEventLogStats),
		"corpus-svc":       investigate.CorpusSearchCollector("Service failure events searched", svcCrashRe, ""),
		"corpus-auth":      investigate.CorpusSearchCollector("Authentication failure events searched", authFailRe, ""),
		"corpus-update":    investigate.CorpusSearchCollector("Windows Update failure events searched", updateRe, ""),
		"corpus-reboot":    investigate.CorpusSearchCollector("Unexpected shutdown events searched", rebootRe, ""),
		"svc-failed":       investigate.DiagCollector("Failed services listed", "svc-failed", nil, diagRun),
		"svc-status":       investigate.DiagCollector("Service state inspected", "svc-status", focusUnit, diagRun),
		"sys-disk":         investigate.DiagCollector("Disk state inspected", "sys-disk", nil, diagRun),
		"sys-memory":       investigate.DiagCollector("Memory state inspected", "sys-memory", nil, diagRun),
		"sys-uptime":       investigate.DiagCollector("Host uptime checked", "sys-uptime", nil, diagRun),
		"login-history":    investigate.DiagCollector("Logon history inspected", "login-history", nil, diagRun),
		"scheduled-tasks":  investigate.DiagCollector("Scheduled tasks listed", "scheduled-tasks", nil, diagRun),
		"firewall-state":   investigate.DiagCollector("Firewall state inspected", "firewall-state", nil, diagRun),
		"history": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			return investigate.GatherHistory(ctx, cc.History, cc.Target.Scope, cc.Target.Name, cc.Now)
		},
	}
}

// Confidence-rule patterns.
var (
	explicitIDRe = investigate.Re(`7031|7034|6008|4625|bugcheck`)
	anyLogRe     = investigate.Re(`.`)
)

// eventlogConfidenceRules score the copilot's confidence from evidence
// quality: explicit event IDs beat live diagnostics, which beat event
// patterns alone.
var eventlogConfidenceRules = []investigate.ConfidenceRule{
	{
		Score: 90, Reason: "the event IDs explicitly identify the failure (SCM crash / bugcheck / audit failure)",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", explicitIDRe)
		},
	},
	{
		Score: 70, Reason: "service state confirmed by live diagnostics",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			for _, e := range ev {
				if strings.HasPrefix(e.Source, "diag/") {
					return true
				}
			}
			return false
		},
	},
	{
		Score: 60, Reason: "event-pattern only — consistent but not state-confirmed",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", anyLogRe)
		},
	},
	{
		Score: 30, Reason: "only weak, indirect correlation available",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return len(ev) > 0
		},
	},
}

// eventlogPrevention maps symptom keys to long-term prevention advice —
// copy-only, never auto-applied.
var eventlogPrevention = map[string][]plugin.RemediationAction{
	"service-crash": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Set service recovery actions (restart with backoff) and alert on repeated SCM 7031/7034."},
	},
	"auth-failure": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Enforce account lockout + MFA, and forward Security log 4625 bursts to alerting."},
	},
	"update-failure": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Stage updates in a pilot ring, keep 15% free disk, and repair the component store (DISM) proactively."},
	},
	"unexpected-reboot": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Add UPS/power monitoring and enable full memory dumps so bugchecks are diagnosable."},
	},
	"disk-error": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Enable SMART monitoring with pre-failure alerts and replace disks at the first hard error."},
	},
	"unknown-events": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Baseline event rates per provider and alert on deviations."},
	},
}

// Prompt wording — the trust-rule skeleton is framework-owned.
const eventlogRole = "a senior Windows systems administrator and incident responder investigating Windows Event Logs"

const eventlogDomainRules = `- Cite Event IDs and provider names exactly as they appear in the corpus — never invent or normalize them.
- Distinguish the parsed event corpus from live host diagnostics (sources prefixed "diag/") when weighing evidence.`

var (
	eventlogConversationPrompt = investigate.ConversationPromptFor(eventlogRole, eventlogDomainRules)
	eventlogLinePrompt         = investigate.LineAnalysisPromptFor(eventlogRole, eventlogDomainRules)
)

// eventlogBaseline contributes the free corpus summary every turn starts from.
func eventlogBaseline(_ context.Context, f investigate.Facts, _ investigate.Target, _ time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	s := sess(f)
	if s == nil || s.Len() == 0 {
		return []plugin.InvestigationStep{{Label: "Corpus loaded", Status: "unavailable",
			Detail: "no event corpus — run an analysis first"}}, nil
	}
	units, scopes := s.Vocabulary()
	from, to := s.TimeRange()
	span := "no timestamped events"
	if !from.IsZero() {
		span = from.Format(time.RFC3339) + " → " + to.Format(time.RFC3339)
	}
	summary := fmt.Sprintf("%d events from %d source(s); %d provider(s), %d host(s); range %s; %d truncated",
		s.Len(), len(s.Sources), len(units), len(scopes), span, s.Truncated())
	step := plugin.InvestigationStep{Label: "Corpus loaded", Status: "done",
		Detail: fmt.Sprintf("%d events across %d provider(s)", s.Len(), len(units))}
	evid := []plugin.EvidenceItem{{Kind: "metric", Source: "corpus", Excerpt: summary}}
	return []plugin.InvestigationStep{step}, evid
}

// eventlogTimeline builds the chronological view: the worst ≤12 error-class
// events for the focus (or corpus-wide), ascending.
func eventlogTimeline(f investigate.Facts, t investigate.Target, _ time.Time) []plugin.TimelineEvent {
	s := sess(f)
	if s == nil {
		return nil
	}
	events, _ := s.Query(investigate.LogQuery{Unit: t.Name, Limit: investigate.MaxSessionEvents})
	if t.Name == "" {
		events, _ = s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	}
	var out []plugin.TimelineEvent
	for _, e := range events {
		if e.At.IsZero() || !errorClass(e.Severity) {
			continue
		}
		label := "Event " + e.Code
		if e.Unit != "" {
			label += " from " + e.Unit
		}
		out = append(out, plugin.TimelineEvent{
			At: e.At, Label: label, Severity: timelineSeverity(e.Severity),
			Source: "event", Detail: firstLine(e.Message),
		})
		if len(out) == 12 {
			break
		}
	}
	return out
}

// eventlogFollowUps proposes next questions, skipping intents the user
// already asked about.
func eventlogFollowUps(intents []string, f investigate.Facts, _ []plugin.InvestigationStep) []string {
	has := func(intent string) bool { return investigate.HasIntent(intents, intent) }
	var out []string
	add := func(s string) {
		if len(out) < 5 {
			out = append(out, s)
		}
	}
	if !has("services") {
		add("Check service crash events")
	}
	if !has("auth") {
		add("Check failed logon attempts")
	}
	if !has("updates") {
		add("Check Windows Update failures")
	}
	if !has("reboot") {
		add("Check for unexpected reboots")
	}
	if !has("disk") {
		add("Check disk health")
	}
	if !has("rca") {
		add("Generate an RCA")
	}
	return out
}

// InvestigationProfile returns the eventlog domain profile for the generic
// investigation framework. Built from package-level catalogs — per-turn state
// arrives via Facts (*investigate.LogSession).
func (p *Plugin) InvestigationProfile() investigate.Profile {
	return investigate.Profile{
		Name:            "eventlog",
		Symptoms:        eventlogSymptoms,
		Edges:           eventlogEdges,
		IntentPatterns:  eventlogIntentPatterns(),
		IntentChecks:    eventlogIntentChecks,
		Collectors:      eventlogCollectors(),
		ConfidenceRules: eventlogConfidenceRules,
		Prevention:      eventlogPrevention,
		TTLs:            eventlogTTL,

		ConversationPrompt: eventlogConversationPrompt,
		LogLinePrompt:      eventlogLinePrompt,

		ResolveFocus: func(prev, _, message string, f investigate.Facts) string {
			s := sess(f)
			if s == nil {
				return prev
			}
			return investigate.ResolveFocusFromVocabulary(prev, message, s)
		},
		Baseline:         eventlogBaseline,
		Timeline:         eventlogTimeline,
		SuggestFollowUps: eventlogFollowUps,
	}
}
