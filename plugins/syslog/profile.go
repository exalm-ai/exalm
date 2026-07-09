package syslog

// profile.go assembles the SYSLOG investigation Profile for the generic
// framework (internal/investigate). The domain Facts are the parsed
// *investigate.LogSession corpus from the most recent analyze run; symptom
// matchers, collectors, confidence rules, and prevention advice all reason
// over that corpus (plus allowlisted SSH diagnostics when a remote host is
// attached). The per-turn pipeline is the framework engine's.

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

// diagRun is the remote-diagnostics runner every DiagCollector registration
// delegates to. Package-level so tests can inject a fake; production keeps
// the allowlisted SSH runner.
var diagRun investigate.DiagFn = investigate.SSHDiagRunner

// runDiag delegates to the current diagRun so a test swap takes effect even
// after the collectors map was built.
func runDiag(ctx context.Context, s *investigate.LogSession, name, param string) (string, string, error) {
	return diagRun(ctx, s, name, param)
}

// Corpus signature patterns — shared by symptom matchers, corpus collectors,
// and the stats counters' investigative twins.
var (
	reAuthFail   = investigate.Re(`Failed password|authentication failure|Invalid user|pam_unix.*fail`)
	reOOM        = investigate.Re(`Out of memory|oom-killer|Killed process`)
	reDiskErr    = investigate.Re(`No space left|EXT4-fs error|I/O error|read-only file ?system`)
	reKernelErr  = investigate.Re(`kernel:.*(panic|BUG|segfault|hung task|oops)`)
	reSvcFailure = investigate.Re(`Failed to start|entered failed state|Main process exited|Failed with result`)
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

// errorClass reports whether a session severity is err-or-worse.
func errorClass(sev string) bool {
	r := severeRank(sev)
	return r >= 0 && r <= 3 // emerg..err
}

// hasErrorEvents reports whether the corpus contains at least one
// error-class event.
func hasErrorEvents(s *investigate.LogSession) bool {
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

// syslogSymptomCatalog is what an experienced Linux operator checks FIRST for
// each syslog failure signature, and the candidate causes to rank.
var syslogSymptomCatalog = []investigate.Symptom{
	{
		Key: "oom-kill",
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return corpusHas(s, reOOM)
		}),
		Checks: []investigate.Check{
			{Collector: "corpus-oom", Reason: "OOM lines in the corpus name the killed process and its score", Priority: 1},
			{Collector: "corpus-window", Reason: "lines around the kill show what was consuming memory beforehand", Priority: 2},
			{Collector: "sys-memory", Reason: "live memory state shows whether pressure persists right now", Priority: 2},
			{Collector: "journal-unit", Reason: "the victim unit's journal shows its behavior before the kill", Priority: 3},
			{Collector: "history", Reason: "a recurring OOM points at a leak, a one-off at a spike", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Process memory exhaustion — the kernel OOM killer intervened", Base: 65,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: investigate.Re(`oom|killed process`), Weight: 20}},
			},
			{
				Title: "Memory leak in a long-running service", Base: 40,
				For: []investigate.EvidenceMatcher{{Kind: "metric", Pattern: investigate.Re(`busiest`), Weight: 10}},
			},
			{Title: "Host under-provisioned for its workload", Base: 30},
		},
	},
	{
		Key: "disk-full",
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return corpusHas(s, reDiskErr)
		}),
		Checks: []investigate.Check{
			{Collector: "corpus-disk", Reason: "disk/filesystem error lines name the failing device or mount", Priority: 1},
			{Collector: "sys-disk", Reason: "live filesystem usage confirms whether space is exhausted now", Priority: 2},
			{Collector: "corpus-window", Reason: "lines around the first disk error show what was writing", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Filesystem out of space", Base: 65,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`no space left`), Weight: 25}},
			},
			{
				Title: "Disk or I/O hardware failure", Base: 35,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`I/O error`), Weight: 25}},
			},
		},
	},
	{
		Key: "service-failure",
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return corpusHas(s, reSvcFailure)
		}),
		Checks: []investigate.Check{
			{Collector: "svc-status", Reason: "systemd's own state for the focus unit is the ground truth", Priority: 1},
			{Collector: "journal-unit", Reason: "the unit's journal shows the exit output that systemd recorded", Priority: 2},
			{Collector: "svc-failed", Reason: "sibling failed units reveal a shared dependency or boot-order fault", Priority: 2},
			{Collector: "corpus-window", Reason: "lines around the failure show what preceded it", Priority: 3},
			{Collector: "history", Reason: "a unit that failed before points at a chronic cause", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Service crashing on startup (bad config or dependency)", Base: 55,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: investigate.Re(`failed to start|exited`), Weight: 20}},
			},
			{Title: "Dependency or ordering failure at boot", Base: 35},
			{
				Title: "Resource exhaustion killing the service", Base: 30,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`oom|memory`), Weight: 20}},
			},
		},
	},
	{
		Key: "auth-failure",
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return corpusCount(s, reAuthFail) >= 3
		}),
		Checks: []investigate.Check{
			{Collector: "corpus-auth", Reason: "the failing usernames and source addresses are in the auth lines", Priority: 1},
			{Collector: "corpus-frequency", Reason: "the failure rate distinguishes a brute force from a stuck client", Priority: 2},
			{Collector: "auth-log", Reason: "the live auth log shows whether attempts are still arriving", Priority: 3},
			{Collector: "login-history", Reason: "recent successful logins show whether anyone got in", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Brute-force authentication attempts", Base: 55,
				For: []investigate.EvidenceMatcher{{Pattern: investigate.Re(`invalid user|failed password`), Weight: 20}},
			},
			{Title: "Misconfigured client or expired credential retrying", Base: 40},
		},
	},
	{
		Key: "kernel-issue",
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return corpusHas(s, reKernelErr)
		}),
		Checks: []investigate.Check{
			{Collector: "corpus-kernel", Reason: "the kernel lines name the faulting module or task", Priority: 1},
			{Collector: "kernel-ring", Reason: "the live ring buffer shows whether the fault is ongoing", Priority: 2},
			{Collector: "corpus-window", Reason: "lines around the fault show what the system was doing", Priority: 3},
			{Collector: "sys-memory", Reason: "memory pressure triggers many kernel-level failures", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{Title: "Kernel or driver fault", Base: 55},
			{Title: "Hardware error surfacing through the kernel", Base: 35},
		},
	},
	{
		Key:      "unknown-degraded",
		Fallback: true,
		Match: matchCorpus(func(s *investigate.LogSession, _ investigate.Target) bool {
			return hasErrorEvents(s)
		}),
		Checks: []investigate.Check{
			{Collector: "corpus-frequency", Reason: "start from when the error rate spiked", Priority: 1},
			{Collector: "corpus-window", Reason: "the lines around the worst event frame every other check", Priority: 2},
			{Collector: "svc-failed", Reason: "a failed unit is the most common cause of unexplained errors", Priority: 3},
			{Collector: "history", Reason: "whatever happened before is the first suspect", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Recent change destabilized a service", Base: 40,
				For: []investigate.EvidenceMatcher{{Kind: "history", Pattern: investigate.Re(`change`), Weight: 15}},
			},
			{Title: "Transient burst — monitor for recurrence", Base: 30},
		},
	},
}

// syslogEdgeRegistry documents the resource-graph relationships the planner
// can follow and why they matter.
var syslogEdgeRegistry = []investigate.Edge{
	{Name: "unit→journal", Collector: "journal-unit", Why: "the unit's own journal is the closest record of why it failed"},
	{Name: "host→memory", Collector: "sys-memory", Why: "host memory pressure explains OOM kills and slow services"},
	{Name: "host→disk", Collector: "sys-disk", Why: "full filesystems break logging, databases, and services alike"},
	{Name: "host→kernel", Collector: "kernel-ring", Why: "kernel faults underlie many userspace symptoms"},
	{Name: "unit→service-state", Collector: "svc-status", Why: "systemd's state for the unit is the ground truth"},
	{Name: "host→auth", Collector: "auth-log", Why: "authentication activity reveals intrusion attempts and lockouts"},
	{Name: "host→services", Collector: "svc-failed", Why: "sibling failed units reveal shared dependencies"},
	{Name: "resource→history", Collector: "history", Why: "prior investigations and incidents cover recurrence"},
	{Name: "corpus→window", Collector: "corpus-window", Why: "context lines around the worst event show the lead-up"},
	{Name: "corpus→frequency", Collector: "corpus-frequency", Why: "the error-rate shape distinguishes bursts from steady failure"},
}

// syslogIntentPatterns extend the framework's common intents with syslog
// domain vocabulary.
var syslogIntentPatterns = append(investigate.CommonIntentPatterns(), []investigate.IntentPattern{
	{Intent: "disk", Re: investigate.Re(`\bdisk\b|filesystem|inode|no space`)},
	{Intent: "auth", Re: investigate.Re(`\bauth\b|login|password|ssh attempt|brute`)},
	{Intent: "memory", Re: investigate.Re(`memory|\boom\b|swap`)},
	{Intent: "services", Re: investigate.Re(`service|systemd|unit|daemon`)},
	{Intent: "kernel", Re: investigate.Re(`kernel|dmesg|panic`)},
	{Intent: "dns", Re: investigate.Re(`\bdns\b|resolve|resolution`)},
}...)

// syslogIntentChecks maps question intents to collector requests — mentioning
// disk schedules the filesystem checks even when no symptom implies them.
// "refresh" is handled by the engine itself (cache bypass), so it has no row.
var syslogIntentChecks = map[string][]investigate.Check{
	"disk": {
		{Collector: "sys-disk", Reason: "you asked about disk — checking live filesystem usage", Priority: 1},
		{Collector: "corpus-disk", Reason: "disk error lines in the corpus name the failing mount", Priority: 2},
	},
	"auth": {
		{Collector: "corpus-auth", Reason: "you asked about authentication — searching the corpus", Priority: 1},
		{Collector: "auth-log", Reason: "the live auth log shows current attempts", Priority: 2},
		{Collector: "login-history", Reason: "recent logins show whether anyone got in", Priority: 3},
	},
	"memory": {
		{Collector: "sys-memory", Reason: "you asked about memory — checking live usage", Priority: 1},
		{Collector: "corpus-oom", Reason: "OOM lines in the corpus name the killed processes", Priority: 2},
	},
	"services": {
		{Collector: "svc-failed", Reason: "you asked about services — listing failed units", Priority: 1},
		{Collector: "svc-status", Reason: "systemd state for the focus unit", Priority: 2},
	},
	"kernel": {
		{Collector: "kernel-ring", Reason: "you asked about the kernel — reading the ring buffer", Priority: 1},
		{Collector: "corpus-kernel", Reason: "kernel fault lines already captured in the corpus", Priority: 2},
	},
	"dns": {
		{Collector: "corpus-window", Reason: "resolver errors show up in the lines around the failure", Priority: 1},
	},
	"previous-logs": {
		{Collector: "corpus-window", Reason: "you asked for the lines before the failure", Priority: 1},
	},
	"comparison": {
		{Collector: "history", Reason: "comparing with the past needs prior investigations and incidents", Priority: 1},
		{Collector: "corpus-frequency", Reason: "the current error-rate shape is the comparison baseline", Priority: 2},
	},
	"history": {
		{Collector: "history", Reason: "you asked whether this happened before", Priority: 1},
		{Collector: "corpus-frequency", Reason: "the error-rate shape shows how the current episode compares", Priority: 2},
	},
	"rca": {
		{Collector: "history", Reason: "an RCA should note recurrence", Priority: 1},
		{Collector: "corpus-frequency", Reason: "an RCA needs the failure's rate and timing", Priority: 2},
	},
}

// syslogCollectorTTL is the per-collector evidence-cache freshness window.
// Corpus collectors read an immutable in-memory snapshot (long TTL); diag
// collectors hit the live host (short TTL).
var syslogCollectorTTL = map[string]time.Duration{
	"corpus-window":    10 * time.Minute,
	"corpus-frequency": 10 * time.Minute,
	"stats-summary":    10 * time.Minute,
	"corpus-auth":      10 * time.Minute,
	"corpus-oom":       10 * time.Minute,
	"corpus-disk":      10 * time.Minute,
	"corpus-kernel":    10 * time.Minute,
	"sys-disk":         90 * time.Second,
	"sys-memory":       90 * time.Second,
	"sys-uptime":       90 * time.Second,
	"svc-failed":       90 * time.Second,
	"svc-status":       90 * time.Second,
	"journal-unit":     90 * time.Second,
	"kernel-ring":      90 * time.Second,
	"auth-log":         90 * time.Second,
	"login-history":    90 * time.Second,
	"history":          10 * time.Minute,
}

// focusUnit derives the single validated diag parameter from the focus.
func focusUnit(cc investigate.CollectCtx) string { return cc.Target.Name }

// renderSyslogStats renders the analyzer-typed stats payload for evidence.
func renderSyslogStats(stats any) string {
	st, ok := stats.(SyslogStats)
	if !ok {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "auth failures: %d; OOM events: %d; disk errors: %d", st.AuthFailures, st.OOMEvents, st.DiskErrors)
	if len(st.TopUnits) > 0 {
		var parts []string
		for _, u := range st.TopUnits {
			parts = append(parts, fmt.Sprintf("%s (%d)", u.Name, u.Count))
		}
		fmt.Fprintf(&b, "; top units: %s", strings.Join(parts, ", "))
	}
	if len(st.TopHosts) > 0 {
		var parts []string
		for _, h := range st.TopHosts {
			parts = append(parts, fmt.Sprintf("%s (%d)", h.Name, h.Count))
		}
		fmt.Fprintf(&b, "; top hosts: %s", strings.Join(parts, ", "))
	}
	if n := len(st.SeverityTimeline); n > 0 {
		fmt.Fprintf(&b, "; %d active minute(s) in the severity timeline", n)
	}
	return b.String()
}

// syslogCollectors is the dispatch table: corpus queries, allowlisted remote
// diagnostics, and the framework's history gatherer.
func syslogCollectors() map[string]investigate.Collector {
	return map[string]investigate.Collector{
		"corpus-window":    investigate.CorpusWindowCollector("Corpus window around worst event", 5*time.Minute, 2*time.Minute),
		"corpus-frequency": investigate.CorpusFrequencyCollector("Error frequency profiled"),
		"stats-summary":    investigate.StatsSummaryCollector("Analysis statistics summarized", renderSyslogStats),
		"corpus-auth": investigate.CorpusSearchCollector("Authentication failures searched", reAuthFail,
			"grep -iE 'Failed password|authentication failure|Invalid user' /var/log/auth.log"),
		"corpus-oom": investigate.CorpusSearchCollector("OOM killer activity searched", reOOM,
			"grep -iE 'Out of memory|oom-killer|Killed process' /var/log/syslog"),
		"corpus-disk": investigate.CorpusSearchCollector("Disk/filesystem errors searched", reDiskErr,
			"grep -iE 'No space left|EXT4-fs error|I/O error' /var/log/syslog"),
		"corpus-kernel": investigate.CorpusSearchCollector("Kernel faults searched", reKernelErr,
			"grep -iE 'kernel:.*(panic|BUG|segfault|hung task|oops)' /var/log/syslog"),
		"sys-disk":      investigate.DiagCollector("Filesystem usage checked", "sys-disk", nil, runDiag),
		"sys-memory":    investigate.DiagCollector("Memory usage checked", "sys-memory", nil, runDiag),
		"sys-uptime":    investigate.DiagCollector("Uptime and load checked", "sys-uptime", nil, runDiag),
		"svc-failed":    investigate.DiagCollector("Failed systemd units listed", "svc-failed", nil, runDiag),
		"svc-status":    investigate.DiagCollector("Focus unit status checked", "svc-status", focusUnit, runDiag),
		"journal-unit":  investigate.DiagCollector("Focus unit journal fetched", "journal-unit", focusUnit, runDiag),
		"kernel-ring":   investigate.DiagCollector("Kernel ring buffer read", "kernel-ring", nil, runDiag),
		"auth-log":      investigate.DiagCollector("Live auth log tailed", "auth-log", nil, runDiag),
		"login-history": investigate.DiagCollector("Recent login history fetched", "login-history", nil, runDiag),
		"history": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			return investigate.GatherHistory(ctx, cc.History, cc.Target.Scope, cc.Target.Name, cc.Now)
		},
	}
}

// syslogConfidenceRules is the syslog evidence-quality table: an explicit
// kernel report beats a systemd-confirmed failure, which beats live resource
// confirmation, which beats a log pattern alone.
var syslogConfidenceRules = []investigate.ConfidenceRule{
	{
		Score: 95, Reason: "the kernel explicitly reported the failure (OOM kill / panic line present)",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", investigate.Re(`oom-killer|killed process|kernel panic`))
		},
	},
	{
		Score: 85, Reason: "service failure confirmed by systemd state and journal output",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "log", investigate.Re(`failed to start|entered failed state`)) &&
				investigate.EvidenceMatching(ev, "metric", investigate.Re(`.`))
		},
	},
	{
		Score: 70, Reason: "diagnostic output confirms the resource pressure",
		Match: func(ev []plugin.EvidenceItem, _ []plugin.InvestigationStep, _ investigate.Facts) bool {
			return investigate.EvidenceMatching(ev, "metric", investigate.Re(`9[0-9]%|no space|filesystem full`)) ||
				investigate.EvidenceMatching(ev, "", investigate.Re(`diag/`))
		},
	},
	{
		Score: 60, Reason: "the conclusion rests on log patterns only — consistent but not state-confirmed",
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

// syslogPreventionCatalog maps symptom keys to preventive advice. Kind
// "advice" keeps them copy-only — prevention is a policy decision, never
// auto-applied.
var syslogPreventionCatalog = map[string][]plugin.RemediationAction{
	"oom-kill": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Add memory alerts at 80% and consider systemd MemoryMax= plus right-sizing the host."},
	},
	"disk-full": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Alert on 85% filesystem usage, enable log rotation, and monitor inode counts."},
	},
	"service-failure": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Set systemd Restart=on-failure with StartLimit alerts, and validate configs in CI before deploy."},
	},
	"auth-failure": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Deploy fail2ban or equivalent, disable password auth in favor of keys, and alert on failed-login bursts."},
	},
	"kernel-issue": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Track kernel/driver updates in a staging ring and monitor mcelog/EDAC for hardware errors."},
	},
	"unknown-degraded": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Ensure services log structured errors and add burn-rate alerts so bursts page before users notice."},
	},
}

// syslogRole is the domain persona for both prompt skeletons.
const syslogRole = "a senior Linux systems engineer investigating syslog/journald output with an operator"

// timelineSeverity maps a session severity onto the TimelineEvent scale.
func timelineSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "crit", "emerg", "alert", "critical", "fatal":
		return "critical"
	case "err", "error", "5xx":
		return "high"
	case "warn", "warning":
		return "medium"
	default:
		return "info"
	}
}

// buildSyslogTimeline picks the worst ≤12 error-class events for the focus
// unit (corpus-wide when no unit is set) and returns them oldest-first.
func buildSyslogTimeline(s *investigate.LogSession, t investigate.Target) []plugin.TimelineEvent {
	if s == nil {
		return nil
	}
	events, _ := s.Query(investigate.LogQuery{Unit: t.Name, Limit: investigate.MaxSessionEvents})
	if t.Name == "" {
		events, _ = s.Query(investigate.LogQuery{Limit: investigate.MaxSessionEvents})
	}
	var errs []investigate.LogEvent
	for _, e := range events {
		if e.At.IsZero() || !errorClass(e.Severity) {
			continue
		}
		errs = append(errs, e)
	}
	// Worst first (severeRank orders worst-first), then most recent.
	sort.SliceStable(errs, func(i, j int) bool {
		ri, rj := severeRank(errs[i].Severity), severeRank(errs[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return errs[i].At.After(errs[j].At)
	})
	if len(errs) > 12 {
		errs = errs[:12]
	}
	sort.Slice(errs, func(i, j int) bool { return errs[i].At.Before(errs[j].At) })
	out := make([]plugin.TimelineEvent, 0, len(errs))
	for _, e := range errs {
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

// suggestSyslogFollowUps proposes up to five next questions, skipping intents
// already asked this turn.
func suggestSyslogFollowUps(intents []string) []string {
	var out []string
	add := func(intent, s string) {
		if len(out) < 5 && !investigate.HasIntent(intents, intent) {
			out = append(out, s)
		}
	}
	add("services", "List failed systemd units")
	add("memory", "Check memory pressure")
	add("disk", "Check disk space")
	add("auth", "Review authentication failures")
	add("kernel", "Check the kernel ring buffer")
	add("rca", "Generate an RCA")
	return out
}

// syslogBaseline emits the free per-turn evidence: the corpus summary, or an
// honest "unavailable" step before the first analysis.
func syslogBaseline(_ context.Context, f investigate.Facts, _ investigate.Target, _ time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
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

// syslogProfile builds the syslog investigation profile from the package's
// catalogs. Package-level catalogs, per-turn state via Facts.
func syslogProfile() investigate.Profile {
	return investigate.Profile{
		Name:            "syslog",
		Symptoms:        syslogSymptomCatalog,
		Edges:           syslogEdgeRegistry,
		IntentPatterns:  syslogIntentPatterns,
		IntentChecks:    syslogIntentChecks,
		Collectors:      syslogCollectors(),
		ConfidenceRules: syslogConfidenceRules,
		Prevention:      syslogPreventionCatalog,
		TTLs:            syslogCollectorTTL,

		ConversationPrompt: investigate.ConversationPromptFor(syslogRole,
			"- systemd unit names must be quoted exactly as they appear in the corpus."),
		LogLinePrompt: investigate.LineAnalysisPromptFor(syslogRole, ""),

		ResolveFocus: func(prev, _, message string, f investigate.Facts) string {
			s := sessionOf(f)
			if s == nil {
				return prev
			}
			return investigate.ResolveFocusFromVocabulary(prev, message, s)
		},
		Baseline: syslogBaseline,
		Timeline: func(f investigate.Facts, t investigate.Target, _ time.Time) []plugin.TimelineEvent {
			return buildSyslogTimeline(sessionOf(f), t)
		},
		SuggestFollowUps: func(intents []string, _ investigate.Facts, _ []plugin.InvestigationStep) []string {
			return suggestSyslogFollowUps(intents)
		},
	}
}

// InvestigationProfile exposes the syslog profile to the serve-time wiring.
func (p *Plugin) InvestigationProfile() investigate.Profile { return syslogProfile() }
