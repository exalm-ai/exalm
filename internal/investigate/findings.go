package investigate

// findings.go promotes a domain's already-computed detection signal into
// structured plugin.Finding objects during `analyze` — the same shape the k8s
// plugin emits, so the CLI/JSON output, the MCP tools, the notify webhook, and
// the web dashboard all treat log-analyzer findings identically to k8s ones.
//
// This is deterministic and LLM-free: it reuses the profile's existing symptom
// catalog (Profile.MatchSymptoms), cause templates, and prevention catalog.
// The interactive investigation engine still owns deep, evidence-backed
// root-cause analysis on demand; FindingsFrom is the cheap up-front pass that
// says "here is what looks wrong, and here is the safe fix if one exists".

import (
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// FindingSource builds a Finding.Source provenance string:
// "<analyzer>/<host>" for a remote SSH collection, "<analyzer>/<file>" for a
// single local file, or bare "<analyzer>" for stdin / multiple files. Shared
// by every analyzer's analyze()/summarize() so Source is formatted uniformly.
func FindingSource(analyzer, host string, session *LogSession) string {
	if host != "" {
		return analyzer + "/" + host
	}
	if session != nil && len(session.Sources) == 1 {
		if p := session.Sources[0].Path; p != "" {
			return analyzer + "/" + p
		}
	}
	return analyzer
}

// FindingsFrom turns every symptom that matches the corpus into a
// plugin.Finding. Symptoms are promoted in catalog order (Profile.MatchSymptoms
// semantics: real rows first, the fallback row only when nothing else matched).
//
// Each finding is populated from the symptom's promotion metadata (Title,
// Category, Severity, Describe, Remediate — all optional, with fallbacks), the
// highest-scoring CauseTemplate (→ RootCause), and the profile's Prevention
// catalog keyed by symptom Key (→ Suggestion + copy-only Fixes). source is the
// finding provenance string, e.g. "syslog/web-01" or "syslog/app.log".
func FindingsFrom(p Profile, f Facts, t Target, source string) []plugin.Finding {
	matched := p.MatchSymptoms(f, t)
	out := make([]plugin.Finding, 0, len(matched))
	for _, s := range matched {
		out = append(out, findingFromSymptom(p, s, f, t, source))
	}
	return out
}

func findingFromSymptom(p Profile, s Symptom, f Facts, t Target, source string) plugin.Finding {
	topCause, topBase := topCause(s.Causes)

	fnd := plugin.Finding{
		Severity:  severityOr(s.Severity, plugin.SeverityMedium),
		Category:  strOr(s.Category, "Log"),
		Title:     strOr(s.Title, titleize(s.Key)),
		RootCause: topCause,
		Source:    source,
	}

	// Carry the investigation target through as the finding's entity. Scope maps
	// to Namespace so Entity.Path() reproduces Target.String() exactly — the
	// same "scope/name" string already used by Conversation.Focus — which keeps
	// every existing consumer working while giving the dashboard a typed
	// identity to group and filter on instead of substring-matching the title.
	if !t.IsZero() {
		fnd.Entity = &plugin.Entity{Namespace: t.Scope, Name: t.Name}
	}

	// Detail: prefer the domain's count-rich description; else a generic line
	// built from the ranked top cause.
	if s.Describe != nil {
		fnd.Detail = s.Describe(f, t)
	}
	if fnd.Detail == "" {
		fnd.Detail = genericDetail(fnd.Title, topCause)
	}

	// Confidence bucket from the top cause's base score. Empty when the
	// symptom carries no causes (nothing to rank).
	if len(s.Causes) > 0 {
		fnd.Confidence = confidenceBucket(topBase)
	}

	// Prevention catalog → copy-only advice fixes + a one-line suggestion.
	if prevention := p.Prevention[s.Key]; len(prevention) > 0 {
		fnd.Fixes = append(fnd.Fixes, prevention...)
		if prevention[0].Description != "" {
			fnd.Suggestion = prevention[0].Description
		}
	}

	// Executable primary remediation, when the symptom knows a safe corrective
	// action (e.g. restart the failed unit). Also surfaced in Fixes so the
	// dashboard's classified fix list shows it alongside the prevention advice.
	if s.Remediate != nil {
		if action := s.Remediate(f, t); action != nil {
			fnd.Remediation = action
			fnd.Fixes = append([]plugin.RemediationAction{*action}, fnd.Fixes...)
		}
	}

	return fnd
}

// topCause returns the Title and Base of the highest-Base cause template. First
// wins on ties (catalog author's preferred ordering). Returns "", 0 when empty.
func topCause(causes []CauseTemplate) (title string, base int) {
	for i, c := range causes {
		if i == 0 || c.Base > base {
			title, base = c.Title, c.Base
		}
	}
	return title, base
}

func confidenceBucket(base int) string {
	switch {
	case base >= 70:
		return "high"
	case base >= 40:
		return "medium"
	default:
		return "low"
	}
}

func genericDetail(title, topCause string) string {
	if topCause != "" {
		return title + ". Most likely cause: " + topCause + "."
	}
	return title + " detected in the analyzed corpus."
}

func strOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func severityOr(v, fallback plugin.Severity) plugin.Severity {
	if v == "" {
		return fallback
	}
	return v
}

// titleize turns a symptom key like "auth-failure" into "Auth Failure" for use
// as a fallback finding title when the symptom sets no explicit Title.
func titleize(key string) string {
	if key == "" {
		return "Log anomaly"
	}
	words := strings.FieldsFunc(key, func(r rune) bool { return r == '-' || r == '_' })
	for i, w := range words {
		if w == "" {
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}
