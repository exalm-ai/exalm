// Package investigate is Exalm's generic AI investigation framework: the
// deterministic per-turn pipeline (focus resolution → intent classification →
// symptom-driven plan → collector execution with per-conversation caching →
// hypothesis ranking → evidence-quality confidence → prevention → ONE
// redacted LLM call → persisted transcript) extracted from the Kubernetes
// copilot so every analyzer (k8s, syslog, httplog, eventlog, iis, logs)
// delivers the identical experience.
//
// A domain plugs in via Profile: its symptom catalog, resource-graph edges,
// intent patterns, collectors, confidence rules, prevention catalog, and
// prompt wording. The engine owns everything else. The trust model is
// enforced HERE: exactly one redacted llm.Complete() per turn, the LLM never
// chooses collectors, and every message passes the Redactor first.
package investigate

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Target is a parsed focus: the resource under discussion. Scope/Name map to
// domain concepts — k8s: namespace/pod; syslog: host/unit; httplog:
// vhost/route; eventlog: host/provider; iis: site/route.
type Target struct {
	Scope string
	Name  string
}

// String renders the canonical "scope/name" focus form.
func (t Target) String() string {
	if t.Scope == "" {
		return t.Name
	}
	return t.Scope + "/" + t.Name
}

// ParseFocus splits a "scope/name" focus string into a Target.
func ParseFocus(focus string) Target {
	if focus == "" {
		return Target{}
	}
	parts := strings.SplitN(focus, "/", 2)
	if len(parts) == 2 {
		return Target{Scope: parts[0], Name: parts[1]}
	}
	return Target{Name: parts[0]}
}

// Facts is the opaque per-turn domain bundle (snapshot, clients, resolved
// resources). Symptom matchers, collectors, and confidence rules type-assert
// it; the engine never inspects it.
type Facts = any

// CollectCtx is what every collector receives: the focus, the domain facts,
// the redactor (anything user-authored must pass through it before being
// stored in evidence), and the engine-owned history sources.
type CollectCtx struct {
	Target  Target
	Focus   string
	Now     time.Time
	Facts   Facts
	Red     plugin.Redactor
	History HistoryDeps
}

// Collector gathers one class of evidence for the focus resource. It must be
// read-only and deterministic given the same domain state, and must report
// an "unavailable" step rather than returning an error — a failed check is
// itself investigation signal.
type Collector func(ctx context.Context, cc CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem)

// Check is one collector request contributed by a symptom or intent.
type Check struct {
	Collector string
	Reason    string // why this check matters — shown verbatim in the plan
	Priority  int    // lower runs earlier
}

// EvidenceMatcher scores evidence for/against a cause: it matches when the
// item's Kind equals Kind (if set) and Pattern matches Source+" "+Excerpt.
type EvidenceMatcher struct {
	Kind    string
	Pattern *regexp.Regexp
	Weight  int
}

// CauseTemplate is one candidate root cause for a symptom.
type CauseTemplate struct {
	Title   string
	Base    int // starting score 0-100 before evidence adjustment
	For     []EvidenceMatcher
	Against []EvidenceMatcher
}

// Symptom is one row of a domain's catalog: what an experienced operator
// checks FIRST for a failure mode, and the candidate causes to rank.
type Symptom struct {
	Key   string
	Match func(f Facts, t Target) bool
	// Fallback marks the catch-all row: it matches only when no other
	// symptom matched (replaces hard-coded key checks).
	Fallback bool
	Checks   []Check
	Causes   []CauseTemplate
}

// Edge documents one resource-graph relationship the planner can follow and
// why it matters — the single source of Edge strings for the plan, the
// evidence, and the UI tree.
type Edge struct {
	Name      string // canonical edge string, e.g. "pod→ownerDeployment"
	Collector string // dispatch key into Profile.Collectors
	Why       string
}

// IntentPattern maps free-text to an intent tag via regex — never an LLM.
type IntentPattern struct {
	Intent string
	Re     *regexp.Regexp
}

// ConfidenceRule is one row of the domain's evidence-quality scoring table.
type ConfidenceRule struct {
	Score  int
	Reason string
	Match  func(ev []plugin.EvidenceItem, steps []plugin.InvestigationStep, f Facts) bool
}

// Profile is everything a domain supplies to the engine. All hooks are
// deterministic; nil hooks degrade gracefully where documented.
type Profile struct {
	Name string // "k8s", "syslog", "httplog", "eventlog", "iis", "logs"

	// Deterministic knowledge catalogs.
	Symptoms        []Symptom
	Edges           []Edge
	IntentPatterns  []IntentPattern
	IntentChecks    map[string][]Check
	Collectors      map[string]Collector
	ConfidenceRules []ConfidenceRule
	Prevention      map[string][]plugin.RemediationAction
	// TTLs is the per-collector evidence-cache freshness window (default 5m).
	TTLs         map[string]time.Duration
	MaxPlanSteps int // 0 => 8

	// Prompts (domain wording — build via ConversationPromptFor /
	// LineAnalysisPromptFor to keep the trust-rule blocks intact).
	ConversationPrompt string
	LogLinePrompt      string

	// Per-turn hooks.
	//
	// ResolveFocus decides the focus for this turn (explicit mention wins,
	// else keep prev). Required.
	ResolveFocus func(prev, anchorID, message string, f Facts) string
	// PrepareTurn lets the domain enrich Facts once focus is known (e.g.
	// k8s resolves the focus pod). Nil => Facts passed through unchanged.
	PrepareTurn func(f Facts, t Target) Facts
	// Baseline contributes the free evidence every turn starts from (pod
	// status, corpus stats, …). Nil => none.
	Baseline func(ctx context.Context, f Facts, t Target, now time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem)
	// Fingerprint names the symptom under investigation for recurrence
	// matching. Nil => "<firstSymptomKey>\x1f<focus>" when a symptom matched.
	Fingerprint func(f Facts, focus string, matched []Symptom) string
	// Timeline builds the chronological event view. Nil => none.
	Timeline func(f Facts, t Target, now time.Time) []plugin.TimelineEvent
	// FixesFor returns known remediations for the anchor (finding). Nil => none.
	FixesFor func(f Facts, anchorID string) []plugin.RemediationAction
	// SuggestFollowUps proposes next questions. Nil => none.
	SuggestFollowUps func(intents []string, f Facts, steps []plugin.InvestigationStep) []string
	// DeterministicLineFallback renders the no-LLM answer for AnalyzeLine.
	// Nil => the framework's generic pattern-match fallback.
	DeterministicLineFallback func(req LineRequest) string
}

// Validate checks the profile's internal consistency: every referenced
// collector exists, symptom keys are unique, and prompts are present.
func (p Profile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("profile: Name is required")
	}
	if p.ConversationPrompt == "" || p.LogLinePrompt == "" {
		return fmt.Errorf("profile %s: prompts are required", p.Name)
	}
	if p.ResolveFocus == nil {
		return fmt.Errorf("profile %s: ResolveFocus is required", p.Name)
	}
	seen := map[string]bool{}
	for _, s := range p.Symptoms {
		if s.Key == "" || s.Match == nil {
			return fmt.Errorf("profile %s: symptom with empty key or nil Match", p.Name)
		}
		if seen[s.Key] {
			return fmt.Errorf("profile %s: duplicate symptom key %q", p.Name, s.Key)
		}
		seen[s.Key] = true
		for _, c := range s.Checks {
			if _, ok := p.Collectors[c.Collector]; !ok {
				return fmt.Errorf("profile %s: symptom %s references unknown collector %q", p.Name, s.Key, c.Collector)
			}
		}
	}
	for intent, checks := range p.IntentChecks {
		for _, c := range checks {
			if _, ok := p.Collectors[c.Collector]; !ok {
				return fmt.Errorf("profile %s: intent %s references unknown collector %q", p.Name, intent, c.Collector)
			}
		}
	}
	for _, e := range p.Edges {
		if _, ok := p.Collectors[e.Collector]; !ok {
			return fmt.Errorf("profile %s: edge %s references unknown collector %q", p.Name, e.Name, e.Collector)
		}
	}
	return nil
}

// edgeFor returns the registered edge for a collector ("" zero value when
// the collector has no graph edge).
func (p Profile) edgeFor(collector string) Edge {
	for _, e := range p.Edges {
		if e.Collector == collector {
			return e
		}
	}
	return Edge{}
}

// maxPlanSteps returns the effective plan cap.
func (p Profile) maxPlanSteps() int {
	if p.MaxPlanSteps > 0 {
		return p.MaxPlanSteps
	}
	return 8
}

// MatchSymptoms returns every catalog row matching the focus, in catalog
// order. Fallback rows match only when nothing else did.
func (p Profile) MatchSymptoms(f Facts, t Target) []Symptom {
	var out []Symptom
	for _, s := range p.Symptoms {
		if s.Fallback {
			continue
		}
		if s.Match(f, t) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		for _, s := range p.Symptoms {
			if s.Fallback && s.Match(f, t) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// Re compiles a case-insensitive pattern — the catalog-authoring helper.
func Re(p string) *regexp.Regexp { return regexp.MustCompile("(?i)" + p) }
