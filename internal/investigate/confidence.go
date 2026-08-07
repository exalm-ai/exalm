package investigate

// confidence.go scores the copilot's confidence numerically (0–100) from
// evidence QUALITY, not quantity. The rule table is the domain's
// (Profile.ConfidenceRules); the scan, corroboration bonus, modeled-metrics
// deduction, cap, and tier mapping are framework-owned and identical across
// domains — moved from plugins/k8s.

import (
	"regexp"
	"strconv"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

var modeledRe = regexp.MustCompile(`(?i)modeled`)

// EvidenceMatching reports whether any evidence item of the given kind
// (empty = any) matches the pattern over Source+" "+Excerpt. Exported for
// profiles to build their confidence rules from.
func EvidenceMatching(ev []plugin.EvidenceItem, kind string, re *regexp.Regexp) bool {
	for _, e := range ev {
		if kind != "" && e.Kind != kind {
			continue
		}
		if re.MatchString(e.Source + " " + e.Excerpt) {
			return true
		}
	}
	return false
}

// ScoreConfidence returns the numeric confidence and a one-sentence
// rationale. Rules: highest matching row wins; +2 per independent evidence
// kind beyond the first (corroboration), capped at 98; modeled metrics
// subtract 15 when metrics are the strongest signal (score 45); floor 10
// when nothing was gathered.
func ScoreConfidence(rules []ConfidenceRule, ev []plugin.EvidenceItem, steps []plugin.InvestigationStep, f Facts) (int, string) {
	best := 0
	reason := "no evidence could be gathered this turn"
	for _, r := range rules {
		if r.Score > best && r.Match(ev, steps, f) {
			best = r.Score
			reason = r.Reason
		}
	}
	if best == 0 {
		return 10, reason
	}

	// Modeled metrics are honest approximations, not measurements.
	if best == 45 && EvidenceMatching(ev, "metric", modeledRe) {
		best -= 15
		reason += " (modeled metrics — reduced accordingly)"
	}

	kinds := map[string]bool{}
	for _, e := range ev {
		kinds[e.Kind] = true
	}
	if extra := len(kinds) - 1; extra > 0 {
		best += 2 * extra
		reason += "; corroborated across " + strconv.Itoa(len(kinds)) + " evidence kinds"
	}
	if best > 98 {
		best = 98
	}
	return best, reason
}

// TierFor maps the numeric score onto the legacy low/medium/high tiers so
// ConversationMessage.Confidence stays populated for older UI paths.
func TierFor(score int) string {
	switch {
	case score >= 75:
		return "high"
	case score >= 45:
		return "medium"
	default:
		return "low"
	}
}
