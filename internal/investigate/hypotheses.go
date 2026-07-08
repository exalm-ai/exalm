package investigate

// hypotheses.go ranks candidate root causes deterministically: the matched
// symptoms' cause templates are scored against the evidence that actually
// came back this turn — matched "for" evidence raises a cause, matched
// "against" evidence lowers it, and every match is recorded by citation
// label so the user sees exactly which evidence argues for and against each
// hypothesis. Moved verbatim from plugins/k8s (already domain-agnostic).

import (
	"sort"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// MaxHypotheses bounds how many alternatives the copilot presents.
const MaxHypotheses = 4

// RankHypotheses scores every cause template from the matched symptoms
// against the labeled evidence. Deterministic; ties break by catalog order.
func RankHypotheses(symptoms []Symptom, evidence []plugin.EvidenceItem) []plugin.Hypothesis {
	var out []plugin.Hypothesis
	seen := map[string]bool{}
	for _, s := range symptoms {
		for _, c := range s.Causes {
			if seen[c.Title] {
				continue
			}
			seen[c.Title] = true
			h := plugin.Hypothesis{Title: c.Title, Score: c.Base}
			for _, m := range c.For {
				if labels := matchLabels(evidence, m); len(labels) > 0 {
					h.Score += m.Weight
					h.EvidenceFor = append(h.EvidenceFor, labels...)
				}
			}
			for _, m := range c.Against {
				if labels := matchLabels(evidence, m); len(labels) > 0 {
					h.Score -= m.Weight
					h.EvidenceAgainst = append(h.EvidenceAgainst, labels...)
				}
			}
			if h.Score < 0 {
				h.Score = 0
			}
			if h.Score > 98 {
				h.Score = 98
			}
			h.Rationale = rationaleFor(h)
			out = append(out, h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if len(out) > MaxHypotheses {
		out = out[:MaxHypotheses]
	}
	return out
}

// matchLabels returns the citation labels of evidence items the matcher hits.
func matchLabels(evidence []plugin.EvidenceItem, m EvidenceMatcher) []string {
	var labels []string
	for _, e := range evidence {
		if m.Kind != "" && e.Kind != m.Kind {
			continue
		}
		if m.Pattern != nil && !m.Pattern.MatchString(e.Source+" "+e.Excerpt) {
			continue
		}
		if e.Label != "" {
			labels = append(labels, e.Label)
		}
	}
	return labels
}

// rationaleFor summarizes why a hypothesis scored the way it did.
func rationaleFor(h plugin.Hypothesis) string {
	switch {
	case len(h.EvidenceFor) > 0 && len(h.EvidenceAgainst) > 0:
		return "supported by " + joinLabels(h.EvidenceFor) + " but weakened by " + joinLabels(h.EvidenceAgainst)
	case len(h.EvidenceFor) > 0:
		return "supported by " + joinLabels(h.EvidenceFor)
	case len(h.EvidenceAgainst) > 0:
		return "weakened by " + joinLabels(h.EvidenceAgainst) + " — kept only as a fallback"
	default:
		return "no direct evidence either way — plausible for this symptom class"
	}
}

func joinLabels(labels []string) string {
	out := ""
	for i, l := range labels {
		if i > 0 {
			out += ", "
		}
		out += "[" + l + "]"
	}
	return out
}
