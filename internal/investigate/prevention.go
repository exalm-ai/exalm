package investigate

// prevention.go maps matched symptoms to long-term prevention advice
// (FixType "prevention") from the domain's catalog. Advice is always
// copy-only — prevention is a policy decision, never auto-applied.

import "github.com/exalm-ai/exalm/pkg/plugin"

// PreventionFor returns the preventive actions for the matched symptoms,
// deduplicated by description, in catalog order.
func PreventionFor(catalog map[string][]plugin.RemediationAction, matched []Symptom) []plugin.RemediationAction {
	var out []plugin.RemediationAction
	seen := map[string]bool{}
	for _, s := range matched {
		for _, a := range catalog[s.Key] {
			if !seen[a.Description] {
				seen[a.Description] = true
				out = append(out, a)
			}
		}
	}
	return out
}
