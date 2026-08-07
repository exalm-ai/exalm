package investigate

// intents.go — deterministic question-intent classification (regex, never an
// LLM call) plus the domain-neutral base patterns every profile extends.

// ClassifyIntent maps free-text to zero or more intent tags via the
// profile's patterns. Returns ["general"] when nothing matches so the engine
// still gathers baseline evidence.
func ClassifyIntent(patterns []IntentPattern, message string) []string {
	var out []string
	for _, p := range patterns {
		if p.Re.MatchString(message) {
			out = append(out, p.Intent)
		}
	}
	if len(out) == 0 {
		out = append(out, "general")
	}
	return out
}

// HasIntent reports whether the classified intents include the given tag.
func HasIntent(intents []string, tag string) bool {
	for _, i := range intents {
		if i == tag {
			return true
		}
	}
	return false
}

// CommonIntentPatterns are the domain-neutral intents every analyzer
// understands. Profiles append their domain-specific patterns.
func CommonIntentPatterns() []IntentPattern {
	return []IntentPattern{
		{"previous-logs", Re(`previous log|logs? before|prior log|last run|before it (crashed|failed)|earlier (entries|events|lines)`)},
		{"comparison", Re(`compare|yesterday|did this happen before|previously|history|happened before`)},
		{"timeline", Re(`timeline|sequence of events|what happened|order of events`)},
		{"rca", Re(`\brca\b|postmortem|incident report|root cause analysis`)},
		{"history", Re(`happened before|recurr|similar (incident|issue)|last time|how often|more frequent`)},
		{"refresh", Re(`\brefresh\b|re-?check|fetch again|latest (data|state)|re-?collect`)},
	}
}
