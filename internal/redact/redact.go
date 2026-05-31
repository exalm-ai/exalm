// Package redact scrubs sensitive content (secrets, tokens, optionally PII)
// from text before it leaves the process boundary.
//
// This is the trust foundation of Exalm. Every plugin that sends data to
// an LLM MUST route it through Engine.Redact() first.
//
// Design principles:
//
//   - Conservative defaults. Built-in patterns target high-entropy secrets
//     with clear shapes (AKIA prefixes, JWT structure, etc.).
//   - Optional patterns (email, IP, credit card) are opt-in because they
//     can hurt LLM accuracy when the data is benign.
//   - Patterns and replacements are inspectable. Users can pass --show-redactions
//     to see what was redacted before the request goes out.
//   - The engine is pure: same input, same output.
package redact

import (
	"strconv"
	"strings"
)

// Engine applies a configured set of patterns to input strings.
type Engine struct {
	patterns []Pattern
}

// New returns an Engine with all default patterns plus the named optional
// patterns enabled. Pass nil for opts to disable all optional patterns.
func New(opts ...string) *Engine {
	patterns := make([]Pattern, 0, len(DefaultPatterns)+len(opts))
	patterns = append(patterns, DefaultPatterns...)
	for _, name := range opts {
		if p, ok := OptionalPatterns[name]; ok {
			patterns = append(patterns, p)
		}
	}
	return &Engine{patterns: patterns}
}

// NewWithPatterns returns an Engine using exactly the supplied patterns.
// Useful for tests and custom deployments.
func NewWithPatterns(patterns []Pattern) *Engine {
	return &Engine{patterns: patterns}
}

// Redact applies all configured patterns to input and returns the
// redacted string. It never returns an error: redaction failures fall
// open to "no match", never to "leak the original".
func (e *Engine) Redact(input string) string {
	if input == "" {
		return ""
	}
	out := input
	for _, p := range e.patterns {
		out = p.Regex.ReplaceAllString(out, p.Replace)
	}
	return out
}

// Diff returns a list of redactions that would be applied to input,
// without modifying it. Useful for `--show-redactions` output.
func (e *Engine) Diff(input string) []Redaction {
	var redactions []Redaction
	for _, p := range e.patterns {
		matches := p.Regex.FindAllStringIndex(input, -1)
		for _, m := range matches {
			redactions = append(redactions, Redaction{
				Pattern: p.Name,
				Start:   m[0],
				End:     m[1],
				Match:   input[m[0]:m[1]],
			})
		}
	}
	return redactions
}

// Redaction describes a single match.
type Redaction struct {
	Pattern string
	Start   int
	End     int
	Match   string
}

// String returns a human-readable summary, masking the actual match.
func (r Redaction) String() string {
	maskLen := len(r.Match)
	if maskLen > 12 {
		maskLen = 12
	}
	masked := strings.Repeat("*", maskLen)
	return r.Pattern + " @ " + strconv.Itoa(r.Start) + "-" + strconv.Itoa(r.End) + " (" + masked + ")"
}
