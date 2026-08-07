package investigate

// questionmode.go — deterministic per-turn answer-mode routing. The
// conversation prompt already describes a direct-answer mode, but the small
// local models exalm targets (3-4B Ollama class) reliably ignore mode-switch
// instructions that live in the distant system prompt once the conversation
// history is full of template-shaped replies: verified live against
// phi4-mini:3.8b, which kept restating the root-cause template when asked
// "what is the current memory limit?" even with the mode documented in the
// system prompt. So, consistent with the engine's deterministic-first design
// (ranked hypotheses, computed confidence — the LLM only narrates), the
// question SHAPE is classified in code and the answering directive is
// injected into the enriched turn itself, adjacent to the QUESTION, where
// proximity gives it force.

import "strings"

// openEndedMarkers anywhere in the question mean the operator wants the full
// investigation narrative, so no directive is injected. Checked before
// directPrefixes: "what is wrong with X" must stay open-ended even though it
// starts with "what is".
var openEndedMarkers = []string{
	"why",
	"wrong",
	"going on",
	"happening",
	"up with",
	"what happened",
	"root cause",
	"rca",
	"postmortem",
	"incident report",
	"investigate",
	"analyze",
	"analyse",
	"diagnose",
	"debug",
	"summarize",
	"summarise",
	"overview",
}

// politenessPrefixes are stripped before classification so "Can you tell me
// the memory limit?" classifies like "tell me the memory limit". Stripping —
// rather than listing them as direct prefixes — keeps "can you fix it?"
// (an action request, no direct prefix after the strip) on the default path.
var politenessPrefixes = []string{
	"please ", "kindly ", "can you ", "could you ", "would you ", "will you ",
}

// directPrefixes open questions that ask for a specific fact: a value, a
// name, a count, a yes/no, a timestamp. Matched against the lowercased,
// trimmed question after politeness prefixes are stripped.
var directPrefixes = []string{
	"what is", "what's", "what are", "what was", "what were",
	"which", "when", "where", "who", "whose",
	"how many", "how much", "how long", "how often", "how big",
	"is ", "are ", "was ", "were ",
	"does ", "do ", "did ", "has ", "have ", "had ",
	"list ", "show ", "name ", "give me", "tell me",
}

// directAnswerDirective is injected right below the QUESTION line. It repeats
// the out-of-scope rule from the conversation prompt because fact-shaped
// questions ("what is the best pizza topping?") are exactly where unrelated
// asks land, and the per-turn copy is the one small models actually follow.
// The scope check is step 1 with a copyable reply, not a trailing exception:
// live-tested against phi4-mini:3.8b, a trailing "if unrelated, say so"
// clause was ignored and the model answered the unrelated question with
// fabricated evidence citations.
const directAnswerDirective = `ANSWER MODE: direct — the question asks for a specific fact.
Step 1 — scope check: if the QUESTION is not about this investigation, its resources, or its EVIDENCE, reply only: "That question is not related to this investigation. Did you mean something about the focus resource?" — cite no evidence — and stop.
Step 2 — answer: reply with ONLY the answer to the question — 1-3 sentences, or a short list when the question asks for one — citing evidence labels like [E3], then STOP — no **Root cause** section, no hypotheses, no mitigation, no prevention. If the answer is not in the EVIDENCE below, say it is not in the gathered evidence and name the check that would get it, then STOP.
`

// directQuestionMaxLen guards against multi-part questions that merely start
// with a direct prefix; past this length the operator is asking for
// reasoning, not a fact lookup.
const directQuestionMaxLen = 160

// answerModeDirective classifies the question shape and returns the per-turn
// directive to inject, or "" when the default template should apply.
func answerModeDirective(question string) string {
	q := strings.ToLower(strings.TrimSpace(question))
	if q == "" || len(q) > directQuestionMaxLen {
		return ""
	}
	for _, m := range openEndedMarkers {
		if strings.Contains(q, m) {
			return ""
		}
	}
	for stripped := true; stripped; {
		stripped = false
		for _, p := range politenessPrefixes {
			if strings.HasPrefix(q, p) {
				q, stripped = q[len(p):], true
			}
		}
	}
	for _, p := range directPrefixes {
		if strings.HasPrefix(q, p) {
			return directAnswerDirective
		}
	}
	return ""
}
