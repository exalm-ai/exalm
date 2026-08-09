package investigate

import (
	"strings"
	"testing"
)

func TestAnswerModeDirective_DirectQuestions(t *testing.T) {
	direct := []string{
		"what is the current memory limit ?",
		"is there a memeory limits ?", // real user phrasing, typo included
		"how many restarts does the pod have?",
		"when did the last restart happen?",
		"which container is crashing?",
		"does the deployment have probes configured?",
		"What's the image tag?",
		"are there any pending pods?",
		"who updated the deployment?",
		"how much memory is the container using?",
		"what is the best pizza topping?", // out-of-scope but fact-shaped: directive handles it
		// Polite/indirect phrasings must classify the same as their bare forms.
		"Can you tell me the memory limit?",
		"could you show me the restart count?",
		"please list the events from the last hour",
		"Would you tell me which container is crashing?",
	}
	for _, q := range direct {
		if d := answerModeDirective(q); d == "" {
			t.Errorf("expected direct-answer directive for %q, got none", q)
		}
	}
}

func TestAnswerModeDirective_OpenEndedQuestions(t *testing.T) {
	open := []string{
		"Why is payment-api failing?",
		"what's going on with the cluster",
		"what is wrong with tempo-ingester-0?",
		"Generate an RCA",
		"write a postmortem for this incident",
		"analyze the memory usage",
		"investigate the crash loop",
		"diagnose the pod",
		"what happened after the deploy?",
		"what is happening with payment-api?",
		"what's up with the api pod?",
		"can you fix it?", // action request, not a fact lookup
		"help",
		"", // empty question: no directive
	}
	for _, q := range open {
		if d := answerModeDirective(q); d != "" {
			t.Errorf("expected NO directive for open-ended %q, got %q", q, d)
		}
	}
}

func TestAnswerModeDirective_LongQuestionsStayDefault(t *testing.T) {
	long := "what is the relationship between the ingester restarts, the config change from yesterday, the node pressure we saw this morning, and the alert storm — and how should we sequence the remediation so we do not make the outage worse while the on-call rotation changes over?"
	if d := answerModeDirective(long); d != "" {
		t.Errorf("multi-part question should use the default template, got directive %q", d)
	}
}

func TestAnswerModeDirective_ContentContract(t *testing.T) {
	d := answerModeDirective("what is the current memory limit?")
	wants := []string{
		"ANSWER MODE: direct",
		"Step 1 — scope check", // scope gate must come FIRST: small models drop trailing conditionals
		"not related to this investigation",
		"Step 2 — answer",
		"1-3 sentences",
		"not in the gathered evidence",
	}
	last := -1
	for _, want := range wants {
		idx := strings.Index(d, want)
		if idx < 0 {
			t.Errorf("directive missing %q:\n%s", want, d)
			continue
		}
		if idx < last {
			t.Errorf("directive parts out of order: %q must come after the previous part", want)
		}
		last = idx
	}
}

func TestBuildEnrichedTurn_InjectsDirectiveNextToQuestion(t *testing.T) {
	tc := turnContext{Question: "what is the current memory limit?", Focus: "prod/api"}
	turn := buildEnrichedTurn(tc)
	if !strings.Contains(turn, "ANSWER MODE: direct") {
		t.Fatalf("enriched turn missing directive:\n%s", turn)
	}
	qIdx := strings.Index(turn, "QUESTION:")
	dIdx := strings.Index(turn, "ANSWER MODE: direct")
	fIdx := strings.Index(turn, "FOCUS RESOURCE:")
	if qIdx >= dIdx || dIdx >= fIdx {
		t.Errorf("directive must sit between QUESTION and FOCUS RESOURCE (q=%d d=%d f=%d)", qIdx, dIdx, fIdx)
	}

	openTurn := buildEnrichedTurn(turnContext{Question: "Why is payment-api failing?", Focus: "prod/api"})
	if strings.Contains(openTurn, "ANSWER MODE:") {
		t.Errorf("open-ended question must not carry a directive:\n%s", openTurn)
	}
}
