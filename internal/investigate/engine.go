package investigate

// engine.go — the generic per-turn conversation pipeline, moved verbatim
// from plugins/k8s/converse.go. Each turn:
//  1. resolve which resource the conversation focuses on (profile hook),
//  2. classify question intents deterministically (profile patterns),
//  3. build a deterministic investigation plan (symptoms + intents),
//  4. execute it through the profile's collectors, serving repeats from the
//     per-conversation evidence cache, labeling evidence E1..En,
//  5. rank hypotheses, score confidence from evidence quality, pick
//     prevention — all deterministic,
//  6. make ONE llm.Complete() call over redacted evidence + history
//     (fallback: a deterministic sectioned reply), and
//  7. persist both turns (redacted transcript only) via convo.Store.
//
// The LLM never chooses collectors — it only narrates what the plan gathered.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/internal/convo"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Engine runs investigations for one domain Profile.
type Engine struct {
	profile Profile
	cache   *evidenceCache
}

// NewEngine validates the profile and returns a ready engine.
func NewEngine(p Profile) (*Engine, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &Engine{profile: p, cache: newEvidenceCache(p.TTLs)}, nil
}

// Profile returns the engine's domain profile (read-only use).
func (e *Engine) Profile() Profile { return e.profile }

// ConverseReq is one user turn.
type ConverseReq struct {
	ConvoID  string
	AnchorID string // finding/alert id the chat was opened from ("" = none)
	Scope    string // namespace/host filter the chat was opened in
	Message  string
}

// Deps carries the per-turn injected dependencies. LLM and History members
// may be nil/zero — the engine degrades gracefully.
type Deps struct {
	LLM     plugin.LLMClient
	Red     plugin.Redactor
	Store   convo.Store
	Facts   Facts
	History HistorySources
}

var convoIDCounter int64

// newConvoID returns a process-unique conversation id. Not cryptographically
// random — conversation ids aren't a security boundary, just a lookup key.
func newConvoID() string {
	convoIDCounter++
	return fmt.Sprintf("c%d%06d", time.Now().UTC().Unix(), convoIDCounter)
}

// Converse runs one turn and returns the updated Conversation (full
// transcript, so the caller never merges partial state).
func (e *Engine) Converse(ctx context.Context, req ConverseReq, d Deps) (*plugin.Conversation, error) {
	now := time.Now().UTC()
	message := strings.TrimSpace(req.Message)
	if message == "" {
		return nil, fmt.Errorf("message is required")
	}

	conv := loadOrCreateConversation(ctx, d.Store, req.ConvoID, req.AnchorID, req.Scope, now)
	conv.Messages = append(conv.Messages, plugin.ConversationMessage{Role: "user", Content: message, At: now})

	conv.Focus = e.profile.ResolveFocus(conv.Focus, req.AnchorID, message, d.Facts)
	target := ParseFocus(conv.Focus)
	facts := d.Facts
	if e.profile.PrepareTurn != nil {
		facts = e.profile.PrepareTurn(facts, target)
	}

	intents := ClassifyIntent(e.profile.IntentPatterns, message)
	// The first turn of every investigation checks recurrence automatically —
	// "has this happened before?" is the first thing a senior operator asks.
	if len(conv.Messages) == 1 && !HasIntent(intents, "history") {
		intents = append(intents, "history")
	}

	// Baseline evidence comes free — always first.
	var steps []plugin.InvestigationStep
	var evidence []plugin.EvidenceItem
	if e.profile.Baseline != nil {
		s, ev := e.profile.Baseline(ctx, facts, target, now)
		steps = append(steps, s...)
		evidence = append(evidence, ev...)
	}

	// Deterministic investigation plan. Still exactly one LLM call.
	e.cache.purge(now)
	plan := e.buildPlan(planInput{
		message: message, intents: intents, focus: conv.Focus, facts: facts,
		cached: func(collector string) bool {
			return e.cache.has(conv.ID, collector, conv.Focus, now)
		},
		refresh: HasIntent(intents, "refresh"),
	})
	matched := e.profile.MatchSymptoms(facts, target)
	if conv.Fingerprint == "" {
		conv.Fingerprint = e.fingerprintFor(facts, conv.Focus, matched)
	}
	cc := CollectCtx{
		Target: target, Focus: conv.Focus, Now: now, Facts: facts, Red: d.Red,
		History: HistoryDeps{
			Sources: d.History, SelfID: conv.ID,
			Focus: conv.Focus, Fingerprint: conv.Fingerprint,
		},
	}
	executedPlan, planSteps, planEvidence := e.executePlan(ctx, plan, cc, conv.ID)
	steps = append(steps, planSteps...)
	evidence = LabelEvidence(append(evidence, planEvidence...))

	// Deterministic reasoning over the gathered evidence.
	hypotheses := RankHypotheses(matched, evidence)
	score, scoreRationale := ScoreConfidence(e.profile.ConfidenceRules, evidence, steps, facts)
	prevention := PreventionFor(e.profile.Prevention, matched)

	var timeline []plugin.TimelineEvent
	if e.profile.Timeline != nil {
		timeline = e.profile.Timeline(facts, target, now)
	}
	var fixes []plugin.RemediationAction
	if req.AnchorID != "" && e.profile.FixesFor != nil {
		fixes = e.profile.FixesFor(facts, req.AnchorID)
	}
	var suggestions []string
	if e.profile.SuggestFollowUps != nil {
		suggestions = e.profile.SuggestFollowUps(intents, facts, steps)
	}

	tc := turnContext{
		Question: message, Focus: conv.Focus,
		Plan: executedPlan, Steps: steps, Evidence: evidence,
		Hypotheses: hypotheses, Score: score, ScoreRationale: scoreRationale,
		Fixes: fixes, Prevention: prevention,
	}
	llmMessages := buildLLMMessages(conv, tc)
	content := e.synthesizeReply(ctx, llmMessages, tc, d.LLM, d.Red)

	conv.Messages = append(conv.Messages, plugin.ConversationMessage{
		Role: "assistant", Content: content, At: time.Now().UTC(),
		Confidence:     TierFor(score),
		Score:          score,
		ScoreRationale: scoreRationale,
		Steps:          steps,
		Evidence:       evidence,
		Fixes:          fixes,
		Timeline:       timeline,
		Suggestions:    suggestions,
		Plan:           executedPlan,
		Hypotheses:     hypotheses,
		Prevention:     prevention,
	})
	conv.UpdatedAt = time.Now().UTC()

	if err := d.Store.Update(ctx, conv); err != nil {
		return nil, fmt.Errorf("persist conversation: %w", err)
	}
	return &conv, nil
}

// loadOrCreateConversation fetches convoID from store, or starts a fresh one
// when it's empty/unknown.
func loadOrCreateConversation(ctx context.Context, store convo.Store, convoID, anchorID, scope string, now time.Time) plugin.Conversation {
	if convoID != "" {
		if existing, err := store.Get(ctx, convoID); err == nil {
			return existing
		}
	}
	id := convoID
	if id == "" {
		id = newConvoID()
	}
	return plugin.Conversation{
		ID: id, FindingID: anchorID, Namespace: scope,
		CreatedAt: now, UpdatedAt: now,
	}
}

// turnContext bundles everything assembled for one turn — the input to both
// the enriched LLM message and the deterministic fallback.
type turnContext struct {
	Question       string
	Focus          string
	Plan           []plugin.PlanStep
	Steps          []plugin.InvestigationStep
	Evidence       []plugin.EvidenceItem
	Hypotheses     []plugin.Hypothesis
	Score          int
	ScoreRationale string
	Fixes          []plugin.RemediationAction
	Prevention     []plugin.RemediationAction
}

// evidenceByteBudget caps the total evidence text per turn so many
// collectors' output can't blow up the prompt. Evidence is emitted in
// collection order (baseline facts first), so what gets summarized away is
// the lowest-priority tail.
const evidenceByteBudget = 48 * 1024

func buildLLMMessages(conv plugin.Conversation, tc turnContext) []plugin.Message {
	msgs := make([]plugin.Message, 0, len(conv.Messages))
	for i, m := range conv.Messages {
		if i == len(conv.Messages)-1 {
			break // last message is this turn's user question; build it enriched below
		}
		msgs = append(msgs, plugin.Message{Role: m.Role, Content: m.Content})
	}
	msgs = append(msgs, plugin.Message{Role: "user", Content: buildEnrichedTurn(tc)})
	return msgs
}

func buildEnrichedTurn(tc turnContext) string {
	var b strings.Builder
	fmt.Fprintf(&b, "QUESTION: %s\n", tc.Question)
	if tc.Focus != "" {
		fmt.Fprintf(&b, "FOCUS RESOURCE: %s\n", tc.Focus)
	}
	if len(tc.Plan) > 0 {
		b.WriteString("\nINVESTIGATION PLAN EXECUTED:\n")
		for _, ps := range tc.Plan {
			cached := ""
			if ps.FromCache {
				cached = " (cached)"
			}
			edge := ""
			if ps.Edge != "" {
				edge = " (" + ps.Edge + ")"
			}
			fmt.Fprintf(&b, "- [%s]%s %s %s%s: %s\n", ps.Status, cached, ps.ID, ps.Collector, edge, ps.Reason)
		}
	}
	if len(tc.Steps) > 0 {
		b.WriteString("\nCHECKS PERFORMED THIS TURN:\n")
		for _, s := range tc.Steps {
			fmt.Fprintf(&b, "- [%s] %s — %s\n", s.Status, s.Label, s.Detail)
		}
	}
	if len(tc.Evidence) > 0 {
		b.WriteString("\nEVIDENCE:\n")
		spent, omitted := 0, 0
		for _, e := range tc.Evidence {
			line := fmt.Sprintf("- [%s] (%s/%s", e.Label, e.Kind, e.Source)
			if e.Edge != "" {
				line += ", edge=" + e.Edge
			}
			line += ") "
			if e.FromCache {
				line += "(cached) "
			}
			line += e.Excerpt + "\n"
			if spent+len(line) > evidenceByteBudget {
				omitted++
				continue
			}
			spent += len(line)
			b.WriteString(line)
		}
		if omitted > 0 {
			fmt.Fprintf(&b, "- …and %d more evidence item(s) omitted for size\n", omitted)
		}
	}
	if len(tc.Hypotheses) > 0 {
		b.WriteString("\nHYPOTHESES (deterministic ranking — explain, do not re-rank):\n")
		for i, h := range tc.Hypotheses {
			fmt.Fprintf(&b, "- %d. %s (score %d) for=%v against=%v — %s\n", i+1, h.Title, h.Score, h.EvidenceFor, h.EvidenceAgainst, h.Rationale)
		}
	}
	if tc.Score > 0 {
		fmt.Fprintf(&b, "\nCONFIDENCE: %d%% — %s\n", tc.Score, tc.ScoreRationale)
	}
	if len(tc.Fixes) > 0 {
		b.WriteString("\nKNOWN FIXES FOR THIS RESOURCE:\n")
		for _, fx := range tc.Fixes {
			fmt.Fprintf(&b, "- [%s] %s\n", fx.FixType, fx.Description)
		}
	}
	if len(tc.Prevention) > 0 {
		b.WriteString("\nPREVENTION:\n")
		for _, fx := range tc.Prevention {
			fmt.Fprintf(&b, "- %s\n", fx.Description)
		}
	}
	return b.String()
}

// synthesizeReply makes the ONE LLM call for this turn, redacting every
// message first. Falls back to a deterministic reply when llm is nil or the
// call fails.
func (e *Engine) synthesizeReply(ctx context.Context, messages []plugin.Message, tc turnContext, llm plugin.LLMClient, red plugin.Redactor) string {
	if llm == nil {
		return deterministicReply(tc)
	}
	redacted := make([]plugin.Message, len(messages))
	for i, m := range messages {
		content := m.Content
		if red != nil {
			content = red.Redact(content)
		}
		redacted[i] = plugin.Message{Role: m.Role, Content: content}
	}
	resp, err := llm.Complete(ctx, plugin.CompleteRequest{System: e.profile.ConversationPrompt, MaxTokens: 900, Messages: redacted})
	if err != nil || strings.TrimSpace(resp.Content) == "" {
		return deterministicReply(tc)
	}
	return strings.TrimSpace(resp.Content)
}

// deterministicReply is the no-LLM fallback: it renders the same sections
// the LLM would — root cause from the top hypothesis, alternatives, fixes,
// prevention — from the deterministic engines alone, so the copilot degrades
// honestly instead of going silent.
func deterministicReply(tc turnContext) string {
	if len(tc.Evidence) == 0 && len(tc.Hypotheses) == 0 {
		return "No information available yet — ask about a specific resource, or run an analysis first so the copilot has data to investigate."
	}
	var b strings.Builder
	b.WriteString("_No LLM is configured — this summary is assembled deterministically from the gathered evidence._\n\n")
	if len(tc.Hypotheses) > 0 {
		top := tc.Hypotheses[0]
		fmt.Fprintf(&b, "**Root cause** (most likely): %s %s", top.Title, citationList(top.EvidenceFor))
		if tc.Score > 0 {
			fmt.Fprintf(&b, " — confidence %d%% (%s)", tc.Score, tc.ScoreRationale)
		}
		b.WriteString("\n")
		if len(tc.Hypotheses) > 1 {
			b.WriteString("\n**Alternative hypotheses**\n")
			for _, h := range tc.Hypotheses[1:] {
				fmt.Fprintf(&b, "- %s (score %d) — %s\n", h.Title, h.Score, h.Rationale)
			}
		}
	}
	var temp, root []plugin.RemediationAction
	for _, fx := range tc.Fixes {
		if fx.FixType == "root-cause" {
			root = append(root, fx)
		} else {
			temp = append(temp, fx)
		}
	}
	if len(temp) > 0 {
		b.WriteString("\n**Immediate mitigation** (temporary)\n")
		for _, fx := range temp {
			fmt.Fprintf(&b, "- %s\n", fx.Description)
		}
	}
	if len(root) > 0 {
		b.WriteString("\n**Root-cause fix**\n")
		for _, fx := range root {
			fmt.Fprintf(&b, "- %s\n", fx.Description)
		}
	}
	if len(tc.Prevention) > 0 {
		b.WriteString("\n**Prevention**\n")
		for _, fx := range tc.Prevention {
			fmt.Fprintf(&b, "- %s\n", fx.Description)
		}
	}
	return strings.TrimSpace(b.String())
}

// citationList renders evidence labels as "[E1] [E3]".
func citationList(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	var b strings.Builder
	for _, l := range labels {
		b.WriteString("[" + l + "] ")
	}
	return strings.TrimSpace(b.String())
}
