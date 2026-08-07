package plugin

// copilot.go holds the explainability types introduced by the conversational
// investigation copilot: the per-turn investigation plan and the ranked
// root-cause hypotheses. They are siblings of Investigation/EvidenceItem —
// pure data, shared across plugins and the web UI.
//
// The plan is built DETERMINISTICALLY (symptom catalog + resource-graph walk
// + question intents) before the turn's single redacted LLM call; it is never
// produced by the LLM. See plugins/k8s/planner.go.

// PlanStep is one node of the deterministic investigation plan for a turn:
// which collector ran, against what, following which resource-graph edge,
// and why the planner scheduled it.
type PlanStep struct {
	// ID is a short stable key within the turn ("p1", "p2", …) so evidence
	// and the UI can reference the step.
	ID string `json:"id"`
	// Collector names the gather function that ran ("owner-chain",
	// "service-endpoints", "storage-chain", "previous-logs", …).
	Collector string `json:"collector"`
	// Target is the resource the collector inspected ("prod/payment-api").
	Target string `json:"target,omitempty"`
	// Edge is the resource-graph relationship that led here
	// ("pod→ownerDeployment"). Empty for question-driven steps.
	Edge string `json:"edge,omitempty"`
	// Reason explains why this step was planned
	// ("reason=OOMKilled ⇒ check memory limits and node pressure").
	Reason string `json:"reason"`
	// Status is "planned", "done", "cached", "unavailable", or "skipped".
	Status string `json:"status"`
	// FromCache is true when the step reused evidence collected earlier in
	// the same conversation instead of calling the cluster again.
	FromCache bool `json:"from_cache,omitempty"`
}

// Hypothesis is one candidate root cause with its evidence balance. The
// engine ranks several hypotheses per turn; the top one becomes the root
// cause, the rest are presented as alternatives with the evidence that
// argues against them.
type Hypothesis struct {
	Title string `json:"title"`
	// Score is 0–100, same scale as ConversationMessage.Score.
	Score int `json:"score"`
	// Rationale explains the score in one sentence.
	Rationale string `json:"rationale,omitempty"`
	// EvidenceFor / EvidenceAgainst reference EvidenceItem.Label values
	// ("E1", "E3") collected in the same turn.
	EvidenceFor     []string `json:"evidence_for,omitempty"`
	EvidenceAgainst []string `json:"evidence_against,omitempty"`
}
