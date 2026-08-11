package investigate

// planner.go builds and executes the per-turn investigation plan. FULLY
// DETERMINISTIC — symptom catalog + question intents + resource-graph edges —
// and runs BEFORE the turn's single redacted LLM call. The LLM never chooses
// collectors; it only narrates the evidence the plan gathered.

import (
	"context"
	"fmt"
	"sort"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// planInput is everything buildPlan needs. cached is optional (nil = nothing
// cached); refresh forces re-collection even for cached steps.
type planInput struct {
	message string
	intents []string
	focus   string
	facts   Facts
	cached  func(collector string) bool
	refresh bool
}

// buildPlan produces the ordered, deduped, capped investigation plan for one
// turn. Deterministic: the same input always yields the same plan.
func (e *Engine) buildPlan(in planInput) []plugin.PlanStep {
	type cand struct {
		check Check
		seq   int // insertion order — stable tie-break
	}
	var cands []cand
	seq := 0
	add := func(c Check) {
		cands = append(cands, cand{check: c, seq: seq})
		seq++
	}

	t := ParseFocus(in.focus)
	for _, s := range e.profile.MatchSymptoms(in.facts, t) {
		for _, c := range s.Checks {
			add(c)
		}
	}
	for _, intent := range in.intents {
		for _, c := range e.profile.IntentChecks[intent] {
			add(c)
		}
	}

	// Dedupe by collector — symptom checks were inserted first, so their
	// reasons win on overlap ("reason=OOMKilled ⇒ …" explains more than
	// "you asked about X").
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].check.Priority != cands[j].check.Priority {
			return cands[i].check.Priority < cands[j].check.Priority
		}
		return cands[i].seq < cands[j].seq
	})
	seen := map[string]bool{}
	var plan []plugin.PlanStep
	for _, c := range cands {
		if seen[c.check.Collector] {
			continue
		}
		seen[c.check.Collector] = true
		if len(plan) >= e.profile.maxPlanSteps() {
			break
		}
		status := "planned"
		if !in.refresh && in.cached != nil && in.cached(c.check.Collector) {
			status = "cached"
		}
		plan = append(plan, plugin.PlanStep{
			ID:        fmt.Sprintf("p%d", len(plan)+1),
			Collector: c.check.Collector,
			Target:    in.focus,
			Edge:      e.profile.edgeFor(c.check.Collector).Name,
			Reason:    c.check.Reason,
			Status:    status,
		})
	}
	return plan
}

// fingerprintFor names the symptom under investigation for recurrence
// matching. Empty when no symptom matched.
func (e *Engine) fingerprintFor(f Facts, focus string, matched []Symptom) string {
	if e.profile.Fingerprint != nil {
		return e.profile.Fingerprint(f, focus, matched)
	}
	if len(matched) > 0 {
		return matched[0].Key + "\x1f" + focus
	}
	return ""
}

// executePlan runs every planned step through the profile's collectors,
// stamps evidence with the step's graph edge, serves fresh cached results,
// and records each step's outcome on the returned plan copy.
func (e *Engine) executePlan(ctx context.Context, plan []plugin.PlanStep, cc CollectCtx, convoID string) ([]plugin.PlanStep, []plugin.InvestigationStep, []plugin.EvidenceItem) {
	var steps []plugin.InvestigationStep
	var evidence []plugin.EvidenceItem
	executed := make([]plugin.PlanStep, len(plan))
	copy(executed, plan)

	for i, ps := range executed {
		if ps.Status == "cached" {
			if entry, ok := e.cache.get(convoID, ps.Collector, ps.Target, cc.Now); ok {
				for _, ev := range entry.Evidence {
					ev.FromCache = true
					ev.CollectedAt = entry.At
					evidence = append(evidence, ev)
				}
				steps = append(steps, entry.Steps...)
				executed[i].FromCache = true
				continue
			}
			executed[i].Status = "planned" // expired between planning and execution
		}

		fn, ok := e.profile.Collectors[ps.Collector]
		if !ok {
			executed[i].Status = "unavailable"
			steps = append(steps, plugin.InvestigationStep{
				Label: ps.Collector + " requested", Status: "unavailable",
				Detail: "collector not available in this build",
			})
			continue
		}
		s, ev := fn(ctx, cc)
		for j := range ev {
			if ev[j].Edge == "" {
				ev[j].Edge = ps.Edge
			}
			if ev[j].CollectedAt.IsZero() {
				ev[j].CollectedAt = cc.Now
			}
			// Redact every excerpt here rather than trusting each collector to
			// remember. Evidence is persisted in the transcript, rendered in the
			// browser, and written into Markdown/HTML/JSON exports, so the LLM
			// call's own redaction pass does not cover it. This is the last
			// chokepoint before a raw secret leaves the process, and it is
			// idempotent for collectors that already redact.
			ev[j].Excerpt = redactWith(cc.Red, ev[j].Excerpt)
		}
		steps = append(steps, s...)
		evidence = append(evidence, ev...)
		executed[i].Status = planStepOutcome(s)
		if executed[i].Status == "done" {
			e.cache.put(convoID, ps.Collector, ps.Target, cachedEvidence{Steps: s, Evidence: ev, At: cc.Now}, cc.Now)
		}
	}
	return executed, steps, evidence
}

// planStepOutcome folds a collector's steps into one plan-step status:
// "done" if anything ran, "unavailable" if everything was unavailable.
func planStepOutcome(steps []plugin.InvestigationStep) string {
	if len(steps) == 0 {
		return "done"
	}
	for _, s := range steps {
		if s.Status == "done" {
			return "done"
		}
	}
	return "unavailable"
}

// LabelEvidence assigns citation keys E1..En in collection order so the
// answer text, hypotheses, and UI can reference items precisely.
func LabelEvidence(evidence []plugin.EvidenceItem) []plugin.EvidenceItem {
	for i := range evidence {
		evidence[i].Label = fmt.Sprintf("E%d", i+1)
	}
	return evidence
}

// PlanPreview builds (without executing) the deterministic plan the engine
// would run for a question — useful for UI previews and for catalog tests
// asserting which collectors a symptom or intent schedules. No cache
// interaction.
func (e *Engine) PlanPreview(message string, intents []string, focus string, f Facts) []plugin.PlanStep {
	return e.buildPlan(planInput{message: message, intents: intents, focus: focus, facts: f})
}
