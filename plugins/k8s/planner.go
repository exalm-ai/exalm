package k8s

// planner.go builds and executes the per-turn investigation plan. The plan is
// FULLY DETERMINISTIC — symptom catalog + question intents + resource-graph
// edges — and runs BEFORE the turn's single redacted LLM call. There is no
// agentic tool-use loop: the LLM never chooses collectors; it only narrates
// the evidence the plan gathered.

import (
	"context"
	"fmt"
	"sort"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/internal/metrics"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// maxPlanSteps caps how many collectors run per turn — keeps latency and
// prompt size bounded even when many symptoms + intents match.
const maxPlanSteps = 8

// planInput is everything buildPlan needs. Cached is optional (nil = nothing
// cached); Refresh forces re-collection even for cached steps.
type planInput struct {
	Message string
	Intents []string
	Focus   string // "ns/name"
	Pod     *PodSummary
	Snap    Snapshot
	Cached  func(collector string) bool
	Refresh bool
}

// intentChecks maps question intents to collector requests — this is what
// makes the planner question-driven on top of symptom-driven: mentioning
// ingress schedules the traffic-path check even when no symptom implies it.
var intentChecks = map[string][]plannedCheck{
	"previous-logs": {{"previous-logs", "you asked for the logs before the crash", 1}},
	"deploy-correlation": {
		{"change-history", "you asked about deployments/changes", 1},
		{"owner-chain", "the owning workload shows what the deploy changed", 2},
	},
	"comparison": {
		{"change-history", "comparing with the past needs the change record", 1},
		{"history", "prior investigations and incidents cover 'has this happened before'", 2},
	},
	"db-connectivity": {
		{"related-services", "locate the database service and its endpoint health", 1},
		{"netpol", "network policies can isolate the pod from the database", 2},
		{"secrets", "rotated credentials mimic database downtime (existence only)", 3},
	},
	"resource-usage": {
		{"metrics", "you asked about resource usage", 1},
		{"owner-chain", "limits/requests live on the owning workload", 2},
		{"node-detail", "node capacity bounds everything the pod can use", 3},
	},
	"node-pressure": {{"node-detail", "you asked about the node", 1}},
	"configmap":     {{"configmaps", "you asked about configuration", 1}},
	"secret":        {{"secrets", "you asked about secrets (existence/type only — values never read)", 1}},
	"dns": {
		{"dns-heuristic", "you asked about DNS", 1},
		{"netpol", "a policy blocking egress to kube-dns mimics DNS failure", 2},
	},
	"rca": {
		{"previous-logs", "an RCA needs the failure output", 1},
		{"change-history", "an RCA needs the change record", 2},
		{"owner-chain", "an RCA needs the workload context", 3},
		{"history", "an RCA should note recurrence", 4},
	},
	"related-services": {
		{"service-endpoints", "you asked about related services", 1},
		{"related-services", "sibling service issues reveal shared dependencies", 2},
	},
	"ingress": {
		{"service-endpoints", "ingress routes through services — check the whole path", 1},
		{"related-services", "edge errors often trace to a backend service issue", 2},
	},
	"storage":       {{"storage-chain", "you asked about storage — walking PVC → PV → StorageClass", 1}},
	"rbac-question": {{"rbac", "you asked about permissions — checking the pod's ServiceAccount grants", 1}},
	"quota":         {{"namespace-detail", "you asked about namespace quotas/limits", 1}},
	"scaling":       {{"scaling", "you asked about autoscaling", 1}},
	"history":       {{"history", "you asked whether this happened before", 1}},
	"vpa":           {{"vpa", "you asked about VPA", 1}},
}

// buildPlan produces the ordered, deduped, capped investigation plan for one
// turn. Deterministic: the same input always yields the same plan.
func buildPlan(in planInput) []plugin.PlanStep {
	type cand struct {
		check  plannedCheck
		origin string // "symptom:<key>" or "intent:<name>"
		seq    int    // insertion order — stable tie-break
	}
	var cands []cand
	seq := 0
	add := func(c plannedCheck, origin string) {
		cands = append(cands, cand{check: c, origin: origin, seq: seq})
		seq++
	}

	ns, name := splitFocus(in.Focus)
	for _, s := range matchSymptoms(in.Pod, in.Snap, ns, name) {
		for _, c := range s.Checks {
			add(c, "symptom:"+s.Key)
		}
	}
	for _, intent := range in.Intents {
		for _, c := range intentChecks[intent] {
			add(c, "intent:"+intent)
		}
	}

	// Dedupe by collector — keep the earliest (question-driven checks were
	// added after symptom checks, so symptom reasons win on overlap, which is
	// right: "reason=OOMKilled ⇒ …" explains more than "you asked about X").
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
		if len(plan) >= maxPlanSteps {
			break
		}
		status := "planned"
		if !in.Refresh && in.Cached != nil && in.Cached(c.check.Collector) {
			status = "cached"
		}
		plan = append(plan, plugin.PlanStep{
			ID:        fmt.Sprintf("p%d", len(plan)+1),
			Collector: c.check.Collector,
			Target:    in.Focus,
			Edge:      edgeFor(c.check.Collector).Name,
			Reason:    c.check.Reason,
			Status:    status,
		})
	}
	return plan
}

// fingerprintFor names the symptom under investigation for cross-conversation
// matching ("has this happened before?"). Empty when no symptom matched.
func fingerprintFor(pod *PodSummary, snap Snapshot, focus string) string {
	ns, name := splitFocus(focus)
	if syms := matchSymptoms(pod, snap, ns, name); len(syms) > 0 && pod != nil {
		return syms[0].Key + "\x1f" + focus
	}
	return ""
}

// execDeps carries the injected dependencies collectors need — the SAME
// already-injected clients Converse holds; executePlan opens no new network
// surface.
type execDeps struct {
	cs    kubernetes.Interface
	red   plugin.Redactor
	newLF func(kubernetes.Interface) logFetcher
	mp    metrics.Provider
	snap  Snapshot
	ns    string
	name  string
	now   time.Time
	// cache/convoID enable per-conversation evidence reuse (both optional).
	cache   *evidenceCache
	convoID string
}

// collectorFn is one dispatch-table entry.
type collectorFn func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem)

// collectorTable maps PlanStep.Collector keys to gather functions. The
// "history" key is registered by the historical-context layer when its
// sources are wired; unknown keys report an unavailable step rather than
// failing the turn.
var collectorTable = map[string]collectorFn{
	"previous-logs": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherPreviousLogs(ctx, d.cs, d.newLF, d.ns, d.name)
	},
	"change-history": func(_ context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherChangeHistory(d.snap, d.ns, d.name, d.now)
	},
	"configmaps": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherConfigMaps(ctx, d.cs, d.red, d.ns, d.name)
	},
	"secrets": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherSecrets(ctx, d.cs, d.ns, d.name)
	},
	"node-detail": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherNodePressure(ctx, d.cs, d.snap, d.ns, d.name)
	},
	"metrics": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherMetrics(ctx, d.mp, d.ns, d.name, d.now)
	},
	"dns-heuristic": func(_ context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherDNSHeuristic(d.snap, d.ns, d.name)
	},
	"related-services": func(_ context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherRelatedResources(d.snap, d.ns)
	},
	"owner-chain": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherOwnerChain(ctx, d.cs, d.red, d.ns, d.name)
	},
	"service-endpoints": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherServiceChain(ctx, d.cs, d.red, d.ns, d.name)
	},
	"storage-chain": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherStorageChain(ctx, d.cs, d.ns, d.name)
	},
	"scaling": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherScaling(ctx, d.cs, d.red, d.ns, d.name)
	},
	"netpol": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherNetpol(ctx, d.cs, d.ns, d.name)
	},
	"rbac": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherRBAC(ctx, d.cs, d.ns, d.name)
	},
	"namespace-detail": func(ctx context.Context, d execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return gatherNamespaceDetail(ctx, d.cs, d.ns)
	},
	"vpa": func(_ context.Context, _ execDeps) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
		return []plugin.InvestigationStep{step("VerticalPodAutoscaler inspected", "unavailable",
			"VPA is a CRD and not supported yet — checking HPA and resource limits instead covers most of the same ground", "")}, nil
	},
}

// executePlan runs every planned step through the dispatch table, stamps the
// resulting evidence with the step's graph edge, and records each step's
// outcome on the returned plan copy.
func executePlan(ctx context.Context, plan []plugin.PlanStep, d execDeps) ([]plugin.PlanStep, []plugin.InvestigationStep, []plugin.EvidenceItem) {
	var steps []plugin.InvestigationStep
	var evidence []plugin.EvidenceItem
	executed := make([]plugin.PlanStep, len(plan))
	copy(executed, plan)

	for i, ps := range executed {
		// Serve from the conversation's evidence cache when the planner
		// marked the step cached and the entry is still fresh.
		if ps.Status == "cached" {
			if entry, ok := d.cache.get(d.convoID, ps.Collector, ps.Target, d.now); ok {
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

		fn, ok := collectorTable[ps.Collector]
		if !ok {
			executed[i].Status = "unavailable"
			steps = append(steps, step(ps.Collector+" requested", "unavailable", "collector not available in this build", ""))
			continue
		}
		s, e := fn(ctx, d)
		for j := range e {
			if e[j].Edge == "" {
				e[j].Edge = ps.Edge
			}
			if e[j].CollectedAt.IsZero() {
				e[j].CollectedAt = d.now
			}
		}
		steps = append(steps, s...)
		evidence = append(evidence, e...)
		executed[i].Status = planStepOutcome(s)
		if executed[i].Status == "done" {
			d.cache.put(d.convoID, ps.Collector, ps.Target, cachedEvidence{Steps: s, Evidence: e, At: d.now}, d.now)
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

// labelEvidence assigns citation keys E1..En in collection order so the
// answer text, hypotheses, and UI can reference items precisely.
func labelEvidence(evidence []plugin.EvidenceItem) []plugin.EvidenceItem {
	for i := range evidence {
		evidence[i].Label = fmt.Sprintf("E%d", i+1)
	}
	return evidence
}
