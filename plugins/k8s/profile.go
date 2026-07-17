package k8s

// profile.go assembles the Kubernetes investigation Profile — the reference
// implementation of the generic framework (internal/investigate). Everything
// domain-specific lives here or in the catalog files (symptoms.go, graph.go,
// confidence.go, prevention.go, prompts.go); the per-turn pipeline is the
// framework engine's.

import (
	"context"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// k8sIntentChecks maps question intents to collector requests — this is what
// makes the planner question-driven on top of symptom-driven: mentioning
// ingress schedules the traffic-path check even when no symptom implies it.
var k8sIntentChecks = map[string][]investigate.Check{
	"previous-logs": {{Collector: "previous-logs", Reason: "you asked for the logs before the crash", Priority: 1}},
	"deploy-correlation": {
		{Collector: "change-history", Reason: "you asked about deployments/changes", Priority: 1},
		{Collector: "owner-chain", Reason: "the owning workload shows what the deploy changed", Priority: 2},
	},
	"comparison": {
		{Collector: "change-history", Reason: "comparing with the past needs the change record", Priority: 1},
		{Collector: "history", Reason: "prior investigations and incidents cover 'has this happened before'", Priority: 2},
	},
	"db-connectivity": {
		{Collector: "related-services", Reason: "locate the database service and its endpoint health", Priority: 1},
		{Collector: "netpol", Reason: "network policies can isolate the pod from the database", Priority: 2},
		{Collector: "secrets", Reason: "rotated credentials mimic database downtime (existence only)", Priority: 3},
	},
	"resource-usage": {
		{Collector: "metrics", Reason: "you asked about resource usage", Priority: 1},
		{Collector: "owner-chain", Reason: "limits/requests live on the owning workload", Priority: 2},
		{Collector: "node-detail", Reason: "node capacity bounds everything the pod can use", Priority: 3},
	},
	"node-pressure": {{Collector: "node-detail", Reason: "you asked about the node", Priority: 1}},
	"configmap":     {{Collector: "configmaps", Reason: "you asked about configuration", Priority: 1}},
	"secret":        {{Collector: "secrets", Reason: "you asked about secrets (existence/type only — values never read)", Priority: 1}},
	"dns": {
		{Collector: "dns-heuristic", Reason: "you asked about DNS", Priority: 1},
		{Collector: "netpol", Reason: "a policy blocking egress to kube-dns mimics DNS failure", Priority: 2},
	},
	"rca": {
		{Collector: "previous-logs", Reason: "an RCA needs the failure output", Priority: 1},
		{Collector: "change-history", Reason: "an RCA needs the change record", Priority: 2},
		{Collector: "owner-chain", Reason: "an RCA needs the workload context", Priority: 3},
		{Collector: "history", Reason: "an RCA should note recurrence", Priority: 4},
	},
	"related-services": {
		{Collector: "service-endpoints", Reason: "you asked about related services", Priority: 1},
		{Collector: "related-services", Reason: "sibling service issues reveal shared dependencies", Priority: 2},
	},
	"ingress": {
		{Collector: "service-endpoints", Reason: "ingress routes through services — check the whole path", Priority: 1},
		{Collector: "related-services", Reason: "edge errors often trace to a backend service issue", Priority: 2},
	},
	"storage":       {{Collector: "storage-chain", Reason: "you asked about storage — walking PVC → PV → StorageClass", Priority: 1}},
	"rbac-question": {{Collector: "rbac", Reason: "you asked about permissions — checking the pod's ServiceAccount grants", Priority: 1}},
	"quota":         {{Collector: "namespace-detail", Reason: "you asked about namespace quotas/limits", Priority: 1}},
	"scaling":       {{Collector: "scaling", Reason: "you asked about autoscaling", Priority: 1}},
	"history":       {{Collector: "history", Reason: "you asked whether this happened before", Priority: 1}},
	"vpa":           {{Collector: "vpa", Reason: "you asked about VPA", Priority: 1}},
}

// collectorTTL is how long each collector class's evidence stays fresh in
// the per-conversation cache.
var collectorTTL = map[string]time.Duration{
	"previous-logs":     90 * time.Second,
	"metrics":           90 * time.Second,
	"service-endpoints": 90 * time.Second,
	"dns-heuristic":     90 * time.Second,
	"related-services":  90 * time.Second,
	"owner-chain":       5 * time.Minute,
	"node-detail":       5 * time.Minute,
	"configmaps":        5 * time.Minute,
	"secrets":           5 * time.Minute,
	"storage-chain":     5 * time.Minute,
	"scaling":           5 * time.Minute,
	"netpol":            5 * time.Minute,
	"rbac":              5 * time.Minute,
	"namespace-detail":  5 * time.Minute,
	"change-history":    10 * time.Minute,
	"history":           10 * time.Minute,
}

// k8sCollectors is the dispatch table: each closure unwraps the facts bundle
// and calls the untouched gather function.
func k8sCollectors() map[string]investigate.Collector {
	return map[string]investigate.Collector{
		"previous-logs": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherPreviousLogs(ctx, k.cs, k.newLF, cc.Target.Scope, cc.Target.Name)
		},
		"change-history": func(_ context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherChangeHistory(k.snap, cc.Target.Scope, cc.Target.Name, cc.Now)
		},
		"configmaps": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherConfigMaps(ctx, k.cs, cc.Red, cc.Target.Scope, cc.Target.Name)
		},
		"secrets": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherSecrets(ctx, k.cs, cc.Target.Scope, cc.Target.Name)
		},
		"node-detail": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherNodePressure(ctx, k.cs, k.snap, cc.Target.Scope, cc.Target.Name)
		},
		"metrics": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherMetrics(ctx, k.mp, cc.Target.Scope, cc.Target.Name, cc.Now)
		},
		"dns-heuristic": func(_ context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherDNSHeuristic(k.snap, cc.Target.Scope, cc.Target.Name)
		},
		"related-services": func(_ context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherRelatedResources(k.snap, cc.Target.Scope)
		},
		"owner-chain": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherOwnerChain(ctx, k.cs, cc.Red, cc.Target.Scope, cc.Target.Name)
		},
		"service-endpoints": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherServiceChain(ctx, k.cs, cc.Red, cc.Target.Scope, cc.Target.Name)
		},
		"storage-chain": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherStorageChain(ctx, k.cs, cc.Target.Scope, cc.Target.Name)
		},
		"scaling": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherScaling(ctx, k.cs, cc.Red, cc.Target.Scope, cc.Target.Name)
		},
		"netpol": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherNetpol(ctx, k.cs, cc.Target.Scope, cc.Target.Name)
		},
		"rbac": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherRBAC(ctx, k.cs, cc.Target.Scope, cc.Target.Name)
		},
		"namespace-detail": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(cc.Facts)
			return gatherNamespaceDetail(ctx, k.cs, cc.Target.Scope)
		},
		"vpa": func(_ context.Context, _ investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			return []plugin.InvestigationStep{step("VerticalPodAutoscaler inspected", "unavailable",
				"VPA is a CRD and not supported yet — checking HPA and resource limits instead covers most of the same ground", "")}, nil
		},
		"history": func(ctx context.Context, cc investigate.CollectCtx) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			return investigate.GatherHistory(ctx, cc.History, cc.Target.Scope, cc.Target.Name, cc.Now)
		},
	}
}

// k8sProfile builds the Kubernetes investigation profile from the package's
// catalogs. Package-level (not per-Plugin): everything it references is
// stateless; per-turn state arrives via Facts.
func k8sProfile() investigate.Profile {
	return investigate.Profile{
		Name:            "k8s",
		Symptoms:        symptomCatalog,
		Edges:           edgeRegistry,
		IntentPatterns:  k8sIntentPatterns,
		IntentChecks:    k8sIntentChecks,
		Collectors:      k8sCollectors(),
		ConfidenceRules: confidenceRules,
		Prevention:      preventionCatalog,
		TTLs:            collectorTTL,

		ConversationPrompt: k8sConversationPrompt,
		LogLinePrompt:      logLineAnalysisPrompt,

		ResolveFocus: func(prev, anchorID, message string, f investigate.Facts) string {
			return resolveFocus(prev, anchorID, message, unwrap(f).snap)
		},
		PrepareTurn: func(f investigate.Facts, t investigate.Target) investigate.Facts {
			k := unwrap(f)
			k.pod = findPod(k.snap, t.Scope, t.Name)
			return k
		},
		Baseline: func(_ context.Context, f investigate.Facts, t investigate.Target, now time.Time) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
			k := unwrap(f)
			if k.pod != nil {
				return investigationSteps(syntheticFinding(*k.pod, t.Scope, t.Name), k.snap),
					podEvidence(*k.pod, t.Scope, t.Name, now)
			}
			if t.Scope != "" || t.Name != "" {
				return []plugin.InvestigationStep{step("Pod status inspected", "unavailable", "no pod "+t.String()+" in the current snapshot", "")}, nil
			}
			return nil, nil
		},
		Fingerprint: func(f investigate.Facts, focus string, matched []investigate.Symptom) string {
			// Preserved k8s behavior: only fingerprint when the focus pod
			// actually exists in the snapshot.
			if unwrap(f).pod == nil || len(matched) == 0 {
				return ""
			}
			return matched[0].Key + "\x1f" + focus
		},
		Timeline: func(f investigate.Facts, t investigate.Target, now time.Time) []plugin.TimelineEvent {
			return buildTimeline(unwrap(f).snap, t.Scope, t.Name, now)
		},
		FixesFor: func(f investigate.Facts, anchorID string) []plugin.RemediationAction {
			return fixesForFinding(unwrap(f).snap, anchorID)
		},
		SuggestFollowUps: func(intents []string, f investigate.Facts, steps []plugin.InvestigationStep) []string {
			return suggestFollowUps(intents, unwrap(f).pod, steps)
		},
		DeterministicLineFallback: func(req investigate.LineRequest) string {
			return deterministicLogAnalysis(lineRequestToK8s(req))
		},
	}
}

// engine returns the plugin's investigation engine, building it on first use.
// The engine owns the per-conversation evidence cache, so it must be a single
// long-lived instance per Plugin.
func (p *Plugin) engine() *investigate.Engine {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.eng == nil {
		eng, err := investigate.NewEngine(k8sProfile())
		if err != nil {
			// A profile validation failure is an init-time programming error
			// (catalog inconsistency), not a runtime condition.
			panic("k8s investigation profile invalid: " + err.Error())
		}
		p.eng = eng
	}
	return p.eng
}
