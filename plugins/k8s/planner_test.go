package k8s

// planner_test.go — pure unit tests for the deterministic investigation
// planner: symptom matching, intent mapping, dedupe/cap, cache marking,
// refresh bypass, and determinism. No clientset needed.

import (
	"reflect"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func oomPod() *PodSummary {
	return &PodSummary{Namespace: "prod", Name: "payment-api-1", Phase: "Running", Reason: "OOMKilled", RestartCount: 12}
}

func collectorsOf(t *testing.T, in planInput) []string {
	t.Helper()
	var out []string
	for _, s := range buildPlan(in) {
		out = append(out, s.Collector)
	}
	return out
}

func TestBuildPlan_OOMSymptomDrivesChecks(t *testing.T) {
	got := collectorsOf(t, planInput{Message: "why did it crash?", Intents: []string{"general"}, Focus: "prod/payment-api-1", Pod: oomPod()})
	want := map[string]bool{"owner-chain": true, "metrics": true, "node-detail": true, "scaling": true, "change-history": true}
	for _, c := range got {
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("OOM symptom should schedule all its checks; missing %v (plan=%v)", want, got)
	}
}

func TestBuildPlan_QuestionDrivenWithoutSymptom(t *testing.T) {
	// No focus pod at all — the question alone must schedule the check.
	got := collectorsOf(t, planInput{Message: "is the ingress healthy?", Intents: []string{"ingress"}, Focus: "prod/web"})
	found := false
	for _, c := range got {
		if c == "service-endpoints" {
			found = true
		}
	}
	if !found {
		t.Errorf("ingress question should schedule service-endpoints, got %v", got)
	}
}

func TestBuildPlan_DedupesAndCaps(t *testing.T) {
	// OOM symptom + resource-usage intent both want metrics/owner-chain —
	// each collector must appear at most once, and the plan must respect cap.
	in := planInput{
		Message: "check memory, cpu, deploys, config, secrets, dns, storage, rbac, quota and scaling",
		Intents: []string{"resource-usage", "deploy-correlation", "configmap", "secret", "dns", "storage", "rbac-question", "quota", "scaling"},
		Focus:   "prod/payment-api-1", Pod: oomPod(),
	}
	got := collectorsOf(t, in)
	if len(got) > maxPlanSteps {
		t.Errorf("plan exceeds cap: %d > %d (%v)", len(got), maxPlanSteps, got)
	}
	seen := map[string]bool{}
	for _, c := range got {
		if seen[c] {
			t.Errorf("collector %q appears twice in %v", c, got)
		}
		seen[c] = true
	}
}

func TestBuildPlan_Deterministic(t *testing.T) {
	in := planInput{Message: "why is payment-api crashing?", Intents: []string{"general"}, Focus: "prod/payment-api-1", Pod: oomPod()}
	a := buildPlan(in)
	b := buildPlan(in)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("same input must yield the same plan:\n%v\nvs\n%v", a, b)
	}
}

func TestBuildPlan_CacheMarksAndRefreshBypasses(t *testing.T) {
	cached := func(collector string) bool { return collector == "owner-chain" }
	in := planInput{Message: "x", Intents: []string{"general"}, Focus: "prod/payment-api-1", Pod: oomPod(), Cached: cached}

	var ownerStatus string
	for _, s := range buildPlan(in) {
		if s.Collector == "owner-chain" {
			ownerStatus = s.Status
		}
	}
	if ownerStatus != "cached" {
		t.Errorf("cached collector should be marked cached, got %q", ownerStatus)
	}

	in.Refresh = true
	for _, s := range buildPlan(in) {
		if s.Collector == "owner-chain" && s.Status == "cached" {
			t.Error("refresh must bypass the cache marking")
		}
	}
}

func TestBuildPlan_FallbackSymptomWhenNothingSpecificMatches(t *testing.T) {
	pod := &PodSummary{Namespace: "prod", Name: "mystery-1", Phase: "Running", Reason: "SomethingWeird"}
	got := collectorsOf(t, planInput{Message: "what's wrong?", Intents: []string{"general"}, Focus: "prod/mystery-1", Pod: pod})
	want := []string{"previous-logs", "owner-chain", "change-history"}
	for _, w := range want {
		found := false
		for _, c := range got {
			if c == w {
				found = true
			}
		}
		if !found {
			t.Errorf("fallback symptom should schedule %q, plan=%v", w, got)
		}
	}
}

func TestMatchSymptoms_MultipleAndFingerprint(t *testing.T) {
	pod := &PodSummary{
		Namespace: "prod", Name: "api-1", Phase: "Running", Reason: "CrashLoopBackOff",
		LogAnomalies: []LogAnomaly{{Category: "db-error", Count: 4, Sample: "pq: connection refused"}},
	}
	syms := matchSymptoms(pod, Snapshot{}, "prod", "api-1")
	keys := map[string]bool{}
	for _, s := range syms {
		keys[s.Key] = true
	}
	if !keys["crashloop"] || !keys["db-error"] {
		t.Errorf("expected crashloop AND db-error to match, got %v", keys)
	}
	fp := fingerprintFor(pod, Snapshot{}, "prod/api-1")
	if fp != "crashloop\x1fprod/api-1" {
		t.Errorf("fingerprint should name the first matched symptom: %q", fp)
	}
}

func TestExecutePlan_UnknownCollectorIsUnavailableNotFatal(t *testing.T) {
	executed, steps, _ := executePlan(t.Context(), []plugin.PlanStep{{ID: "p1", Collector: "does-not-exist", Reason: "test", Status: "planned"}}, execDeps{})
	if executed[0].Status != "unavailable" {
		t.Errorf("unknown collector should be unavailable, got %q", executed[0].Status)
	}
	if len(steps) != 1 || steps[0].Status != "unavailable" {
		t.Errorf("expected one unavailable step, got %+v", steps)
	}
}

func TestClassifyIntent_NewCopilotIntents(t *testing.T) {
	cases := map[string]string{
		"refresh the data please":            "refresh",
		"has this happened before?":          "history",
		"is the pvc full?":                   "storage",
		"does the serviceaccount have rbac?": "rbac-question",
		"are we hitting the quota?":          "quota",
		"is the hpa maxed out?":              "scaling",
		"check the vpa":                      "vpa",
	}
	for msg, want := range cases {
		if !hasIntent(classifyIntent(msg), want) {
			t.Errorf("classifyIntent(%q) should include %q, got %v", msg, want, classifyIntent(msg))
		}
	}
}
