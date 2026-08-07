package k8s

// planner_test.go — pure unit tests for the KUBERNETES planner catalog:
// symptom matching, intent mapping, dedupe/cap, and determinism, expressed
// through the engine's PlanPreview seam. No clientset needed. Cache marking,
// refresh bypass, and unknown-collector execution are framework behavior,
// covered in internal/investigate.

import (
	"reflect"
	"testing"
)

// planCap mirrors the framework's default plan cap (Profile.MaxPlanSteps == 0
// ⇒ 8); the k8s profile does not override it.
const planCap = 8

func oomPod() *PodSummary {
	return &PodSummary{Namespace: "prod", Name: "payment-api-1", Phase: "Running", Reason: "OOMKilled", RestartCount: 12}
}

// previewCollectors builds (without executing) the deterministic plan for one
// question and returns its collector names. PlanPreview does not run
// PrepareTurn, so the focus pod is passed explicitly in the facts bundle.
func previewCollectors(t *testing.T, message string, intents []string, focus string, pod *PodSummary) []string {
	t.Helper()
	var out []string
	for _, s := range New().engine().PlanPreview(message, intents, focus, k8sFacts{snap: Snapshot{}, pod: pod}) {
		out = append(out, s.Collector)
	}
	return out
}

func TestBuildPlan_OOMSymptomDrivesChecks(t *testing.T) {
	got := previewCollectors(t, "why did it crash?", []string{"general"}, "prod/payment-api-1", oomPod())
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
	got := previewCollectors(t, "is the ingress healthy?", []string{"ingress"}, "prod/web", nil)
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
	got := previewCollectors(t,
		"check memory, cpu, deploys, config, secrets, dns, storage, rbac, quota and scaling",
		[]string{"resource-usage", "deploy-correlation", "configmap", "secret", "dns", "storage", "rbac-question", "quota", "scaling"},
		"prod/payment-api-1", oomPod())
	if len(got) > planCap {
		t.Errorf("plan exceeds cap: %d > %d (%v)", len(got), planCap, got)
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
	eng := New().engine()
	facts := k8sFacts{snap: Snapshot{}, pod: oomPod()}
	a := eng.PlanPreview("why is payment-api crashing?", []string{"general"}, "prod/payment-api-1", facts)
	b := eng.PlanPreview("why is payment-api crashing?", []string{"general"}, "prod/payment-api-1", facts)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("same input must yield the same plan:\n%v\nvs\n%v", a, b)
	}
}

func TestBuildPlan_FallbackSymptomWhenNothingSpecificMatches(t *testing.T) {
	pod := &PodSummary{Namespace: "prod", Name: "mystery-1", Phase: "Running", Reason: "SomethingWeird"}
	got := previewCollectors(t, "what's wrong?", []string{"general"}, "prod/mystery-1", pod)
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
	fp := k8sProfile().Fingerprint(k8sFacts{snap: Snapshot{}, pod: pod}, "prod/api-1", syms)
	if fp != "crashloop\x1fprod/api-1" {
		t.Errorf("fingerprint should name the first matched symptom: %q", fp)
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
