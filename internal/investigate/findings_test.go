package investigate

import (
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// A tiny profile whose symptom matching keys off a string Facts value, so the
// tests need no real corpus. Facts is `any`; here it's the "corpus" string.
func testProfile() Profile {
	has := func(substr string) func(Facts, Target) bool {
		return func(f Facts, _ Target) bool {
			s, _ := f.(string)
			return substr != "" && containsFold(s, substr)
		}
	}
	return Profile{
		Name:               "test",
		ConversationPrompt: "x",
		LogLinePrompt:      "x",
		ResolveFocus:       func(prev, _, _ string, _ Facts) string { return prev },
		Symptoms: []Symptom{
			{
				Key: "oom-kill", Match: has("oom"),
				Title: "OOM kill", Category: "Reliability", Severity: plugin.SeverityCritical,
				Describe: func(f Facts, _ Target) string { return "3 OOM events" },
				Causes: []CauseTemplate{
					{Title: "Memory exhaustion", Base: 65},
					{Title: "Host under-provisioned", Base: 30},
				},
				Remediate: func(_ Facts, _ Target) *plugin.RemediationAction {
					return &plugin.RemediationAction{Kind: "svc-restart-linux", Name: "app", Shell: "bash"}
				},
			},
			{
				Key: "service-failure", Match: has("failed to start"),
				// No Title/Category/Severity/Describe: exercises the fallbacks.
				Causes: []CauseTemplate{{Title: "Bad config", Base: 45}},
			},
			{Key: "degraded", Match: func(Facts, Target) bool { return true }, Fallback: true},
		},
		Prevention: map[string][]plugin.RemediationAction{
			"oom-kill": {{Kind: "advice", FixType: "prevention", Description: "Set memory limits"}},
		},
	}
}

func containsFold(s, sub string) bool {
	return len(sub) == 0 || indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	ls, lsub := toLower(s), toLower(sub)
	for i := 0; i+len(lsub) <= len(ls); i++ {
		if ls[i:i+len(lsub)] == lsub {
			return i
		}
	}
	return -1
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func TestFindingsFrom_PromotesMatchedSymptom(t *testing.T) {
	p := testProfile()
	got := FindingsFrom(p, "kernel: oom-killer: Killed process 123", Target{}, "syslog/web-01")

	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != plugin.SeverityCritical || f.Category != "Reliability" || f.Title != "OOM kill" {
		t.Errorf("header wrong: %+v", f)
	}
	if f.Detail != "3 OOM events" {
		t.Errorf("Describe should drive Detail, got %q", f.Detail)
	}
	if f.RootCause != "Memory exhaustion" {
		t.Errorf("RootCause should be the highest-Base cause, got %q", f.RootCause)
	}
	if f.Confidence != "medium" { // base 65 -> medium
		t.Errorf("Confidence bucket wrong for base 65: %q", f.Confidence)
	}
	if f.Source != "syslog/web-01" {
		t.Errorf("Source: %q", f.Source)
	}
	if f.Remediation == nil || f.Remediation.Kind != "svc-restart-linux" {
		t.Errorf("expected executable remediation, got %+v", f.Remediation)
	}
	// Executable fix first, then the prevention advice.
	if len(f.Fixes) != 2 || f.Fixes[0].Kind != "svc-restart-linux" || f.Fixes[1].FixType != "prevention" {
		t.Errorf("Fixes ordering wrong: %+v", f.Fixes)
	}
	if f.Suggestion != "Set memory limits" {
		t.Errorf("Suggestion should come from prevention[0], got %q", f.Suggestion)
	}
}

func TestFindingsFrom_Fallbacks(t *testing.T) {
	p := testProfile()
	got := FindingsFrom(p, "systemd: Failed to start nginx", Target{}, "syslog/db")

	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.Severity != plugin.SeverityMedium {
		t.Errorf("severity fallback should be medium, got %q", f.Severity)
	}
	if f.Category != "Log" {
		t.Errorf("category fallback should be Log, got %q", f.Category)
	}
	if f.Title != "Service Failure" {
		t.Errorf("title fallback should titleize the key, got %q", f.Title)
	}
	if f.Detail != "Service Failure. Most likely cause: Bad config." {
		t.Errorf("generic detail wrong: %q", f.Detail)
	}
	if f.Confidence != "medium" { // base 45 -> medium
		t.Errorf("confidence for base 45: %q", f.Confidence)
	}
	if f.Remediation != nil {
		t.Errorf("service-failure in this test profile has no Remediate hook; got %+v", f.Remediation)
	}
}

func TestFindingsFrom_FallbackRowOnlyWhenNothingElse(t *testing.T) {
	p := testProfile()
	// Nothing matches oom-kill/service-failure => the fallback row promotes.
	got := FindingsFrom(p, "everything is fine here", Target{}, "syslog/x")
	if len(got) != 1 || got[0].Title != "Degraded" {
		t.Fatalf("expected only the fallback finding, got %+v", got)
	}
	if got[0].Confidence != "" {
		t.Errorf("fallback has no causes => confidence should be empty, got %q", got[0].Confidence)
	}
}

func TestTitleize(t *testing.T) {
	cases := map[string]string{
		"auth-failure": "Auth Failure",
		"oom_kill":     "Oom Kill",
		"burst-5xx":    "Burst 5xx",
		"":             "Log anomaly",
	}
	for in, want := range cases {
		if got := titleize(in); got != want {
			t.Errorf("titleize(%q) = %q, want %q", in, got, want)
		}
	}
}
