package k8s

import (
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestClassify_TemporaryGetsComplementaryRootCause(t *testing.T) {
	f := plugin.Finding{
		Severity:   plugin.SeverityCritical,
		Category:   "Pods",
		Title:      "CrashLoopBackOff: prod/payment-api",
		Detail:     "Pod has restarted 22 times.",
		Suggestion: "Increase the memory limit to 512Mi.",
		Remediation: &plugin.RemediationAction{
			Kind: "delete-pod", Namespace: "prod", Name: "payment-api",
		},
	}
	Classify(&f)

	if f.Remediation.FixType != "temporary" {
		t.Errorf("delete-pod should classify as temporary, got %q", f.Remediation.FixType)
	}
	if f.Remediation.Rollback == "" || f.Remediation.ExpectedOutcome == "" {
		t.Error("temporary fix should get rollback + expected-outcome metadata")
	}
	// A complementary root-cause fix should be synthesized from the suggestion.
	var hasRoot bool
	for _, fx := range f.Fixes {
		if fx.FixType == "root-cause" {
			hasRoot = true
			if fx.Description != "Increase the memory limit to 512Mi." {
				t.Errorf("root-cause advice should carry the suggestion, got %q", fx.Description)
			}
		}
	}
	if !hasRoot {
		t.Errorf("expected a complementary root-cause fix; got %d fixes", len(f.Fixes))
	}
}

func TestClassify_RootCauseKind(t *testing.T) {
	f := plugin.Finding{
		Title:       "No resource limits: prod (namespace-wide)",
		Remediation: &plugin.RemediationAction{Kind: "add-limits", Namespace: "prod"},
	}
	Classify(&f)
	if f.Remediation.FixType != "root-cause" {
		t.Errorf("add-limits should classify as root-cause, got %q", f.Remediation.FixType)
	}
}

func TestDeriveConfidence(t *testing.T) {
	recent := plugin.Finding{LikelyCause: &plugin.ChangeRef{AgoSeconds: 120}}
	if got := deriveConfidence(recent); got != "high" {
		t.Errorf("recent change correlation should be high confidence, got %q", got)
	}
	evid := plugin.Finding{Evidence: []plugin.EvidenceItem{{Kind: "log"}, {Kind: "event"}, {Kind: "change"}}}
	if got := deriveConfidence(evid); got != "high" {
		t.Errorf("3+ evidence items should be high confidence, got %q", got)
	}
	none := plugin.Finding{Title: "x"}
	if got := deriveConfidence(none); got != "low" {
		t.Errorf("no signal should be low confidence, got %q", got)
	}
}

func TestClassify_PreservesExplicitFixType(t *testing.T) {
	f := plugin.Finding{Remediation: &plugin.RemediationAction{Kind: "delete-pod", FixType: "root-cause"}}
	Classify(&f)
	if f.Remediation.FixType != "root-cause" {
		t.Errorf("Classify must not overwrite an explicit FixType, got %q", f.Remediation.FixType)
	}
}
