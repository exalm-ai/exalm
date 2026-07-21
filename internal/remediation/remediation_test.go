package remediation

import (
	"context"
	"errors"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestFixableFromReport(t *testing.T) {
	r := plugin.Report{Findings: []plugin.Finding{
		{Title: "no fix"},
		{Title: "delete", Remediation: &plugin.RemediationAction{Kind: "delete-pod"}},
		{Title: "restart", Remediation: &plugin.RemediationAction{Kind: "rollout-restart"}},
	}}
	items := FixableFromReport(r)
	if len(items) != 2 || items[0].Title != "delete" || items[1].Title != "restart" {
		t.Errorf("expected [delete restart] in report order, got %+v", items)
	}
}

func TestOrderForBatch(t *testing.T) {
	items := []FixableItem{
		{Title: "z-delete", Action: plugin.RemediationAction{Kind: "delete-pod"}},
		{Title: "unknown", Action: plugin.RemediationAction{Kind: "patch-resource"}},
		{Title: "a-restart", Action: plugin.RemediationAction{Kind: "rollout-restart"}},
		{Title: "b-restart", Action: plugin.RemediationAction{Kind: "rollout-restart"}},
		{Title: "resume", Action: plugin.RemediationAction{Kind: "resume-cronjob"}},
	}
	original := append([]FixableItem(nil), items...)

	ordered := OrderForBatch(items)
	want := []string{"a-restart", "b-restart", "resume", "z-delete", "unknown"}
	if len(ordered) != len(want) {
		t.Fatalf("length mismatch: %+v", ordered)
	}
	for i, w := range want {
		if ordered[i].Title != w {
			t.Errorf("position %d: got %q, want %q (full: %+v)", i, ordered[i].Title, w, ordered)
		}
	}

	// Must not mutate the input.
	for i := range items {
		if items[i].Title != original[i].Title {
			t.Errorf("OrderForBatch mutated its input at %d: %+v", i, items)
		}
	}
}

func TestApplyAll(t *testing.T) {
	items := []FixableItem{
		{Title: "ok-one", Action: plugin.RemediationAction{Kind: "rollout-restart"}},
		{Title: "fails", Action: plugin.RemediationAction{Kind: "delete-pod"}},
	}
	results := ApplyAll(context.Background(), items, func(_ context.Context, a plugin.RemediationAction) error {
		if a.Kind == "delete-pod" {
			return errors.New("boom")
		}
		return nil
	})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %+v", results)
	}
	if !results[0].OK || results[0].Error != "" || results[0].Title != "ok-one" {
		t.Errorf("result[0]: %+v", results[0])
	}
	if results[1].OK || results[1].Error != "boom" || results[1].Title != "fails" {
		t.Errorf("result[1]: %+v", results[1])
	}
}
