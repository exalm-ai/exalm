package service

import (
	"context"
	"errors"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestRemediationService_Preview(t *testing.T) {
	report := sampleReport()
	svc := NewRemediationService(NewFindingsService(func() plugin.Report { return report }),
		func() plugin.Report { return report }, nil)

	action, err := svc.Preview("prod/db")
	if err != nil || action.Kind != "delete-pod" {
		t.Errorf("Preview(prod/db): action=%+v err=%v", action, err)
	}
	if _, err := svc.Preview("nope"); err == nil {
		t.Error("Preview(nope) should error: finding not found")
	}
	if _, err := svc.Preview("prod/api"); err == nil {
		t.Error("Preview(prod/api) should error: no remediation attached")
	}
}

func TestRemediationService_Apply(t *testing.T) {
	report := sampleReport()
	var applied plugin.RemediationAction
	svc := NewRemediationService(NewFindingsService(func() plugin.Report { return report }),
		func() plugin.Report { return report },
		func(_ context.Context, a plugin.RemediationAction) error { applied = a; return nil })

	if err := svc.Apply(context.Background(), "prod/db"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if applied.Kind != "delete-pod" {
		t.Errorf("apply handler received %+v", applied)
	}
}

func TestRemediationService_Apply_NoHandlerConfigured(t *testing.T) {
	report := sampleReport()
	svc := NewRemediationService(NewFindingsService(func() plugin.Report { return report }),
		func() plugin.Report { return report }, nil)
	if err := svc.Apply(context.Background(), "prod/db"); err == nil {
		t.Error("Apply with a nil applyFn should error, not panic or silently succeed")
	}
}

func TestRemediationService_ApplyAll_OrdersAndReportsFailures(t *testing.T) {
	report := plugin.Report{Findings: []plugin.Finding{
		{Title: "z-delete", Remediation: &plugin.RemediationAction{Kind: "delete-pod"}},
		{Title: "a-restart", Remediation: &plugin.RemediationAction{Kind: "rollout-restart"}},
	}}
	svc := NewRemediationService(NewFindingsService(func() plugin.Report { return report }),
		func() plugin.Report { return report },
		func(_ context.Context, a plugin.RemediationAction) error {
			if a.Kind == "delete-pod" {
				return errors.New("boom")
			}
			return nil
		})

	results := svc.ApplyAll(context.Background())
	if len(results) != 2 || results[0].Title != "a-restart" || !results[0].OK {
		t.Errorf("expected restart first and OK, got %+v", results)
	}
	if results[1].Title != "z-delete" || results[1].OK || results[1].Error != "boom" {
		t.Errorf("expected delete second and failed, got %+v", results)
	}
}
