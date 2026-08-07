package service

import (
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func sampleReport() plugin.Report {
	return plugin.Report{
		Title: "t", Summary: "s",
		Findings: []plugin.Finding{
			{Title: "prod/api", Severity: plugin.SeverityCritical, Category: "Pods"},
			{Title: "staging/api", Severity: plugin.SeverityHigh, Category: "Pods"},
			{Title: "prod/db", Severity: plugin.SeverityHigh, Category: "Storage",
				Remediation: &plugin.RemediationAction{Kind: "delete-pod"}},
		},
	}
}

func TestFindingsService_List(t *testing.T) {
	svc := NewFindingsService(sampleReport)

	all := svc.List(FindingsFilter{})
	if len(all) != 3 {
		t.Fatalf("expected 3 findings unfiltered, got %d", len(all))
	}
	bySev := svc.List(FindingsFilter{Severity: "high"})
	if len(bySev) != 2 {
		t.Errorf("severity filter: got %d, want 2", len(bySev))
	}
	byCat := svc.List(FindingsFilter{Category: "Storage"})
	if len(byCat) != 1 || byCat[0].Title != "prod/db" {
		t.Errorf("category filter: %+v", byCat)
	}
	byNS := svc.List(FindingsFilter{Namespace: "prod"})
	if len(byNS) != 2 {
		t.Errorf("namespace filter: got %d, want 2 (prod/api, prod/db)", len(byNS))
	}
}

func TestFindingsService_Get(t *testing.T) {
	svc := NewFindingsService(sampleReport)
	f, ok := svc.Get("prod/api")
	if !ok || f.Severity != plugin.SeverityCritical {
		t.Errorf("Get(prod/api): ok=%v f=%+v", ok, f)
	}
	if _, ok := svc.Get("nope"); ok {
		t.Error("Get(nope) should report not-found")
	}
}

func TestFindingsService_Summary(t *testing.T) {
	svc := NewFindingsService(sampleReport)
	sum := svc.Summary()
	if sum.Title != "t" || sum.Total != 3 || sum.Counts["high"] != 2 || sum.Counts["critical"] != 1 {
		t.Errorf("Summary: %+v", sum)
	}
}

func TestFindingsService_Remediable(t *testing.T) {
	svc := NewFindingsService(sampleReport)
	rem := svc.Remediable()
	if len(rem) != 1 || rem[0].Title != "prod/db" {
		t.Errorf("Remediable: %+v", rem)
	}
}

func TestFindingsService_ReflectsLiveReport(t *testing.T) {
	current := plugin.Report{Findings: []plugin.Finding{{Title: "v1"}}}
	svc := NewFindingsService(func() plugin.Report { return current })
	if len(svc.List(FindingsFilter{})) != 1 {
		t.Fatal("expected 1 finding on first read")
	}
	current = plugin.Report{Findings: []plugin.Finding{{Title: "v1"}, {Title: "v2"}}}
	if len(svc.List(FindingsFilter{})) != 2 {
		t.Error("service should read the report fresh on every call, not cache it")
	}
}
