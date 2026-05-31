package main

import (
	"context"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
	k8splugin "github.com/exalm-ai/exalm/plugins/k8s"
	sloplugin "github.com/exalm-ai/exalm/plugins/slo"
)

// ---- findSubcommand --------------------------------------------------------

func TestFindSubcommand_Found(t *testing.T) {
	k8s := k8splugin.New()
	sc, ok := findSubcommand(k8s, "analyze")
	if !ok {
		t.Fatal("expected to find 'analyze' subcommand")
	}
	if sc.Name != "analyze" {
		t.Errorf("got subcommand name %q, want 'analyze'", sc.Name)
	}
}

func TestFindSubcommand_Watch(t *testing.T) {
	k8s := k8splugin.New()
	sc, ok := findSubcommand(k8s, "watch")
	if !ok {
		t.Fatal("expected to find 'watch' subcommand")
	}
	if sc.Name != "watch" {
		t.Errorf("got subcommand name %q, want 'watch'", sc.Name)
	}
}

func TestFindSubcommand_NotFound(t *testing.T) {
	k8s := k8splugin.New()
	_, ok := findSubcommand(k8s, "nonexistent")
	if ok {
		t.Fatal("expected false for nonexistent subcommand")
	}
}

func TestFindSubcommand_SLOCheck(t *testing.T) {
	slo := sloplugin.New()
	sc, ok := findSubcommand(slo, "check")
	if !ok {
		t.Fatal("expected to find 'check' subcommand in SLO plugin")
	}
	if sc.Name != "check" {
		t.Errorf("got %q, want 'check'", sc.Name)
	}
}

// ---- mergeReports ----------------------------------------------------------

func TestMergeReports_NoExtraFindings(t *testing.T) {
	r := plugin.Report{
		Title:    "K8s watch",
		Summary:  "all green",
		Findings: []plugin.Finding{{Title: "pod crash"}},
	}
	got := mergeReports(r, nil)
	if got.Title != "K8s watch" {
		t.Errorf("title changed unexpectedly: %q", got.Title)
	}
	if len(got.Findings) != 1 {
		t.Errorf("want 1 finding, got %d", len(got.Findings))
	}
}

func TestMergeReports_WithSLOFindings(t *testing.T) {
	base := plugin.Report{
		Title:    "Kubernetes watch",
		Summary:  "2 unhealthy pods",
		Findings: []plugin.Finding{{Title: "CrashLoopBackOff"}},
	}
	extra := []plugin.Finding{
		{Title: "SLO burn: api-slo", Category: "SLO"},
		{Title: "SLO burn: payment-slo", Category: "SLO"},
	}
	got := mergeReports(base, extra)

	if got.Title != "Exalm live dashboard" {
		t.Errorf("merged title = %q, want 'Exalm live dashboard'", got.Title)
	}
	if len(got.Findings) != 3 {
		t.Errorf("want 3 findings (1 k8s + 2 SLO), got %d", len(got.Findings))
	}
	if got.Findings[0].Title != "CrashLoopBackOff" {
		t.Errorf("first finding should be k8s finding, got %q", got.Findings[0].Title)
	}
	if got.Findings[1].Category != "SLO" || got.Findings[2].Category != "SLO" {
		t.Errorf("last two findings should be SLO category")
	}
}

func TestMergeReports_Immutable(t *testing.T) {
	// Verify mergeReports does not mutate the input report's Findings slice.
	orig := plugin.Report{
		Findings: []plugin.Finding{{Title: "pod-a"}},
	}
	extra := []plugin.Finding{{Title: "slo-x"}}
	_ = mergeReports(orig, extra)

	if len(orig.Findings) != 1 {
		t.Errorf("mergeReports mutated input Findings: got len %d, want 1", len(orig.Findings))
	}
}

func TestMergeReports_WithSpareCapacity(t *testing.T) {
	// Regression test for the spare-capacity aliasing bug: if the input slice
	// has extra capacity, a naive append would write the extra findings into
	// the caller's backing array. mergeReports must use copy so the original
	// slice's backing array is never touched.
	backing := make([]plugin.Finding, 1, 4) // len=1, cap=4
	backing[0] = plugin.Finding{Title: "original"}
	orig := plugin.Report{Findings: backing}

	extra := []plugin.Finding{{Title: "slo-injected"}}
	merged := mergeReports(orig, extra)

	// The merge should produce 2 findings.
	if len(merged.Findings) != 2 {
		t.Fatalf("want 2 findings after merge, got %d", len(merged.Findings))
	}
	// Extend the slice to its full capacity to inspect slots beyond len=1.
	// If mergeReports wrote into the spare capacity, slot [1] will have been
	// overwritten with the injected finding.
	full := backing[:cap(backing)]
	if full[1].Title == "slo-injected" {
		t.Error("mergeReports wrote into the caller's backing array (spare capacity aliasing)")
	}
}

// ---- mergeLiveUpdates ------------------------------------------------------

func TestMergeLiveUpdates_ForwardsWithoutSLO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := make(chan plugin.Report, 1)
	dst := make(chan plugin.Report, 1)

	go mergeLiveUpdates(ctx, src, dst, nil)

	r := plugin.Report{Title: "K8s refresh", Findings: []plugin.Finding{{Title: "OOM"}}}
	src <- r

	select {
	case got := <-dst:
		if got.Title != "K8s refresh" {
			t.Errorf("title = %q, want 'K8s refresh'", got.Title)
		}
		if len(got.Findings) != 1 {
			t.Errorf("want 1 finding, got %d", len(got.Findings))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for forwarded report")
	}
}

func TestMergeLiveUpdates_MergesSLOFindings(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := make(chan plugin.Report, 1)
	dst := make(chan plugin.Report, 1)
	sloFindings := []plugin.Finding{{Title: "SLO burn: api", Category: "SLO"}}

	go mergeLiveUpdates(ctx, src, dst, sloFindings)

	src <- plugin.Report{
		Title:    "K8s watch",
		Findings: []plugin.Finding{{Title: "CrashLoop"}},
	}

	select {
	case got := <-dst:
		if len(got.Findings) != 2 {
			t.Fatalf("want 2 findings (1 k8s + 1 SLO), got %d", len(got.Findings))
		}
		if got.Title != "Exalm live dashboard" {
			t.Errorf("merged title = %q, want 'Exalm live dashboard'", got.Title)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for merged report")
	}
}

func TestMergeLiveUpdates_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	src := make(chan plugin.Report)
	dst := make(chan plugin.Report, 1)

	done := make(chan struct{})
	go func() {
		mergeLiveUpdates(ctx, src, dst, nil)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// mergeLiveUpdates exited cleanly
	case <-time.After(time.Second):
		t.Fatal("timed out: mergeLiveUpdates did not stop after context cancel")
	}
}

func TestMergeLiveUpdates_StopsOnClosedSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := make(chan plugin.Report)
	dst := make(chan plugin.Report, 1)

	done := make(chan struct{})
	go func() {
		mergeLiveUpdates(ctx, src, dst, nil)
		close(done)
	}()

	close(src)

	select {
	case <-done:
		// exited cleanly after source channel closed
	case <-time.After(time.Second):
		t.Fatal("timed out: mergeLiveUpdates did not stop after source channel closed")
	}
}

// ---- runSLOCheck (no-op when sloFile is empty) ----------------------------

func TestRunSLOCheck_EmptySLOFile(t *testing.T) {
	findings, err := runSLOCheck(
		context.Background(),
		&serveCLIFlags{sloFile: ""},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("expected nil error for empty sloFile, got: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for empty sloFile, got %v", findings)
	}
}

// ---- buildCreatePRFn -------------------------------------------------------

func TestBuildCreatePRFn_NoToken(t *testing.T) {
	fn := buildCreatePRFn(&serveCLIFlags{githubRepo: "owner/repo"})
	if fn != nil {
		t.Error("expected nil when token is missing")
	}
}

func TestBuildCreatePRFn_NoRepo(t *testing.T) {
	fn := buildCreatePRFn(&serveCLIFlags{githubToken: "ghp-test"})
	if fn != nil {
		t.Error("expected nil when repo is missing")
	}
}

func TestBuildCreatePRFn_InvalidRepoFormat(t *testing.T) {
	fn := buildCreatePRFn(&serveCLIFlags{
		githubToken: "ghp-test",
		githubRepo:  "no-slash-here",
		gitProvider: "github",
	})
	if fn != nil {
		t.Error("expected nil for repo without slash separator")
	}
}
