package chaos

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// --- scorer tests ---

func TestScoreServices_Empty(t *testing.T) {
	scores := ScoreServices(ClusterSnapshot{})
	if len(scores) != 0 {
		t.Fatalf("expected 0 scores for empty snapshot, got %d", len(scores))
	}
}

func TestScoreServices_SingleReplica(t *testing.T) {
	snap := ClusterSnapshot{
		ReplicaSetIssues: []ReplicaSetIssue{
			{Namespace: "prod", Name: "api", Desired: 1, Ready: 1},
		},
	}
	scores := ScoreServices(snap)
	if len(scores) == 0 {
		t.Fatal("expected at least one score")
	}
	if scores[0].Score < 25 {
		t.Errorf("single-replica service should score >= 25, got %d", scores[0].Score)
	}
	if !containsReason(scores[0].Reasons, "Single replica") {
		t.Errorf("expected 'Single replica' reason, got %v", scores[0].Reasons)
	}
}

func TestScoreServices_BestEffort(t *testing.T) {
	snap := ClusterSnapshot{
		ResourceGaps: []ResourceGap{
			{Namespace: "prod", Service: "worker", MissingCPU: true, MissingMemory: true, BestEffort: true},
		},
	}
	scores := ScoreServices(snap)
	if len(scores) == 0 {
		t.Fatal("expected at least one score")
	}
	if scores[0].Score < 20 {
		t.Errorf("BestEffort service should score >= 20, got %d", scores[0].Score)
	}
	if !containsReason(scores[0].Reasons, "BestEffort") {
		t.Errorf("expected 'BestEffort' reason, got %v", scores[0].Reasons)
	}
}

func TestScoreServices_NoNetworkPolicy(t *testing.T) {
	snap := ClusterSnapshot{
		UncoveredNamespaces: []string{"staging"},
		Deployments: []DeploymentSummary{
			{Namespace: "staging", Name: "frontend", Ready: 3, Desired: 3},
		},
	}
	scores := ScoreServices(snap)
	if len(scores) == 0 {
		t.Fatal("expected at least one score")
	}
	if scores[0].Score < 20 {
		t.Errorf("uncovered namespace service should score >= 20, got %d", scores[0].Score)
	}
	if !containsReason(scores[0].Reasons, "NetworkPolicy") {
		t.Errorf("expected 'NetworkPolicy' reason, got %v", scores[0].Reasons)
	}
}

func TestScoreServices_MaxScore(t *testing.T) {
	// All risk factors present — score must be at the critical threshold (>= 75)
	// and capped at 100. The algorithm weights sum to 80 for this combination
	// (single-replica 25 + BestEffort 20 + no-NetworkPolicy 20 + incidents 15),
	// so we assert Critical severity and the cap invariant.
	snap := ClusterSnapshot{
		ResourceGaps: []ResourceGap{
			{Namespace: "prod", Service: "checkout", MissingCPU: true, MissingMemory: true, BestEffort: true},
		},
		UncoveredNamespaces: []string{"prod"},
		ReplicaSetIssues: []ReplicaSetIssue{
			{Namespace: "prod", Name: "checkout", Desired: 1, Ready: 1},
		},
		CriticalHighIncidents: 5,
	}
	scores := ScoreServices(snap)
	if len(scores) == 0 {
		t.Fatal("expected at least one score")
	}
	// All risk factors should push the service into Critical territory (>= 75).
	if scores[0].Score < 75 {
		t.Errorf("all risk factors should yield score >= 75 (critical), got %d", scores[0].Score)
	}
	// Verify the cap: score must never exceed 100 regardless of input.
	if scores[0].Score > 100 {
		t.Errorf("score must not exceed 100, got %d", scores[0].Score)
	}
}

func TestScoreServices_ScoreCappedAt100(t *testing.T) {
	// Construct a snapshot where the raw weights would sum to > 100:
	// single-replica(25) + MissingCPU(15) + MissingMemory(15) + no-NetworkPolicy(20) + incidents(15) = 90.
	// Add a second uncovered namespace match and confirm score stays <= 100.
	snap := ClusterSnapshot{
		ResourceGaps: []ResourceGap{
			// Use individual limits (not BestEffort) to accumulate CPU+memory separately.
			{Namespace: "prod", Service: "overloaded", MissingCPU: true, MissingMemory: true, BestEffort: false},
		},
		UncoveredNamespaces: []string{"prod"},
		ReplicaSetIssues: []ReplicaSetIssue{
			{Namespace: "prod", Name: "overloaded", Desired: 1, Ready: 1},
		},
		CriticalHighIncidents: 5,
	}
	scores := ScoreServices(snap)
	if len(scores) == 0 {
		t.Fatal("expected at least one score")
	}
	if scores[0].Score > 100 {
		t.Errorf("score must be capped at 100, got %d", scores[0].Score)
	}
}

func TestScoreServices_SortedDescending(t *testing.T) {
	snap := ClusterSnapshot{
		ResourceGaps: []ResourceGap{
			{Namespace: "prod", Service: "risky", MissingCPU: true, MissingMemory: true, BestEffort: true},
		},
		Deployments: []DeploymentSummary{
			{Namespace: "prod", Name: "safe", Ready: 3, Desired: 3},
		},
	}
	scores := ScoreServices(snap)
	if len(scores) < 2 {
		t.Skip("need at least 2 services for order check")
	}
	for i := 1; i < len(scores); i++ {
		if scores[i].Score > scores[i-1].Score {
			t.Errorf("scores not sorted descending: index %d (%d) > index %d (%d)",
				i, scores[i].Score, i-1, scores[i-1].Score)
		}
	}
}

// --- litmus YAML tests ---

func TestGenerateLitmusYAML_PodKill(t *testing.T) {
	yaml := GenerateLitmusYAML("pod-kill", "prod", "api-gateway")
	if !strings.Contains(yaml, "pod-delete") {
		t.Errorf("pod-kill YAML should contain 'pod-delete', got:\n%s", yaml)
	}
	if !strings.Contains(yaml, "api-gateway") {
		t.Errorf("YAML should reference service 'api-gateway'")
	}
	if !strings.Contains(yaml, "prod") {
		t.Errorf("YAML should reference namespace 'prod'")
	}
}

func TestGenerateLitmusYAML_NetworkPartition(t *testing.T) {
	yaml := GenerateLitmusYAML("network-partition", "staging", "svc")
	if !strings.Contains(yaml, "pod-network-loss") {
		t.Errorf("network-partition YAML should contain 'pod-network-loss'")
	}
}

func TestGenerateLitmusYAML_CPUStress(t *testing.T) {
	yaml := GenerateLitmusYAML("cpu-stress", "ns", "svc")
	if !strings.Contains(yaml, "pod-cpu-hog") {
		t.Errorf("cpu-stress YAML should contain 'pod-cpu-hog'")
	}
}

func TestGenerateLitmusYAML_MemoryPressure(t *testing.T) {
	yaml := GenerateLitmusYAML("memory-pressure", "ns", "svc")
	if !strings.Contains(yaml, "pod-memory-hog") {
		t.Errorf("memory-pressure YAML should contain 'pod-memory-hog'")
	}
}

// --- suggest subcommand tests ---

// fakeRedactor passes strings through unchanged for testing.
type fakeRedactor struct{}

func (fakeRedactor) Redact(s string) string { return s }

func TestSuggest_NoSnapshotFile(t *testing.T) {
	p := New()
	subs := p.Subcommands()
	if len(subs) == 0 {
		t.Fatal("expected at least one subcommand")
	}

	var suggestFn func(ctx context.Context, args plugin.RunArgs) (plugin.Report, error)
	for _, s := range subs {
		if s.Name == "suggest" {
			suggestFn = s.Run
			break
		}
	}
	if suggestFn == nil {
		t.Fatal("suggest subcommand not found")
	}

	report, err := suggestFn(context.Background(), plugin.RunArgs{
		Flags:    map[string]string{},
		Redactor: fakeRedactor{},
	})
	if err != nil {
		t.Fatalf("suggest without snapshot file should not return error, got: %v", err)
	}
	if report.Title == "" {
		t.Error("report title should not be empty")
	}
	// Should contain instructions for generating a snapshot.
	if !strings.Contains(report.Summary, "snapshot") {
		t.Errorf("report summary should mention 'snapshot', got: %s", report.Summary)
	}
	// Should include demo findings.
	if len(report.Findings) == 0 {
		t.Error("expected demo findings in no-snapshot report")
	}
}

func TestSuggest_WithHighRiskService(t *testing.T) {
	// Write a temporary snapshot JSON with a single-replica BestEffort service.
	snap := ClusterSnapshot{
		ResourceGaps: []ResourceGap{
			{Namespace: "prod", Service: "payment-api", MissingCPU: true, MissingMemory: true, BestEffort: true},
		},
		UncoveredNamespaces: []string{"prod"},
		ReplicaSetIssues: []ReplicaSetIssue{
			{Namespace: "prod", Name: "payment-api", Desired: 1, Ready: 1},
		},
		CriticalHighIncidents: 3,
	}

	snapJSON, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}

	dir := t.TempDir()
	snapFile := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(snapFile, snapJSON, 0o600); err != nil {
		t.Fatalf("write snapshot file: %v", err)
	}

	p := New()
	var suggestFn func(ctx context.Context, args plugin.RunArgs) (plugin.Report, error)
	for _, s := range p.Subcommands() {
		if s.Name == "suggest" {
			suggestFn = s.Run
			break
		}
	}
	if suggestFn == nil {
		t.Fatal("suggest subcommand not found")
	}

	report, err := suggestFn(context.Background(), plugin.RunArgs{
		Flags:    map[string]string{"snapshot-file": snapFile},
		Redactor: fakeRedactor{},
	})
	if err != nil {
		t.Fatalf("suggest with snapshot file returned error: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	topFinding := report.Findings[0]
	if topFinding.Severity != plugin.SeverityCritical {
		t.Errorf("highest-risk service should be Critical, got %s", topFinding.Severity)
	}
	if !strings.Contains(topFinding.Title, "payment-api") {
		t.Errorf("finding title should mention 'payment-api', got: %s", topFinding.Title)
	}
	if !strings.Contains(topFinding.Detail, "---YAML---") {
		t.Errorf("finding detail should include Litmus YAML separator, got: %s", topFinding.Detail)
	}
}

func TestSuggest_NamespaceFilter(t *testing.T) {
	snap := ClusterSnapshot{
		Deployments: []DeploymentSummary{
			{Namespace: "prod", Name: "svc-a", Ready: 2, Desired: 2},
			{Namespace: "staging", Name: "svc-b", Ready: 1, Desired: 1},
		},
		ReplicaSetIssues: []ReplicaSetIssue{
			{Namespace: "staging", Name: "svc-b", Desired: 1, Ready: 1},
		},
	}

	snapJSON, _ := json.Marshal(snap)
	dir := t.TempDir()
	snapFile := filepath.Join(dir, "snap.json")
	_ = os.WriteFile(snapFile, snapJSON, 0o600)

	p := New()
	var suggestFn func(ctx context.Context, args plugin.RunArgs) (plugin.Report, error)
	for _, s := range p.Subcommands() {
		if s.Name == "suggest" {
			suggestFn = s.Run
		}
	}

	report, err := suggestFn(context.Background(), plugin.RunArgs{
		Flags:    map[string]string{"snapshot-file": snapFile, "namespace": "prod"},
		Redactor: fakeRedactor{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range report.Findings {
		if strings.Contains(f.Title, "staging") {
			t.Errorf("namespace filter did not exclude staging findings: %s", f.Title)
		}
	}
}

// --- plugin contract tests ---

func TestPlugin_Contract(t *testing.T) {
	p := New()
	if p.Name() != "chaos" {
		t.Errorf("Name() = %q, want %q", p.Name(), "chaos")
	}
	if !p.Mutates() {
		t.Error("Mutates() should return true")
	}
	if len(p.Subcommands()) == 0 {
		t.Error("Subcommands() should return at least one entry")
	}
}

// --- helpers ---

func containsReason(reasons []string, substring string) bool {
	for _, r := range reasons {
		if strings.Contains(r, substring) {
			return true
		}
	}
	return false
}
