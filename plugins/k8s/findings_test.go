package k8s

import (
	"fmt"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func findingsBySeverity(findings []plugin.Finding, sev plugin.Severity) []plugin.Finding {
	var out []plugin.Finding
	for _, f := range findings {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

func TestBuildFindings_CrashLoopBackOff(t *testing.T) {
	s := Snapshot{
		UnhealthyPods: []PodSummary{
			{Namespace: "prod", Name: "api-xyz", Reason: "CrashLoopBackOff", RestartCount: 22},
		},
	}
	findings := BuildFindings(s)
	critical := findingsBySeverity(findings, plugin.SeverityCritical)
	if len(critical) == 0 {
		t.Fatal("expected a critical finding for CrashLoopBackOff")
	}
}

func TestBuildFindings_OOMKilled(t *testing.T) {
	s := Snapshot{
		UnhealthyPods: []PodSummary{
			{Namespace: "prod", Name: "worker-abc", Reason: "OOMKilled", RestartCount: 3},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Fatal("expected a high finding for OOMKilled")
	}
}

func TestBuildFindings_InitContainerError(t *testing.T) {
	for _, reason := range []string{"Init:Error", "Init:CrashLoopBackOff"} {
		s := Snapshot{
			UnhealthyPods: []PodSummary{
				{Namespace: "prod", Name: "job-xyz", Reason: reason},
			},
		}
		findings := BuildFindings(s)
		high := findingsBySeverity(findings, plugin.SeverityHigh)
		if len(high) == 0 {
			t.Errorf("expected high finding for %s", reason)
		}
	}
}

func TestBuildFindings_Deployment(t *testing.T) {
	s := Snapshot{
		Deployments: []DeploymentSummary{
			{Namespace: "prod", Name: "checkout", Desired: 3, Available: 1, Unavailable: 2, StallReason: "ProgressDeadlineExceeded"},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Fatal("expected high finding for stalled deployment")
	}
}

func TestBuildFindings_HPACannotScale(t *testing.T) {
	s := Snapshot{
		HPAs: []HPASummary{
			{Namespace: "prod", Name: "api-hpa", TargetKind: "Deployment", TargetName: "api", Issue: "CannotScale: MetricsNotAvailable"},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Fatal("expected high finding for HPA issue")
	}
}

func TestBuildFindings_QuotaPressure(t *testing.T) {
	s := Snapshot{
		Quotas: []QuotaSummary{
			{Namespace: "prod", Resource: "memory", Used: "900Mi", Hard: "1Gi", UsedPct: 90},
			{Namespace: "prod", Resource: "cpu", Used: "800m", Hard: "1", UsedPct: 80},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Error("expected high finding for 90% quota")
	}
	med := findingsBySeverity(findings, plugin.SeverityMedium)
	if len(med) == 0 {
		t.Error("expected medium finding for 80% quota")
	}
}

func TestBuildFindings_NodeNetworkUnavailable(t *testing.T) {
	s := Snapshot{
		NodeIssues: []NodeIssue{
			{Name: "node-1", Conditions: []string{"NetworkUnavailable"}},
		},
	}
	findings := BuildFindings(s)
	critical := findingsBySeverity(findings, plugin.SeverityCritical)
	if len(critical) == 0 {
		t.Fatal("expected critical finding for NetworkUnavailable")
	}
}

func TestBuildFindings_EventSpike(t *testing.T) {
	s := Snapshot{
		Events: []EventSummary{
			{Namespace: "prod", PodName: "api-xyz", Reason: "BackOff", Count: 100, Density: 2.5, LastSeen: "5s ago"},
		},
	}
	findings := BuildFindings(s)
	med := findingsBySeverity(findings, plugin.SeverityMedium)
	if len(med) == 0 {
		t.Fatal("expected medium finding for event spike")
	}
}

func TestBuildFindings_LogAnomalies(t *testing.T) {
	s := Snapshot{
		UnhealthyPods: []PodSummary{
			{
				Namespace: "prod", Name: "api-xyz", Reason: "NotReady",
				LogAnomalies: []LogAnomaly{
					{Category: "db-error", Count: 5, Sample: "connection refused"},
					{Category: "http-5xx", Count: 10, Sample: `"status": 503`},
				},
			},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Error("expected high finding for db-error")
	}
	med := findingsBySeverity(findings, plugin.SeverityMedium)
	if len(med) == 0 {
		t.Error("expected medium finding for http-5xx")
	}
}

func TestBuildFindings_NoLimits(t *testing.T) {
	s := Snapshot{
		UnhealthyPods: []PodSummary{
			{Namespace: "prod", Name: "worker-abc", Reason: "OOMKilled", HasNoLimits: true},
		},
	}
	findings := BuildFindings(s)
	low := findingsBySeverity(findings, plugin.SeverityLow)
	if len(low) == 0 {
		t.Fatal("expected low finding for no-limits container")
	}
}

func TestBuildFindings_EmptySnapshot(t *testing.T) {
	findings := BuildFindings(Snapshot{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty snapshot, got %d", len(findings))
	}
}

func TestDetectCascade_DBError(t *testing.T) {
	pods := make([]PodSummary, 3)
	for i := range pods {
		pods[i] = PodSummary{
			Namespace:    "prod",
			Name:         fmt.Sprintf("api-%d", i),
			Reason:       "CrashLoopBackOff",
			LogAnomalies: []LogAnomaly{{Category: "db-error", Count: 5, Sample: "connection refused"}},
		}
	}
	findings := BuildFindings(Snapshot{UnhealthyPods: pods})
	// Cascade finding must come first and be critical.
	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}
	if findings[0].Severity != plugin.SeverityCritical {
		t.Errorf("expected first finding to be critical (cascade), got %s: %s", findings[0].Severity, findings[0].Title)
	}
	if !containsCI(findings[0].Title, "cascade") {
		t.Errorf("cascade finding title should mention cascade, got: %q", findings[0].Title)
	}
}

func TestDetectCascade_BelowThreshold(t *testing.T) {
	pods := make([]PodSummary, 2)
	for i := range pods {
		pods[i] = PodSummary{
			Namespace:    "prod",
			Name:         fmt.Sprintf("api-%d", i),
			LogAnomalies: []LogAnomaly{{Category: "db-error", Count: 3}},
		}
	}
	findings := BuildFindings(Snapshot{UnhealthyPods: pods})
	for _, f := range findings {
		if containsCI(f.Title, "cascade") {
			t.Errorf("unexpected cascade finding for 2 pods: %s", f.Title)
		}
	}
}

func TestDetectCascade_CertExpiry(t *testing.T) {
	pods := make([]PodSummary, 2)
	for i := range pods {
		pods[i] = PodSummary{
			Namespace:    "platform",
			Name:         fmt.Sprintf("gateway-%d", i),
			Reason:       "NotReady",
			LogAnomalies: []LogAnomaly{{Category: "cert-expiry", Count: 10}},
		}
	}
	findings := BuildFindings(Snapshot{UnhealthyPods: pods})
	if len(findings) == 0 || findings[0].Severity != plugin.SeverityCritical {
		t.Errorf("expected critical cascade finding for cert-expiry × 2, got: %v", findings)
	}
}

func TestBuildFindings_PVCIssue(t *testing.T) {
	s := Snapshot{
		PVCIssues: []PVCIssue{
			{Namespace: "data", Name: "postgres-pvc", Phase: "Pending", StorageClass: "fast-ssd", Reason: "no provisioner"},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Fatal("expected high finding for PVC in Pending phase")
	}
}

func TestBuildFindings_ServiceIssue(t *testing.T) {
	s := Snapshot{
		ServiceIssues: []ServiceIssue{
			{Namespace: "prod", Name: "payments-svc", Issue: "no ready endpoints"},
		},
	}
	findings := BuildFindings(s)
	med := findingsBySeverity(findings, plugin.SeverityMedium)
	if len(med) == 0 {
		t.Fatal("expected medium finding for service with no endpoints")
	}
}

func TestBuildFindings_IngressMissingClass(t *testing.T) {
	s := Snapshot{
		IngressIssues: []IngressHealth{
			{Namespace: "prod", Name: "api-ingress", MissingClass: true},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Fatal("expected high finding for ingress missing class")
	}
	if findings[0].Category != "Networking" {
		t.Errorf("expected category Networking, got %q", findings[0].Category)
	}
}

func TestBuildFindings_IngressMissingTLS(t *testing.T) {
	s := Snapshot{
		IngressIssues: []IngressHealth{
			{Namespace: "prod", Name: "api-ingress", MissingTLSSecret: []string{"tls-cert"}},
		},
	}
	findings := BuildFindings(s)
	critical := findingsBySeverity(findings, plugin.SeverityCritical)
	if len(critical) == 0 {
		t.Fatal("expected critical finding for missing TLS secret")
	}
}

func TestBuildFindings_ResourceGapBestEffort(t *testing.T) {
	s := Snapshot{
		ResourceGaps: []ResourceGap{
			{Namespace: "default", PodName: "api-1", ContainerName: "app", MissingCPU: true, MissingMemory: true, BestEffort: true},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Fatal("expected high finding for BestEffort QoS pod")
	}
	if findings[0].Category != "Resources" {
		t.Errorf("expected category Resources, got %q", findings[0].Category)
	}
}

func TestBuildFindings_ResourceGapMedium(t *testing.T) {
	s := Snapshot{
		ResourceGaps: []ResourceGap{
			{Namespace: "default", PodName: "worker-1", ContainerName: "app", MissingCPU: true, BestEffort: false},
		},
	}
	findings := BuildFindings(s)
	med := findingsBySeverity(findings, plugin.SeverityMedium)
	if len(med) == 0 {
		t.Fatal("expected medium finding for missing CPU limit")
	}
}

func TestBuildFindings_NetworkPolicyCoverage(t *testing.T) {
	s := Snapshot{
		UncoveredNamespaces: []string{"staging", "dev"},
	}
	findings := BuildFindings(s)
	med := findingsBySeverity(findings, plugin.SeverityMedium)
	if len(med) < 2 {
		t.Fatalf("expected 2 medium findings for uncovered namespaces, got %d", len(med))
	}
	for _, f := range med {
		if f.Category != "Security" {
			t.Errorf("expected category Security, got %q", f.Category)
		}
	}
}

func TestBuildFindings_RBACClusterAdmin(t *testing.T) {
	s := Snapshot{
		RBACRisks: []RBACRisk{
			{Kind: "ClusterRoleBinding", Name: "admin-binding", Reason: "cluster-admin binding", Subject: "serviceaccount:default/sa"},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Fatal("expected high finding for cluster-admin binding")
	}
	if high[0].Category != "Security" {
		t.Errorf("expected category Security, got %q", high[0].Category)
	}
}

func TestBuildFindings_ReplicaSetNotReady(t *testing.T) {
	s := Snapshot{
		ReplicaSetIssues: []ReplicaSetIssue{
			{Namespace: "prod", Name: "api-rs", Desired: 3, Ready: 1},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Fatal("expected high finding for ReplicaSet not ready")
	}
}

func TestBuildFindings_StatefulSetStuckRollout(t *testing.T) {
	s := Snapshot{
		StatefulSetIssues: []StatefulSetIssue{
			{Namespace: "data", Name: "postgres", Desired: 3, Ready: 2, StuckRollout: true},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Fatal("expected high finding for StatefulSet stuck rollout")
	}
}

func TestBuildFindings_FailedJob(t *testing.T) {
	s := Snapshot{
		FailedJobs: []JobIssue{
			{Namespace: "batch", Name: "nightly-report", Failed: 3, Reason: "BackoffLimitExceeded"},
		},
	}
	findings := BuildFindings(s)
	high := findingsBySeverity(findings, plugin.SeverityHigh)
	if len(high) == 0 {
		t.Fatal("expected high finding for failed job")
	}
	if high[0].Category != "Workloads" {
		t.Errorf("expected category Workloads, got %q", high[0].Category)
	}
}

func TestBuildFindings_SuspendedCronJob(t *testing.T) {
	s := Snapshot{
		CronJobIssues: []CronJobIssue{
			{Namespace: "batch", Name: "cleanup", Suspended: true, LastSchedule: "2h ago"},
		},
	}
	findings := BuildFindings(s)
	med := findingsBySeverity(findings, plugin.SeverityMedium)
	if len(med) == 0 {
		t.Fatal("expected medium finding for suspended CronJob")
	}
	if med[0].Category != "Workloads" {
		t.Errorf("expected category Workloads, got %q", med[0].Category)
	}
}

func TestBuildFindings_CategoryPresent(t *testing.T) {
	s := Snapshot{
		UnhealthyPods: []PodSummary{
			{Namespace: "prod", Name: "api", Reason: "CrashLoopBackOff", RestartCount: 5},
		},
	}
	for _, f := range BuildFindings(s) {
		if f.Category == "" {
			t.Errorf("finding %q has empty Category", f.Title)
		}
	}
}

// containsCI returns true if s contains substr (case-insensitive).
func containsCI(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
