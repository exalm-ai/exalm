package k8s

import (
	"testing"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Every finding that names a resource must come out of enrichment with a typed
// entity — that identity is what lets the dashboard group, filter, and link a
// finding to its logs, changes, and conversation without substring-matching the
// title.
func TestEnrichFindings_AttachesEntity(t *testing.T) {
	in := []plugin.Finding{
		{Severity: plugin.SeverityCritical, Category: "Pods", Title: "CrashLoopBackOff: prod/api-0"},
		{Severity: plugin.SeverityHigh, Category: "Storage", Title: "PVC near capacity: analytics/data-pvc (94%)"},
		{Severity: plugin.SeverityMedium, Category: "Nodes", Title: "Node worker-3 unreachable"},
	}

	out := enrichFindings(in, Snapshot{}, nil, time.Now())

	pod := out[0]
	if pod.Entity == nil {
		t.Fatal("pod finding should carry an entity")
	}
	if pod.Entity.Path() != "prod/api-0" {
		t.Errorf("pod entity path = %q, want prod/api-0", pod.Entity.Path())
	}
	if pod.Entity.Kind != "Pod" {
		t.Errorf("pod entity kind = %q, want Pod", pod.Entity.Kind)
	}

	pvc := out[1]
	if pvc.Entity == nil || pvc.Entity.Path() != "analytics/data-pvc" {
		t.Errorf("pvc entity = %+v, want analytics/data-pvc", pvc.Entity)
	}
	if pvc.Entity.Kind != "PersistentVolumeClaim" {
		t.Errorf("pvc entity kind = %q", pvc.Entity.Kind)
	}

	// A title with no "ns/name" yields no entity rather than a bogus one.
	if node := out[2]; node.Entity != nil && !node.Entity.IsZero() {
		t.Errorf("unparseable title should not invent an entity, got %+v", node.Entity)
	}
}

// Findings must carry the real times their resource was observed misbehaving.
// Without them the frequency chart has nothing to bucket by, which is what
// drove the previous synthetic series.
func TestEnrichFindings_AttachesObservationWindow(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	snap := Snapshot{Events: []EventSummary{
		{Namespace: "prod", PodName: "api-0", Reason: "BackOff", Count: 3, LastSeenAt: now.Add(-2 * time.Hour)},
		{Namespace: "prod", PodName: "api-0", Reason: "Unhealthy", Count: 4, LastSeenAt: now.Add(-30 * time.Minute)},
		{Namespace: "prod", PodName: "other", Reason: "BackOff", Count: 1, LastSeenAt: now.Add(-5 * time.Hour)},
	}}
	in := []plugin.Finding{
		{Severity: plugin.SeverityCritical, Category: "Pods", Title: "CrashLoopBackOff: prod/api-0"},
		{Severity: plugin.SeverityHigh, Category: "Pods", Title: "CrashLoopBackOff: prod/no-events"},
	}

	out := enrichFindings(in, snap, nil, now)

	got := out[0]
	if got.FirstSeen == nil || !got.FirstSeen.Equal(now.Add(-2*time.Hour)) {
		t.Errorf("FirstSeen = %v, want the earliest event time", got.FirstSeen)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(now.Add(-30*time.Minute)) {
		t.Errorf("LastSeen = %v, want the latest event time", got.LastSeen)
	}
	if got.Count != 7 {
		t.Errorf("Count = %d, want 7 (summed across both events)", got.Count)
	}

	// A finding with no matching events must stay zero rather than be stamped
	// with "now" — an unknown observation time is not the present moment.
	if quiet := out[1]; quiet.FirstSeen != nil || quiet.LastSeen != nil {
		t.Errorf("finding without events must keep nil times, got %v/%v", quiet.FirstSeen, quiet.LastSeen)
	}
}

// A finding whose remediation already names the resource must use that exact
// identity rather than re-parsing prose out of the title.
func TestEnrichFindings_PrefersRemediationIdentityOverTitle(t *testing.T) {
	in := []plugin.Finding{{
		Severity: plugin.SeverityCritical,
		Category: "Pods",
		Title:    "CrashLoopBackOff: prod/api-0",
		Remediation: &plugin.RemediationAction{
			Kind: "rollout-restart", Resource: "Deployment", Namespace: "prod", Name: "api",
		},
	}}

	out := enrichFindings(in, Snapshot{}, nil, time.Now())
	got := out[0].Entity
	if got == nil {
		t.Fatal("expected an entity")
	}
	if got.Kind != "Deployment" || got.Path() != "prod/api" {
		t.Errorf("entity = %+v, want Deployment prod/api", got)
	}
}

// Two pods hitting the same symptom must stay distinct findings. Before
// Finding.Entity they hashed to one ID and merged in the dashboard.
func TestEnrichFindings_SameSymptomDifferentPodsStayDistinct(t *testing.T) {
	in := []plugin.Finding{
		{Severity: plugin.SeverityCritical, Category: "Pods", Title: "OOMKilled: prod/api-0", Source: "k8s/c1"},
		{Severity: plugin.SeverityCritical, Category: "Pods", Title: "OOMKilled: prod/api-1", Source: "k8s/c1"},
	}
	out := enrichFindings(in, Snapshot{}, nil, time.Now())
	if out[0].ID() == out[1].ID() {
		t.Errorf("findings on different pods share an ID: %s", out[0].ID())
	}
}
