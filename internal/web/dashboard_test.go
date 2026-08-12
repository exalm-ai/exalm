package web

import (
	"testing"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestNamespaceOf(t *testing.T) {
	cases := []struct {
		name string
		f    plugin.Finding
		want string
	}{
		{"from remediation", plugin.Finding{Title: "x", Remediation: &plugin.RemediationAction{Namespace: "prod"}}, "prod"},
		{"from likely cause", plugin.Finding{Title: "x", LikelyCause: &plugin.ChangeRef{Namespace: "staging"}}, "staging"},
		{"from title path", plugin.Finding{Title: "CrashLoopBackOff: jx-dev/price-collector-3.4"}, "jx-dev"},
		{"fallback cluster", plugin.Finding{Title: "Node worker-3 unreachable"}, "cluster"},
	}
	for _, tc := range cases {
		if got := namespaceOf(tc.f); got != tc.want {
			t.Errorf("%s: namespaceOf = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestFindingID_StableAndDistinct(t *testing.T) {
	a := plugin.Finding{Category: "Pods", Title: "CrashLoopBackOff: ns/a", Source: "k8s/c1"}
	b := plugin.Finding{Category: "Pods", Title: "CrashLoopBackOff: ns/b", Source: "k8s/c1"}
	// A separately-constructed but identical finding must hash to the same id
	// (deterministic across re-collections), which is what the fix/investigate
	// endpoints rely on.
	aCopy := plugin.Finding{Category: "Pods", Title: "CrashLoopBackOff: ns/a", Source: "k8s/c1"}
	if findingID(a) != findingID(aCopy) {
		t.Error("findingID should be stable for identical findings")
	}
	if findingID(a) == findingID(b) {
		t.Error("findingID should differ for different findings")
	}
}

func TestRestartsOf(t *testing.T) {
	if got := restartsOf(plugin.Finding{Detail: "Pod has restarted 142 times."}); got != "142" {
		t.Errorf("restartsOf = %q, want 142", got)
	}
	if got := restartsOf(plugin.Finding{Detail: "No restart info here."}); got != "—" {
		t.Errorf("restartsOf with no count = %q, want em-dash", got)
	}
}

func TestGroupAndSevMapping(t *testing.T) {
	if groupOf("Networking") != "Services" {
		t.Errorf("Networking should fold into Services, got %q", groupOf("Networking"))
	}
	if groupOf("Nodes") != "Workloads" {
		t.Errorf("Nodes should fold into Workloads, got %q", groupOf("Nodes"))
	}
	if groupOf("Mystery") != "Other" {
		t.Errorf("unknown category should fold into Other, got %q", groupOf("Mystery"))
	}
	if sevKey(plugin.SeverityInfo) != "low" {
		t.Errorf("info should map to low, got %q", sevKey(plugin.SeverityInfo))
	}
}

func TestBuildDashboard_AggregatesAndUsesPodInfo(t *testing.T) {
	report := plugin.Report{
		Summary: "Analysed 165 pods (14 unhealthy) using ollama.",
		Findings: []plugin.Finding{
			{Severity: plugin.SeverityCritical, Category: "Pods", Title: "CrashLoopBackOff: prod/api-0",
				Detail: "Pod has restarted 12 times.", Remediation: &plugin.RemediationAction{Namespace: "prod", Name: "api-0"}},
			{Severity: plugin.SeverityHigh, Category: "Security", Title: "Privileged container: prod/debug",
				Remediation: &plugin.RemediationAction{Namespace: "prod", Name: "debug"}},
			{Severity: plugin.SeverityMedium, Category: "Resources", Title: "No limits: staging/web",
				Remediation: &plugin.RemediationAction{Namespace: "staging", Name: "web"}},
		},
	}
	pi := &PodInfo{Total: 165, Unhealthy: 14, ByNamespace: map[string]int{"prod": 92, "staging": 34, "idle": 39}}

	d := buildDashboard(report, pi, "", true)

	if d.Pods != 165 || d.Unhealthy != 14 {
		t.Errorf("cluster totals not carried: pods=%d unhealthy=%d", d.Pods, d.Unhealthy)
	}
	if d.Provider != "ollama" {
		t.Errorf("provider = %q, want ollama", d.Provider)
	}
	if len(d.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(d.Findings))
	}
	// "idle" has pods but no findings — it must still appear so cluster totals add up.
	var prod, idle *dashNamespace
	for i := range d.Namespaces {
		switch d.Namespaces[i].Key {
		case "prod":
			prod = &d.Namespaces[i]
		case "idle":
			idle = &d.Namespaces[i]
		}
	}
	if prod == nil || idle == nil {
		t.Fatalf("expected prod and idle namespaces, got %+v", d.Namespaces)
	}
	if prod.Pods != 92 || prod.Crit != 1 || prod.High != 1 {
		t.Errorf("prod ns wrong: %+v", *prod)
	}
	if idle.Findings != 0 || idle.Pods != 39 {
		t.Errorf("idle ns should have 0 findings, 39 pods: %+v", *idle)
	}
	// First finding should expose the restart count and resource path.
	f0 := d.Findings[0]
	if f0.Restarts != "12" {
		t.Errorf("restarts = %q, want 12", f0.Restarts)
	}
	if f0.Ns != "prod/api-0" {
		t.Errorf("ns path = %q, want prod/api-0", f0.Ns)
	}
	if !f0.Fix {
		t.Error("finding with remediation should be fixable")
	}
}

func TestBuildDashboard_NilPodInfoDegrades(t *testing.T) {
	report := plugin.Report{Findings: []plugin.Finding{
		{Severity: plugin.SeverityLow, Category: "Pods", Title: "x: ns/a"},
	}}
	d := buildDashboard(report, nil, "", false)
	if d.Pods != 0 || d.Unhealthy != 0 {
		t.Errorf("with no pod info, cluster totals should be 0, got pods=%d unhealthy=%d", d.Pods, d.Unhealthy)
	}
	if len(d.Namespaces) != 1 || d.Namespaces[0].Pods != 0 {
		t.Errorf("namespace pods should be 0 without pod info: %+v", d.Namespaces)
	}
}

func TestAgeOf_UnknownStaysUnknown(t *testing.T) {
	// A finding with no observation time must render as unknown, never as a
	// guess — the dashboard previously hardcoded an em-dash for every row,
	// which hid the fact that ages were never computed at all.
	if got := ageOf(plugin.Finding{}); got != "—" {
		t.Errorf("no timestamp should render as em-dash, got %q", got)
	}
	cases := []struct {
		ago  time.Duration
		want string
	}{
		{30 * time.Second, "just now"},
		{45 * time.Minute, "45m"},
		{5 * time.Hour, "5h"},
		{50 * time.Hour, "2d"},
	}
	for _, tc := range cases {
		f := plugin.Finding{LastSeen: time.Now().Add(-tc.ago)}
		if got := ageOf(f); got != tc.want {
			t.Errorf("ageOf(%v ago) = %q, want %q", tc.ago, got, tc.want)
		}
	}
}

func TestRFC3339OrEmpty(t *testing.T) {
	if got := rfc3339OrEmpty(time.Time{}); got != "" {
		t.Errorf("zero time must serialise as empty so the UI can tell it is unknown, got %q", got)
	}
	at := time.Date(2026, 8, 12, 9, 30, 0, 0, time.UTC)
	if got := rfc3339OrEmpty(at); got != "2026-08-12T09:30:00Z" {
		t.Errorf("rfc3339OrEmpty = %q", got)
	}
}
