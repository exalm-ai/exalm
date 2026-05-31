package evidence

import (
	"strings"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/changestore"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestExtractNamespaceAndName(t *testing.T) {
	cases := []struct {
		in     string
		wantNs string
		wantNm string
	}{
		{"CrashLoopBackOff: exalm-prod/api-gateway-7c9b", "exalm-prod", "api-gateway-7c9b"},
		{"Log db-error in exalm-test/crash-loop-jd6hl", "exalm-test", "crash-loop-jd6hl"},
		{"Selector mismatch: ns1/svc", "ns1", "svc"},
		{"Cross-namespace blocked: ns1 → ns2", "", ""},
		{"Generic title without slash", "", ""},
	}
	for _, c := range cases {
		gotNs, gotNm := extractNamespaceAndName(c.in)
		if gotNs != c.wantNs || gotNm != c.wantNm {
			t.Errorf("extractNamespaceAndName(%q) = (%q,%q), want (%q,%q)", c.in, gotNs, gotNm, c.wantNs, c.wantNm)
		}
	}
}

func TestBuild_LogEvidence(t *testing.T) {
	now := time.Now()
	src := Source{
		LogTails: map[string]string{
			"ns/api-pod/app": "INFO starting up\nERROR dial tcp 10.0.0.5:5432: connection refused\nINFO retrying",
		},
	}
	finding := plugin.Finding{Title: "CrashLoopBackOff: ns/api-pod"}
	got := Build(finding, src, nil, now)
	if len(got) != 1 {
		t.Fatalf("want 1 log evidence, got %d", len(got))
	}
	if got[0].Kind != "log" {
		t.Errorf("kind=%q want log", got[0].Kind)
	}
	if !strings.Contains(got[0].Excerpt, "connection refused") {
		t.Errorf("excerpt should contain error line, got %q", got[0].Excerpt)
	}
	if !strings.Contains(got[0].Anchor, "kubectl logs -n ns api-pod -c app") {
		t.Errorf("anchor should be kubectl logs command, got %q", got[0].Anchor)
	}
}

func TestBuild_ChangeEvidence_DirectMatch(t *testing.T) {
	now := time.Now()
	change := changestore.ChangeEvent{
		ID:        "abc123",
		Kind:      "Deployment",
		Namespace: "ns",
		Name:      "api-gateway",
		Action:    "updated",
		Actor:     "alice",
		Timestamp: now.Add(-15 * time.Minute),
	}
	finding := plugin.Finding{Title: "CrashLoopBackOff: ns/api-gateway-7c9b"}
	got := Build(finding, Source{}, []changestore.ChangeEvent{change}, now)
	if len(got) != 1 {
		t.Fatalf("want 1 change evidence via prefix match, got %d", len(got))
	}
	if got[0].Kind != "change" || got[0].Source != "abc123" {
		t.Errorf("unexpected evidence item: %+v", got[0])
	}
	if !strings.Contains(got[0].Excerpt, "alice") {
		t.Errorf("excerpt should mention actor, got %q", got[0].Excerpt)
	}
}

func TestBuild_ChangeEvidence_ViaLikelyCause(t *testing.T) {
	now := time.Now()
	change := changestore.ChangeEvent{
		ID: "xyz789", Kind: "ConfigMap", Namespace: "other", Name: "shared",
		Action: "updated", Timestamp: now.Add(-5 * time.Minute),
	}
	// LikelyCause links a different-namespace ConfigMap to the finding.
	finding := plugin.Finding{
		Title:       "CrashLoopBackOff: ns/api-pod",
		LikelyCause: &plugin.ChangeRef{ID: "xyz789"},
	}
	got := Build(finding, Source{}, []changestore.ChangeEvent{change}, now)
	if len(got) != 1 {
		t.Fatalf("want 1 change evidence via LikelyCause, got %d", len(got))
	}
	if got[0].Source != "xyz789" {
		t.Errorf("LikelyCause linkage broken: %+v", got[0])
	}
}

func TestBuild_NilInputs(t *testing.T) {
	got := Build(plugin.Finding{Title: "something"}, Source{}, nil, time.Now())
	if len(got) != 0 {
		t.Errorf("Build with no data should return empty, got %d items", len(got))
	}
}
