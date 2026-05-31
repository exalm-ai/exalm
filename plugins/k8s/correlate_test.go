package k8s

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/changestore"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func mkStore(t *testing.T) *changestore.Store {
	t.Helper()
	s, err := changestore.Open(filepath.Join(t.TempDir(), "changes.jsonl"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestCorrelate_NoStore(t *testing.T) {
	findings := []plugin.Finding{{Title: "CrashLoopBackOff: ns/api"}}
	got := Correlate(findings, nil, time.Now())
	if got[0].LikelyCause != nil {
		t.Errorf("nil store should leave LikelyCause unset")
	}
}

func TestCorrelate_RecentDeployMatches(t *testing.T) {
	now := time.Now()
	store := mkStore(t)
	_ = store.Append(changestore.ChangeEvent{
		Kind: "Deployment", Namespace: "ns", Name: "api-gateway",
		Action: "updated", Actor: "alice",
		Timestamp: now.Add(-10 * time.Minute),
	})

	findings := []plugin.Finding{
		{Title: "CrashLoopBackOff: ns/api-gateway-7c9b-abc"},
		{Title: "OOMKilled: other-ns/api-gateway-7c9b-abc"}, // wrong NS
		{Title: "Service no endpoints: ns/api-gateway"},
	}
	got := Correlate(findings, store, now)

	if got[0].LikelyCause == nil {
		t.Errorf("finding 0 (matching NS+prefix) should have LikelyCause")
	} else if got[0].LikelyCause.Actor != "alice" {
		t.Errorf("LikelyCause actor wrong: %+v", got[0].LikelyCause)
	}
	if got[1].LikelyCause != nil {
		t.Errorf("finding 1 (wrong NS) should NOT have LikelyCause")
	}
	if got[2].LikelyCause == nil {
		t.Errorf("finding 2 (exact name match) should have LikelyCause")
	}
}

func TestCorrelate_OutsideWindow(t *testing.T) {
	now := time.Now()
	store := mkStore(t)
	_ = store.Append(changestore.ChangeEvent{
		Kind: "Deployment", Namespace: "ns", Name: "api",
		Action: "updated", Timestamp: now.Add(-2 * time.Hour),
	})
	got := Correlate([]plugin.Finding{{Title: "CrashLoopBackOff: ns/api-pod"}}, store, now)
	if got[0].LikelyCause != nil {
		t.Errorf("change outside 30min window should not correlate, got %+v", got[0].LikelyCause)
	}
}

func TestCorrelate_PicksNewest(t *testing.T) {
	now := time.Now()
	store := mkStore(t)
	_ = store.Append(changestore.ChangeEvent{
		Kind: "Deployment", Namespace: "ns", Name: "api",
		Action: "updated", Actor: "old-user",
		Timestamp: now.Add(-20 * time.Minute),
	})
	_ = store.Append(changestore.ChangeEvent{
		Kind: "Deployment", Namespace: "ns", Name: "api",
		Action: "updated", Actor: "new-user",
		Timestamp: now.Add(-3 * time.Minute),
	})
	got := Correlate([]plugin.Finding{{Title: "CrashLoopBackOff: ns/api-xyz"}}, store, now)
	if got[0].LikelyCause == nil {
		t.Fatalf("expected LikelyCause")
	}
	if got[0].LikelyCause.Actor != "new-user" {
		t.Errorf("should pick newest change, got actor=%s", got[0].LikelyCause.Actor)
	}
}

func TestParseResourceFromTitle(t *testing.T) {
	cases := []struct {
		in     string
		wantNs string
		wantNm string
	}{
		{"CrashLoopBackOff: ns1/pod-abc", "ns1", "pod-abc"},
		{"OOMKilled: prod-east/api-xyz", "prod-east", "api-xyz"},
		{"Log db-error in ns/api", "ns", "api"},
		{"Selector mismatch: ns/svc", "ns", "svc"},
		{"Unrelated finding title", "", ""},
		// Don't be fooled by image paths.
		{"Pulling image gcr.io/google-containers/pause", "", ""},
	}
	for _, c := range cases {
		gotNs, gotNm := parseResourceFromTitle(c.in)
		if gotNs != c.wantNs || gotNm != c.wantNm {
			t.Errorf("parseResourceFromTitle(%q)=(%q,%q) want (%q,%q)", c.in, gotNs, gotNm, c.wantNs, c.wantNm)
		}
	}
}
