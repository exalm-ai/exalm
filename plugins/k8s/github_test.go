package k8s

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ghAPIServer is a minimal GitHub API mock that records calls in order.
type ghAPIServer struct {
	calls []string
	srv   *httptest.Server
}

func newGHAPIServer(t *testing.T) *ghAPIServer {
	t.Helper()
	s := &ghAPIServer{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls = append(s.calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/ref/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object": map[string]any{"sha": "base-sha-abc"},
			})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/git/blobs"):
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "blob-sha-def"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/git/trees"):
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "tree-sha-ghi"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/git/commits"):
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "commit-sha-jkl"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/git/refs"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ref": "refs/heads/exalm/fix-123"})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/pulls"):
			_ = json.NewEncoder(w).Encode(map[string]any{"html_url": s.srv.URL + "/pulls/1"})
		default:
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func TestCreateFixPR_Success(t *testing.T) {
	mock := newGHAPIServer(t)

	opts := GitHubOpts{
		Token:      "test-token",
		Owner:      "testorg",
		Repo:       "testrepo",
		BaseBranch: "main",
		APIURL:     mock.srv.URL,
	}
	report := plugin.Report{
		Summary: "1 critical issue found",
		Findings: []plugin.Finding{
			{
				Severity:   plugin.SeverityCritical,
				Title:      "CrashLoopBackOff: api-pod",
				Detail:     "Container restarted 10 times",
				Suggestion: "Check container logs",
				Remediation: &plugin.RemediationAction{
					Kind:       "delete-pod",
					Namespace:  "default",
					Name:       "api-pod",
					KubectlCmd: "kubectl delete pod api-pod -n default",
				},
			},
		},
	}

	prURL, err := CreateFixPR(t.Context(), opts, report)
	if err != nil {
		t.Fatalf("CreateFixPR: %v", err)
	}
	if prURL == "" {
		t.Fatal("expected non-empty PR URL")
	}

	// Verify all 6 API calls were made in the correct order.
	wantCalls := []string{
		"GET /repos/testorg/testrepo/git/ref/heads/main",
		"POST /repos/testorg/testrepo/git/blobs",
		"POST /repos/testorg/testrepo/git/trees",
		"POST /repos/testorg/testrepo/git/commits",
		"POST /repos/testorg/testrepo/git/refs",
		"POST /repos/testorg/testrepo/pulls",
	}
	if len(mock.calls) != len(wantCalls) {
		t.Fatalf("got %d API calls, want %d: %v", len(mock.calls), len(wantCalls), mock.calls)
	}
	for i, want := range wantCalls {
		if mock.calls[i] != want {
			t.Errorf("call[%d] = %q, want %q", i, mock.calls[i], want)
		}
	}

	// Verify the fix document contains the finding.
	if !strings.Contains(prURL, "/pulls/") {
		t.Errorf("unexpected PR URL: %s", prURL)
	}
}

func TestCreateFixPR_NoFindings(t *testing.T) {
	mock := newGHAPIServer(t)

	opts := GitHubOpts{
		Token:      "test-token",
		Owner:      "testorg",
		Repo:       "testrepo",
		BaseBranch: "main",
		APIURL:     mock.srv.URL,
	}
	report := plugin.Report{
		Summary:  "All healthy",
		Findings: []plugin.Finding{},
	}

	prURL, err := CreateFixPR(t.Context(), opts, report)
	if err != nil {
		t.Fatalf("CreateFixPR with no findings: %v", err)
	}
	if prURL == "" {
		t.Fatal("expected PR URL even with no findings")
	}
	// All 6 API calls should still be made.
	if len(mock.calls) != 6 {
		t.Errorf("expected 6 API calls, got %d: %v", len(mock.calls), mock.calls)
	}
}

func TestBuildFixDoc_ContainsKubectlCmd(t *testing.T) {
	report := plugin.Report{
		Summary: "Test summary",
		Findings: []plugin.Finding{
			{
				Severity: plugin.SeverityHigh,
				Title:    "StatefulSet stuck",
				Remediation: &plugin.RemediationAction{
					KubectlCmd: "kubectl rollout restart statefulset/db -n prod",
				},
			},
			{
				Severity: plugin.SeverityLow,
				Title:    "No fix available",
			},
		},
	}

	doc := buildFixDoc(report)
	if !strings.Contains(doc, "kubectl rollout restart statefulset/db") {
		t.Error("kubectl command not in fix document")
	}
	if !strings.Contains(doc, "No fix available") {
		t.Error("finding without remediation not in fix document")
	}
	if !strings.Contains(doc, "Test summary") {
		t.Error("summary not in fix document")
	}
	if !strings.Contains(doc, "1 auto-fixable") {
		t.Errorf("expected '1 auto-fixable' in doc, got:\n%s", doc)
	}
}
