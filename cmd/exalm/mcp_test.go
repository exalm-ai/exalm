package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/internal/mcp"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// A minimal but valid kubeconfig pointing at an address nothing listens on.
// Building a client never dials it (kubernetes.NewForConfig is lazy), so
// wireK8sApplyHandler succeeds; only an actual apply_remediation call would
// reach the network, and 127.0.0.1:1 refuses instantly (no hang, no real
// cluster needed).
const fakeKubeconfigForMCP = `
apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: https://127.0.0.1:1
current-context: test-context
contexts:
- name: test-context
  context:
    cluster: test-cluster
    user: test-user
users:
- name: test-user
  user:
    token: fake-token
`

func writeFakeKubeconfigForMCP(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(fakeKubeconfigForMCP), 0o600); err != nil {
		t.Fatalf("write fake kubeconfig: %v", err)
	}
	return path
}

func applyRemediationVia(srv *mcp.Server, title string) []byte {
	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"apply_remediation","arguments":{"title":"` + title + `"}}}`)
	return srv.Handle(req)
}

func reportWithOneRemediableFinding() plugin.Report {
	return plugin.Report{Findings: []plugin.Finding{
		{Title: "ns/pod", Remediation: &plugin.RemediationAction{Kind: "delete-pod", Namespace: "ns", Name: "pod"}},
	}}
}

func TestWireMCPApplyHandler_ValidKubeconfigWiresARealExecutor(t *testing.T) {
	defer mcp.SetApplyHandler(nil)
	wireMCPApplyHandler(mcpWriteConfig{kubeconfigPath: writeFakeKubeconfigForMCP(t)})

	srv := mcp.NewServer(reportWithOneRemediableFinding(), true)
	resp := decodeMCPResponse(t, applyRemediationVia(srv, "ns/pod"))

	if resp.Error == nil {
		t.Fatal("expected an error — 127.0.0.1:1 refuses connections — but got success")
	}
	if strings.Contains(resp.Error.Message, "not configured") {
		t.Errorf("handler should be wired (a real, if unreachable, executor); got the unconfigured message: %s", resp.Error.Message)
	}
}

func TestWireMCPApplyHandler_NoConfigLeavesApplyUnconfigured(t *testing.T) {
	defer mcp.SetApplyHandler(nil)
	// No kubeconfig and no host → no executor is registered at all.
	wireMCPApplyHandler(mcpWriteConfig{kubeconfigPath: filepath.Join(t.TempDir(), "does-not-exist")})

	srv := mcp.NewServer(reportWithOneRemediableFinding(), true)
	resp := decodeMCPResponse(t, applyRemediationVia(srv, "ns/pod"))

	if resp.Error == nil || !strings.Contains(resp.Error.Message, "not configured") {
		t.Errorf("expected the graceful \"not configured\" message, got: %+v", resp.Error)
	}
}

func TestWireMCPApplyHandler_RoutesSSHKindToHost(t *testing.T) {
	defer mcp.SetApplyHandler(nil)
	// A host is configured but no kubeconfig; an SSH remediation kind must
	// route to the SSH executor (which dials 127.0.0.1:1 and is refused), NOT
	// report "not configured".
	wireMCPApplyHandler(mcpWriteConfig{host: "127.0.0.1", sshPort: 1})

	report := plugin.Report{Findings: []plugin.Finding{
		{Title: "svc/down", Remediation: &plugin.RemediationAction{Kind: "svc-restart-linux", Name: "nginx.service", Shell: "bash"}},
	}}
	srv := mcp.NewServer(report, true)
	resp := decodeMCPResponse(t, applyRemediationVia(srv, "svc/down"))

	if resp.Error == nil {
		t.Fatal("expected a dial error against 127.0.0.1:1")
	}
	if strings.Contains(resp.Error.Message, "not configured") || strings.Contains(resp.Error.Message, "needs an SSH host") {
		t.Errorf("SSH kind should route to the wired SSH executor, got: %s", resp.Error.Message)
	}
}

func decodeMCPResponse(t *testing.T, raw []byte) mcp.JSONRPCResponse {
	t.Helper()
	var r mcp.JSONRPCResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("response not JSON: %v\nraw=%s", err, raw)
	}
	return r
}

func writeReportFile(t *testing.T, r plugin.Report) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write report file: %v", err)
	}
	return path
}

func TestLoadReportFile_ValidReport(t *testing.T) {
	want := plugin.Report{
		Title:   "k8s findings",
		Summary: "1 critical",
		Findings: []plugin.Finding{
			{Title: "prod/api", Severity: plugin.SeverityCritical},
		},
	}
	path := writeReportFile(t, want)

	got, err := loadReportFile(path)
	if err != nil {
		t.Fatalf("loadReportFile: %v", err)
	}
	if got.Title != want.Title || len(got.Findings) != 1 || got.Findings[0].Title != "prod/api" {
		t.Errorf("loadReportFile roundtrip: got %+v", got)
	}
}

func TestLoadReportFile_MissingFile(t *testing.T) {
	if _, err := loadReportFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestLoadReportFile_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}
	_, err := loadReportFile(path)
	if err == nil {
		t.Fatal("expected a JSON parse error")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should name the parse failure, got: %v", err)
	}
}

func TestLoadReportFile_OversizedRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create huge file: %v", err)
	}
	if err := f.Truncate(maxMCPReportFileBytes + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	_, err = loadReportFile(path)
	if err == nil {
		t.Fatal("expected the size-limit error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should explain the size limit, got: %v", err)
	}
}
