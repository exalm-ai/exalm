package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func sampleReport() plugin.Report {
	return plugin.Report{
		Title:   "Test report",
		Summary: "1 critical, 1 high",
		Findings: []plugin.Finding{
			{
				Severity: plugin.SeverityCritical,
				Category: "Pods",
				Title:    "CrashLoopBackOff: ns/api-pod",
				Detail:   "22 restarts in 10 minutes",
				Remediation: &plugin.RemediationAction{
					Kind:       "delete-pod",
					Namespace:  "ns",
					Resource:   "pod",
					Name:       "api-pod",
					KubectlCmd: "kubectl delete pod -n ns api-pod",
				},
			},
			{
				Severity: plugin.SeverityHigh,
				Category: "SLO",
				Title:    "Burn-rate page: checkout-api",
				Detail:   "1h burn rate 20x",
			},
		},
	}
}

func decodeResp(t *testing.T, raw []byte) JSONRPCResponse {
	t.Helper()
	var r JSONRPCResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("response not JSON: %v\nraw=%s", err, raw)
	}
	return r
}

func TestInitialize(t *testing.T) {
	s := NewServer(sampleReport(), false)
	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	resp := decodeResp(t, s.Handle(req))
	if resp.Error != nil {
		t.Fatalf("initialize error: %+v", resp.Error)
	}
	m, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result not map: %T", resp.Result)
	}
	if m["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion=%v want %s", m["protocolVersion"], ProtocolVersion)
	}
}

func TestToolsList_HidesWriteToolsWhenReadOnly(t *testing.T) {
	s := NewServer(sampleReport(), false) // read-only
	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	resp := decodeResp(t, s.Handle(req))
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	listMap, _ := resp.Result.(map[string]interface{})
	tools, _ := listMap["tools"].([]interface{})
	for _, raw := range tools {
		tm, _ := raw.(map[string]interface{})
		if tm["name"] == "apply_remediation" {
			t.Errorf("apply_remediation should not be listed in read-only mode")
		}
	}
}

func TestToolsList_ShowsWriteToolsWhenAllowed(t *testing.T) {
	s := NewServer(sampleReport(), true)
	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	resp := decodeResp(t, s.Handle(req))
	listMap, _ := resp.Result.(map[string]interface{})
	tools, _ := listMap["tools"].([]interface{})
	found := false
	for _, raw := range tools {
		if tm, ok := raw.(map[string]interface{}); ok && tm["name"] == "apply_remediation" {
			found = true
		}
	}
	if !found {
		t.Errorf("apply_remediation should be listed when allowWrite=true")
	}
}

func TestToolCall_ListFindings(t *testing.T) {
	s := NewServer(sampleReport(), false)
	req := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_findings","arguments":{"severity":"critical"}}}`)
	resp := decodeResp(t, s.Handle(req))
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	m, _ := resp.Result.(map[string]interface{})
	content, _ := m["content"].([]interface{})
	textMap, _ := content[0].(map[string]interface{})
	text, _ := textMap["text"].(string)
	if !strings.Contains(text, "CrashLoopBackOff") || strings.Contains(text, "Burn-rate") {
		t.Errorf("severity filter failed; text=%s", text)
	}
}

func TestToolCall_GetFinding(t *testing.T) {
	s := NewServer(sampleReport(), false)
	req := []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_finding","arguments":{"title":"CrashLoopBackOff: ns/api-pod"}}}`)
	resp := decodeResp(t, s.Handle(req))
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
}

func TestToolCall_ApplyRemediation_RequiresWrite(t *testing.T) {
	s := NewServer(sampleReport(), false) // read-only
	req := []byte(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"apply_remediation","arguments":{"title":"CrashLoopBackOff: ns/api-pod"}}}`)
	resp := decodeResp(t, s.Handle(req))
	if resp.Error == nil {
		t.Fatalf("expected permission denied error")
	}
	if resp.Error.Code != ErrCodePermissionDenied {
		t.Errorf("got code %d want %d", resp.Error.Code, ErrCodePermissionDenied)
	}
}

func TestToolCall_ApplyRemediation_RunsHandler(t *testing.T) {
	defer SetApplyHandler(nil)
	calledWith := plugin.RemediationAction{}
	SetApplyHandler(func(a plugin.RemediationAction) error {
		calledWith = a
		return nil
	})

	s := NewServer(sampleReport(), true)
	req := []byte(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"apply_remediation","arguments":{"title":"CrashLoopBackOff: ns/api-pod"}}}`)
	resp := decodeResp(t, s.Handle(req))
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	if calledWith.Kind != "delete-pod" {
		t.Errorf("apply handler not invoked with the right action: %+v", calledWith)
	}
}

func TestMethodNotFound(t *testing.T) {
	s := NewServer(sampleReport(), false)
	req := []byte(`{"jsonrpc":"2.0","id":99,"method":"unknown/method"}`)
	resp := decodeResp(t, s.Handle(req))
	if resp.Error == nil || resp.Error.Code != ErrCodeMethodNotFound {
		t.Errorf("want method-not-found, got %+v", resp.Error)
	}
}

func TestServeStdio_RoundTrip(t *testing.T) {
	s := NewServer(sampleReport(), false)
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	var out bytes.Buffer
	if err := ServeStdio(s, in, &out); err != nil {
		t.Fatalf("ServeStdio: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 responses, got %d: %s", len(lines), out.String())
	}
	var pingResp JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[0]), &pingResp); err != nil {
		t.Fatalf("ping not JSON: %v", err)
	}
	pm, _ := pingResp.Result.(map[string]interface{})
	if pm["status"] != "ok" {
		t.Errorf("ping result %v", pingResp.Result)
	}
}
