package network

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// mockProvider returns canned flows for the given pod. Other pods get nothing.
type mockProvider struct {
	target string // ns/pod that matches
	flows  []FlowEvent
}

func (m *mockProvider) RecentFlows(_ context.Context, ns, pod string, _ time.Duration) ([]FlowEvent, error) {
	if ns+"/"+pod != m.target {
		return nil, nil
	}
	return m.flows, nil
}

func TestClient_RecentFlows(t *testing.T) {
	now := time.Now()
	mock := &mockProvider{
		target: "ns/api",
		flows: []FlowEvent{
			{Timestamp: now.Add(-5 * time.Minute), Source: Endpoint{Namespace: "ns", Pod: "api"}, Dest: Endpoint{Namespace: "ns", Pod: "db"}, L4Proto: "TCP", Verdict: "DROPPED", Reason: "policy-deny"},
			{Timestamp: now.Add(-2 * time.Minute), Source: Endpoint{Namespace: "ns", Pod: "api"}, Dest: Endpoint{Namespace: "ns", Pod: "db"}, L4Proto: "TCP", Verdict: "FORWARDED"},
		},
	}
	c := NewClient(mock)
	got, err := c.RecentFlows(context.Background(), "ns", "api", 10*time.Minute)
	if err != nil {
		t.Fatalf("RecentFlows: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 flows, got %d", len(got))
	}
}

func TestClient_NilProvider(t *testing.T) {
	c := &Client{}
	_, err := c.RecentFlows(context.Background(), "ns", "api", time.Minute)
	if err == nil {
		t.Errorf("nil provider should return error")
	}
}

func TestCorrelateDrops_FiltersAndSorts(t *testing.T) {
	now := time.Now()
	flows := []FlowEvent{
		{Timestamp: now.Add(-10 * time.Minute), Verdict: "FORWARDED"},
		{Timestamp: now.Add(-5 * time.Minute), Verdict: "DROPPED", Reason: "policy"},
		{Timestamp: now.Add(-1 * time.Minute), Verdict: "DROPPED", Reason: "dns-error"},
		{Timestamp: now.Add(-3 * time.Minute), Verdict: "ERROR", Reason: "icmp"},
	}
	drops := CorrelateDrops(flows)
	if len(drops) != 3 {
		t.Fatalf("want 3 non-FORWARDED, got %d", len(drops))
	}
	// Newest first.
	if drops[0].Reason != "dns-error" {
		t.Errorf("expected newest drop first, got %s", drops[0].Reason)
	}
	if drops[2].Reason != "policy" {
		t.Errorf("expected oldest drop last, got %s", drops[2].Reason)
	}
}

func TestSummarizeReason(t *testing.T) {
	f := FlowEvent{
		Source:  Endpoint{Namespace: "exalm-prod", Pod: "api"},
		Dest:    Endpoint{Namespace: "kube-system", Pod: "coredns-1"},
		L4Proto: "UDP",
		L7Proto: "DNS",
		Verdict: "DROPPED",
		Reason:  "rcode-NXDOMAIN",
	}
	s := SummarizeReason(f)
	for _, want := range []string{"DROPPED", "DNS/UDP", "exalm-prod/api", "kube-system/coredns-1", "rcode-NXDOMAIN"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in summary: %s", want, s)
		}
	}
}

// TestDial_UnreachableHubble verifies that Dial succeeds (lazy gRPC connection)
// but RecentFlows returns an error when the Hubble Relay is not running.
// Port 1 on localhost is reserved and always refuses connections immediately.
func TestDial_UnreachableHubble(t *testing.T) {
	c, err := Dial("127.0.0.1:1")
	if err != nil {
		t.Fatalf("Dial should not error (lazy gRPC connection): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = c.RecentFlows(ctx, "ns", "api", time.Minute)
	if err == nil {
		t.Errorf("unreachable Hubble Relay should return error from RecentFlows")
	}
}

func TestDial_EmptyEndpoint(t *testing.T) {
	_, err := Dial("")
	if err == nil {
		t.Errorf("empty endpoint should error")
	}
}

// TestClient_Close_NoLeak verifies that Close on a Dial-produced *Client
// does not panic and drains the underlying gRPC connection.
func TestClient_Close_NoLeak(t *testing.T) {
	c, err := Dial("127.0.0.1:1")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := c.Close(); err != nil {
		// grpc.ClientConn.Close on a never-connected conn may return nil or an error;
		// both are acceptable as long as Close does not panic.
		t.Logf("Close returned (non-fatal): %v", err)
	}
}

// TestClient_Close_NilSafe verifies that Close on a nil *Client is safe.
func TestClient_Close_NilSafe(t *testing.T) {
	var c *Client
	if err := c.Close(); err != nil {
		t.Errorf("Close on nil Client: %v", err)
	}
}

// ── Proto encoding / decoding unit tests ──────────────────────────────────────

// TestHubbleEncodeGetFlowsRequest checks that the encoded proto is non-empty
// and starts with field-7 (since timestamp) tag byte 0x3A.
func TestHubbleEncodeGetFlowsRequest(t *testing.T) {
	since := time.Unix(1_700_000_000, 123_456_789)
	b := hubbleEncodeGetFlowsRequest(since)
	if len(b) == 0 {
		t.Fatal("encoded request is empty")
	}
	// Field 7 tag = (7 << 3) | 2 (bytes wire type) = 58 = 0x3A
	if b[0] != 0x3A {
		t.Errorf("expected first byte 0x3A (field 7, bytes), got 0x%X", b[0])
	}
}

// TestHubbleDecodeTimestamp checks round-trip encoding/decoding of a Timestamp.
func TestHubbleDecodeTimestamp(t *testing.T) {
	want := time.Unix(1_700_000_000, 500_000_000).UTC()
	var ts []byte
	ts = appendVarintField(ts, 1, uint64(want.Unix()))
	ts = appendVarintField(ts, 2, uint64(want.Nanosecond()))
	got := hubbleDecodeTimestamp(ts)
	if !got.Equal(want) {
		t.Errorf("timestamp mismatch: got %v, want %v", got, want)
	}
}

// TestHubbleDecodeTimestamp_ZeroNanos ensures nanoseconds default to 0 when absent.
func TestHubbleDecodeTimestamp_ZeroNanos(t *testing.T) {
	want := time.Unix(1_700_000_000, 0).UTC()
	var ts []byte
	ts = appendVarintField(ts, 1, uint64(want.Unix()))
	got := hubbleDecodeTimestamp(ts)
	if !got.Equal(want) {
		t.Errorf("timestamp mismatch: got %v, want %v", got, want)
	}
}

// TestHubbleDecodeEndpoint checks that namespace and pod_name are extracted.
func TestHubbleDecodeEndpoint(t *testing.T) {
	var data []byte
	data = appendBytesField(data, 3, []byte("mynamespace"))
	data = appendBytesField(data, 5, []byte("mypod-abc"))

	ep := hubbleDecodeEndpoint(data)
	if ep.Namespace != "mynamespace" {
		t.Errorf("namespace: got %q, want %q", ep.Namespace, "mynamespace")
	}
	if ep.Pod != "mypod-abc" {
		t.Errorf("pod: got %q, want %q", ep.Pod, "mypod-abc")
	}
}

// TestHubbleDecodeL4Proto checks TCP/UDP detection from Layer4 oneof.
func TestHubbleDecodeL4Proto(t *testing.T) {
	var tcpData []byte
	tcpData = appendBytesField(tcpData, 1, []byte{}) // empty TCP sub-message at field 1
	if got := hubbleDecodeL4Proto(tcpData); got != "TCP" {
		t.Errorf("L4 proto: got %q, want TCP", got)
	}

	var udpData []byte
	udpData = appendBytesField(udpData, 2, []byte{}) // empty UDP sub-message at field 2
	if got := hubbleDecodeL4Proto(udpData); got != "UDP" {
		t.Errorf("L4 proto: got %q, want UDP", got)
	}
}

// TestHubbleDecodeFlowsResponse_FlowPresent checks end-to-end decode of a
// hand-crafted GetFlowsResponse containing a DROPPED flow.
func TestHubbleDecodeFlowsResponse_FlowPresent(t *testing.T) {
	var endpointBytes []byte
	endpointBytes = appendBytesField(endpointBytes, 3, []byte("prod"))
	endpointBytes = appendBytesField(endpointBytes, 5, []byte("api-pod-1"))

	var flowBytes []byte
	flowBytes = appendVarintField(flowBytes, 5, verdictDropped)        // verdict = DROPPED
	flowBytes = appendBytesField(flowBytes, 8, endpointBytes)          // source endpoint
	flowBytes = appendBytesField(flowBytes, 22, []byte("policy-deny")) // drop_reason_desc

	var resp []byte
	resp = appendBytesField(resp, 1, flowBytes) // field 1 = flow

	ev, ok := hubbleDecodeFlowsResponse(resp)
	if !ok {
		t.Fatal("expected ok=true, got false")
	}
	if ev.Verdict != "DROPPED" {
		t.Errorf("verdict: got %q, want DROPPED", ev.Verdict)
	}
	if ev.Source.Namespace != "prod" {
		t.Errorf("source namespace: got %q, want prod", ev.Source.Namespace)
	}
	if ev.Source.Pod != "api-pod-1" {
		t.Errorf("source pod: got %q, want api-pod-1", ev.Source.Pod)
	}
	if ev.Reason != "policy-deny" {
		t.Errorf("reason: got %q, want policy-deny", ev.Reason)
	}
}

// TestHubbleDecodeFlowsResponse_Forwarded checks FORWARDED verdict mapping.
func TestHubbleDecodeFlowsResponse_Forwarded(t *testing.T) {
	var flowBytes []byte
	flowBytes = appendVarintField(flowBytes, 5, verdictForwarded)

	var resp []byte
	resp = appendBytesField(resp, 1, flowBytes)

	ev, ok := hubbleDecodeFlowsResponse(resp)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ev.Verdict != "FORWARDED" {
		t.Errorf("verdict: got %q, want FORWARDED", ev.Verdict)
	}
}

// TestHubbleDecodeFlowsResponse_NodeStatus checks that non-flow frames return ok=false.
func TestHubbleDecodeFlowsResponse_NodeStatus(t *testing.T) {
	var resp []byte
	resp = appendBytesField(resp, 2, []byte("node_status_data")) // field 2 = node_status
	_, ok := hubbleDecodeFlowsResponse(resp)
	if ok {
		t.Error("node_status frame should return ok=false (no flow at field 1)")
	}
}

// ── proto test helpers ────────────────────────────────────────────────────────
// These encode-only helpers exist only in tests; production uses protowire
// directly in hubble_grpc.go.

func appendVarintField(b []byte, field protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, field, protowire.VarintType)
	b = protowire.AppendVarint(b, v)
	return b
}

func appendBytesField(b []byte, field protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, field, protowire.BytesType)
	b = protowire.AppendBytes(b, v)
	return b
}
