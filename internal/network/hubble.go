// Package network ingests L4/L7 network flow data from Hubble (Cilium's
// observability layer) and cross-correlates it with Exalm k8s findings so
// network drops, DNS failures, and CNI policy denials show up alongside
// application errors in the same finding.
//
// Competitive gap:
//   - OpenObserve weakness #3: "No eBPF or network-layer visibility: cannot
//     detect TCP retransmits, DNS failures, Cilium policy drops, or inter-pod
//     network flow data." Neither OpenObserve nor Komodor has this layer.
//   - Komodor weakness #3: "No eBPF or network-layer visibility."
//
// This module ships ADAPTER + UNIT TESTS only. Production runtime activation
// requires Cilium + Hubble on the cluster; the adapter degrades gracefully
// when Hubble's gRPC endpoint is unreachable (Dial returns an error and the
// CLI proceeds without network evidence).
//
// The FlowProvider interface lets us inject a mock provider in tests so the
// correlation logic is exercised without a live cluster.
package network

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Endpoint identifies one side of a network flow.
type Endpoint struct {
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	IP        string `json:"ip,omitempty"`
}

// FlowEvent is one L4/L7 packet decision observed by Hubble.
type FlowEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Source    Endpoint  `json:"source"`
	Dest      Endpoint  `json:"dest"`
	L4Proto   string    `json:"l4_proto"`           // "TCP", "UDP", "ICMP"
	L7Proto   string    `json:"l7_proto,omitempty"` // "HTTP", "DNS", "gRPC"
	Verdict   string    `json:"verdict"`            // "FORWARDED", "DROPPED", "ERROR"
	Reason    string    `json:"reason,omitempty"`   // CNI policy name, DNS error, etc.
}

// FlowProvider is the abstraction over a Hubble client. Production uses
// HubbleClient; tests use a fake provider that returns pre-canned flows.
type FlowProvider interface {
	// RecentFlows returns flows touching (ns, pod) in [now-within, now].
	// Implementations must be safe to call concurrently. Returning an empty
	// slice is normal (no recent flows = healthy).
	RecentFlows(ctx context.Context, ns, pod string, within time.Duration) ([]FlowEvent, error)
}

// Client wraps a FlowProvider so callers always go through the same surface.
type Client struct {
	provider FlowProvider
}

// NewClient creates a Client backed by the supplied provider.
func NewClient(p FlowProvider) *Client {
	return &Client{provider: p}
}

// RecentFlows is a thin pass-through; provided so the rest of the code never
// touches the FlowProvider interface directly (eases swapping providers later).
func (c *Client) RecentFlows(ctx context.Context, ns, pod string, within time.Duration) ([]FlowEvent, error) {
	if c == nil || c.provider == nil {
		return nil, errors.New("network: no FlowProvider configured")
	}
	return c.provider.RecentFlows(ctx, ns, pod, within)
}

// Close releases any resources held by the underlying provider (e.g. a gRPC
// connection created by Dial). Callers that receive a *Client from Dial must
// call Close when done to avoid connection leaks.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	type closer interface{ Close() error }
	if cl, ok := c.provider.(closer); ok {
		return cl.Close()
	}
	return nil
}

// Dial returns a Client connected to the Hubble Relay gRPC endpoint.
//
// The underlying gRPC connection is lazy — the TCP handshake happens on the
// first RPC call, not here. If the endpoint is unreachable, RecentFlows will
// return an error and the caller should degrade gracefully (omit network
// evidence rather than aborting the analysis).
//
// TLS: connections use insecure credentials by default (Hubble Relay inside a
// cluster is typically reached on localhost or via a mesh mTLS layer). A
// future flag --hubble-tls can enable TLS.
//
// Proto encoding is handled by hubble_grpc.go using
// google.golang.org/protobuf/encoding/protowire with hand-coded field numbers
// from Hubble's observer.proto / flow.proto. This avoids a dependency on the
// full github.com/cilium/cilium package.
func Dial(endpoint string) (*Client, error) {
	if endpoint == "" {
		return nil, errors.New("network: empty endpoint")
	}
	conn, err := dialHubble(endpoint)
	if err != nil {
		// grpc.NewClient rarely fails (lazy dial), but fall back to a
		// disconnected provider so callers always receive a usable *Client.
		return &Client{provider: &disconnectedProvider{reason: err.Error()}}, nil
	}
	return &Client{provider: &hubbleGRPCProvider{conn: conn}}, nil
}

// disconnectedProvider is a FlowProvider used when Hubble is unavailable.
// It returns a clear error so callers can detect the "not connected" state.
type disconnectedProvider struct{ reason string }

func (d *disconnectedProvider) RecentFlows(_ context.Context, _, _ string, _ time.Duration) ([]FlowEvent, error) {
	if d.reason != "" {
		return nil, fmt.Errorf("hubble: not connected (%s)", d.reason)
	}
	return nil, errors.New("hubble: not connected")
}

// CorrelateDrops returns the subset of flows that represent DROP verdicts,
// sorted newest-first. This is the typical entry point for evidence-chain
// builders: "show me the drops that preceded this crash."
func CorrelateDrops(flows []FlowEvent) []FlowEvent {
	out := make([]FlowEvent, 0, len(flows))
	for _, f := range flows {
		if f.Verdict == "DROPPED" || f.Verdict == "ERROR" {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	return out
}

// SummarizeReason returns a short human-readable line for an individual flow,
// suitable for use as an EvidenceItem excerpt. Example:
//
//	"DROPPED TCP exalm-prod/api → kube-system/coredns:53 (policy-deny)"
func SummarizeReason(f FlowEvent) string {
	src := f.Source.Namespace + "/" + f.Source.Pod
	if f.Source.Pod == "" {
		src = f.Source.IP
	}
	dst := f.Dest.Namespace + "/" + f.Dest.Pod
	if f.Dest.Pod == "" {
		dst = f.Dest.IP
	}
	proto := f.L4Proto
	if f.L7Proto != "" {
		proto = f.L7Proto + "/" + f.L4Proto
	}
	reason := f.Reason
	if reason == "" {
		reason = "no-reason"
	}
	return f.Verdict + " " + proto + " " + src + " → " + dst + " (" + reason + ")"
}
