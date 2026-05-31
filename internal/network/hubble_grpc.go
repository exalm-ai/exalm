package network

// hubble_grpc.go — Phase 5: real Hubble Relay gRPC client.
//
// Dependency justification (DEVELOPMENT.md §"Things to NEVER do"):
//   google.golang.org/grpc is the only protocol Hubble Relay exposes;
//   there is no REST alternative. The package is maintained by Google,
//   has a strong security track record, and adds only ~3 net-new transitive
//   dependencies (genproto/rpc) since x/net, x/sys, and protobuf are already
//   present. We do NOT add github.com/cilium/cilium — instead we hand-code
//   the minimal protobuf field mapping using google.golang.org/protobuf/encoding/protowire
//   (already an indirect dep) to avoid pulling in Cilium's entire dep tree.
//
// Proto field numbers are sourced from:
//   api/v1/observer/observer.proto  (GetFlowsRequest, GetFlowsResponse)
//   api/v1/flow/flow.proto          (Flow, Endpoint, Layer4, Layer7)
// These have been stable since Cilium 1.x and are documented at
// https://github.com/cilium/cilium/tree/main/api/v1.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
)

// hubbleGetFlowsMethod is the fully-qualified gRPC method for Hubble Relay.
const hubbleGetFlowsMethod = "/observer.Observer/GetFlows"

// Verdict enum values from flow.proto.
const (
	verdictForwarded = 1
	verdictDropped   = 2
	verdictError     = 3
	verdictAudit     = 4
)

// rawCodec is a gRPC encoding.Codec that passes []byte through unchanged.
// It is applied per-connection via grpc.WithDefaultCallOptions(grpc.ForceCodec(…))
// so it does not affect other gRPC usage in the process.
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("hubble rawCodec: cannot marshal %T, want []byte", v)
	}
	return b, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	p, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("hubble rawCodec: cannot unmarshal into %T, want *[]byte", v)
	}
	*p = make([]byte, len(data))
	copy(*p, data)
	return nil
}

// hubbleGRPCProvider implements FlowProvider over a live Hubble Relay gRPC
// connection. The connection is lazy (established on first RPC call).
type hubbleGRPCProvider struct {
	conn *grpc.ClientConn
}

// Close releases the underlying gRPC connection.
func (h *hubbleGRPCProvider) Close() error { return h.conn.Close() }

// RecentFlows calls Observer.GetFlows on the Hubble Relay endpoint and returns
// flows whose source matches (ns, pod) that occurred in the last [within] window.
// If the Relay is unreachable the returned error causes the k8s analyser to
// omit the network evidence section (graceful degradation).
func (h *hubbleGRPCProvider) RecentFlows(ctx context.Context, ns, pod string, within time.Duration) ([]FlowEvent, error) {
	since := time.Now().Add(-within)
	reqBytes := hubbleEncodeGetFlowsRequest(since)

	stream, err := h.conn.NewStream(ctx,
		&grpc.StreamDesc{ServerStreams: true},
		hubbleGetFlowsMethod,
	)
	if err != nil {
		return nil, fmt.Errorf("hubble: open stream: %w", err)
	}
	if err := stream.SendMsg(reqBytes); err != nil {
		return nil, fmt.Errorf("hubble: send GetFlowsRequest: %w", err)
	}
	if err := stream.CloseSend(); err != nil {
		return nil, fmt.Errorf("hubble: close send: %w", err)
	}

	var flows []FlowEvent
	for {
		var raw []byte
		if err := stream.RecvMsg(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("hubble: recv GetFlowsResponse: %w", err)
		}
		ev, ok := hubbleDecodeFlowsResponse(raw)
		if !ok {
			continue // node_status / lost_events frame — skip
		}
		if ev.Source.Namespace == ns && ev.Source.Pod == pod {
			flows = append(flows, ev)
		}
	}
	return flows, nil
}

// ── Proto encoding ────────────────────────────────────────────────────────────

// hubbleEncodeGetFlowsRequest serialises a minimal GetFlowsRequest.
//
// Field map (observer.proto):
//
//	1 = number  (uint64, 0 → stream until context deadline or since exhausted)
//	7 = since   (google.protobuf.Timestamp sub-message)
func hubbleEncodeGetFlowsRequest(since time.Time) []byte {
	// Encode google.protobuf.Timestamp: field 1 = seconds, field 2 = nanos.
	var ts []byte
	ts = protowire.AppendTag(ts, 1, protowire.VarintType)
	ts = protowire.AppendVarint(ts, uint64(since.Unix())) //nolint:gosec // G115: Unix() is always non-negative
	if ns := since.Nanosecond(); ns != 0 {
		ts = protowire.AppendTag(ts, 2, protowire.VarintType)
		ts = protowire.AppendVarint(ts, uint64(ns)) //nolint:gosec // G115: Nanosecond() is always in [0,999999999]
	}

	var req []byte
	req = protowire.AppendTag(req, 7, protowire.BytesType) // field 7 = since
	req = protowire.AppendBytes(req, ts)
	return req
}

// ── Proto decoding ────────────────────────────────────────────────────────────

// hubbleDecodeFlowsResponse decodes a raw GetFlowsResponse wire frame.
//
// GetFlowsResponse field map (observer.proto):
//
//	1 = flow        (Flow sub-message, oneof)
//	2 = node_status (skip)
//	3 = lost_events (skip)
func hubbleDecodeFlowsResponse(data []byte) (FlowEvent, bool) {
	b := data
	var flowBytes []byte
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType { // flow
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				return FlowEvent{}, false
			}
			b = b[n2:]
			flowBytes = v
		} else {
			n2 := protowire.ConsumeFieldValue(num, typ, b)
			if n2 < 0 {
				return FlowEvent{}, false
			}
			b = b[n2:]
		}
	}
	if flowBytes == nil {
		return FlowEvent{}, false
	}
	return hubbleDecodeFlow(flowBytes)
}

// hubbleDecodeFlow decodes a Flow proto message into a FlowEvent.
//
// Flow field map (flow.proto):
//
//	1  = time            (google.protobuf.Timestamp)
//	5  = verdict         (enum: FORWARDED=1, DROPPED=2, ERROR=3, AUDIT=4)
//	6  = l4              (Layer4 sub-message)
//	8  = source          (Endpoint sub-message)
//	9  = destination     (Endpoint sub-message)
//	10 = l7              (Layer7 sub-message — currently skipped)
//	22 = drop_reason_desc (string)
func hubbleDecodeFlow(data []byte) (FlowEvent, bool) {
	var ev FlowEvent
	b := data
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.BytesType: // time
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				return FlowEvent{}, false
			}
			b = b[n2:]
			ev.Timestamp = hubbleDecodeTimestamp(v)

		case num == 5 && typ == protowire.VarintType: // verdict
			v, n2 := protowire.ConsumeVarint(b)
			if n2 < 0 {
				return FlowEvent{}, false
			}
			b = b[n2:]
			switch v {
			case verdictForwarded:
				ev.Verdict = "FORWARDED"
			case verdictDropped:
				ev.Verdict = "DROPPED"
			case verdictError:
				ev.Verdict = "ERROR"
			case verdictAudit:
				ev.Verdict = "AUDIT"
			default:
				ev.Verdict = "UNKNOWN"
			}

		case num == 6 && typ == protowire.BytesType: // l4
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				return FlowEvent{}, false
			}
			b = b[n2:]
			ev.L4Proto = hubbleDecodeL4Proto(v)

		case num == 8 && typ == protowire.BytesType: // source
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				return FlowEvent{}, false
			}
			b = b[n2:]
			ev.Source = hubbleDecodeEndpoint(v)

		case num == 9 && typ == protowire.BytesType: // destination
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				return FlowEvent{}, false
			}
			b = b[n2:]
			ev.Dest = hubbleDecodeEndpoint(v)

		case num == 22 && typ == protowire.BytesType: // drop_reason_desc
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				return FlowEvent{}, false
			}
			b = b[n2:]
			ev.Reason = string(v)

		default:
			n2 := protowire.ConsumeFieldValue(num, typ, b)
			if n2 < 0 {
				return FlowEvent{}, false
			}
			b = b[n2:]
		}
	}
	if ev.Verdict == "" {
		ev.Verdict = "UNKNOWN"
	}
	return ev, true
}

// hubbleDecodeTimestamp decodes google.protobuf.Timestamp.
// Field 1 = seconds (int64 as varint), field 2 = nanos (int32 as varint).
func hubbleDecodeTimestamp(data []byte) time.Time {
	var secs, nanos int64
	b := data
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.VarintType:
			v, n2 := protowire.ConsumeVarint(b)
			if n2 < 0 {
				return time.Time{}
			}
			b = b[n2:]
			secs = int64(v) //nolint:gosec // G115: proto timestamp seconds; overflow is not a concern here
		case num == 2 && typ == protowire.VarintType:
			v, n2 := protowire.ConsumeVarint(b)
			if n2 < 0 {
				return time.Time{}
			}
			b = b[n2:]
			nanos = int64(v) //nolint:gosec // G115: proto timestamp nanos [0,999999999]; always fits int64
		default:
			n2 := protowire.ConsumeFieldValue(num, typ, b)
			if n2 < 0 {
				return time.Time{}
			}
			b = b[n2:]
		}
	}
	return time.Unix(secs, nanos).UTC()
}

// hubbleDecodeEndpoint decodes a flow.Endpoint proto message.
//
// Endpoint field map:
//
//	3 = namespace (string)
//	5 = pod_name  (string)
func hubbleDecodeEndpoint(data []byte) Endpoint {
	var ep Endpoint
	b := data
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		switch {
		case num == 3 && typ == protowire.BytesType: // namespace
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				return Endpoint{}
			}
			b = b[n2:]
			ep.Namespace = string(v)
		case num == 5 && typ == protowire.BytesType: // pod_name
			v, n2 := protowire.ConsumeBytes(b)
			if n2 < 0 {
				return Endpoint{}
			}
			b = b[n2:]
			ep.Pod = string(v)
		default:
			n2 := protowire.ConsumeFieldValue(num, typ, b)
			if n2 < 0 {
				return Endpoint{}
			}
			b = b[n2:]
		}
	}
	return ep
}

// hubbleDecodeL4Proto reads a Layer4 oneof to identify the transport protocol.
//
// Layer4 oneof field map:
//
//	1 = tcp (TCP sub-message)
//	2 = udp (UDP sub-message)
//	3 = icmpv4
//	4 = icmpv6
func hubbleDecodeL4Proto(data []byte) string {
	b := data
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		n2 := protowire.ConsumeFieldValue(num, typ, b)
		if n2 < 0 {
			break
		}
		b = b[n2:]
		switch num {
		case 1:
			return "TCP"
		case 2:
			return "UDP"
		case 3, 4:
			return "ICMP"
		}
	}
	return ""
}

// dialHubble creates a gRPC client connection to a Hubble Relay endpoint.
// The connection is lazy — the handshake occurs on the first RPC call.
// grpc.ForceCodec(rawCodec{}) installs our raw-bytes codec on this connection
// only; it does not affect other gRPC usage in the process.
func dialHubble(endpoint string) (*grpc.ClientConn, error) {
	return grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
}
