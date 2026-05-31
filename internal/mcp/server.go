// Package mcp implements a Model Context Protocol server exposing Exalm's
// findings, remediation actions, change store, and incident store as
// structured tools that any MCP-compatible LLM agent can call.
//
// Competitive gap:
//   - OpenObserve (HIGH opp #5): "Kubernetes MCP server companion to OO's
//     telemetry MCP server" — OO has an MCP for telemetry but no K8s tools.
//   - Komodor (HIGH opp #1): "MCP server wrapping Komodor's REST API as
//     structured tools" — Komodor has zero MCP layer; integration is
//     REST-only.
//
// Exalm's MCP exposes BOTH telemetry findings AND the remediation action
// surface, enabling closed-loop agentic SRE workflows. Read tools are
// always available; write tools require --mcp-write at server startup
// (the same gate as the CLI --apply flag).
//
// Transport: stdio (default) and SSE on :7434 when --mcp-sse is set.
// Protocol: JSON-RPC 2.0 over MCP framing. No external SDK dependency —
// the message envelope is small enough to hand-roll per DEVELOPMENT.md's
// stdlib-first rule.
//
// MCP methods supported:
//   - initialize       (handshake, returns protocolVersion + serverInfo)
//   - tools/list       (returns the catalogue, with input JSON schemas)
//   - tools/call       (executes a tool by name with arguments)
//   - ping             (lightweight liveness check)
package mcp

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ProtocolVersion is the MCP version this server implements.
// (MCP currently uses date-string versions, e.g. "2024-11-05".)
const ProtocolVersion = "2024-11-05"

// ServerName is reported in initialize responses.
const ServerName = "exalm"

// Server is the MCP server core: it owns the tool catalogue and dispatches
// JSON-RPC requests to handlers. Transports (stdio / SSE) call s.Handle.
type Server struct {
	mu         sync.RWMutex
	report     plugin.Report
	tools      []Tool
	allowWrite bool
}

// Tool describes one MCP tool the server exposes.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// InputSchema is a JSON-schema-shaped map. Stored as raw bytes so we
	// don't need to depend on a schema library.
	InputSchema json.RawMessage `json:"inputSchema"`
	// Handler implements the tool. Read tools have allowWrite=false; write
	// tools must check s.allowWrite themselves and return an error if not set.
	Handler func(s *Server, args json.RawMessage) (interface{}, error) `json:"-"`
	// Write indicates this tool mutates state; the server returns
	// "permission denied" unless --mcp-write was passed at startup.
	Write bool `json:"-"`
}

// NewServer constructs a Server with the default tool catalogue.
// allowWrite gates the mutating tools (apply_remediation, open_incident).
func NewServer(initial plugin.Report, allowWrite bool) *Server {
	s := &Server{
		report:     initial,
		allowWrite: allowWrite,
	}
	s.tools = builtinTools()
	return s
}

// SetReport refreshes the report the read tools query. Useful for watch mode.
func (s *Server) SetReport(r plugin.Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.report = r
}

// getReport returns a snapshot of the current report.
func (s *Server) getReport() plugin.Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.report
}

// JSONRPCRequest is the inbound envelope.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // pass-through, can be int or string
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is the outbound envelope. Either Result or Error is set.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError matches the JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC error codes plus a couple of MCP-specific ones.
const (
	ErrCodeParse            = -32700
	ErrCodeInvalidRequest   = -32600
	ErrCodeMethodNotFound   = -32601
	ErrCodeInvalidParams    = -32602
	ErrCodeInternal         = -32603
	ErrCodePermissionDenied = -32001
)

// Handle dispatches a single JSON-RPC request and returns the response bytes.
// Errors in handling are converted to JSON-RPC error responses, NOT returned
// up — the transport sees only valid JSON-RPC frames.
func (s *Server) Handle(reqBytes []byte) []byte {
	var req JSONRPCRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return mustMarshal(JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &JSONRPCError{Code: ErrCodeParse, Message: err.Error()},
		})
	}
	resp := JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = s.handleInitialize()
	case "ping":
		resp.Result = map[string]string{"status": "ok"}
	case "tools/list":
		resp.Result = s.handleToolsList()
	case "tools/call":
		out, err := s.handleToolsCall(req.Params)
		if err != nil {
			resp.Error = err
		} else {
			resp.Result = out
		}
	default:
		resp.Error = &JSONRPCError{
			Code:    ErrCodeMethodNotFound,
			Message: "method not found: " + req.Method,
		}
	}
	return mustMarshal(resp)
}

func (s *Server) handleInitialize() map[string]interface{} {
	return map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"serverInfo": map[string]string{
			"name":    ServerName,
			"version": "0.2.0",
		},
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{}, // means: tools/list and tools/call are supported
		},
	}
}

func (s *Server) handleToolsList() map[string]interface{} {
	visible := make([]Tool, 0, len(s.tools))
	for _, t := range s.tools {
		if t.Write && !s.allowWrite {
			continue
		}
		visible = append(visible, t)
	}
	return map[string]interface{}{"tools": visible}
}

// toolCallParams is the wire shape of `tools/call` parameters.
type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func (s *Server) handleToolsCall(rawParams json.RawMessage) (interface{}, *JSONRPCError) {
	var p toolCallParams
	if err := json.Unmarshal(rawParams, &p); err != nil {
		return nil, &JSONRPCError{Code: ErrCodeInvalidParams, Message: err.Error()}
	}
	for _, t := range s.tools {
		if t.Name != p.Name {
			continue
		}
		if t.Write && !s.allowWrite {
			return nil, &JSONRPCError{
				Code:    ErrCodePermissionDenied,
				Message: fmt.Sprintf("tool %q requires --mcp-write at server startup", p.Name),
			}
		}
		out, err := t.Handler(s, p.Arguments)
		if err != nil {
			return nil, &JSONRPCError{Code: ErrCodeInternal, Message: err.Error()}
		}
		// MCP wraps tool results in a content array.
		content, _ := json.Marshal(out)
		return map[string]interface{}{
			"content": []map[string]string{
				{"type": "text", "text": string(content)},
			},
			"isError": false,
		}, nil
	}
	return nil, &JSONRPCError{
		Code:    ErrCodeMethodNotFound,
		Message: "no such tool: " + p.Name,
	}
}

func mustMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"marshal failed"}}`)
	}
	return b
}
