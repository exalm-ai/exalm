package mcp

// SSE transport: a minimal Server-Sent Events handler that exposes the MCP
// server over HTTP. POST /mcp delivers a request; the response is streamed
// back as a single "event: message" frame. This is enough for the simplest
// MCP-over-SSE clients and keeps the code under 50 lines.
//
// Note: full MCP-over-SSE specifies a separate event-stream for server-to-
// client notifications. This implementation handles request/response only,
// matching the "tools" capability we advertise. Bidirectional streaming
// can be layered on later without breaking the wire format.

import (
	"fmt"
	"io"
	"net/http"
)

// SSEHandler returns an http.Handler that serves MCP requests over SSE.
// Mount it on a single path: mux.Handle("/mcp", mcp.SSEHandler(s)).
func SSEHandler(s *Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		respBytes := s.Handle(body)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		// SSE frame: event name + data line + blank line.
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(respBytes)) //nolint:errcheck // SSE write; client disconnect is harmless
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})
}
