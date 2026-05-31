package mcp

// Stdio transport: newline-delimited JSON-RPC.
// Each inbound message is a single line of JSON; each outbound message
// likewise. This is the default MCP transport when launched as a child
// process by a client like Claude Desktop.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// ServeStdio reads requests from r line-by-line, dispatches via s.Handle,
// and writes responses to w. Returns when r reaches EOF or w errors.
//
// The bufio.Scanner default buffer is 64KB; we raise it to 1MB to
// accommodate large tool results.
func ServeStdio(s *Server, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	bw := bufio.NewWriter(w)
	defer bw.Flush() //nolint:errcheck

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		resp := s.Handle(line)
		if _, err := bw.Write(resp); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
		if _, err := bw.WriteString("\n"); err != nil {
			return fmt.Errorf("write newline: %w", err)
		}
		if err := bw.Flush(); err != nil {
			return fmt.Errorf("flush: %w", err)
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read: %w", err)
	}
	return nil
}
