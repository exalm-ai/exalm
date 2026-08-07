package web

// ingest.go — POST /api/ingest/session: an analyzer `--open` run hands its
// parsed corpus (investigate.SessionSnapshot) to the running hub instead of
// binding its own server.
//
// Trust model:
//   - Loopback-only: the ingest endpoint refuses any non-local peer.
//   - Shared secret: the hub generates a random per-run secret, stores it at
//     ~/.exalm/hub.json (0600), and requires it in the X-Exalm-Ingest header.
//     A custom header doubles as CSRF protection — browsers cannot send it
//     cross-origin without a CORS preflight, which this server never grants.
//   - Bounded body: snapshots are capped at slightly above the session's own
//     memory cap; RestoreLogSession re-applies the caps regardless.
//   - No credentials: RemoteParams.Password is json:"-", so ingested
//     sessions run without remote SSH diagnostics by construction.

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
)

// maxIngestBody bounds an ingest request: the session byte cap plus slack
// for JSON framing and metadata.
const maxIngestBody = investigate.MaxSessionBytes + (8 << 20)

// IngestHeader carries the hub's per-run shared secret.
const IngestHeader = "X-Exalm-Ingest"

// isLoopbackAddr reports whether the remote address is a loopback peer.
func isLoopbackAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// handleIngestSession serves POST /api/ingest/session.
func (s *liveServer) handleIngestSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sessions == nil || s.ingestAuth == "" || s.buildHandlersFn == nil || s.profileLookupFn == nil {
		http.Error(w, "ingest not available on this server", http.StatusServiceUnavailable)
		return
	}
	if !isLoopbackAddr(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	got := r.Header.Get(IngestHeader)
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.ingestAuth)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	var snap investigate.SessionSnapshot
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxIngestBody))
	if err := dec.Decode(&snap); err != nil {
		http.Error(w, "decode snapshot: "+err.Error(), http.StatusBadRequest)
		return
	}

	profile, ok := s.profileLookupFn(snap.Analyzer)
	if !ok {
		http.Error(w, "unknown analyzer: "+snap.Analyzer, http.StatusUnprocessableEntity)
		return
	}
	session, err := investigate.RestoreLogSession(snap)
	if err != nil {
		http.Error(w, "restore session: "+err.Error(), http.StatusBadRequest)
		return
	}
	handlers, err := s.buildHandlersFn(session, profile)
	if err != nil {
		http.Error(w, "build session handlers: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.sessions.Put(&DashSession{
		Analyzer:    session.Analyzer,
		Session:     session,
		Stats:       session.Stats,
		Handlers:    handlers,
		CollectedAt: session.CollectedAt,
		IngestedAt:  time.Now().UTC(),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"ok":  true,
		"url": fmt.Sprintf("http://localhost:%d/#%s", s.port, session.Analyzer),
	})
}
