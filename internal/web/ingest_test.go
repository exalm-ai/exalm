package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/investigate"
)

func ingestServer() *liveServer {
	return &liveServer{
		sessions:   NewSessionRegistry(),
		ingestAuth: "sekrit",
		profileLookupFn: func(analyzer string) (investigate.Profile, bool) {
			if analyzer != "syslog" {
				return investigate.Profile{}, false
			}
			return investigate.Profile{}, true
		},
		buildHandlersFn: func(_ *investigate.LogSession, _ investigate.Profile) (SessionHandlers, error) {
			return SessionHandlers{
				LogQuery: func(_ context.Context, _ LogQueryRequest) (LogQueryResponse, error) {
					return LogQueryResponse{}, nil
				},
			}, nil
		},
		port: 7433,
	}
}

func snapBody(t *testing.T, analyzer string) []byte {
	t.Helper()
	s := investigate.NewLogSession(analyzer)
	src := s.AddSource(investigate.SourceDesc{Path: "/var/log/syslog"})
	s.Append(investigate.LogEvent{At: time.Now().UTC(), Severity: "err", Unit: "sshd", Message: "boom", Raw: "boom", Source: src})
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func ingestReq(body []byte, secret, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/ingest/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set(IngestHeader, secret)
	}
	if remote != "" {
		req.RemoteAddr = remote
	}
	rec := httptest.NewRecorder()
	return rec
}

func TestIngest_HappyPath(t *testing.T) {
	s := ingestServer()
	rec := ingestReq(snapBody(t, "syslog"), "sekrit", "127.0.0.1:5555")
	req := httptest.NewRequest("POST", "/api/ingest/session", bytes.NewReader(snapBody(t, "syslog")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(IngestHeader, "sekrit")
	req.RemoteAddr = "127.0.0.1:5555"
	s.handleIngestSession(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	ds, ok := s.sessions.Get("syslog")
	if !ok || ds.Session.Len() != 1 {
		t.Errorf("session not registered after ingest: %+v", ds)
	}
}

func TestIngest_Refusals(t *testing.T) {
	s := ingestServer()
	cases := []struct {
		name   string
		secret string
		remote string
		body   []byte
		want   int
	}{
		{"missing secret", "", "127.0.0.1:5555", snapBody(t, "syslog"), 403},
		{"wrong secret", "nope", "127.0.0.1:5555", snapBody(t, "syslog"), 403},
		{"non-loopback peer", "sekrit", "203.0.113.9:4444", snapBody(t, "syslog"), 403},
		{"unknown analyzer", "sekrit", "127.0.0.1:5555", snapBody(t, "ghost"), 422},
		{"garbage body", "sekrit", "127.0.0.1:5555", []byte("{nope"), 400},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("POST", "/api/ingest/session", bytes.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		if tc.secret != "" {
			req.Header.Set(IngestHeader, tc.secret)
		}
		req.RemoteAddr = tc.remote
		rec := httptest.NewRecorder()
		s.handleIngestSession(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: expected %d, got %d: %s", tc.name, tc.want, rec.Code, rec.Body.String())
		}
	}
}

func TestIngest_UnwiredServer503(t *testing.T) {
	s := &liveServer{} // no sessions/secret/closures
	req := httptest.NewRequest("POST", "/api/ingest/session", bytes.NewReader(nil))
	rec := httptest.NewRecorder()
	s.handleIngestSession(rec, req)
	if rec.Code != 503 {
		t.Errorf("expected 503 on a non-hub server, got %d", rec.Code)
	}
}

func TestIngest_ReingestReplaces(t *testing.T) {
	s := ingestServer()
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/api/ingest/session", bytes.NewReader(snapBody(t, "syslog")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(IngestHeader, "sekrit")
		req.RemoteAddr = "127.0.0.1:5555"
		rec := httptest.NewRecorder()
		s.handleIngestSession(rec, req)
		if rec.Code != 200 {
			t.Fatalf("ingest %d failed: %d", i, rec.Code)
		}
	}
	if ids := s.sessions.IDs(); len(ids) != 1 || ids[0] != "syslog" {
		t.Errorf("re-ingest must replace, not duplicate: %v", ids)
	}
}
