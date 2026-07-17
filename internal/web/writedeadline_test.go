package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestExtendWriteDeadline_OutlivesServerWriteTimeout reproduces the "empty
// reply from server" failure: a chat turn whose LLM inference exceeds the
// global 30s WriteTimeout had its connection killed mid-handler. A handler
// that extends its own deadline must survive a response slower than the
// server-wide timeout.
func TestExtendWriteDeadline_OutlivesServerWriteTimeout(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extendWriteDeadline(w, 5*time.Second)
		time.Sleep(500 * time.Millisecond) // "inference" slower than the server timeout
		w.Write([]byte("ok"))              //nolint:errcheck
	}))
	srv.Config.WriteTimeout = 200 * time.Millisecond
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed — write deadline was not extended: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body: %q", body)
	}
}

// TestExtendWriteDeadline_ToleratesRecorder pins the best-effort contract:
// httptest.ResponseRecorder does not support deadlines, and the helper must
// not panic or fail the request because of that.
func TestExtendWriteDeadline_ToleratesRecorder(t *testing.T) {
	rr := httptest.NewRecorder()
	extendWriteDeadline(rr, time.Minute) // must not panic
}
