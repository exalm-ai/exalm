package incident

import (
	"context"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// tempStore points the file store at a throwaway directory.
func tempStore(t *testing.T) Store {
	t.Helper()
	IncidentDir = t.TempDir()
	t.Cleanup(func() { IncidentDir = "" })
	return newStore()
}

func TestOpen_CreatesRecordWithScope(t *testing.T) {
	s := tempStore(t)
	inc, err := Open(context.Background(), s, OpenRequest{
		Title:     "checkout 5xx spike",
		Severity:  plugin.SeverityHigh,
		Namespace: "prod",
		Service:   "checkout",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if inc.ID == "" || inc.Status != IncidentOpen {
		t.Errorf("unexpected record: %+v", inc)
	}
	got, err := s.Get(context.Background(), inc.ID)
	if err != nil {
		t.Fatalf("Get after Open: %v", err)
	}
	if got.Namespace != "prod" || got.Service != "checkout" || got.Severity != plugin.SeverityHigh {
		t.Errorf("scope not persisted: %+v", got)
	}
}

func TestOpen_DefaultsSeverityToMedium(t *testing.T) {
	s := tempStore(t)
	inc, err := Open(context.Background(), s, OpenRequest{Title: "t"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if inc.Severity != plugin.SeverityMedium {
		t.Errorf("severity = %q, want medium", inc.Severity)
	}
}

func TestOpen_Validation(t *testing.T) {
	s := tempStore(t)
	cases := []struct {
		name string
		req  OpenRequest
		want string
	}{
		{"empty title", OpenRequest{Title: "  "}, "title is required"},
		{"long title", OpenRequest{Title: strings.Repeat("x", maxTitleLen+1)}, "exceeds"},
		{"bad severity", OpenRequest{Title: "t", Severity: "urgent"}, "unknown severity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Open(context.Background(), s, tc.req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestCloseAndReopen_RoundTrip(t *testing.T) {
	s := tempStore(t)
	inc, err := Open(context.Background(), s, OpenRequest{Title: "t"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	closed, err := Close(context.Background(), s, inc.ID)
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if closed.Status != IncidentClosed || closed.ClosedAt == nil {
		t.Errorf("close did not stick: %+v", closed)
	}

	reopened, err := Reopen(context.Background(), s, inc.ID)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	if reopened.Status != IncidentOpen || reopened.ClosedAt != nil {
		t.Errorf("reopen did not stick: %+v", reopened)
	}
}

func TestCloseAndReopen_UnknownID(t *testing.T) {
	s := tempStore(t)
	if _, err := Close(context.Background(), s, "INC-nope"); err == nil {
		t.Error("Close(unknown id) should error")
	}
	if _, err := Reopen(context.Background(), s, "INC-nope"); err == nil {
		t.Error("Reopen(unknown id) should error")
	}
	if _, err := Close(context.Background(), s, ""); err == nil || !strings.Contains(err.Error(), "id is required") {
		t.Errorf("Close(empty) err = %v", err)
	}
}
