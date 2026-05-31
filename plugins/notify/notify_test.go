package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ── isSlackURL ───────────────────────────────────────────────────────────────

func TestIsSlackURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://hooks.slack.com/services/T000/B000/xxxx", true},
		{"https://hooks.slack.com/workflows/xxxx", true},
		// url.Parse lowercases the host, so mixed-case host is accepted.
		{"https://HOOKS.SLACK.COM/services/T000/B000/xxxx", true},
		{"https://discord.com/api/webhooks/000/xxxx", false},
		{"https://outlook.office.com/webhook/xxxx", false},
		// Exact host match — subdomain/superdomain variants must not match.
		{"https://myhooks.slack.company.com/services/T000", false},
		{"https://api.hooks.slack.com/services/T000", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isSlackURL(tc.url)
		if got != tc.want {
			t.Errorf("isSlackURL(%q): got %v, want %v", tc.url, got, tc.want)
		}
	}
}

// ── formatSlack ──────────────────────────────────────────────────────────────

func TestFormatSlack_EmptyReport(t *testing.T) {
	r := plugin.Report{}
	data, err := formatSlack(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var p slackPayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !strings.Contains(p.Text, "Exalm Report") {
		t.Errorf("expected default title in text, got: %q", p.Text)
	}
	if !strings.Contains(p.Text, "🟢") {
		t.Errorf("expected green emoji for no findings, got: %q", p.Text)
	}
	if len(p.Blocks) == 0 {
		t.Error("expected at least one block")
	}
}

func TestFormatSlack_CriticalFindings(t *testing.T) {
	r := plugin.Report{
		Title:   "Prod Alert",
		Summary: "Two pods crashed",
		Findings: []plugin.Finding{
			{Severity: plugin.SeverityCritical, Title: "OOMKilled: api-server"},
			{Severity: plugin.SeverityCritical, Title: "CrashLoop: worker"},
			{Severity: plugin.SeverityHigh, Title: "High CPU: db-proxy"},
			{Severity: plugin.SeverityMedium, Title: "Slow query detected"},
		},
	}
	data, err := formatSlack(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var p slackPayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Should show red emoji for critical severity.
	if !strings.Contains(p.Text, "🔴") {
		t.Errorf("expected red emoji for critical findings, got: %q", p.Text)
	}
	// Should include count.
	if !strings.Contains(p.Text, "2 critical") {
		t.Errorf("expected '2 critical' in text, got: %q", p.Text)
	}
	// Should include title header.
	if !strings.Contains(p.Text, "*Prod Alert*") {
		t.Errorf("expected bold title, got: %q", p.Text)
	}
	// Should include top findings (at most 3: 2 critical + 1 high = 3).
	if !strings.Contains(p.Text, "OOMKilled: api-server") {
		t.Errorf("expected first critical finding in text, got: %q", p.Text)
	}
	if !strings.Contains(p.Text, "CrashLoop: worker") {
		t.Errorf("expected second critical finding in text, got: %q", p.Text)
	}
	if !strings.Contains(p.Text, "High CPU: db-proxy") {
		t.Errorf("expected high-severity finding in text, got: %q", p.Text)
	}
	// Medium finding is the 4th — should NOT appear (top-3 cap).
	if strings.Contains(p.Text, "Slow query") {
		t.Errorf("medium finding should not appear in top-3, got: %q", p.Text)
	}
}

func TestFormatSlack_HighOnlySeverity(t *testing.T) {
	r := plugin.Report{
		Findings: []plugin.Finding{
			{Severity: plugin.SeverityHigh, Title: "Disk almost full"},
		},
	}
	data, err := formatSlack(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), "🟠") {
		t.Errorf("expected orange emoji for high findings, got: %s", string(data))
	}
}

func TestFormatSlack_MediumOnlySeverity(t *testing.T) {
	r := plugin.Report{
		Findings: []plugin.Finding{
			{Severity: plugin.SeverityMedium, Title: "High p99 latency"},
		},
	}
	data, err := formatSlack(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(data), "🟡") {
		t.Errorf("expected yellow emoji for medium findings, got: %s", string(data))
	}
}

// ── formatGeneric ─────────────────────────────────────────────────────────────

func TestFormatGeneric(t *testing.T) {
	r := plugin.Report{
		Title:   "DORA Report",
		Summary: "Deployment frequency is elite",
		Findings: []plugin.Finding{
			{Severity: plugin.SeverityInfo, Title: "Lead time < 1 hour"},
		},
	}
	data, err := formatGeneric(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var p genericPayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if p.Source != "exalm" {
		t.Errorf("source: got %q, want %q", p.Source, "exalm")
	}
	if p.Timestamp == "" {
		t.Error("timestamp should not be empty")
	}
	if p.Report.Title != r.Title {
		t.Errorf("report.title: got %q, want %q", p.Report.Title, r.Title)
	}
	if len(p.Report.Findings) != 1 {
		t.Errorf("report.findings: got %d, want 1", len(p.Report.Findings))
	}
}

// ── Send ──────────────────────────────────────────────────────────────────────

func TestSend_GenericEndpoint_Success(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %q", ct)
		}
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := plugin.Report{Title: "Test", Summary: "ok", Findings: []plugin.Finding{
		{Severity: plugin.SeverityHigh, Title: "Something broke"},
	}}
	if err := Send(context.Background(), srv.URL, r); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if len(received) == 0 {
		t.Fatal("server received no body")
	}
	var p genericPayload
	if err := json.Unmarshal(received, &p); err != nil {
		t.Fatalf("server received invalid JSON: %v", err)
	}
	if p.Report.Title != "Test" {
		t.Errorf("payload report title: got %q, want %q", p.Report.Title, "Test")
	}
}

// TestSend_SlackBranch_Success verifies that Send uses Block Kit formatting
// (not the generic envelope) when checkIsSlackURL returns true. It overrides
// checkIsSlackURL to route the call through a local httptest.Server.
func TestSend_SlackBranch_Success(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Override the Slack detector so Send thinks the test server is Slack.
	prev := checkIsSlackURL
	checkIsSlackURL = func(string) bool { return true }
	defer func() { checkIsSlackURL = prev }()

	r := plugin.Report{Title: "Slack Alert", Findings: []plugin.Finding{
		{Severity: plugin.SeverityCritical, Title: "Pod crashed"},
	}}
	if err := Send(context.Background(), srv.URL, r); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if len(received) == 0 {
		t.Fatal("server received no body")
	}

	// Body should be a Slack Block Kit payload (has "blocks" field), NOT the
	// generic envelope (which has "source" and "report" fields).
	var p slackPayload
	if err := json.Unmarshal(received, &p); err != nil {
		t.Fatalf("server received invalid JSON: %v", err)
	}
	if p.Text == "" {
		t.Error("Slack payload text should not be empty")
	}
	if len(p.Blocks) == 0 {
		t.Error("Slack payload should have at least one block")
	}
	if !strings.Contains(p.Text, "Slack Alert") {
		t.Errorf("Slack payload should contain report title, got: %q", p.Text)
	}
	// Verify it is NOT the generic envelope (which would have "source" field).
	if strings.Contains(string(received), `"source"`) {
		t.Error("Slack branch should not produce a generic envelope payload")
	}
}

func TestSend_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	r := plugin.Report{Title: "Test"}
	err := Send(context.Background(), srv.URL, r)
	if err == nil {
		t.Fatal("expected error for non-2xx response, got nil")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

func TestSend_InvalidScheme(t *testing.T) {
	cases := []string{
		"file:///etc/passwd",
		"gopher://example.com/1",
		"ftp://example.com/report",
		"",
	}
	for _, u := range cases {
		err := Send(context.Background(), u, plugin.Report{Title: "Test"})
		if err == nil {
			t.Errorf("expected error for scheme in URL %q, got nil", u)
		}
	}
}

func TestSend_ContextCancelled(t *testing.T) {
	// Server that never responds — cancelled context should fail fast.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Never write; but the context will be cancelled by the caller.
		select {}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	r := plugin.Report{Title: "Test"}
	err := Send(ctx, srv.URL, r)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

// ── sendWebhook (the plugin.Subcommand.Run function) ─────────────────────────

func TestSendWebhook_MissingURL(t *testing.T) {
	_, err := sendWebhook(context.Background(), plugin.RunArgs{
		Stdin: strings.NewReader(""),
		Flags: map[string]string{},
	})
	if err == nil {
		t.Fatal("expected error when --url is missing, got nil")
	}
	if !strings.Contains(err.Error(), "--url is required") {
		t.Errorf("error should mention --url, got: %v", err)
	}
}

func TestSendWebhook_EmptyStdin(t *testing.T) {
	_, err := sendWebhook(context.Background(), plugin.RunArgs{
		Stdin: strings.NewReader(""),
		Flags: map[string]string{"url": "https://example.com/hook"},
	})
	if err == nil {
		t.Fatal("expected error for empty stdin, got nil")
	}
	if !strings.Contains(err.Error(), "no input") {
		t.Errorf("error should mention no input, got: %v", err)
	}
}

func TestSendWebhook_InvalidJSON(t *testing.T) {
	_, err := sendWebhook(context.Background(), plugin.RunArgs{
		Stdin: strings.NewReader("{not valid json}"),
		Flags: map[string]string{"url": "https://example.com/hook"},
	})
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "not a valid Exalm report JSON") {
		t.Errorf("expected JSON validation error, got: %v", err)
	}
}

func TestSendWebhook_FromStdin_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report := plugin.Report{Title: "K8s Analysis", Summary: "All clear"}
	reportJSON, _ := json.Marshal(report)

	result, err := sendWebhook(context.Background(), plugin.RunArgs{
		Stdin: bytes.NewReader(reportJSON),
		Flags: map[string]string{"url": srv.URL},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Title != "Webhook notification sent" {
		t.Errorf("result title: got %q", result.Title)
	}
	if !strings.Contains(result.Summary, "K8s Analysis") {
		t.Errorf("result summary should mention report title, got: %q", result.Summary)
	}
}

func TestSendWebhook_FromFile_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report := plugin.Report{Title: "DORA Report", Summary: "Elite performer"}
	reportJSON, _ := json.Marshal(report)

	// Write report to a temp file.
	f, err := os.CreateTemp(t.TempDir(), "report-*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(reportJSON); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()

	result, err := sendWebhook(context.Background(), plugin.RunArgs{
		Stdin: strings.NewReader(""), // stdin not used when --file is set
		Flags: map[string]string{"url": srv.URL, "file": f.Name()},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Summary, "DORA Report") {
		t.Errorf("result summary should mention report title, got: %q", result.Summary)
	}
}

func TestSendWebhook_FromFile_NotFound(t *testing.T) {
	_, err := sendWebhook(context.Background(), plugin.RunArgs{
		Stdin: strings.NewReader(""),
		Flags: map[string]string{
			"url":  "https://example.com/hook",
			"file": "/nonexistent/report.json",
		},
	})
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "read file") {
		t.Errorf("error should mention read file, got: %v", err)
	}
}

func TestSendWebhook_ExceedsSizeLimit(t *testing.T) {
	// Construct a payload just over the 5 MB limit.
	oversized := make([]byte, maxBodyBytes+2)
	for i := range oversized {
		oversized[i] = 'x'
	}
	// Wrap in a valid-looking JSON structure so the limit check triggers first.
	payload := append([]byte(`{"title":"t","summary":"s","raw":"`), oversized...)
	payload = append(payload, '"', '}')

	_, err := sendWebhook(context.Background(), plugin.RunArgs{
		Stdin: bytes.NewReader(payload),
		Flags: map[string]string{"url": "https://example.com/hook"},
	})
	if err == nil {
		t.Fatal("expected error for oversized input, got nil")
	}
	if !strings.Contains(err.Error(), "MB limit") {
		t.Errorf("error should mention MB limit, got: %v", err)
	}
}
