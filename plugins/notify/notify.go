// Package notify implements the `exalm notify` plugin, which posts analysis
// reports to webhook endpoints (Slack, Teams, Discord, PagerDuty, or any
// custom HTTP endpoint).
//
// # Standalone usage
//
//	exalm notify webhook --url https://hooks.slack.com/... --file report.json
//	cat report.json | exalm notify webhook --url https://hooks.slack.com/...
//
// # Inline with any analysis (--notify-url persistent flag)
//
//	exalm k8s analyze --notify-url https://hooks.slack.com/...
//	exalm dora report --notify-url https://hooks.slack.com/...
//
// Slack URLs are auto-detected and the payload is formatted as Slack Block Kit.
// All other URLs receive the full JSON report payload.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// defaultClient is reused across Send calls to enable HTTP/1.1 connection
// pooling. Creating a fresh http.Client per call would leak transport
// goroutines and bypass the keep-alive pool.
var defaultClient = &http.Client{Timeout: 10 * time.Second} //nolint:gochecknoglobals

const maxBodyBytes = 5 * 1024 * 1024 // 5 MB — generous for large reports

// Plugin implements plugin.Plugin for the notify domain.
type Plugin struct{}

// New returns a new notify plugin.
func New() *Plugin { return &Plugin{} }

// Name returns "notify".
func (p *Plugin) Name() string { return "notify" }

// Description is shown in the top-level --help.
func (p *Plugin) Description() string {
	return "Post analysis reports to Slack, Teams, or any webhook endpoint"
}

// Mutates returns false: posting a notification is read-only from the system's
// perspective (we never change infrastructure state).
func (p *Plugin) Mutates() bool { return false }

// Subcommands lists the actions this plugin supports.
func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "webhook",
			Description: "POST a report to a webhook URL (Slack, Teams, Discord, custom)",
			Run:         sendWebhook,
		},
	}
}

// sendWebhook is the runner for `exalm notify webhook`.
func sendWebhook(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	url := args.Flags["url"]
	if url == "" {
		return plugin.Report{}, fmt.Errorf("notify webhook: --url is required")
	}

	// Read the JSON report from --file or stdin.
	var data []byte
	var err error
	if f := args.Flags["file"]; f != "" {
		// filepath.Clean removes path traversal sequences; gosec G304 is
		// acceptable here because --file is set by the CLI operator (the
		// same user who runs the process), not by untrusted remote input.
		f = filepath.Clean(f)
		data, err = os.ReadFile(f) //nolint:gosec
		if err != nil {
			return plugin.Report{}, fmt.Errorf("notify webhook: read file: %w", err)
		}
	} else {
		data, err = io.ReadAll(io.LimitReader(args.Stdin, int64(maxBodyBytes)+1)) //nolint:gosec // G115: maxBodyBytes is a positive int constant; always fits int64
		if err != nil {
			return plugin.Report{}, fmt.Errorf("notify webhook: read stdin: %w", err)
		}
		if len(data) == 0 {
			return plugin.Report{}, fmt.Errorf("notify webhook: no input — pipe a report JSON or use --file")
		}
	}
	if int64(len(data)) > int64(maxBodyBytes) { //nolint:gosec // G115: len() and maxBodyBytes are always non-negative
		return plugin.Report{}, fmt.Errorf("notify webhook: input exceeds %d MB limit", maxBodyBytes/(1024*1024))
	}

	// Unmarshal to a report for summary/formatting purposes.
	var report plugin.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return plugin.Report{}, fmt.Errorf("notify webhook: input is not a valid Exalm report JSON: %w", err)
	}

	if err := Send(ctx, url, report); err != nil {
		return plugin.Report{}, fmt.Errorf("notify webhook: %w", err)
	}

	return plugin.Report{
		Title:   "Webhook notification sent",
		Summary: fmt.Sprintf("Posted %q to %s", report.Title, url),
	}, nil
}

// Send posts report to webhookURL. The payload format is auto-detected:
//   - Slack (hooks.slack.com): Slack Block Kit JSON
//   - Everything else: the full Exalm report JSON
//
// Send is exported so other packages (e.g. the CLI persistent-flag path) can
// call it directly without going through the plugin interface.
func Send(ctx context.Context, webhookURL string, report plugin.Report) error {
	// Guard: only http and https schemes are permitted to prevent SSRF via
	// non-HTTP transports (file://, gopher://, etc.).
	parsed, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("webhook URL must use http or https scheme, got %q", parsed.Scheme)
	}

	var payload []byte

	if checkIsSlackURL(webhookURL) {
		payload, err = formatSlack(report)
	} else {
		payload, err = formatGeneric(report)
	}
	if err != nil {
		return fmt.Errorf("format payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payload)) //nolint:gosec // G107: webhookURL is operator-configured webhook destination
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "exalm-notify/1")

	resp, err := defaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST to %s: %w", webhookURL, err) //nolint:staticcheck // ST1005: "POST" is an HTTP method acronym
	}
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST to %s: unexpected status %d", webhookURL, resp.StatusCode) //nolint:staticcheck // ST1005: "POST" is an HTTP method acronym
	}
	return nil
}

// checkIsSlackURL is a package-level variable so tests can override it to
// route Slack-formatted payloads through a local httptest server.
var checkIsSlackURL = isSlackURL

// isSlackURL reports whether rawURL targets the Slack Incoming Webhooks host.
// It parses the URL and compares the host case-insensitively (RFC 3986 §3.2.2)
// to avoid false positives from look-alike hostnames (e.g. myhooks.slack.company.com).
func isSlackURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && strings.EqualFold(u.Host, "hooks.slack.com")
}

// slackPayload is the Slack Block Kit message envelope.
type slackPayload struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks,omitempty"`
}

type slackBlock struct {
	Type string     `json:"type"`
	Text *slackText `json:"text,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// formatSlack builds a Slack Block Kit payload summarising the report.
func formatSlack(r plugin.Report) ([]byte, error) {
	// Header block
	header := fmt.Sprintf("*%s*", r.Title)
	if r.Title == "" {
		header = "*Exalm Report*"
	}

	// Severity summary — info findings are intentionally omitted from the
	// Slack summary to avoid noise; they are still present in the full JSON
	// payload sent to generic webhook endpoints.
	counts := map[plugin.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}

	var severity string
	switch {
	case counts[plugin.SeverityCritical] > 0:
		severity = fmt.Sprintf("🔴 %d critical", counts[plugin.SeverityCritical])
	case counts[plugin.SeverityHigh] > 0:
		severity = fmt.Sprintf("🟠 %d high", counts[plugin.SeverityHigh])
	case counts[plugin.SeverityMedium] > 0:
		severity = fmt.Sprintf("🟡 %d medium", counts[plugin.SeverityMedium])
	default:
		severity = "🟢 no critical/high findings"
	}

	summary := r.Summary
	if summary == "" {
		summary = fmt.Sprintf("%d finding(s)", len(r.Findings))
	}

	body := fmt.Sprintf("%s — %s", severity, summary)

	// Top-3 critical/high findings.
	var topFindings []string
	for _, f := range r.Findings {
		if f.Severity == plugin.SeverityCritical || f.Severity == plugin.SeverityHigh {
			topFindings = append(topFindings, fmt.Sprintf("• [%s] %s", strings.ToUpper(string(f.Severity)), f.Title))
		}
		if len(topFindings) >= 3 {
			break
		}
	}

	text := header + "\n" + body
	if len(topFindings) > 0 {
		text += "\n" + strings.Join(topFindings, "\n")
	}

	p := slackPayload{
		Text: text,
		Blocks: []slackBlock{
			{Type: "section", Text: &slackText{Type: "mrkdwn", Text: text}},
		},
	}
	return json.Marshal(p)
}

// genericPayload wraps a report for non-Slack webhook endpoints.
type genericPayload struct {
	Source    string        `json:"source"`
	Timestamp string        `json:"timestamp"`
	Report    plugin.Report `json:"report"`
}

// formatGeneric wraps the full report in a standard envelope JSON.
func formatGeneric(r plugin.Report) ([]byte, error) {
	p := genericPayload{
		Source:    "exalm",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Report:    r,
	}
	return json.Marshal(p)
}
