package mcp

// Built-in tool catalogue. Each tool is a thin wrapper over internal/service:
// the read tools query a service.FindingsService built from the server's
// live report, and the write tool goes through service.RemediationService
// so the batch-ordering/error-shape policy is defined once, not duplicated
// across MCP, the web /api/fix handlers, and any future REST surface.
//
// Schemas are kept inline as JSON-string literals so this file doesn't need a
// JSON-schema library. They're tested in server_test.go.

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/exalm-ai/exalm/internal/service"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

func builtinTools() []Tool {
	return []Tool{
		{
			Name:        "list_findings",
			Description: "Return the current diagnostic findings, optionally filtered by severity, category, or namespace.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"severity":  {"type": "string", "enum": ["critical","high","medium","low","info"]},
					"category":  {"type": "string"},
					"namespace": {"type": "string"}
				}
			}`),
			Handler: toolListFindings,
		},
		{
			Name:        "get_finding",
			Description: "Return one finding by its title (with full evidence chain and likely cause).",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": { "title": {"type": "string"} },
				"required": ["title"]
			}`),
			Handler: toolGetFinding,
		},
		{
			Name:        "report_summary",
			Description: "Return the report's title, summary, and severity counts.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
			Handler:     toolReportSummary,
		},
		{
			Name:        "list_remediable",
			Description: "Return the subset of findings that have an attached RemediationAction (i.e. can be auto-fixed).",
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
			Handler:     toolListRemediable,
		},
		{
			Name:        "apply_remediation",
			Description: "Apply the RemediationAction attached to a finding. WRITE — requires --mcp-write.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": { "title": {"type": "string"} },
				"required": ["title"]
			}`),
			Handler: toolApplyRemediation,
			Write:   true,
		},
	}
}

// ── Read tools ────────────────────────────────────────────────────────────

func toolListFindings(s *Server, raw json.RawMessage) (interface{}, error) {
	var args struct {
		Severity  string `json:"severity,omitempty"`
		Category  string `json:"category,omitempty"`
		Namespace string `json:"namespace,omitempty"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
	}
	findings := service.NewFindingsService(s.getReport).List(service.FindingsFilter{
		Severity:  args.Severity,
		Category:  args.Category,
		Namespace: args.Namespace,
	})
	return findings, nil
}

func toolGetFinding(s *Server, raw json.RawMessage) (interface{}, error) {
	var args struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	if args.Title == "" {
		return nil, errors.New("title required")
	}
	f, ok := service.NewFindingsService(s.getReport).Get(args.Title)
	if !ok {
		return nil, errors.New("finding not found: " + args.Title)
	}
	return f, nil
}

func toolReportSummary(s *Server, _ json.RawMessage) (interface{}, error) {
	sum := service.NewFindingsService(s.getReport).Summary()
	return map[string]interface{}{
		"title":   sum.Title,
		"summary": sum.Summary,
		"counts":  sum.Counts,
		"total":   sum.Total,
	}, nil
}

func toolListRemediable(s *Server, _ json.RawMessage) (interface{}, error) {
	return service.NewFindingsService(s.getReport).Remediable(), nil
}

// ── Write tools ───────────────────────────────────────────────────────────

// applyHandler is the function the CLI provides to actually execute a fix.
// Set via SetApplyHandler before serving. nil = "not configured" → returns
// error (checked inside applyRemediationFn, which adapts it to the
// service.RemediationService signature).
var applyHandler func(plugin.RemediationAction) error

// SetApplyHandler registers the production remediation executor. Pass nil to
// reset (useful for tests).
func SetApplyHandler(h func(plugin.RemediationAction) error) {
	applyHandler = h
}

// applyRemediationFn adapts the package-level applyHandler (checked fresh on
// every call, so tests can swap it between calls) to the context-taking
// signature service.RemediationService expects.
func applyRemediationFn(_ context.Context, a plugin.RemediationAction) error {
	if applyHandler == nil {
		return errors.New("apply handler not configured at server startup")
	}
	return applyHandler(a)
}

func toolApplyRemediation(s *Server, raw json.RawMessage) (interface{}, error) {
	var args struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	if args.Title == "" {
		return nil, errors.New("title required")
	}
	findings := service.NewFindingsService(s.getReport)
	remediation := service.NewRemediationService(findings, s.getReport, applyRemediationFn)
	if err := remediation.Apply(context.Background(), args.Title); err != nil {
		return nil, err
	}
	return map[string]interface{}{"ok": true, "title": args.Title}, nil
}
