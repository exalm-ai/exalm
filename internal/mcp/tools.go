package mcp

// Built-in tool catalogue. Each tool is a thin wrapper over an Exalm internal
// API: the read tools query the current Report, the write tools forward to
// handlers registered by the CLI (e.g. ApplyRemediation, the incident store).
//
// Schemas are kept inline as JSON-string literals so this file doesn't need a
// JSON-schema library. They're tested in server_test.go.

import (
	"encoding/json"
	"errors"
	"strings"

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
	r := s.getReport()
	out := make([]plugin.Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if args.Severity != "" && string(f.Severity) != args.Severity {
			continue
		}
		if args.Category != "" && f.Category != args.Category {
			continue
		}
		if args.Namespace != "" && !strings.Contains(f.Title, args.Namespace+"/") {
			continue
		}
		out = append(out, f)
	}
	return out, nil
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
	r := s.getReport()
	for _, f := range r.Findings {
		if f.Title == args.Title {
			return f, nil
		}
	}
	return nil, errors.New("finding not found: " + args.Title)
}

func toolReportSummary(s *Server, _ json.RawMessage) (interface{}, error) {
	r := s.getReport()
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range r.Findings {
		if _, ok := counts[string(f.Severity)]; ok {
			counts[string(f.Severity)]++
		}
	}
	return map[string]interface{}{
		"title":   r.Title,
		"summary": r.Summary,
		"counts":  counts,
		"total":   len(r.Findings),
	}, nil
}

func toolListRemediable(s *Server, _ json.RawMessage) (interface{}, error) {
	r := s.getReport()
	out := make([]plugin.Finding, 0)
	for _, f := range r.Findings {
		if f.Remediation != nil {
			out = append(out, f)
		}
	}
	return out, nil
}

// ── Write tools ───────────────────────────────────────────────────────────

// applyHandler is the function the CLI provides to actually execute a fix.
// Set via SetApplyHandler before serving. nil = "not configured" → returns error.
var applyHandler func(plugin.RemediationAction) error

// SetApplyHandler registers the production remediation executor. Pass nil to
// reset (useful for tests).
func SetApplyHandler(h func(plugin.RemediationAction) error) {
	applyHandler = h
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
	if applyHandler == nil {
		return nil, errors.New("apply handler not configured at server startup")
	}
	r := s.getReport()
	for _, f := range r.Findings {
		if f.Title != args.Title {
			continue
		}
		if f.Remediation == nil {
			return nil, errors.New("finding has no remediation")
		}
		if err := applyHandler(*f.Remediation); err != nil {
			return nil, err
		}
		return map[string]interface{}{"ok": true, "title": args.Title}, nil
	}
	return nil, errors.New("finding not found: " + args.Title)
}
