package service

import (
	"context"
	"fmt"

	"github.com/exalm-ai/exalm/internal/remediation"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// RemediationService previews and applies the remediation action attached
// to a finding, individually or as an ordered batch. Wraps FindingsService
// for lookup and internal/remediation for the batch-apply policy —
// previously duplicated: internal/mcp's apply_remediation tool re-scanned
// findings inline, and the fix-all ordering lived in a web handler (see
// internal/remediation's own extraction commit).
type RemediationService interface {
	// Preview returns the RemediationAction attached to the named finding.
	// Errors distinguish "finding not found" from "finding has no
	// remediation" — same two failure modes the MCP tool and the /api/fix
	// handlers already surface.
	Preview(title string) (plugin.RemediationAction, error)
	// Apply previews then applies the action for one finding.
	Apply(ctx context.Context, title string) error
	// ApplyAll applies every remediable finding in the current report, in
	// the safe batch order (internal/remediation.OrderForBatch).
	ApplyAll(ctx context.Context) []remediation.Result
}

type findingsRemediationService struct {
	findings  FindingsService
	getReport func() plugin.Report
	applyFn   func(context.Context, plugin.RemediationAction) error
}

// NewRemediationService builds a RemediationService. applyFn may be nil —
// Apply/ApplyAll then report "not configured" per-call rather than panic,
// matching the MCP apply_remediation tool's existing behavior when no
// apply handler was registered at startup.
func NewRemediationService(findings FindingsService, getReport func() plugin.Report, applyFn func(context.Context, plugin.RemediationAction) error) RemediationService {
	return &findingsRemediationService{findings: findings, getReport: getReport, applyFn: applyFn}
}

func (s *findingsRemediationService) Preview(title string) (plugin.RemediationAction, error) {
	f, ok := s.findings.Get(title)
	if !ok {
		return plugin.RemediationAction{}, fmt.Errorf("finding not found: %s", title)
	}
	if f.Remediation == nil {
		return plugin.RemediationAction{}, fmt.Errorf("finding has no remediation: %s", title)
	}
	return *f.Remediation, nil
}

func (s *findingsRemediationService) Apply(ctx context.Context, title string) error {
	action, err := s.Preview(title)
	if err != nil {
		return err
	}
	if s.applyFn == nil {
		return fmt.Errorf("apply handler not configured")
	}
	return s.applyFn(ctx, action)
}

func (s *findingsRemediationService) ApplyAll(ctx context.Context) []remediation.Result {
	if s.applyFn == nil {
		items := remediation.FixableFromReport(s.getReport())
		out := make([]remediation.Result, len(items))
		for i, item := range items {
			out[i] = remediation.Result{Title: item.Title, Error: "apply handler not configured"}
		}
		return out
	}
	items := remediation.OrderForBatch(remediation.FixableFromReport(s.getReport()))
	return remediation.ApplyAll(ctx, items, s.applyFn)
}
