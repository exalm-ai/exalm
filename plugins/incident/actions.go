package incident

// actions.go — store-level incident lifecycle operations shared by the CLI
// subcommands and the web dashboard's incident actions. Both paths validate
// input here so the rules cannot drift.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// maxTitleLen bounds incident titles; longer input is rejected, not truncated.
const maxTitleLen = 200

// OpenRequest carries the fields for creating a new incident record.
type OpenRequest struct {
	Title     string
	Severity  plugin.Severity // empty => medium
	Namespace string
	Service   string
	// RelatedDeploymentID links the incident to the deployment that likely
	// caused it (the CLI's --from-deploy).
	RelatedDeploymentID string
}

// validSeverities is the closed set accepted for incident records.
var validSeverities = map[plugin.Severity]bool{
	plugin.SeverityInfo:     true,
	plugin.SeverityLow:      true,
	plugin.SeverityMedium:   true,
	plugin.SeverityHigh:     true,
	plugin.SeverityCritical: true,
}

// Open validates req and creates a new open incident in s.
func Open(ctx context.Context, s Store, req OpenRequest) (Incident, error) {
	title := strings.TrimSpace(req.Title)
	if title == "" {
		return Incident{}, fmt.Errorf("open incident: title is required")
	}
	if len(title) > maxTitleLen {
		return Incident{}, fmt.Errorf("open incident: title exceeds %d characters", maxTitleLen)
	}
	sev := req.Severity
	if sev == "" {
		sev = plugin.SeverityMedium
	}
	if !validSeverities[sev] {
		return Incident{}, fmt.Errorf("open incident: unknown severity %q (use critical, high, medium, low, or info)", sev)
	}

	now := time.Now().UTC()
	inc := Incident{
		ID:                  newIncidentID(now),
		Title:               title,
		Status:              IncidentOpen,
		Severity:            sev,
		OpenedAt:            now,
		Namespace:           strings.TrimSpace(req.Namespace),
		Service:             strings.TrimSpace(req.Service),
		RelatedDeploymentID: strings.TrimSpace(req.RelatedDeploymentID),
	}
	if err := s.Create(ctx, inc); err != nil {
		return Incident{}, fmt.Errorf("open incident: %w", err)
	}
	return inc, nil
}

// Close marks the incident closed and returns the updated record.
func Close(ctx context.Context, s Store, id string) (Incident, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Incident{}, fmt.Errorf("close incident: id is required")
	}
	inc, err := s.Get(ctx, id)
	if err != nil {
		return Incident{}, fmt.Errorf("close incident: %w", err)
	}
	now := time.Now().UTC()
	inc.Status = IncidentClosed
	inc.ClosedAt = &now
	if err := s.Update(ctx, inc); err != nil {
		return Incident{}, fmt.Errorf("close incident: %w", err)
	}
	return inc, nil
}

// Reopen returns a closed or mitigated incident to the open state.
func Reopen(ctx context.Context, s Store, id string) (Incident, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Incident{}, fmt.Errorf("reopen incident: id is required")
	}
	inc, err := s.Get(ctx, id)
	if err != nil {
		return Incident{}, fmt.Errorf("reopen incident: %w", err)
	}
	inc.Status = IncidentOpen
	inc.ClosedAt = nil
	if err := s.Update(ctx, inc); err != nil {
		return Incident{}, fmt.Errorf("reopen incident: %w", err)
	}
	return inc, nil
}
