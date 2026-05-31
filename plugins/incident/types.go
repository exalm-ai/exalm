package incident

import (
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Incident represents a single production incident record.
//
// SRE use case: when Exalm detects a critical cluster condition, an incident
// record is opened. Each subsequent `exalm k8s analyze` run during the incident
// appends findings to the Timeline. On resolution, `exalm incident postmortem`
// synthesises the timeline into a structured blameless postmortem document.
type Incident struct {
	// ID is a unique identifier, e.g. "INC-2026-001" or a timestamp string.
	ID     string         `json:"id"`
	Title  string         `json:"title"`
	Status IncidentStatus `json:"status"`
	// Severity is the highest severity finding observed during the incident.
	Severity plugin.Severity `json:"severity"`
	OpenedAt time.Time       `json:"opened_at"`
	ClosedAt *time.Time      `json:"closed_at,omitempty"`
	// Namespace and Service scope the incident to a specific workload (optional).
	Namespace string `json:"namespace,omitempty"`
	Service   string `json:"service,omitempty"`
	// Timeline accumulates events from detection through resolution.
	Timeline []TimelineEntry `json:"timeline,omitempty"`
	// Postmortem is nil until `exalm incident postmortem` is run.
	Postmortem *Postmortem `json:"postmortem,omitempty"`
	// RelatedDeploymentID links this incident to the deployment event that likely
	// caused it (populated via --from-deploy on incident open).
	RelatedDeploymentID string `json:"related_deployment_id,omitempty"`
}

// IncidentStatus tracks where an incident is in its lifecycle.
type IncidentStatus string

const (
	// IncidentOpen is set when the incident is first created.
	IncidentOpen IncidentStatus = "open"
	// IncidentMitigated is set when the immediate impact is reduced but root
	// cause is not yet fully resolved (e.g. rolled back but not fixed).
	IncidentMitigated IncidentStatus = "mitigated"
	// IncidentClosed is set when the incident is fully resolved.
	IncidentClosed IncidentStatus = "closed"
)

// TimelineEntry is one event in the incident timeline.
//
// TODO: auto-populate from k8s watch channel events during `exalm k8s watch`
//
//	by forwarding critical/high findings to the active incident's timeline.
type TimelineEntry struct {
	At    time.Time `json:"at"`
	Event string    `json:"event"` // human-readable description
	// Source identifies who or what added the entry.
	// Examples: "exalm-k8s", "exalm-slo", "user", "alert-webhook".
	Source  string          `json:"source"`
	Finding *plugin.Finding `json:"finding,omitempty"`
	// RelatedChangeID links this entry to a changestore.ChangeEvent ID when the
	// timeline event correlates with a cluster mutation (deploy, RBAC change,
	// config edit). Populated by Phase 4's change-correlation engine.
	//
	// Strength: komodor — "Change timeline: every deploy, config edit, node
	// event, scaling action, RBAC change captured and overlaid on workload state".
	RelatedChangeID string `json:"related_change_id,omitempty"`
}

// Postmortem is the AI-generated incident review document.
//
// TODO: align schema with DORA metrics (lead time to restore, MTTR) once the
//
//	DORA metrics plugin exists. MTTR here is computed from OpenedAt → ClosedAt.
type Postmortem struct {
	GeneratedAt time.Time `json:"generated_at"`
	Summary     string    `json:"summary"`
	// RootCauses lists the primary failure causes identified from the timeline.
	RootCauses []string `json:"root_causes"`
	// ContributingFactors are conditions that worsened the impact or delayed resolution.
	ContributingFactors []string `json:"contributing_factors"`
	Mitigation          string   `json:"mitigation"`
	// ActionItems are follow-up tasks to prevent recurrence.
	ActionItems []string      `json:"action_items"`
	MTTR        time.Duration `json:"mttr_seconds"`
}
