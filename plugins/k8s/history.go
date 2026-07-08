package k8s

// history.go — the k8s wiring for the framework's historical-recurrence
// layer (internal/investigate/history.go). The gather logic lives in the
// framework; this file keeps the plugin's public API stable.

import "github.com/exalm-ai/exalm/internal/investigate"

// PastIncident / IncidentHistoryFn are re-exported so cmd/exalm/main.go's
// wiring compiles unchanged.
type (
	PastIncident      = investigate.PastIncident
	IncidentHistoryFn = investigate.IncidentHistoryFn
)

// SetHistorySources wires the optional historical sources into the copilot.
// Safe to call once at startup; nil disables incident history gracefully.
func (p *Plugin) SetHistorySources(incidents IncidentHistoryFn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.incidentHistory = incidents
}
