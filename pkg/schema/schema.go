// Package schema defines the canonical telemetry schema for Exalm findings,
// reports, and remediations. This is the stable public API surface — types
// here are versioned and backward-compatible across minor releases.
//
// Schema version: v0 (Phase 1). Breaking changes require a new sub-package
// (schema/v1/) per Go module conventions.
//
// External consumers should import this package, not pkg/plugin directly.
package schema

import "github.com/exalm-ai/exalm/pkg/plugin"

// Version is the current schema version string embedded in exported data.
const Version = "v0"

// Type aliases — identical at the type level to plugin types, exposed here
// as the stable public surface.
type (
	Finding           = plugin.Finding
	Report            = plugin.Report
	RemediationAction = plugin.RemediationAction
	EvidenceItem      = plugin.EvidenceItem
	ChangeRef         = plugin.ChangeRef
	Severity          = plugin.Severity
)

// Severity constants re-exported for convenience.
const (
	SeverityInfo     = plugin.SeverityInfo
	SeverityLow      = plugin.SeverityLow
	SeverityMedium   = plugin.SeverityMedium
	SeverityHigh     = plugin.SeverityHigh
	SeverityCritical = plugin.SeverityCritical
)
