// Package metrics defines a small, Prometheus-ready interface for the time-series
// the dashboard charts hover and drill-down need (series values, thresholds, and
// event/deploy annotations). Today only a derived implementation exists, which
// synthesizes a modeled series from the finding magnitude and overlays REAL
// change annotations from the changestore. A future PrometheusProvider can
// implement the same interface so the UI needs no changes.
package metrics

import (
	"context"
	"time"
)

// Query selects what to return. Magnitude is a caller-supplied scale hint (e.g.
// the finding count for the scope) used by the derived provider to size its
// modeled series; a real backend would ignore it.
type Query struct {
	Namespace string
	Name      string
	Window    time.Duration
	Now       time.Time
	Magnitude int
}

// Point is one sample.
type Point struct {
	T time.Time `json:"t"`
	V float64   `json:"v"`
}

// Annotation marks an event on the timeline (a deploy, a change, an incident).
type Annotation struct {
	T     time.Time `json:"t"`
	Label string    `json:"label"`
	Kind  string    `json:"kind"` // "change" | "deploy" | "incident" | "warning"
}

// Series is one named metric line with an optional alert threshold and overlaid
// annotations.
type Series struct {
	Name        string       `json:"name"`
	Unit        string       `json:"unit,omitempty"`
	Threshold   float64      `json:"threshold,omitempty"`
	Modeled     bool         `json:"modeled"` // true when values are synthesized, not measured
	Points      []Point      `json:"points"`
	Annotations []Annotation `json:"annotations,omitempty"`
}

// Provider returns metric series for a query.
type Provider interface {
	// Available reports whether real metric values are available (false for the
	// derived provider, true for a wired Prometheus backend).
	Available() bool
	Series(ctx context.Context, q Query) ([]Series, error)
}
