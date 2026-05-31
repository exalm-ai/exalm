package slo

import "time"

// SLOSpec defines a single service level objective.
//
// SRE use case: encode "the payment-service must have an error rate < 0.1%
// over a 30-day rolling window" as a machine-readable spec. Exalm evaluates
// it against current RED metrics and forecasts error budget exhaustion.
type SLOSpec struct {
	// Name is a unique identifier for this SLO, e.g. "payment-availability".
	Name string `json:"name"`
	// Service is the Kubernetes service name this SLO targets.
	Service   string `json:"service"`
	Namespace string `json:"namespace"`
	// Window is the compliance window, e.g. "30d", "7d".
	Window string `json:"window"`
	// Objective is the target reliability expressed as a fraction, e.g. 0.999 (99.9%).
	Objective float64 `json:"objective"`
	// SLI describes how to measure compliance.
	SLI SLIQuery `json:"sli"`
	// Annotations are arbitrary key-value labels for grouping (team, tier, etc.).
	Annotations map[string]string `json:"annotations,omitempty"`
}

// SLIQuery describes how to measure the service level indicator.
//
// TODO: implement Prometheus query execution in collect.go.
// TODO: add support for latency SLIs using histogram_quantile-based queries.
type SLIQuery struct {
	// GoodQuery is a PromQL expression counting "good" requests (numerator).
	// Example: sum(rate(http_requests_total{status!~"5.."}[5m]))
	GoodQuery string `json:"good_query"`
	// TotalQuery is a PromQL expression counting all requests (denominator).
	// Example: sum(rate(http_requests_total[5m]))
	TotalQuery string `json:"total_query"`
	// TODO: LatencyQuery + LatencyThreshold for latency SLIs.
	// TODO: multi-window burn rates (1h, 6h, 72h) for Google SRE-style alerting.
}

// ErrorBudget is the computed budget state for an SLO at a point in time.
//
// Single-window legacy view. For Google SRE-style alert tiering (1h/6h/72h
// burn rates with 14.4/6/1 thresholds), use BurnRates in Snapshot, which is
// populated by ComputeMultiWindow in burnrate.go (Phase 3).
type ErrorBudget struct {
	Spec SLOSpec
	// Remaining is the fraction of the error budget still available (0.0–1.0).
	// Example: 0.42 means 42% of the budget is left for the window.
	Remaining float64
	// BurnRate is the current consumption rate relative to the allowed rate.
	// A burn rate of 1.0 exactly exhausts the budget by the window end.
	// >1.0 = over-burning; will exhaust early.
	//
	// DEPRECATED: prefer Snapshot.BurnRates (multi-window) over this single
	// scalar. Retained for back-compat with Phase 1 reports.
	BurnRate float64
	// ExhaustionETA is when the budget will be fully consumed if burn continues.
	ExhaustionETA time.Time
}
