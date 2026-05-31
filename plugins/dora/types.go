package dora

import "time"

// DeploymentEvent represents a single deployment recorded to the local store.
//
// Deployments are appended to ~/.exalm/deployments.jsonl (one JSON object per line).
// They can be added manually via `exalm dora log-deploy` or written automatically
// by `exalm k8s watch` when it detects a Deployment rollout.
type DeploymentEvent struct {
	// ID is a unique deployment identifier.
	ID string `json:"id"`
	// Service is the name of the deployed workload (e.g. "payments-api").
	Service string `json:"service"`
	// Namespace is the Kubernetes namespace (empty for non-k8s deployments).
	Namespace string `json:"namespace,omitempty"`
	// Version is the deployed artefact version (image tag, chart version, git SHA).
	Version string `json:"version,omitempty"`
	// DeployedAt is when the deployment completed.
	DeployedAt time.Time `json:"deployed_at"`
	// DeployedBy identifies the actor (e.g. "ci/cd", "github-actions", username).
	DeployedBy string `json:"deployed_by,omitempty"`
	// Success indicates whether the deployment succeeded.
	Success bool `json:"success"`
	// CommitSHA is the git commit hash that triggered this deployment.
	// Used to compute Lead Time for Changes.
	CommitSHA string `json:"commit_sha,omitempty"`
	// CommitTime is when the triggering commit was authored/merged.
	// Lead Time = DeployedAt - CommitTime (when CommitTime is non-zero).
	CommitTime time.Time `json:"commit_time,omitempty"`
}

// DORAMetrics holds the computed DORA engineering-health metrics for a time window.
type DORAMetrics struct {
	// Window is the analysis period.
	Window time.Duration

	// DeploymentFrequency is the average number of successful deployments per day.
	DeploymentFrequency float64
	// DeploymentFrequencyRating is the DORA performance band.
	DeploymentFrequencyRating DORABand

	// LeadTimeHours is the average time from first deployment attempt to success, in hours.
	// Without commit-to-prod tracing, we approximate this as 0 (not enough data).
	// A future version will integrate git blame timestamps.
	LeadTimeHours float64
	// LeadTimeRating is the DORA performance band for lead time.
	LeadTimeRating DORABand

	// ChangeFailureRate is (failed deployments + high/critical incidents) / total deployments.
	ChangeFailureRate float64
	// ChangeFailureRateRating is the DORA performance band for CFR.
	ChangeFailureRateRating DORABand

	// MTTRHours is the mean time to restore (average incident duration in hours).
	MTTRHours float64
	// MTTRRating is the DORA performance band for MTTR.
	MTTRRating DORABand

	// TotalDeployments is the count of deployment events in the window.
	TotalDeployments int
	// SuccessfulDeployments is the count of successful deployments.
	SuccessfulDeployments int
	// TotalIncidents is the total number of incidents in the window.
	TotalIncidents int
	// CriticalHighIncidents is the count of high/critical severity incidents.
	CriticalHighIncidents int

	// OverallRating is the lowest band across all four metrics.
	OverallRating DORABand
}

// DORABand is the DORA research performance tier.
type DORABand string

const (
	BandElite  DORABand = "Elite"
	BandHigh   DORABand = "High"
	BandMedium DORABand = "Medium"
	BandLow    DORABand = "Low"
	BandNA     DORABand = "N/A" // insufficient data
)

// TrendArrow returns ↑, ↓, or → for display based on direction.
type TrendArrow string

const (
	TrendUp   TrendArrow = "↑"
	TrendDown TrendArrow = "↓"
	TrendFlat TrendArrow = "→"
)

// bandOrder maps bands to a numeric order for comparison (higher = better).
var bandOrder = map[DORABand]int{
	BandLow:    0,
	BandMedium: 1,
	BandHigh:   2,
	BandElite:  3,
	BandNA:     -1,
}

// lowestBand returns the worst-performing band across the given list.
func lowestBand(bands ...DORABand) DORABand {
	lowest := BandElite
	for _, b := range bands {
		if b == BandNA {
			continue
		}
		if bandOrder[b] < bandOrder[lowest] {
			lowest = b
		}
	}
	return lowest
}
