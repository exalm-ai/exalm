package dora

import (
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
	incidentpkg "github.com/exalm-ai/exalm/plugins/incident"
)

// calculateDORA computes all four DORA metrics from deployments and incidents.
//
// deployments: events in the analysis window.
// incidents:   incidents whose OpenedAt falls in the window.
func calculateDORA(window time.Duration, deployments []DeploymentEvent, incidents []incidentpkg.Incident) DORAMetrics {
	days := window.Hours() / 24

	m := DORAMetrics{Window: window}

	// ── 1. Deployment Frequency ──────────────────────────────────────────────
	for _, d := range deployments {
		m.TotalDeployments++
		if d.Success {
			m.SuccessfulDeployments++
		}
	}
	if days > 0 {
		m.DeploymentFrequency = float64(m.SuccessfulDeployments) / days
	}
	m.DeploymentFrequencyRating = rateDeploymentFrequency(m.DeploymentFrequency, m.SuccessfulDeployments)

	// ── 2. Lead Time ─────────────────────────────────────────────────────────
	var totalLeadTime time.Duration
	var leadCount int
	for _, d := range deployments {
		if !d.CommitTime.IsZero() && d.DeployedAt.After(d.CommitTime) {
			totalLeadTime += d.DeployedAt.Sub(d.CommitTime)
			leadCount++
		}
	}
	if leadCount > 0 {
		m.LeadTimeHours = totalLeadTime.Hours() / float64(leadCount)
	}
	m.LeadTimeRating = rateLeadTime(m.LeadTimeHours, leadCount)

	// ── 3. Change Failure Rate ────────────────────────────────────────────────
	//
	// CFR = (failed deployments + high/critical incidents) / total deployments
	var failedDeps int
	for _, d := range deployments {
		if !d.Success {
			failedDeps++
		}
	}
	for _, inc := range incidents {
		m.TotalIncidents++
		if inc.Severity == plugin.SeverityHigh || inc.Severity == plugin.SeverityCritical {
			m.CriticalHighIncidents++
		}
	}
	if m.TotalDeployments > 0 {
		failures := failedDeps + m.CriticalHighIncidents
		m.ChangeFailureRate = float64(failures) / float64(m.TotalDeployments)
	}
	m.ChangeFailureRateRating = rateCFR(m.ChangeFailureRate, m.TotalDeployments)

	// ── 4. MTTR ───────────────────────────────────────────────────────────────
	var totalRestoreTime time.Duration
	var closedCount int
	for _, inc := range incidents {
		if inc.ClosedAt != nil {
			totalRestoreTime += inc.ClosedAt.Sub(inc.OpenedAt)
			closedCount++
		}
	}
	if closedCount > 0 {
		m.MTTRHours = totalRestoreTime.Hours() / float64(closedCount)
	}
	m.MTTRRating = rateMTTR(m.MTTRHours, closedCount)

	// ── Overall rating ────────────────────────────────────────────────────────
	// Overall = worst band across DF, Lead Time, CFR, MTTR.
	// BandNA is skipped by lowestBand, so Lead Time only affects the overall
	// rating when commit timestamps are present.
	m.OverallRating = lowestBand(
		m.DeploymentFrequencyRating,
		m.LeadTimeRating,
		m.ChangeFailureRateRating,
		m.MTTRRating,
	)

	return m
}

// rateDeploymentFrequency maps deployments-per-day to a DORA band.
//
// Based on 2023 DORA State of DevOps Report thresholds:
//
//	Elite:  multiple per day  (>= 1/day)
//	High:   1/week to 1/day  (>= 1/7 per day)
//	Medium: 1/month to 1/week (>= 1/30 per day)
//	Low:    < 1/month
func rateDeploymentFrequency(freqPerDay float64, total int) DORABand {
	if total == 0 {
		return BandNA
	}
	switch {
	case freqPerDay >= 1.0:
		return BandElite
	case freqPerDay >= 1.0/7:
		return BandHigh
	case freqPerDay >= 1.0/30:
		return BandMedium
	default:
		return BandLow
	}
}

// rateCFR maps change failure rate to a DORA band.
//
//	Elite:  < 5%
//	High:   5–10%
//	Medium: 10–15%
//	Low:    > 15%
func rateCFR(cfr float64, totalDeployments int) DORABand {
	if totalDeployments == 0 {
		return BandNA
	}
	switch {
	case cfr < 0.05:
		return BandElite
	case cfr < 0.10:
		return BandHigh
	case cfr < 0.15:
		return BandMedium
	default:
		return BandLow
	}
}

// rateMTTR maps mean-time-to-restore (hours) to a DORA band.
//
//	Elite:  < 1 hour
//	High:   < 24 hours
//	Medium: < 168 hours (1 week)
//	Low:    >= 168 hours
func rateMTTR(mttrHours float64, closedIncidents int) DORABand {
	if closedIncidents == 0 {
		return BandNA
	}
	switch {
	case mttrHours < 1:
		return BandElite
	case mttrHours < 24:
		return BandHigh
	case mttrHours < 168:
		return BandMedium
	default:
		return BandLow
	}
}

// rateLeadTime maps mean lead-time (hours) to a DORA band.
//
//	Elite:  < 1 hour
//	High:   < 24 hours (1 day)
//	Medium: < 168 hours (1 week)
//	Low:    >= 168 hours
func rateLeadTime(ltHours float64, count int) DORABand {
	if count == 0 {
		return BandNA
	}
	switch {
	case ltHours < 1:
		return BandElite
	case ltHours < 24:
		return BandHigh
	case ltHours < 168:
		return BandMedium
	default:
		return BandLow
	}
}

// bandEmoji returns a coloured indicator for each band.
func bandEmoji(b DORABand) string {
	switch b {
	case BandElite:
		return "🟢 Elite"
	case BandHigh:
		return "🔵 High"
	case BandMedium:
		return "🟡 Medium"
	case BandLow:
		return "🔴 Low"
	default:
		return "⬜ N/A"
	}
}
