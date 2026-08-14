package anomaly

import (
	"fmt"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Findings converts detections into candidate plugin.Finding records.
//
// These are CANDIDATES: the detector knows that something moved, not why. The
// severity reflects how far outside normal the bucket sits, the root cause is
// left empty, and the suggestion points at the investigation engine — which is
// the part that can actually gather evidence and rank hypotheses. Writing a
// confident root cause here would be inventing one.
//
// entity may be zero for corpus-wide series; source is the usual provenance
// string ("syslog/web-01").
func Findings(anomalies []Anomaly, entity plugin.Entity, source string) []plugin.Finding {
	out := make([]plugin.Finding, 0, len(anomalies))
	for _, a := range anomalies {
		f := plugin.Finding{
			Severity:   severityFor(a),
			Category:   "Anomaly",
			Title:      titleFor(a, entity),
			Detail:     a.Reason + ".",
			Suggestion: "Investigate this window to establish whether the change has a cause worth acting on.",
			Source:     source,
			Confidence: confidenceFor(a),
			Count:      a.Observed,
		}
		start := a.At
		end := a.At.Add(a.Window)
		f.FirstSeen, f.LastSeen = &start, &end
		if !entity.IsZero() {
			e := entity
			f.Entity = &e
		}
		out = append(out, f)
	}
	return out
}

func titleFor(a Anomaly, e plugin.Entity) string {
	where := ""
	if !e.IsZero() {
		where = " on " + e.Path()
	}
	when := a.At.UTC().Format("15:04")
	if a.Kind == KindDrop {
		return fmt.Sprintf("Activity dropped %s at %s%s", signedPct(a.PercentChange), when, where)
	}
	return fmt.Sprintf("Activity spiked %s at %s%s", signedPct(a.PercentChange), when, where)
}

// severityFor scales with how far outside normal the bucket sits, and is
// deliberately capped at high: a statistical outlier on its own is not a
// critical incident, and calling it one would train people to ignore criticals.
func severityFor(a Anomaly) plugin.Severity {
	switch {
	case a.Kind == KindDrop:
		return plugin.SeverityMedium
	case a.PercentChange >= 500:
		return plugin.SeverityHigh
	case a.PercentChange >= 200:
		return plugin.SeverityMedium
	default:
		return plugin.SeverityLow
	}
}

// confidenceFor reflects how much history backed the comparison, not how sure
// we are about a cause — there is no cause claim to be sure about.
func confidenceFor(a Anomaly) string {
	switch {
	case a.BaselineBuckets >= 10 && a.Baseline > 0:
		return "high"
	case a.BaselineBuckets >= 5:
		return "medium"
	default:
		return "low"
	}
}
