package investigate

import (
	"time"

	"github.com/exalm-ai/exalm/internal/anomaly"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// TimeBucket is one bucket of a stats timeline: how many events landed in a
// slice of time, and the worst severity seen in it.
//
// It lives here rather than in each analyzer because all six log analyzers had
// byte-identical copies, and because the dashboard contract depends on the
// shape: a chart bar that cannot name its own time range cannot drill into the
// log lines behind it.
type TimeBucket struct {
	// T is the display label ("15:04"). Kept for the axis and tooltips.
	T string `json:"t"`
	// At is the bucket's start instant. The label alone is ambiguous — it drops
	// the date, so a corpus spanning midnight collapses two different minutes
	// onto one bar and a click cannot be resolved back to a time range. Charts
	// use this to drill into an exact window instead of text-matching the label.
	At time.Time `json:"at,omitempty"`
	// Width is how much time the bucket covers, so a consumer can derive the
	// bucket's end without assuming a fixed granularity.
	Width time.Duration `json:"widthNs,omitempty"`
	Count int           `json:"count"`
	Sev   string        `json:"sev,omitempty"`
}

// BucketMinute returns the minute-aligned start of t, the granularity every
// analyzer timeline currently uses.
func BucketMinute(t time.Time) time.Time { return t.Truncate(time.Minute) }

// AnomalyPoints converts a stats timeline into the counted series the anomaly
// detector consumes. Buckets with no instant are skipped: a bucket that cannot
// say when it happened cannot be compared with its neighbours.
func AnomalyPoints(buckets []TimeBucket) []anomaly.Point {
	pts := make([]anomaly.Point, 0, len(buckets))
	for _, b := range buckets {
		if b.At.IsZero() {
			continue
		}
		pts = append(pts, anomaly.Point{At: b.At, Count: b.Count})
	}
	return pts
}

// DetectAnomalies is the one-line path from a stats timeline to candidate
// findings, shared by every analyzer so they all use the same thresholds.
//
// sess supplies the corpus time range, which matters more than it looks.
// Severity timelines only contain buckets for intervals that had a matching
// event, so a service that was healthy for twenty minutes and then failed
// contributes exactly one bucket. Zero-filling between the first and last
// bucket of such a series covers nothing. Filling across the CORPUS range puts
// the quiet minutes back, which is what the burst has to be measured against.
func DetectAnomalies(sess *LogSession, buckets []TimeBucket, entity plugin.Entity, source string) []plugin.Finding {
	pts := AnomalyPoints(buckets)
	if len(pts) == 0 {
		return nil
	}
	width := time.Minute
	if buckets[0].Width > 0 {
		width = buckets[0].Width
	}
	if sess != nil {
		if from, to := sess.TimeRange(); !from.IsZero() && !to.IsZero() {
			pts = anomaly.DensifyRange(pts, width, from, to)
		}
	}
	pts = anomaly.Densify(pts, width)
	return anomaly.Findings(anomaly.Detect(pts, width, anomaly.DefaultOptions()), entity, source)
}
