package investigate

import "time"

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
