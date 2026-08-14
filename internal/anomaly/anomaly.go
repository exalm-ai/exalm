// Package anomaly turns a counted time series into candidate findings.
//
// It answers one question: "is this bucket unusual compared with what came
// before it?" — deliberately without machine learning. Everything here is
// arithmetic an operator can check by hand, which matters because the output
// becomes a finding that claims something changed, and a claim nobody can
// verify is worse than no claim.
//
// # Why the median, not the mean
//
// The baseline is the median of the preceding window. A mean is dragged upward
// by the very spike being measured (and by any earlier spike still inside the
// window), so a mean baseline systematically under-reports real spikes and
// invents small ones after quiet periods. The median is unmoved by up to half
// the window being outliers.
//
// # Why an absolute floor as well as a ratio
//
// Ratios are meaningless at small numbers: 1 error becoming 3 is "+200%" but is
// almost never worth waking someone. Every detection must clear BOTH a relative
// multiple of the baseline AND an absolute delta, so quiet systems stay quiet.
//
// # What this deliberately does not do
//
// No seasonality, no forecasting, no trend fitting. A daily traffic cycle will
// read as a spike each morning if the baseline window is shorter than the
// cycle — the caller controls the window and is expected to size it sensibly.
// Detections are described as "unusual compared with the preceding N buckets",
// which is exactly what was computed, and no more.
package anomaly

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Point is one bucket of a counted series.
type Point struct {
	At    time.Time
	Count int
}

// Kind classifies what was detected.
type Kind string

const (
	// KindSpike is a bucket far above its baseline.
	KindSpike Kind = "spike"
	// KindDrop is a bucket far below an established non-zero baseline —
	// often more alarming than a spike, because it usually means something
	// stopped reporting rather than got healthier.
	KindDrop Kind = "drop"
)

// Anomaly is one unusual bucket, with the arithmetic that justified it.
type Anomaly struct {
	Kind Kind
	// At is the start of the unusual bucket; Window is how much time it covers.
	At     time.Time
	Window time.Duration
	// Observed is the bucket's count; Baseline is the median of the preceding
	// window that it was compared against.
	Observed int
	Baseline float64
	// PercentChange is relative to Baseline: +380 means "+380%". It is capped
	// rather than infinite when the baseline is zero.
	PercentChange float64
	// BaselineBuckets is how much history the baseline was computed from, so a
	// consumer can weigh a detection made from thin evidence.
	BaselineBuckets int
	// Reason is a one-line, human-checkable explanation.
	Reason string
}

// Options tunes detection. The zero value is unusable; use DefaultOptions.
type Options struct {
	// BaselineBuckets is how many preceding buckets form the baseline.
	BaselineBuckets int
	// MinBaselineBuckets is the minimum history required before any detection
	// is attempted, so the first few buckets of a corpus cannot be anomalies.
	MinBaselineBuckets int
	// SpikeMultiple: observed must be at least baseline * SpikeMultiple.
	SpikeMultiple float64
	// MinAbsoluteDelta: observed must also exceed baseline by this many events.
	MinAbsoluteDelta int
	// MinObserved: buckets below this count are never reported as spikes.
	MinObserved int
	// DropFraction: observed at or below baseline * DropFraction is a drop.
	// Zero disables drop detection.
	DropFraction float64
	// MinBaselineForDrop: drops are only meaningful once the baseline is
	// substantial; below this the series is too quiet to call a drop.
	MinBaselineForDrop float64
}

// DefaultOptions is tuned for per-minute log and event buckets: roughly
// "three times the recent normal, and at least five more events than usual".
func DefaultOptions() Options {
	return Options{
		BaselineBuckets:    15,
		MinBaselineBuckets: 5,
		SpikeMultiple:      3.0,
		MinAbsoluteDelta:   5,
		MinObserved:        5,
		DropFraction:       0.2,
		MinBaselineForDrop: 10,
	}
}

// maxDensifiedPoints bounds Densify so a corpus spanning weeks at minute
// granularity cannot allocate an enormous series.
const maxDensifiedPoints = 20000

// Densify fills the gaps in a sparse series with explicit zero buckets.
//
// This is not cosmetic. Analyzer timelines only emit buckets for intervals that
// contained a matching event, so twenty quiet minutes are ABSENT rather than
// twenty zeros. Fed to Detect directly, a jump from no errors to seventy is
// invisible: the baseline is computed from the neighbouring busy buckets, and
// the quiet period it should be compared against was never in the series.
//
// Returns the input unchanged when the range is empty or would exceed
// maxDensifiedPoints.
func Densify(series []Point, window time.Duration) []Point {
	if len(series) < 2 || window <= 0 {
		return series
	}
	pts := make([]Point, len(series))
	copy(pts, series)
	sort.Slice(pts, func(i, j int) bool { return pts[i].At.Before(pts[j].At) })

	span := pts[len(pts)-1].At.Sub(pts[0].At)
	slots := int(span/window) + 1
	if slots <= len(pts) || slots > maxDensifiedPoints {
		return pts
	}

	byInstant := make(map[time.Time]int, len(pts))
	for _, p := range pts {
		byInstant[p.At.UTC()] = p.Count
	}
	out := make([]Point, 0, slots)
	for t := pts[0].At.UTC(); !t.After(pts[len(pts)-1].At.UTC()); t = t.Add(window) {
		out = append(out, Point{At: t, Count: byInstant[t]})
	}
	return out
}

// DensifyRange zero-fills a series across an explicit [from,to] window rather
// than the span the series happens to cover.
//
// Use it when the series is a filtered view of something larger — an
// error-only timeline, say, where healthy intervals produce no bucket at all.
// Densify alone cannot help there: with one bucket of errors, the span between
// first and last bucket is zero, so there is nothing to fill. The corpus window
// is what supplies the quiet baseline.
func DensifyRange(series []Point, window time.Duration, from, to time.Time) []Point {
	if window <= 0 || from.IsZero() || to.IsZero() || !to.After(from) {
		return series
	}
	start := from.UTC().Truncate(window)
	end := to.UTC().Truncate(window)
	if int(end.Sub(start)/window)+1 > maxDensifiedPoints {
		return series
	}
	byInstant := make(map[time.Time]int, len(series))
	for _, p := range series {
		byInstant[p.At.UTC().Truncate(window)] = p.Count
	}
	out := make([]Point, 0, int(end.Sub(start)/window)+1)
	for t := start; !t.After(end); t = t.Add(window) {
		out = append(out, Point{At: t, Count: byInstant[t]})
	}
	return out
}

// Detect scans the series in chronological order and returns the buckets that
// are unusual against their own recent history. Input need not be sorted.
//
// Callers working from analyzer timelines should pass the series through
// Densify first; a sparse series has no zeros to establish a quiet baseline.
//
// The series is not modified.
func Detect(series []Point, window time.Duration, o Options) []Anomaly {
	if len(series) == 0 || o.MinBaselineBuckets <= 0 || o.BaselineBuckets <= 0 {
		return nil
	}
	pts := make([]Point, len(series))
	copy(pts, series)
	sort.Slice(pts, func(i, j int) bool { return pts[i].At.Before(pts[j].At) })

	var out []Anomaly
	for i := range pts {
		if i < o.MinBaselineBuckets {
			continue // not enough history behind this bucket to judge it
		}
		lo := i - o.BaselineBuckets
		if lo < 0 {
			lo = 0
		}
		hist := pts[lo:i]
		base := median(counts(hist))
		observed := pts[i].Count

		if a, ok := spike(pts[i], observed, base, len(hist), window, o); ok {
			out = append(out, a)
			continue
		}
		if a, ok := drop(pts[i], observed, base, len(hist), window, o); ok {
			out = append(out, a)
		}
	}
	return out
}

func spike(p Point, observed int, base float64, histLen int, window time.Duration, o Options) (Anomaly, bool) {
	if observed < o.MinObserved {
		return Anomaly{}, false
	}
	if float64(observed)-base < float64(o.MinAbsoluteDelta) {
		return Anomaly{}, false
	}
	// A zero baseline means "this never happened before", which is a spike as
	// soon as the absolute floors above are cleared.
	if base > 0 && float64(observed) < base*o.SpikeMultiple {
		return Anomaly{}, false
	}
	pct := percentChange(float64(observed), base)
	return Anomaly{
		Kind: KindSpike, At: p.At, Window: window,
		Observed: observed, Baseline: base, PercentChange: pct,
		BaselineBuckets: histLen,
		Reason: fmt.Sprintf("%d events in %s versus a median of %s across the preceding %d buckets (%s)",
			observed, humanWindow(window), trim(base), histLen, signedPct(pct)),
	}, true
}

func drop(p Point, observed int, base float64, histLen int, window time.Duration, o Options) (Anomaly, bool) {
	if o.DropFraction <= 0 || base < o.MinBaselineForDrop {
		return Anomaly{}, false
	}
	if float64(observed) > base*o.DropFraction {
		return Anomaly{}, false
	}
	pct := percentChange(float64(observed), base)
	return Anomaly{
		Kind: KindDrop, At: p.At, Window: window,
		Observed: observed, Baseline: base, PercentChange: pct,
		BaselineBuckets: histLen,
		Reason: fmt.Sprintf("%d events in %s versus a median of %s across the preceding %d buckets (%s) — a source that stopped reporting looks like this",
			observed, humanWindow(window), trim(base), histLen, signedPct(pct)),
	}, true
}

// percentChange is relative to base. With a zero baseline the true value is
// undefined, so it is reported as a large finite number rather than +Inf, which
// would serialise as invalid JSON.
func percentChange(observed, base float64) float64 {
	if base <= 0 {
		if observed <= 0 {
			return 0
		}
		return 100 * observed // "from nothing" — finite and obviously large
	}
	return (observed - base) / base * 100
}

func counts(pts []Point) []float64 {
	out := make([]float64, len(pts))
	for i, p := range pts {
		out[i] = float64(p.Count)
	}
	return out
}

// median returns the middle value of vals. vals is copied before sorting so the
// caller's slice ordering (which is chronological) is preserved.
func median(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	s := make([]float64, len(vals))
	copy(s, vals)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

func trim(f float64) string {
	if f == math.Trunc(f) {
		return fmt.Sprintf("%.0f", f)
	}
	return fmt.Sprintf("%.1f", f)
}

func signedPct(p float64) string {
	if p >= 0 {
		return fmt.Sprintf("+%.0f%%", p)
	}
	return fmt.Sprintf("%.0f%%", p)
}

func humanWindow(d time.Duration) string {
	switch {
	case d <= 0:
		return "the bucket"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}
