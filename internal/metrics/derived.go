package metrics

import (
	"context"
	"math"
	"time"

	"github.com/exalm-ai/exalm/internal/changestore"
)

// Derived is the no-backend Provider: it synthesizes a deterministic hourly
// series scaled by Query.Magnitude and overlays real change annotations from the
// changestore. Series are marked Modeled=true so the UI can label them honestly.
type Derived struct {
	// openStore opens the changestore; overridable in tests. Returns nil when
	// the store is unavailable (annotations are then omitted, not fatal).
	openStore func() *changestore.Store
}

// NewDerived returns a Derived provider backed by the default changestore.
func NewDerived() *Derived {
	return &Derived{openStore: func() *changestore.Store {
		s, err := changestore.Open("")
		if err != nil {
			return nil
		}
		return s
	}}
}

// Available is false: values are modeled, not measured.
func (d *Derived) Available() bool { return false }

// Series returns a single modeled "Findings activity" line over 24 hourly
// buckets in the window, with a threshold and real change annotations.
func (d *Derived) Series(_ context.Context, q Query) ([]Series, error) {
	now := q.Now
	if now.IsZero() {
		// Caller should pass Now; fall back defensively without panicking.
		now = time.Unix(0, 0)
	}
	window := q.Window
	if window <= 0 {
		window = 24 * time.Hour
	}
	const buckets = 24
	step := window / buckets
	mag := q.Magnitude
	if mag <= 0 {
		mag = 1
	}

	// Deterministic wave shaped by the bucket index (no RNG → reproducible).
	points := make([]Point, 0, buckets)
	peak := 0.0
	for i := 0; i < buckets; i++ {
		t := now.Add(-window + time.Duration(i+1)*step)
		wave := 0.5 + 0.5*math.Sin(float64(i)/buckets*math.Pi*2-1.1)
		v := math.Round(wave*float64(mag)*0.6 + float64(mag)*0.15)
		if v > peak {
			peak = v
		}
		points = append(points, Point{T: t, V: v})
	}

	series := Series{
		Name:      "Findings activity",
		Unit:      "findings",
		Threshold: math.Max(1, math.Round(peak*0.8)),
		Modeled:   true,
		Points:    points,
	}

	// Overlay real change annotations from the window.
	if d.openStore != nil {
		if store := d.openStore(); store != nil {
			if changes, err := store.All(now.Add(-window)); err == nil {
				for _, c := range changes {
					if q.Namespace != "" && q.Namespace != "all" && c.Namespace != q.Namespace {
						continue
					}
					series.Annotations = append(series.Annotations, Annotation{
						T:     c.Timestamp,
						Label: c.Action + " " + c.Kind + " " + c.Name,
						Kind:  "change",
					})
				}
			}
		}
	}

	return []Series{series}, nil
}
