package anomaly

import (
	"testing"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// series builds a per-minute series from counts, starting at a fixed instant.
func series(counts ...int) []Point {
	start := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	pts := make([]Point, len(counts))
	for i, c := range counts {
		pts[i] = Point{At: start.Add(time.Duration(i) * time.Minute), Count: c}
	}
	return pts
}

func TestDetect_FlatSeriesHasNoAnomalies(t *testing.T) {
	got := Detect(series(10, 10, 11, 9, 10, 10, 11, 10, 9, 10), time.Minute, DefaultOptions())
	if len(got) != 0 {
		t.Errorf("steady traffic must not be flagged, got %d: %+v", len(got), got)
	}
}

func TestDetect_ObviousSpike(t *testing.T) {
	// Ten quiet minutes, then a burst.
	got := Detect(series(10, 10, 11, 9, 10, 10, 11, 10, 9, 10, 120), time.Minute, DefaultOptions())
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 spike, got %d: %+v", len(got), got)
	}
	a := got[0]
	if a.Kind != KindSpike {
		t.Errorf("kind = %q, want spike", a.Kind)
	}
	if a.Observed != 120 {
		t.Errorf("observed = %d, want 120", a.Observed)
	}
	if a.Baseline != 10 {
		t.Errorf("baseline = %v, want the median 10", a.Baseline)
	}
	if a.PercentChange != 1100 {
		t.Errorf("percent change = %v, want 1100", a.PercentChange)
	}
	if a.At != series(0)[0].At.Add(10*time.Minute) {
		t.Errorf("anomaly landed on the wrong bucket: %v", a.At)
	}
}

// The baseline must be the median, not the mean. An earlier spike still inside
// the window drags a mean upward and hides the next one.
func TestDetect_EarlierSpikeDoesNotHideTheNextOne(t *testing.T) {
	got := Detect(series(10, 10, 200, 10, 10, 10, 10, 10, 10, 10, 150), time.Minute, DefaultOptions())
	found := false
	for _, a := range got {
		if a.Observed == 150 {
			found = true
			if a.Baseline != 10 {
				t.Errorf("baseline = %v, want 10 — a mean would be inflated by the earlier 200", a.Baseline)
			}
		}
	}
	if !found {
		t.Errorf("the second spike must still be detected, got %+v", got)
	}
}

// Ratios are meaningless at small numbers; quiet systems must stay quiet.
func TestDetect_SmallNumbersAreNotSpikes(t *testing.T) {
	// 1 -> 3 is "+200%" but only 2 extra events.
	got := Detect(series(1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 3), time.Minute, DefaultOptions())
	if len(got) != 0 {
		t.Errorf("tiny absolute change must not be reported, got %+v", got)
	}
}

func TestDetect_NoDetectionWithoutEnoughHistory(t *testing.T) {
	// A big value in the warmup region cannot be judged.
	got := Detect(series(200, 1, 1), time.Minute, DefaultOptions())
	if len(got) != 0 {
		t.Errorf("buckets inside the warmup window must not be flagged, got %+v", got)
	}
}

func TestDetect_Drop(t *testing.T) {
	// A busy source that suddenly goes quiet.
	got := Detect(series(50, 52, 48, 51, 49, 50, 50, 51, 49, 50, 1), time.Minute, DefaultOptions())
	if len(got) != 1 || got[0].Kind != KindDrop {
		t.Fatalf("expected one drop, got %+v", got)
	}
	if got[0].PercentChange >= 0 {
		t.Errorf("a drop must report a negative change, got %v", got[0].PercentChange)
	}
}

func TestDetect_QuietSeriesNeverReportsDrops(t *testing.T) {
	// Baseline below MinBaselineForDrop: going to zero here is not signal.
	got := Detect(series(2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 0), time.Minute, DefaultOptions())
	for _, a := range got {
		if a.Kind == KindDrop {
			t.Errorf("a quiet series must not produce drops: %+v", a)
		}
	}
}

func TestPercentChange_ZeroBaselineStaysFinite(t *testing.T) {
	// +Inf would serialise as invalid JSON and break every consumer.
	got := Detect(series(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40), time.Minute, DefaultOptions())
	if len(got) != 1 {
		t.Fatalf("expected a spike from a zero baseline, got %+v", got)
	}
	pct := got[0].PercentChange
	if pct <= 0 || pct > 1e9 || pct != pct { // NaN check via self-inequality
		t.Errorf("percent change must be finite and positive, got %v", pct)
	}
}

func TestDetect_UnsortedInputIsHandled(t *testing.T) {
	s := series(10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 120)
	s[0], s[len(s)-1] = s[len(s)-1], s[0] // shuffle
	got := Detect(s, time.Minute, DefaultOptions())
	if len(got) != 1 || got[0].Observed != 120 {
		t.Errorf("detector must sort by time first, got %+v", got)
	}
}

func TestDetect_DoesNotMutateInput(t *testing.T) {
	s := series(10, 10, 10, 10, 10, 10, 120, 10, 10, 10)
	before := make([]Point, len(s))
	copy(before, s)
	_ = Detect(s, time.Minute, DefaultOptions())
	for i := range s {
		if s[i] != before[i] {
			t.Fatalf("input mutated at %d: %+v vs %+v", i, s[i], before[i])
		}
	}
}

func TestFindings_ShapeAndHonesty(t *testing.T) {
	an := Detect(series(10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 120), time.Minute, DefaultOptions())
	fs := Findings(an, plugin.Entity{Kind: "Host", Name: "web-01"}, "syslog/web-01")
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Category != "Anomaly" {
		t.Errorf("category = %q", f.Category)
	}
	if f.RootCause != "" {
		t.Errorf("a detector must not claim a root cause, got %q", f.RootCause)
	}
	if f.FirstSeen == nil || f.LastSeen == nil {
		t.Fatal("anomaly findings must carry their window")
	}
	if !f.LastSeen.After(*f.FirstSeen) {
		t.Errorf("window must be non-empty: %v..%v", f.FirstSeen, f.LastSeen)
	}
	if f.Entity == nil || f.Entity.Name != "web-01" {
		t.Errorf("entity not carried: %+v", f.Entity)
	}
	if f.Count != 120 {
		t.Errorf("count = %d, want the observed 120", f.Count)
	}
}

// Analyzer timelines omit intervals with no events, so a burst after a quiet
// period has no zeros to be measured against. This is the exact case that went
// undetected against a real corpus before Densify existed.
func TestDensify_MakesQuietPeriodsVisible(t *testing.T) {
	start := time.Date(2026, 8, 13, 9, 0, 0, 0, time.UTC)
	// Only two buckets exist: minute 20 and 21. Minutes 0-19 were silent and are
	// simply absent from the series.
	sparse := []Point{
		{At: start.Add(20 * time.Minute), Count: 70},
		{At: start.Add(21 * time.Minute), Count: 25},
	}
	if got := Detect(sparse, time.Minute, DefaultOptions()); len(got) != 0 {
		t.Fatalf("precondition: a 2-point series cannot be judged, got %+v", got)
	}

	// Zero-fill the whole span, including the quiet lead-in.
	full := append([]Point{{At: start, Count: 0}}, sparse...)
	dense := Densify(full, time.Minute)
	if len(dense) != 22 {
		t.Fatalf("expected 22 minute buckets, got %d", len(dense))
	}
	got := Detect(dense, time.Minute, DefaultOptions())
	if len(got) == 0 {
		t.Fatal("the burst must be detected once the quiet minutes are present")
	}
	if got[0].Observed != 70 {
		t.Errorf("first anomaly observed = %d, want the 70-event burst", got[0].Observed)
	}
	if got[0].Kind != KindSpike {
		t.Errorf("kind = %q, want spike", got[0].Kind)
	}
}

func TestDensify_LeavesDenseSeriesAlone(t *testing.T) {
	s := series(1, 2, 3, 4)
	if got := Densify(s, time.Minute); len(got) != len(s) {
		t.Errorf("a already-dense series must not grow: %d -> %d", len(s), len(got))
	}
}

func TestDensify_RefusesAbsurdRanges(t *testing.T) {
	// Two points a decade apart at minute granularity would be millions of
	// buckets; the series is returned unchanged rather than allocated.
	far := []Point{
		{At: time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC), Count: 1},
		{At: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Count: 1},
	}
	if got := Densify(far, time.Minute); len(got) != 2 {
		t.Errorf("expected the input back, got %d points", len(got))
	}
}
