package investigate

import (
	"testing"
	"time"
)

func TestBucketMinute(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		want time.Time
	}{
		{
			"drops seconds and nanos",
			time.Date(2026, 7, 18, 21, 55, 42, 123456789, time.UTC),
			time.Date(2026, 7, 18, 21, 55, 0, 0, time.UTC),
		},
		{
			"already aligned is unchanged",
			time.Date(2026, 7, 18, 21, 55, 0, 0, time.UTC),
			time.Date(2026, 7, 18, 21, 55, 0, 0, time.UTC),
		},
		{
			"one second before the hour stays in the previous minute",
			time.Date(2026, 7, 18, 21, 59, 59, 0, time.UTC),
			time.Date(2026, 7, 18, 21, 59, 0, 0, time.UTC),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BucketMinute(tc.in); !got.Equal(tc.want) {
				t.Errorf("BucketMinute(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// The same minute on two different days must not collapse into one bucket.
// Keying timelines by the formatted "15:04" label used to do exactly that,
// silently merging a corpus that spanned midnight.
func TestBucketMinute_DistinguishesDays(t *testing.T) {
	day1 := BucketMinute(time.Date(2026, 7, 18, 23, 59, 10, 0, time.UTC))
	day2 := BucketMinute(time.Date(2026, 7, 19, 23, 59, 10, 0, time.UTC))
	if day1.Equal(day2) {
		t.Fatal("buckets one day apart must not be equal")
	}
	if day1.Format("15:04") != day2.Format("15:04") {
		t.Fatal("precondition: both should share a display label")
	}
}
