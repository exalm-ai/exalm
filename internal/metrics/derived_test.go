package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/internal/changestore"
)

func TestDerived_SeriesIsDeterministicAndModeled(t *testing.T) {
	// No changestore so the test stays hermetic (no filesystem access).
	d := &Derived{openStore: func() *changestore.Store { return nil }}
	if d.Available() {
		t.Error("derived provider should report Available()=false")
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	q := Query{Namespace: "all", Window: 24 * time.Hour, Now: now, Magnitude: 40}

	got1, err := d.Series(context.Background(), q)
	if err != nil {
		t.Fatalf("Series: %v", err)
	}
	if len(got1) != 1 {
		t.Fatalf("expected 1 series, got %d", len(got1))
	}
	s := got1[0]
	if !s.Modeled {
		t.Error("derived series must be marked Modeled")
	}
	if len(s.Points) != 24 {
		t.Errorf("expected 24 hourly points, got %d", len(s.Points))
	}
	if s.Threshold <= 0 {
		t.Errorf("expected a positive threshold, got %v", s.Threshold)
	}

	// Same query → identical output (deterministic, no RNG).
	got2, _ := d.Series(context.Background(), q)
	for i := range s.Points {
		if got2[0].Points[i].V != s.Points[i].V {
			t.Fatalf("series not deterministic at point %d: %v vs %v", i, got2[0].Points[i].V, s.Points[i].V)
		}
	}
}
