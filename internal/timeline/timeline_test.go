package timeline

import (
	"context"
	"testing"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
	incidentpkg "github.com/exalm-ai/exalm/plugins/incident"
)

// isolate points the incident store and changestore at fresh temp
// directories so Aggregate's tests never touch the real ~/.exalm data.
func isolate(t *testing.T) {
	t.Helper()
	incidentpkg.IncidentDir = t.TempDir()
	t.Cleanup(func() { incidentpkg.IncidentDir = "" })
	t.Setenv("EXALM_HOME", t.TempDir())
}

func TestAggregate_FindingsFromReport(t *testing.T) {
	isolate(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	report := plugin.Report{Findings: []plugin.Finding{
		{Title: "pod crash", Severity: plugin.SeverityCritical, Detail: "OOMKilled"},
		{Title: "drifted resource", Category: "IaC", Severity: plugin.SeverityLow},
	}}

	data := Aggregate(context.Background(), report, nil, now)

	if len(data.Events) != 2 {
		t.Fatalf("expected 2 events, got %+v", data.Events)
	}
	if data.Events[0].Severity != "critical" || data.Events[0].Source != "finding" {
		t.Errorf("event 0: %+v", data.Events[0])
	}
	// Category "IaC" folds into the "iac" severity lane regardless of the
	// finding's own Severity field.
	if data.Events[1].Severity != "iac" {
		t.Errorf("IaC-categorized finding should fold to severity=iac, got %+v", data.Events[1])
	}
	if data.EndISO != now.Format(time.RFC3339) {
		t.Errorf("EndISO: %s", data.EndISO)
	}
}

func TestAggregate_SnapshotHistoryWidensWindow(t *testing.T) {
	isolate(t)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	old := now.Add(-30 * 24 * time.Hour) // well outside the default 7-day window
	snapshots := []Snapshot{
		{CollectedAt: old, Report: plugin.Report{Findings: []plugin.Finding{
			{Title: "old finding", Severity: plugin.SeverityMedium},
		}}},
	}

	data := Aggregate(context.Background(), plugin.Report{}, snapshots, now)

	if data.StartISO != old.Format(time.RFC3339) {
		t.Errorf("StartISO should widen to the oldest snapshot, got %s (want %s)", data.StartISO, old.Format(time.RFC3339))
	}
	found := false
	for _, ev := range data.Events {
		if ev.Label == "old finding" && ev.At == old.Format(time.RFC3339) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the snapshot's finding as an event, got %+v", data.Events)
	}
}

func TestAggregate_EmptyEventsIsEmptySliceNotNil(t *testing.T) {
	isolate(t)
	data := Aggregate(context.Background(), plugin.Report{}, nil, time.Now())
	if data.Events == nil {
		t.Error("Events must be an empty slice, not nil (so JSON encodes [] not null)")
	}
	if len(data.Events) != 0 {
		t.Errorf("expected no events, got %+v", data.Events)
	}
}

func TestAggregate_IncidentsFromStore(t *testing.T) {
	isolate(t)
	ctx := context.Background()
	store := incidentpkg.NewFileStore()
	now := time.Now().UTC()
	_, err := incidentpkg.Open(ctx, store, incidentpkg.OpenRequest{
		Title: "db outage", Severity: plugin.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("seed incident: %v", err)
	}

	data := Aggregate(ctx, plugin.Report{}, nil, now.Add(time.Hour))

	found := false
	for _, ev := range data.Events {
		if ev.Source == "incident" {
			found = true
			if ev.Severity != "high" {
				t.Errorf("incident event severity: %+v", ev)
			}
		}
	}
	if !found {
		t.Errorf("expected an incident event, got %+v", data.Events)
	}
}
