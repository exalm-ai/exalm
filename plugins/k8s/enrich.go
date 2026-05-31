package k8s

// enrich.go layers two competitive-gap features on top of BuildFindings:
//   1. Change correlation — annotates each finding with its LikelyCause from
//      the changestore (Phase 4 Komodor-style change timeline).
//   2. Evidence chain — attaches verifiable log/event/change items to each
//      finding (Phase 4 OpenObserve-style evidence transparency).
//
// Both layers are non-fatal: when the changestore is unavailable or evidence
// sources are empty, the finding still ships unannotated.

import (
	"fmt"
	"time"

	"github.com/exalm-ai/exalm/internal/changestore"
	"github.com/exalm-ai/exalm/internal/evidence"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// BuildAndEnrichFindings is the production entry point: runs BuildFindings
// then layers in change correlation + evidence chain using the default
// changestore at $EXALM_HOME/changes.jsonl.
func BuildAndEnrichFindings(snap Snapshot) []plugin.Finding {
	findings := BuildFindings(snap)
	return enrichFindings(findings, snap, defaultStore(), time.Now())
}

// enrichFindings is the testable inner function — accepts an explicit store
// and clock for hermetic tests.
func enrichFindings(findings []plugin.Finding, snap Snapshot, store *changestore.Store, now time.Time) []plugin.Finding {
	var changes []changestore.ChangeEvent
	if store != nil {
		findings = Correlate(findings, store, now)
		// Pull the last hour of changes for evidence attribution. Older entries
		// rarely add signal — the LikelyCause already points to the newest one.
		changes, _ = store.All(now.Add(-1 * time.Hour))
	}
	src := buildEvidenceSource(snap)
	for i := range findings {
		items := evidence.Build(findings[i], src, changes, now)
		if len(items) > 0 {
			findings[i].Evidence = items
		}
	}
	return findings
}

// defaultStore returns a Store at the default location or nil if it can't be
// opened. Never panics — change correlation is opportunistic, not required.
func defaultStore() *changestore.Store {
	s, err := changestore.Open("")
	if err != nil {
		return nil
	}
	return s
}

// buildEvidenceSource projects the k8s Snapshot into the evidence.Source shape.
func buildEvidenceSource(snap Snapshot) evidence.Source {
	src := evidence.Source{
		LogTails:          make(map[string]string),
		EventsForResource: make(map[string][]string),
	}
	for _, pod := range snap.UnhealthyPods {
		for _, tail := range pod.LogTails {
			if tail.Error != "" || tail.Lines == "" {
				continue
			}
			key := pod.Namespace + "/" + pod.Name + "/" + tail.Container
			src.LogTails[key] = tail.Lines
		}
	}
	for _, ev := range snap.Events {
		key := ev.Namespace + "/" + ev.PodName
		src.EventsForResource[key] = append(src.EventsForResource[key], fmt.Sprintf("%s: %s", ev.Reason, ev.Message))
	}
	return src
}
