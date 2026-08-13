package k8s

// enrich.go layers two features on top of BuildFindings:
//   1. Change correlation — annotates each finding with its LikelyCause from
//      the changestore (the change-timeline signal).
//   2. Evidence chain — attaches verifiable log/event/change items to each
//      finding (evidence transparency).
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
	observed := observationIndex(snap)
	for i := range findings {
		items := evidence.Build(findings[i], src, changes, now)
		if len(items) > 0 {
			findings[i].Evidence = items
		}
		attachEntity(&findings[i])
		attachObservationWindow(&findings[i], observed)
		// Classify the remediation (temporary vs root-cause), derive confidence
		// + a root-cause sentence, and assemble the explainable Fixes set. Runs
		// after evidence/correlation so it can use both as signals.
		Classify(&findings[i])
	}
	return findings
}

// attachEntity gives a finding a typed resource identity. Detectors in
// findings.go encode the resource in the title ("CrashLoopBackOff: ns/pod"), so
// the identity is recovered here in one place rather than threading an Entity
// through ~18 detector call sites. A detector that sets Entity itself wins;
// this only fills the gap.
//
// Without this, the dashboard can only group and filter findings by
// substring-matching the title, and the same symptom on two different pods
// collides onto a single finding ID.
func attachEntity(f *plugin.Finding) {
	if f.Entity != nil && !f.Entity.IsZero() {
		return
	}
	// A correlated change already carries an exact, typed identity — prefer it
	// over re-parsing prose.
	if c := f.LikelyCause; c != nil && c.Name != "" {
		f.Entity = &plugin.Entity{Kind: c.Kind, Namespace: c.Namespace, Name: c.Name}
		return
	}
	if r := f.Remediation; r != nil && r.Name != "" {
		f.Entity = &plugin.Entity{Kind: r.Resource, Namespace: r.Namespace, Name: r.Name}
		return
	}
	if e := plugin.ParseEntityFromTitle(f.Title, kindForCategory(f.Category)); !e.IsZero() {
		f.Entity = &e
	}
}

// observed bounds when a resource's condition was actually seen, derived from
// the real event timestamps in the snapshot.
type observed struct {
	first, last time.Time
	count       int
}

// observationIndex maps "namespace/name" to the window of real event times for
// that resource. Kubernetes events carry LastSeenAt plus an occurrence count,
// so the window is bounded by what the cluster actually reported — nothing is
// extrapolated.
func observationIndex(snap Snapshot) map[string]observed {
	idx := make(map[string]observed, len(snap.Events))
	for _, ev := range snap.Events {
		if ev.LastSeenAt.IsZero() || ev.PodName == "" {
			continue
		}
		key := ev.Namespace + "/" + ev.PodName
		o, ok := idx[key]
		if !ok || ev.LastSeenAt.Before(o.first) {
			o.first = ev.LastSeenAt
		}
		if ev.LastSeenAt.After(o.last) {
			o.last = ev.LastSeenAt
		}
		o.count += int(ev.Count)
		idx[key] = o
	}
	return idx
}

// attachObservationWindow stamps a finding with when its resource was actually
// observed misbehaving. Findings without a matching event keep zero times,
// which callers must read as "unknown" — a finding placed on a time axis at
// render time is not on a time axis at all, it is just stacked at "now".
func attachObservationWindow(f *plugin.Finding, idx map[string]observed) {
	if f.Entity == nil || f.Entity.IsZero() {
		return
	}
	o, ok := idx[f.Entity.Path()]
	if !ok {
		return
	}
	if f.FirstSeen == nil && !o.first.IsZero() {
		first := o.first
		f.FirstSeen = &first
	}
	if f.LastSeen == nil && !o.last.IsZero() {
		last := o.last
		f.LastSeen = &last
	}
	if f.Count == 0 {
		f.Count = o.count
	}
}

// kindForCategory maps a finding category onto the resource kind its detectors
// report on. Best-effort: an unknown category yields an untyped entity, which
// still carries a usable namespace/name identity.
func kindForCategory(category string) string {
	switch category {
	case "Pods":
		return "Pod"
	case "Nodes":
		return "Node"
	case "Storage":
		return "PersistentVolumeClaim"
	case "Networking", "Services":
		return "Service"
	case "Workloads":
		return "Deployment"
	}
	return ""
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
