package k8s

// Change-correlation engine — ties each finding to the most recent cluster
// change (Deployment update, ConfigMap edit, RBAC change) that occurred
// within a configurable window before the finding's first observation. If a
// match is found, finding.LikelyCause is populated with a ChangeRef so the
// dashboard can show "Likely caused by deploy 12m ago by alice".
//
// Competitive gap:
//   - Komodor strength #1: "Change-correlation engine is best-in-class for K8s:
//     most cluster incidents are change-induced and this is Komodor's core thesis."
//     Exalm needs an equivalent.
//   - OpenObserve opportunity #4 (HIGH): "Change-correlation engine to suppress
//     deployment-induced anomalies." We don't suppress (the user still wants to
//     see the failure) but we annotate, which is the same signal in a different
//     form.
//
// Correlation rules (Exalm's first cut):
//   1. Parse the finding title for "<namespace>/<name>" (pod or workload).
//   2. Query the changestore for events in (Deployment, StatefulSet, DaemonSet,
//      ConfigMap, Secret, RoleBinding) affecting that name or its owner
//      workload, within ChangeCorrelationWindow (default 30 minutes).
//   3. If any match, the newest one becomes LikelyCause. Older matches do not
//      "compete" — recency is the strongest predictor per Komodor's thesis.
//
// The engine is non-destructive: it returns a new slice of findings with
// LikelyCause set where applicable, leaving the input slice untouched.

import (
	"strings"
	"time"

	"github.com/exalm-ai/exalm/internal/changestore"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ChangeCorrelationWindow is how far back the correlator looks for a recent
// change that could have caused the finding. Default 30 minutes matches
// Komodor's empirical default; long enough to catch a slow-rolling deploy,
// short enough to avoid false positives on unrelated activity.
const ChangeCorrelationWindow = 30 * time.Minute

// correlationKinds is the set of K8s object kinds we treat as causal candidates.
var correlationKinds = []string{
	"Deployment",
	"StatefulSet",
	"DaemonSet",
	"ConfigMap",
	"Secret",
	"RoleBinding",
	"ClusterRoleBinding",
	"NetworkPolicy",
}

// Correlate annotates each finding with a LikelyCause when a recent change
// matches the finding's resource. Returns a new slice; the input is not
// modified. If store is nil, the input is returned unchanged.
func Correlate(findings []plugin.Finding, store *changestore.Store, now time.Time) []plugin.Finding {
	if store == nil || len(findings) == 0 {
		return findings
	}
	out := make([]plugin.Finding, len(findings))
	copy(out, findings)

	for i := range out {
		ns, name := parseResourceFromTitle(out[i].Title)
		if ns == "" || name == "" {
			continue
		}
		matches, err := store.RecentForResource(ns, name, correlationKinds, ChangeCorrelationWindow, now)
		if err != nil || len(matches) == 0 {
			continue
		}
		newest := matches[0]                              // RecentForResource sorts newest-first
		ago := int64(now.Sub(newest.Timestamp).Seconds()) //nolint:gosec // G115: duration in seconds; truncation is intentional
		if ago < 0 {
			ago = 0
		}
		out[i].LikelyCause = &plugin.ChangeRef{
			ID:         newest.ID,
			Kind:       newest.Kind,
			Namespace:  newest.Namespace,
			Name:       newest.Name,
			Actor:      newest.Actor,
			AgoSeconds: ago,
			DiffURL:    newest.DiffURL,
		}
	}
	return out
}

// parseResourceFromTitle pulls "namespace/name" out of a finding title.
// Mirrors the JS heuristic in app.js buildRootCauseMap so server-side
// correlation lines up with client-side rendering.
func parseResourceFromTitle(title string) (ns, name string) {
	// Common patterns in our analyzers:
	//   "CrashLoopBackOff: ns/pod"
	//   "Log db-error in ns/pod"
	//   "Selector mismatch: ns/svc"
	//   "Container missing limits: ns/pod"
	for _, sep := range []string{": ", " in "} {
		if i := strings.Index(title, sep); i >= 0 {
			rest := title[i+len(sep):]
			if slash := strings.Index(rest, "/"); slash > 0 {
				maybeNs := rest[:slash]
				maybeName := rest[slash+1:]
				maybeName = strings.TrimRight(maybeName, " .,;")
				if isValidK8sIdent(maybeNs) && maybeName != "" && !strings.Contains(maybeNs, ".") {
					return maybeNs, firstWord(maybeName)
				}
			}
		}
	}
	return "", ""
}

func isValidK8sIdent(s string) bool {
	if len(s) < 2 {
		return false
	}
	for _, r := range s {
		if r != '-' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " \t\n"); i >= 0 {
		return s[:i]
	}
	return s
}
