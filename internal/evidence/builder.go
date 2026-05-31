// Package evidence assembles a verifiable evidence chain for each AI-generated
// or rule-based RCA. Users can see exactly which log lines, metric values,
// events, and cluster changes back each finding, with a deep-link or kubectl
// command to retrieve the full context themselves.
//
// Competitive gap:
//   - Komodor's Klaudia AI is opaque about evidence — its RCA text is the only
//     output (komodor_config.json weakness #4: "AI RCA evidence-chain
//     transparency is opaque relative to tools that expose exact log lines and
//     metric values backing each conclusion").
//   - OpenObserve's AI SRE Agent has the evidence chain but exposes it only
//     inside the agent output, not as a queryable first-class field
//     (openobserve_config.json strength #4 acknowledges this but no
//     queryable surface exists).
//
// Exalm puts EvidenceItem on every Finding, so the UI, the MCP server, and
// downstream consumers all read it the same way.
package evidence

import (
	"fmt"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/internal/changestore"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Source is the data needed to build evidence. Plugins assemble this from
// their snapshots, then pass it to Build.
type Source struct {
	// LogTails maps "namespace/pod/container" → tail content.
	LogTails map[string]string
	// EventsForResource maps "namespace/resource-name" → list of K8s events
	// (already in user-facing string form).
	EventsForResource map[string][]string
	// MetricsForResource maps "namespace/resource-name" → label/value pairs
	// (e.g. "container_memory_working_set_bytes" → "1.2Gi").
	MetricsForResource map[string]map[string]string
}

// Build returns a slice of EvidenceItem for the given finding. The function is
// non-destructive and idempotent — running it twice with the same inputs
// produces the same output. Sources that are nil or empty contribute nothing,
// so it's safe to call with a partial Source.
func Build(finding plugin.Finding, src Source, changes []changestore.ChangeEvent, now time.Time) []plugin.EvidenceItem {
	var out []plugin.EvidenceItem

	ns, name := extractNamespaceAndName(finding.Title)

	// 1. Log evidence — any tail line containing an error-ish keyword.
	if src.LogTails != nil && name != "" {
		prefix := ns + "/" + name + "/"
		for key, tail := range src.LogTails {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			snippet := firstErrorLine(tail)
			if snippet == "" {
				continue
			}
			container := strings.TrimPrefix(key, prefix)
			out = append(out, plugin.EvidenceItem{
				Kind:    "log",
				Source:  container,
				Excerpt: truncate(snippet, 200),
				At:      now,
				Anchor:  fmt.Sprintf("kubectl logs -n %s %s -c %s --tail=200", ns, name, container),
			})
		}
	}

	// 2. Event evidence — Warning events for this resource.
	if src.EventsForResource != nil && name != "" {
		key := ns + "/" + name
		for _, ev := range src.EventsForResource[key] {
			out = append(out, plugin.EvidenceItem{
				Kind:    "event",
				Source:  key,
				Excerpt: truncate(ev, 200),
				At:      now,
				Anchor:  fmt.Sprintf("kubectl describe pod -n %s %s", ns, name),
			})
		}
	}

	// 3. Metric evidence — labelled values associated with the resource.
	if src.MetricsForResource != nil && name != "" {
		key := ns + "/" + name
		for metric, value := range src.MetricsForResource[key] {
			out = append(out, plugin.EvidenceItem{
				Kind:    "metric",
				Source:  metric,
				Excerpt: value,
				At:      now,
				Anchor:  fmt.Sprintf("# %s = %s (recorded at %s)", metric, value, now.Format(time.RFC3339)),
			})
		}
	}

	// 4. Change evidence — any recent change referenced by the finding's
	// LikelyCause OR matching the finding's resource directly.
	for _, c := range changes {
		if finding.LikelyCause != nil && finding.LikelyCause.ID == c.ID {
			out = append(out, plugin.EvidenceItem{
				Kind:    "change",
				Source:  c.ID,
				Excerpt: fmt.Sprintf("%s %s/%s %s by %s", c.Kind, c.Namespace, c.Name, c.Action, fallback(c.Actor, "unknown")),
				At:      c.Timestamp,
				Anchor:  fallback(c.DiffURL, fmt.Sprintf("kubectl describe %s -n %s %s", strings.ToLower(c.Kind), c.Namespace, c.Name)),
			})
			continue
		}
		// Direct namespace+name match (no LikelyCause yet, but co-located).
		if c.Namespace == ns && (strings.EqualFold(c.Name, name) || strings.HasPrefix(name, c.Name+"-")) {
			out = append(out, plugin.EvidenceItem{
				Kind:    "change",
				Source:  c.ID,
				Excerpt: fmt.Sprintf("%s %s/%s %s by %s", c.Kind, c.Namespace, c.Name, c.Action, fallback(c.Actor, "unknown")),
				At:      c.Timestamp,
				Anchor:  fallback(c.DiffURL, fmt.Sprintf("kubectl describe %s -n %s %s", strings.ToLower(c.Kind), c.Namespace, c.Name)),
			})
		}
	}
	return out
}

// extractNamespaceAndName parses titles like:
//
//	"CrashLoopBackOff: exalm-prod/api-gateway-7c9b"
//	"Selector mismatch: ns/svc"
//	"Log db-error in exalm-prod/api-gateway-7c9b"
//
// Returns ("", "") when no match. Best-effort — extra-cautious to avoid
// matching image paths like gcr.io/google-containers.
func extractNamespaceAndName(title string) (ns, name string) {
	for _, sep := range []string{": ", " in ", "blocked: "} {
		if i := strings.Index(title, sep); i >= 0 {
			rest := title[i+len(sep):]
			if slash := strings.Index(rest, "/"); slash > 0 {
				maybeNs := rest[:slash]
				maybeName := rest[slash+1:]
				// Trim trailing punctuation/garbage.
				maybeName = strings.TrimRight(maybeName, " .,;")
				if isValidIdent(maybeNs) && maybeName != "" && !strings.Contains(maybeNs, ".") {
					return maybeNs, firstWord(maybeName)
				}
			}
		}
	}
	return "", ""
}

func isValidIdent(s string) bool {
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

// firstWord returns the first whitespace-delimited token of s.
func firstWord(s string) string {
	if i := strings.IndexAny(s, " \t\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// firstErrorLine scans a log tail for the first line containing an error
// indicator. Returns the empty string if nothing matches.
func firstErrorLine(tail string) string {
	indicators := []string{"ERROR", "error", "panic", "Panic", "FATAL", "fatal", "Exception", "connection refused", "timeout", "OOM"}
	for _, line := range strings.Split(tail, "\n") {
		for _, ind := range indicators {
			if strings.Contains(line, ind) {
				return line
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func fallback(v, dflt string) string {
	if v == "" {
		return dflt
	}
	return v
}
