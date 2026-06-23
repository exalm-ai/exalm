package web

// dashboard.go maps the internal plugin.Report into the JSON contract the
// redesigned single-page dashboard consumes (see HANDOFF.md). All derivation
// is done from the findings the server already holds; per-namespace pod counts
// come from an optional PodInfo provider supplied by the k8s plugin.

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"sort"
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// PodInfo carries real pod inventory for the dashboard, supplied by the k8s
// plugin from its most recently collected Snapshot. The provider is optional;
// when absent the dashboard still renders, with pod-derived metrics at zero.
type PodInfo struct {
	Total       int            `json:"total"`
	Unhealthy   int            `json:"unhealthy"`
	ByNamespace map[string]int `json:"byNamespace"`
}

// nsPalette cycles deterministic namespace colours (matches the reference set
// in the design prototype). Index by sorted-namespace position.
var nsPalette = []string{
	"#4c8dff", "#7b5bff", "#3ddc97", "#f5c542", "#ff6fb5", "#ff9f45", "#5b9bff", "#34d399",
}

// dashNamespace is one entry in the namespace selector / donut.
type dashNamespace struct {
	Key      string `json:"key"`
	Color    string `json:"color"`
	Crit     int    `json:"crit"`
	High     int    `json:"high"`
	Med      int    `json:"med"`
	Low      int    `json:"low"`
	Pods     int    `json:"pods"`
	Findings int    `json:"findings"`
}

// dashFinding is one finding in the shape the front-end expects.
type dashFinding struct {
	ID         string `json:"id"`
	NsKey      string `json:"nsKey"`
	Group      string `json:"group"`
	Sev        string `json:"sev"`
	Title      string `json:"title"`
	Ns         string `json:"ns"`
	Age        string `json:"age"`
	Restarts   string `json:"restarts"`
	Reason     string `json:"reason"`
	Root       string `json:"root"`
	Log        string `json:"log"`
	Suggestion string `json:"suggestion"`
	Fix        bool   `json:"fix"`
}

// dashboardPayload is the full JSON document served at /api/dashboard and
// embedded into the page for instant first paint.
type dashboardPayload struct {
	Namespaces []dashNamespace `json:"namespaces"`
	Findings   []dashFinding   `json:"findings"`
	Provider   string          `json:"provider"`
	Raw        string          `json:"raw"`
	Title      string          `json:"title"`
	Summary    string          `json:"summary"`
	// Pods / Unhealthy are cluster-wide totals from the pod-info provider, used
	// for the "all namespaces" scope. Zero when no provider is wired.
	Pods        int  `json:"pods"`
	Unhealthy   int  `json:"unhealthy"`
	AutoRefresh bool `json:"autoRefresh"`
}

// groupOf folds the many internal categories into the six display groups the
// design uses (Other, Pods, Resources, Security, Services, Workloads).
func groupOf(category string) string {
	switch category {
	case "Pods":
		return "Pods"
	case "Resources", "Storage":
		return "Resources"
	case "Security", "RBAC":
		return "Security"
	case "Services", "Networking":
		return "Services"
	case "Workloads", "Scaling", "Jobs", "Nodes", "Node":
		return "Workloads"
	default:
		return "Other"
	}
}

// sevKey normalises plugin severities to the dashboard's keys. "info" has no
// dedicated lane in the design, so it folds into "low".
func sevKey(sev plugin.Severity) string {
	switch sev {
	case plugin.SeverityCritical:
		return "critical"
	case plugin.SeverityHigh:
		return "high"
	case plugin.SeverityMedium:
		return "medium"
	case plugin.SeverityLow, plugin.SeverityInfo:
		return "low"
	default:
		return "low"
	}
}

// findingID derives a stable id from a finding's identity so the front-end can
// reference it and the fix endpoint can look it back up across re-collections.
func findingID(f plugin.Finding) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(f.Category + "\x1f" + f.Title + "\x1f" + f.Source))
	return fmt.Sprintf("f%08x", h.Sum32())
}

// Exalm titles format the resource as "<Reason>: <namespace>/<name>", so the
// path after the last ": " is the most reliable. afterColonPathRe captures
// that; nsNamePathRe is a looser fallback for titles without the colon form.
var (
	afterColonPathRe = regexp.MustCompile(`:\s+([a-z0-9][a-z0-9.-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)`)
	nsNamePathRe     = regexp.MustCompile(`([a-z0-9][a-z0-9.-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)`)
)

// nsNameFromTitle extracts (namespace, "namespace/name") from a finding title,
// preferring the path that follows ": " so phrases like "requests/limits" don't
// get mistaken for a namespace/name.
func nsNameFromTitle(title string) (ns, path string) {
	if m := afterColonPathRe.FindStringSubmatch(title); m != nil {
		return m[1], m[1] + "/" + m[2]
	}
	if m := nsNamePathRe.FindStringSubmatch(title); m != nil {
		return m[1], m[1] + "/" + m[2]
	}
	return "", ""
}

// namespaceOf extracts the best-available namespace for a finding.
func namespaceOf(f plugin.Finding) string {
	if f.Remediation != nil && f.Remediation.Namespace != "" {
		return f.Remediation.Namespace
	}
	if f.LikelyCause != nil && f.LikelyCause.Namespace != "" {
		return f.LikelyCause.Namespace
	}
	if ns, _ := nsNameFromTitle(f.Title); ns != "" {
		return ns
	}
	return "cluster"
}

// resourcePath returns the "namespace/resource" path shown under each finding.
func resourcePath(f plugin.Finding, nsKey string) string {
	if f.Remediation != nil && f.Remediation.Name != "" {
		return nsKey + "/" + f.Remediation.Name
	}
	if _, path := nsNameFromTitle(f.Title); path != "" {
		return path
	}
	if nsKey != "" && nsKey != "cluster" {
		return nsKey
	}
	return f.Source
}

var restartsRe = regexp.MustCompile(`restarted (\d+) time`)

// restartsOf pulls a restart count out of the finding detail when present.
func restartsOf(f plugin.Finding) string {
	if m := restartsRe.FindStringSubmatch(f.Detail); m != nil {
		return m[1]
	}
	return "—"
}

// firstSentence returns the first sentence of s (used as the short "reason").
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	if i := strings.IndexAny(s, ".\n"); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// rootOf builds the root-cause line, enriching with change-correlation when set.
func rootOf(f plugin.Finding) string {
	root := strings.TrimSpace(f.Detail)
	if f.LikelyCause != nil {
		lc := f.LikelyCause
		ago := humanizeAgo(lc.AgoSeconds)
		cause := fmt.Sprintf("Likely linked to %s %s/%s", lc.Kind, lc.Namespace, lc.Name)
		if lc.Actor != "" {
			cause += " by " + lc.Actor
		}
		if ago != "" {
			cause += " (" + ago + ")"
		}
		if root == "" {
			root = cause
		} else {
			root += " — " + cause
		}
	}
	if root == "" {
		return "—"
	}
	return root
}

// logOf joins the finding's evidence excerpts into a log snippet.
func logOf(f plugin.Finding) string {
	var b strings.Builder
	for _, e := range f.Evidence {
		if e.Excerpt == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(e.Excerpt)
	}
	return b.String()
}

// humanizeAgo renders a seconds-ago duration compactly ("3h", "2d", "12m").
func humanizeAgo(sec int64) string {
	switch {
	case sec <= 0:
		return ""
	case sec < 3600:
		return fmt.Sprintf("%dm", sec/60)
	case sec < 86400:
		return fmt.Sprintf("%dh", sec/3600)
	default:
		return fmt.Sprintf("%dd", sec/86400)
	}
}

var usingProviderRe = regexp.MustCompile(`using ([A-Za-z0-9_-]+)`)

// providerFromSummary extracts the LLM provider name from the report summary
// ("... using ollama."). Falls back to "llm".
func providerFromSummary(summary string) string {
	if m := usingProviderRe.FindStringSubmatch(summary); m != nil {
		return m[1]
	}
	return "llm"
}

// buildDashboard maps a Report (+ optional pod inventory) into the dashboard
// JSON contract. provider names the LLM ("ollama", "claude", …); when empty it
// is parsed from the report summary as a best-effort fallback.
func buildDashboard(r plugin.Report, podInfo *PodInfo, provider string, autoRefresh bool) dashboardPayload {
	type nsAcc struct{ crit, high, med, low, findings int }
	accs := map[string]*nsAcc{}
	order := []string{}
	ensure := func(ns string) *nsAcc {
		a := accs[ns]
		if a == nil {
			a = &nsAcc{}
			accs[ns] = a
			order = append(order, ns)
		}
		return a
	}

	findings := make([]dashFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		ns := namespaceOf(f)
		a := ensure(ns)
		a.findings++
		switch sevKey(f.Severity) {
		case "critical":
			a.crit++
		case "high":
			a.high++
		case "medium":
			a.med++
		default:
			a.low++
		}
		findings = append(findings, dashFinding{
			ID:         findingID(f),
			NsKey:      ns,
			Group:      groupOf(f.Category),
			Sev:        sevKey(f.Severity),
			Title:      f.Title,
			Ns:         resourcePath(f, ns),
			Age:        "—",
			Restarts:   restartsOf(f),
			Reason:     firstSentence(f.Detail),
			Root:       rootOf(f),
			Log:        logOf(f),
			Suggestion: f.Suggestion,
			Fix:        f.Remediation != nil,
		})
	}

	// Fold in namespaces that have pods but no findings, so the selector and
	// the cluster-wide pod total reflect the whole cluster.
	if podInfo != nil {
		for ns := range podInfo.ByNamespace {
			ensure(ns)
		}
	}

	// Sort by findings desc, then name, for a stable, sensible ordering.
	sort.SliceStable(order, func(i, j int) bool {
		ai, aj := accs[order[i]], accs[order[j]]
		if ai.findings != aj.findings {
			return ai.findings > aj.findings
		}
		return order[i] < order[j]
	})

	namespaces := make([]dashNamespace, 0, len(order))
	for i, ns := range order {
		a := accs[ns]
		pods := 0
		if podInfo != nil {
			pods = podInfo.ByNamespace[ns]
		}
		namespaces = append(namespaces, dashNamespace{
			Key:      ns,
			Color:    nsPalette[i%len(nsPalette)],
			Crit:     a.crit,
			High:     a.high,
			Med:      a.med,
			Low:      a.low,
			Pods:     pods,
			Findings: a.findings,
		})
	}

	clusterPods, clusterUnhealthy := 0, 0
	if podInfo != nil {
		clusterPods = podInfo.Total
		clusterUnhealthy = podInfo.Unhealthy
	}

	if provider == "" {
		provider = providerFromSummary(r.Summary)
	}

	return dashboardPayload{
		Namespaces:  namespaces,
		Findings:    findings,
		Provider:    provider,
		Raw:         r.Raw,
		Title:       r.Title,
		Summary:     r.Summary,
		Pods:        clusterPods,
		Unhealthy:   clusterUnhealthy,
		AutoRefresh: autoRefresh,
	}
}
