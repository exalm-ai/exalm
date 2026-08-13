package web

// dashboard.go maps the internal plugin.Report into the JSON contract the
// redesigned single-page dashboard consumes (see HANDOFF.md). All derivation
// is done from the findings the server already holds; per-namespace pod counts
// come from an optional PodInfo provider supplied by the k8s plugin.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

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
	// Explainability fields (from classify.go via the Finding).
	Confidence string         `json:"confidence,omitempty"` // "low" | "medium" | "high"
	Fixes      []dashFix      `json:"fixes,omitempty"`      // classified temporary + root-cause fixes
	Evidence   []dashEvidence `json:"evidence,omitempty"`   // verifiable supporting items
	// FirstSeen/LastSeen are RFC3339 observation bounds, empty when the
	// producer could not determine them. They are what lets the frontend place
	// findings on a real time axis; a chart cannot be built without them.
	FirstSeen string `json:"firstSeen,omitempty"`
	LastSeen  string `json:"lastSeen,omitempty"`
	// Count is how many times the condition was observed. 0 = uncounted.
	Count int `json:"count,omitempty"`
}

// dashFix is the front-end shape of a classified remediation.
type dashFix struct {
	FixType         string `json:"fixType"` // "temporary" | "root-cause"
	Kind            string `json:"kind"`
	Description     string `json:"description"`
	KubectlCmd      string `json:"kubectlCmd,omitempty"`
	Risk            string `json:"risk,omitempty"`
	Rollback        string `json:"rollback,omitempty"`
	ExpectedOutcome string `json:"expectedOutcome,omitempty"`
	Downtime        string `json:"downtime,omitempty"`
	Resource        string `json:"resource,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name,omitempty"`
	Applicable      bool   `json:"applicable"` // true if the server can auto-apply it (Kind != "advice")
}

// dashEvidence is the front-end shape of an evidence item.
type dashEvidence struct {
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	Excerpt string `json:"excerpt,omitempty"`
	Anchor  string `json:"anchor,omitempty"`
	// Copilot enrichment (empty on non-chat evidence).
	Label       string `json:"label,omitempty"`       // citation key "E1"…
	Edge        string `json:"edge,omitempty"`        // resource-graph edge
	FromCache   bool   `json:"fromCache,omitempty"`   // reused, not re-fetched
	CollectedAt string `json:"collectedAt,omitempty"` // original collection time
}

// applicableKinds are the remediation kinds the server can auto-apply. The
// k8s kinds go through k8s ApplyRemediation; the SSH kinds
// (svc-restart-linux/-windows, iis-pool-recycle) go through the allowlisted
// SSH remediation executor. Anything else (e.g. "advice") is copy-only
// guidance. The dashboard shows an active "Apply this fix" button only for
// kinds listed here; whether ApplyFix is actually wired (a live cluster or a
// remote host) is a separate server-side gate.
var applicableKinds = map[string]bool{
	"rollout-restart": true, "resume-cronjob": true, "delete-pod": true,
	"patch-resource": true, "scale-deployment": true, "add-limits": true,
	"label-resource": true, "cordon-node": true,
	"svc-restart-linux": true, "svc-restart-windows": true, "iis-pool-recycle": true,
}

func mapFixes(fixes []plugin.RemediationAction) []dashFix {
	if len(fixes) == 0 {
		return nil
	}
	out := make([]dashFix, 0, len(fixes))
	for _, a := range fixes {
		out = append(out, dashFix{
			FixType:         a.FixType,
			Kind:            a.Kind,
			Description:     a.Description,
			KubectlCmd:      a.KubectlCmd,
			Risk:            a.Risk,
			Rollback:        a.Rollback,
			ExpectedOutcome: a.ExpectedOutcome,
			Downtime:        a.Downtime,
			Resource:        a.Resource,
			Namespace:       a.Namespace,
			Name:            a.Name,
			Applicable:      applicableKinds[a.Kind],
		})
	}
	return out
}

func mapEvidence(items []plugin.EvidenceItem) []dashEvidence {
	if len(items) == 0 {
		return nil
	}
	out := make([]dashEvidence, 0, len(items))
	for _, e := range items {
		de := dashEvidence{
			Kind: e.Kind, Source: e.Source, Excerpt: e.Excerpt, Anchor: e.Anchor,
			Label: e.Label, Edge: e.Edge, FromCache: e.FromCache,
		}
		if !e.CollectedAt.IsZero() {
			de.CollectedAt = e.CollectedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, de)
	}
	return out
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

	// Analyzer + Stats drive the per-analyzer dashboards (syslog, httplog,
	// eventlog, iis, logs). Empty/nil for the k8s dashboard — the payload
	// stays byte-compatible for existing consumers.
	Analyzer string `json:"analyzer,omitempty"`
	Stats    any    `json:"stats,omitempty"`

	// Dashboards is the settings-filtered dashboard registry driving the
	// SPA navigation. Omitted in legacy single-dashboard mode, in which the
	// frontend falls back to its built-in navigation.
	Dashboards []DashboardDesc `json:"dashboards,omitempty"`
	// SupportsAI mirrors the global settings toggle so the frontend can
	// hide AI affordances everywhere. Nil in legacy mode (treated as true).
	SupportsAI *bool `json:"supportsAI,omitempty"`
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
// reference it and the fix/investigate endpoints can look it back up across
// re-collections. Delegates to plugin.Finding.ID so the web layer, the k8s
// investigation engine, and the MCP server all agree on the same id.
func findingID(f plugin.Finding) string {
	return f.ID()
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

// rfc3339OrEmpty renders a timestamp for the frontend, or "" when the producer
// could not determine it. An em-dash or a substituted "now" would let the UI
// present a guess as an observation.
func rfc3339OrEmpty(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ageOf renders how long ago the finding was last observed. Returns an em-dash
// when the producer supplied no timestamp — the honest answer for a finding
// whose age is genuinely unknown.
func ageOf(f plugin.Finding) string {
	if f.LastSeen == nil || f.LastSeen.IsZero() {
		return "—"
	}
	d := time.Since(*f.LastSeen)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
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
	// Only an explicit root cause (set by classify.go for k8s and by the analyzer
	// findings promoter) may appear under the "Likely cause" label.
	//
	// This deliberately does NOT fall back to Detail. Detail is what was
	// observed; presenting it as a cause both duplicates the line above it and
	// asserts a conclusion nothing derived. Anomaly findings make the problem
	// obvious — the detector knows a bucket moved and says so in Detail, but has
	// no cause to offer, and the card rendered "Likely cause: 70 events in 1m
	// versus a median of 0" as though that were an explanation. The UI omits the
	// line when this returns empty.
	root := strings.TrimSpace(f.RootCause)
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
	// Empty, not an em-dash: the card renders the "Likely cause" line only when
	// this is non-empty, and "—" is truthy in JS, so a placeholder here produced
	// a cause line reading "Likely cause: —".
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
			Age:        ageOf(f),
			Restarts:   restartsOf(f),
			Reason:     firstSentence(f.Detail),
			Root:       rootOf(f),
			Log:        logOf(f),
			Suggestion: f.Suggestion,
			Fix:        f.Remediation != nil,
			Confidence: f.Confidence,
			Fixes:      mapFixes(f.Fixes),
			Evidence:   mapEvidence(f.Evidence),
			FirstSeen:  rfc3339OrEmpty(f.FirstSeen),
			LastSeen:   rfc3339OrEmpty(f.LastSeen),
			Count:      f.Count,
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
