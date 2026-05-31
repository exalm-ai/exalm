// Package chaos provides `exalm chaos suggest` — resilience risk scoring and
// targeted chaos experiment generation for Kubernetes workloads.
//
// # How it works
//
// 1. Run `exalm k8s analyze --output json > snapshot.json` to capture cluster state.
// 2. Pass the snapshot to this plugin:
//
//	exalm chaos suggest --snapshot-file snapshot.json --apply
//
// The scorer assigns each service a 0–100 risk score based on replica count,
// resource limits, NetworkPolicy coverage, and recent incident history.
// For each service it generates ready-to-apply Litmus ChaosEngine YAML.
//
// # Apply semantics
//
// Because `Mutates()` returns true, the CLI requires `--apply`. When --apply
// is set the plugin prints the YAML for the lowest-risk experiment targeting
// the highest-risk service and asks for explicit confirmation before printing
// the kubectl apply instructions. No kubectl command is ever executed by Exalm.
package chaos

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

const (
	// MaxSnapshotBytes caps the snapshot JSON file size to prevent runaway reads.
	MaxSnapshotBytes = 10 * 1024 * 1024 // 10 MB

	demoNamespace = "production"
	demoService   = "checkout-api"
)

// Plugin is the chaos resilience scoring and experiment suggestion plugin.
type Plugin struct{}

// New returns a new chaos plugin instance.
func New() *Plugin { return &Plugin{} }

// Name returns "chaos".
func (p *Plugin) Name() string { return "chaos" }

// Description returns the short help text shown in `exalm --help`.
func (p *Plugin) Description() string {
	return "Score service resilience risk and suggest targeted chaos experiments"
}

// Mutates returns true because the --apply path prints YAML that can be piped
// to kubectl apply, which mutates the cluster.
func (p *Plugin) Mutates() bool { return true }

// Subcommands returns the single chaos subcommand.
func (p *Plugin) Subcommands() []plugin.Subcommand {
	return []plugin.Subcommand{
		{
			Name:        "suggest",
			Description: "Score services by resilience risk and suggest Litmus chaos experiments",
			Mutates:     true, // --apply path prints Litmus YAML intended for kubectl apply
			Run:         p.suggest,
		},
	}
}

// suggest is the Run function for `exalm chaos suggest`.
func (p *Plugin) suggest(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
	snapshotFile := args.Flags["snapshot-file"]
	namespace := args.Flags["namespace"]
	applyMode := args.Flags["apply"] == "true"

	// No snapshot file: return a helpful instructional report with a demo score.
	if snapshotFile == "" {
		return noSnapshotReport(namespace), nil
	}

	snap, err := loadSnapshot(filepath.Clean(snapshotFile))
	if err != nil {
		return plugin.Report{}, fmt.Errorf("chaos suggest: load snapshot: %w", err)
	}

	// Namespace filter.
	if namespace != "" {
		snap = filterByNamespace(snap, namespace)
	}

	scores := ScoreServices(snap)
	if len(scores) == 0 {
		return plugin.Report{
			Title:   "Chaos resilience assessment",
			Summary: "No services found in the snapshot" + nsHint(namespace) + ".",
		}, nil
	}

	findings := scoresToFindings(scores)

	summary := fmt.Sprintf(
		"%d services scored — %d critical, %d high, %d medium, %d low risk.",
		len(scores),
		countSeverity(findings, plugin.SeverityCritical),
		countSeverity(findings, plugin.SeverityHigh),
		countSeverity(findings, plugin.SeverityMedium),
		countSeverity(findings, plugin.SeverityLow),
	)

	report := plugin.Report{
		Title:    "Chaos resilience assessment",
		Summary:  summary,
		Findings: findings,
	}

	// Apply mode: prompt to apply the safest experiment for the highest-risk service.
	if applyMode {
		if err := runApplyMode(ctx, scores, args); err != nil {
			return report, err
		}
	}

	return report, nil
}

// runApplyMode prints confirmation prompt and YAML for the highest-risk service.
func runApplyMode(_ context.Context, scores []ResilienceScore, args plugin.RunArgs) error {
	if len(scores) == 0 {
		return nil
	}
	top := scores[0] // already sorted descending by score
	if len(top.Experiments) == 0 {
		return nil
	}

	// Pick the lowest-risk experiment of the highest-risk service.
	exp := lowestRiskExperiment(top.Experiments)

	stdout := args.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stdin := args.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}

	fmt.Fprintf(stdout, "\n"+ //nolint:errcheck // best-effort stdout output
		"WARNING: Chaos experiment will kill pods in the %s/%s deployment.\n"+
		"Apply chaos experiment %q to %s/%s? This will kill pods. [y/N]: ",
		top.Namespace, top.Service,
		exp.Name,
		top.Namespace, top.Service,
	)

	scanner := bufio.NewScanner(stdin)
	scanner.Scan()
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))

	if answer != "y" && answer != "yes" {
		fmt.Fprintln(stdout, "Aborted — no changes made.") //nolint:errcheck // best-effort stdout output
		return nil
	}

	fmt.Fprintf(stdout, "\nApply the following YAML with:\n  kubectl apply -f -\n\n---\n%s\n", exp.LitmusYAML) //nolint:errcheck // best-effort stdout output
	return nil
}

// lowestRiskExperiment returns the experiment with the lowest risk level from the list.
// Priority: low < medium < high.
func lowestRiskExperiment(exps []ChaosExperiment) ChaosExperiment {
	best := exps[0]
	for _, e := range exps[1:] {
		if riskRank(e.RiskLevel) < riskRank(best.RiskLevel) {
			best = e
		}
	}
	return best
}

func riskRank(level string) int {
	switch level {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	}
	return 2
}

// scoresToFindings converts ResilienceScore entries into plugin.Finding values.
func scoresToFindings(scores []ResilienceScore) []plugin.Finding {
	findings := make([]plugin.Finding, 0, len(scores))
	for _, rs := range scores {
		if len(rs.Experiments) == 0 {
			continue
		}
		topExp := rs.Experiments[0]

		detail := strings.Join(rs.Reasons, "\n")
		if rs.LitmusYAML() != "" {
			detail += "\n---YAML---\n" + rs.LitmusYAML()
		}

		findings = append(findings, plugin.Finding{
			Severity:   scoreToSeverity(rs.Score),
			Category:   "Chaos",
			Title:      fmt.Sprintf("%s/%s — risk score %d/100", rs.Namespace, rs.Service, rs.Score),
			Detail:     detail,
			Suggestion: fmt.Sprintf("%s: %s", topExp.Name, topExp.Description),
		})
	}
	return findings
}

// LitmusYAML returns the YAML for the first experiment attached to a ResilienceScore.
// This is a method helper used only inside this file; it avoids field pollution on
// the scorer struct.
func (rs ResilienceScore) LitmusYAML() string {
	if len(rs.Experiments) == 0 {
		return ""
	}
	return rs.Experiments[0].LitmusYAML
}

// scoreToSeverity maps a numeric risk score to a plugin.Severity level.
func scoreToSeverity(score int) plugin.Severity {
	switch {
	case score >= 75:
		return plugin.SeverityCritical
	case score >= 50:
		return plugin.SeverityHigh
	case score >= 25:
		return plugin.SeverityMedium
	default:
		return plugin.SeverityLow
	}
}

// noSnapshotReport returns the instructional report shown when no --snapshot-file
// is provided. It includes a demo score to illustrate the output format.
func noSnapshotReport(namespace string) plugin.Report {
	hint := ""
	if namespace != "" {
		hint = fmt.Sprintf(" (namespace: %s)", namespace)
	}

	demoSnap := ClusterSnapshot{
		ResourceGaps: []ResourceGap{
			{Namespace: demoNamespace, Service: demoService, MissingCPU: true, MissingMemory: true, BestEffort: true},
		},
		UncoveredNamespaces: []string{demoNamespace},
		ReplicaSetIssues: []ReplicaSetIssue{
			{Namespace: demoNamespace, Name: demoService, Desired: 1, Ready: 1},
		},
		CriticalHighIncidents: 2,
	}
	demoScores := ScoreServices(demoSnap)
	demoFindings := scoresToFindings(demoScores)

	for i := range demoFindings {
		demoFindings[i].Title = "[DEMO] " + demoFindings[i].Title
	}

	return plugin.Report{
		Title: "Chaos resilience assessment",
		Summary: fmt.Sprintf(
			"No snapshot file provided%s. "+
				"Pass --snapshot-file <path> to score real services.\n\n"+
				"Generate a snapshot with:\n"+
				"  exalm k8s analyze --output json > snapshot.json\n"+
				"Then run:\n"+
				"  exalm chaos suggest --snapshot-file snapshot.json --apply\n\n"+
				"Demo output below (using synthetic data).",
			hint,
		),
		Findings: demoFindings,
	}
}

// loadSnapshot reads and unmarshals a ClusterSnapshot from a JSON file produced
// by `exalm k8s analyze --output json`.
func loadSnapshot(path string) (ClusterSnapshot, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path comes from user-supplied --file flag, validated before use
	if err != nil {
		return ClusterSnapshot{}, fmt.Errorf("open snapshot file: %w", err)
	}
	defer f.Close()

	// The k8s analyze JSON output is a plugin.Report; the snapshot lives in the
	// Raw field as an embedded JSON string, or the entire file may be a direct
	// ClusterSnapshot JSON. We try both shapes.
	//
	// io.ReadAll(io.LimitReader) is used rather than a single f.Read call because
	// the io.Reader contract allows partial reads; a single call may silently
	// truncate large files delivered in multiple OS blocks.
	rawBytes, err := io.ReadAll(io.LimitReader(f, int64(MaxSnapshotBytes)+1))
	if err != nil {
		return ClusterSnapshot{}, fmt.Errorf("read snapshot file: %w", err)
	}
	if len(rawBytes) > MaxSnapshotBytes {
		return ClusterSnapshot{}, fmt.Errorf("snapshot file exceeds %d bytes", MaxSnapshotBytes)
	}

	// Try direct ClusterSnapshot first.
	var snap ClusterSnapshot
	if err := json.Unmarshal(rawBytes, &snap); err == nil {
		return snap, nil
	}

	// Try plugin.Report wrapper — extract Raw field.
	var report struct {
		Raw string `json:"raw"`
	}
	if err := json.Unmarshal(rawBytes, &report); err != nil {
		return ClusterSnapshot{}, fmt.Errorf("parse snapshot JSON: %w", err)
	}
	if report.Raw == "" {
		return ClusterSnapshot{}, fmt.Errorf("snapshot file contains no 'raw' field with cluster data")
	}
	if err := json.Unmarshal([]byte(report.Raw), &snap); err != nil {
		return ClusterSnapshot{}, fmt.Errorf("parse cluster snapshot from raw field: %w", err)
	}
	return snap, nil
}

// filterByNamespace returns a copy of the snapshot filtered to a single namespace.
func filterByNamespace(snap ClusterSnapshot, ns string) ClusterSnapshot {
	out := ClusterSnapshot{
		TotalIncidents:        snap.TotalIncidents,
		CriticalHighIncidents: snap.CriticalHighIncidents,
	}
	for _, g := range snap.ResourceGaps {
		if g.Namespace == ns {
			out.ResourceGaps = append(out.ResourceGaps, g)
		}
	}
	for _, r := range snap.ReplicaSetIssues {
		if r.Namespace == ns {
			out.ReplicaSetIssues = append(out.ReplicaSetIssues, r)
		}
	}
	for _, d := range snap.Deployments {
		if d.Namespace == ns {
			out.Deployments = append(out.Deployments, d)
		}
	}
	for _, u := range snap.UncoveredNamespaces {
		if u == ns {
			out.UncoveredNamespaces = append(out.UncoveredNamespaces, u)
		}
	}
	return out
}

// countSeverity counts findings with the given severity.
func countSeverity(findings []plugin.Finding, sev plugin.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

// nsHint returns a namespace qualifier string for empty-result messages.
func nsHint(ns string) string {
	if ns == "" {
		return ""
	}
	return fmt.Sprintf(" in namespace %q", ns)
}
