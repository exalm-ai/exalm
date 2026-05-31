// Package chaos provides resilience risk scoring and chaos experiment suggestions.
//
// The scorer evaluates cluster state captured in a ClusterSnapshot and assigns
// each service a 0–100 risk score based on replica count, resource limits,
// network policy coverage, and incident history. Higher scores indicate services
// most in need of chaos-driven resilience validation.
package chaos

// ClusterSnapshot is a lightweight, decoupled view of cluster state used by
// the chaos scorer. It is populated either from a JSON file produced by
// `exalm k8s analyze --output json` or from flag-supplied overrides.
// It deliberately avoids importing k8s.io/client-go so the chaos package
// stays testable without a running cluster.
type ClusterSnapshot struct {
	// ResourceGaps lists containers that are missing CPU or memory limits.
	ResourceGaps []ResourceGap `json:"resource_gaps"`
	// UncoveredNamespaces lists namespaces that have pods but no NetworkPolicy.
	UncoveredNamespaces []string `json:"uncovered_namespaces"`
	// ReplicaSetIssues lists workloads where ready < desired or desired == 1.
	ReplicaSetIssues []ReplicaSetIssue `json:"replica_set_issues"`
	// TotalIncidents is the number of incidents opened in the past 30 days.
	TotalIncidents int `json:"total_incidents"`
	// CriticalHighIncidents is the number of critical or high-severity incidents
	// opened in the past 30 days.
	CriticalHighIncidents int `json:"critical_high_incidents"`
	// Deployments lists all deployments collected from the cluster.
	Deployments []DeploymentSummary `json:"deployments"`
}

// ResourceGap records a container that is missing CPU or memory limits.
type ResourceGap struct {
	Namespace     string `json:"namespace"`
	Service       string `json:"service"` // owning deployment or pod name
	MissingCPU    bool   `json:"missing_cpu"`
	MissingMemory bool   `json:"missing_memory"`
	BestEffort    bool   `json:"best_effort"` // both requests AND limits absent
}

// ReplicaSetIssue records a workload where the desired replica count is 1
// or where fewer than 2 replicas are ready — indicating no redundancy.
type ReplicaSetIssue struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Desired   int32  `json:"desired"`
	Ready     int32  `json:"ready"`
}

// DeploymentSummary is a compact view of one Deployment's availability.
type DeploymentSummary struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Ready     int32  `json:"ready"`
	Desired   int32  `json:"desired"`
}

// ResilienceScore is the scorer's assessment of one service.
type ResilienceScore struct {
	// Namespace and Service identify the workload.
	Namespace string
	Service   string
	// Score is 0–100; higher = more at risk of failure under load.
	Score int
	// Reasons lists the risk factors that contributed to the score.
	Reasons []string
	// Experiments are the suggested chaos experiments for this service,
	// ordered from most to least impactful.
	Experiments []ChaosExperiment
}

// ChaosExperiment describes one targeted chaos experiment.
type ChaosExperiment struct {
	// Name is the short experiment identifier used in Litmus ChaosEngine YAML.
	Name string // "pod-kill", "network-partition", "cpu-stress", "memory-pressure"
	// Description is a one-line human-readable summary.
	Description string
	// LitmusYAML is a ready-to-apply Litmus ChaosEngine manifest.
	LitmusYAML string
	// RiskLevel is "low", "medium", or "high".
	RiskLevel string
}

// ScoreServices evaluates every unique namespace/service pair found in the
// snapshot and returns a ResilienceScore for each, sorted by Score descending.
func ScoreServices(snap ClusterSnapshot) []ResilienceScore {
	// Build a set of all namespace/service pairs referenced in the snapshot.
	type key struct{ ns, svc string }
	services := map[key]struct{}{}

	for _, g := range snap.ResourceGaps {
		services[key{g.Namespace, g.Service}] = struct{}{}
	}
	for _, r := range snap.ReplicaSetIssues {
		services[key{r.Namespace, r.Name}] = struct{}{}
	}
	for _, d := range snap.Deployments {
		services[key{d.Namespace, d.Name}] = struct{}{}
	}

	if len(services) == 0 {
		return nil
	}

	// Build lookup maps for quick scoring.
	gapByService := map[key]ResourceGap{}
	for _, g := range snap.ResourceGaps {
		gapByService[key{g.Namespace, g.Service}] = g
	}

	replicaByService := map[key]ReplicaSetIssue{}
	for _, r := range snap.ReplicaSetIssues {
		replicaByService[key{r.Namespace, r.Name}] = r
	}

	deployByService := map[key]DeploymentSummary{}
	for _, d := range snap.Deployments {
		deployByService[key{d.Namespace, d.Name}] = d
	}

	uncoveredNS := map[string]bool{}
	for _, ns := range snap.UncoveredNamespaces {
		uncoveredNS[ns] = true
	}

	var scores []ResilienceScore

	for k := range services {
		rs := scoreOne(
			k.ns, k.svc,
			gapByService[k],
			replicaByService[k],
			deployByService[k],
			uncoveredNS[k.ns],
			snap.CriticalHighIncidents,
		)
		scores = append(scores, rs)
	}

	// Sort descending by score; tie-break alphabetically for determinism.
	sortScores(scores)
	return scores
}

// scoreOne computes the ResilienceScore for a single namespace/service pair.
func scoreOne(
	ns, svc string,
	gap ResourceGap,
	replica ReplicaSetIssue,
	deploy DeploymentSummary,
	uncoveredNS bool,
	criticalHighIncidents int,
) ResilienceScore {
	rs := ResilienceScore{Namespace: ns, Service: svc}

	// --- Single-replica check ---
	// Check both ReplicaSetIssue and Deployment.
	isSingleReplica := (replica.Name != "" && (replica.Desired == 1 || replica.Ready < 2))
	if deploy.Name != "" && (deploy.Desired == 1 || deploy.Ready < 2) {
		isSingleReplica = true
	}
	if isSingleReplica {
		rs.Score += 25
		rs.Reasons = append(rs.Reasons, "Single replica — no redundancy")
	}

	// --- Resource limit checks ---
	if gap.Service != "" {
		if gap.BestEffort {
			// BestEffort supersedes the individual missing-limits checks.
			rs.Score += 20
			rs.Reasons = append(rs.Reasons, "BestEffort QoS — eviction risk under pressure")
		} else {
			if gap.MissingCPU {
				rs.Score += 15
				rs.Reasons = append(rs.Reasons, "No CPU limits — CPU starvation risk")
			}
			if gap.MissingMemory {
				rs.Score += 15
				rs.Reasons = append(rs.Reasons, "No memory limits — OOM risk")
			}
		}
	}

	// --- Network policy coverage ---
	if uncoveredNS {
		rs.Score += 20
		rs.Reasons = append(rs.Reasons, "No NetworkPolicy — unrestricted lateral movement")
	}

	// --- Incident rate ---
	if criticalHighIncidents > 0 {
		rs.Score += 15
		rs.Reasons = append(rs.Reasons, "Recent high/critical incidents")
	}

	// Cap at 100.
	if rs.Score > 100 {
		rs.Score = 100
	}

	rs.Experiments = selectExperiments(ns, svc, rs.Score)
	return rs
}

// selectExperiments chooses chaos experiments based on the risk score.
func selectExperiments(ns, svc string, score int) []ChaosExperiment {
	switch {
	case score >= 75:
		return []ChaosExperiment{
			buildExperiment("pod-kill", ns, svc),
			buildExperiment("network-partition", ns, svc),
		}
	case score >= 50:
		return []ChaosExperiment{
			buildExperiment("cpu-stress", ns, svc),
			buildExperiment("memory-pressure", ns, svc),
		}
	case score >= 25:
		return []ChaosExperiment{
			buildExperiment("pod-kill", ns, svc),
		}
	default:
		return []ChaosExperiment{
			buildExperiment("pod-kill", ns, svc),
		}
	}
}

// buildExperiment constructs a ChaosExperiment for the given type and workload.
func buildExperiment(name, ns, svc string) ChaosExperiment {
	var desc, risk string
	switch name {
	case "pod-kill":
		desc = "Randomly terminate a pod replica to validate restart/recovery behaviour"
		risk = "low"
	case "network-partition":
		desc = "Inject network latency and packet loss to validate circuit-breaker and timeout handling"
		risk = "high"
	case "cpu-stress":
		desc = "Saturate CPU to validate throttling resilience and autoscaler response"
		risk = "medium"
	case "memory-pressure":
		desc = "Apply memory pressure to validate OOM handling and eviction recovery"
		risk = "medium"
	}
	return ChaosExperiment{
		Name:        name,
		Description: desc,
		LitmusYAML:  GenerateLitmusYAML(name, ns, svc),
		RiskLevel:   risk,
	}
}

// sortScores sorts a ResilienceScore slice by Score descending, then by
// Namespace+Service ascending for deterministic output.
func sortScores(scores []ResilienceScore) {
	n := len(scores)
	for i := 1; i < n; i++ {
		for j := i; j > 0; j-- {
			a, b := scores[j-1], scores[j]
			if a.Score < b.Score ||
				(a.Score == b.Score && (a.Namespace+"/"+a.Service) > (b.Namespace+"/"+b.Service)) {
				scores[j-1], scores[j] = scores[j], scores[j-1]
			} else {
				break
			}
		}
	}
}
