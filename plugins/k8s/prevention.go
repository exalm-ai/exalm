package k8s

// prevention.go recommends long-term prevention (FixType "prevention") for
// the symptom under investigation — distinct from the immediate mitigation
// and the root-cause fix. Static per-symptom mapping; no LLM involved.

import "github.com/exalm-ai/exalm/pkg/plugin"

// preventionCatalog maps symptom keys to preventive actions. Kind "advice"
// keeps them copy-only — prevention is a policy decision, never auto-applied.
var preventionCatalog = map[string][]plugin.RemediationAction{
	"oom-killed": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Set memory requests and limits on every container (enforce with a namespace LimitRange) and alert when working-set exceeds 80% of the limit — catches growth before the OOM kill."},
	},
	"image-pull": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Pin images by digest instead of mutable tags, and rotate imagePullSecrets with an overlap window so deploys never race a credential rotation."},
	},
	"crashloop": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Gate rollouts on a canary/health check so a crashing revision auto-rolls back, and validate ConfigMap/Secret references in CI before deploy."},
	},
	"probe-failure": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Size initialDelaySeconds/failureThreshold from measured startup time (p99, not average), and prefer a startupProbe for slow-booting services."},
	},
	"pending-unschedulable": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Alert on namespace quota utilization above 80% and keep cluster-autoscaler headroom so new pods never wait on capacity."},
	},
	"evicted": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Set resource requests on every pod (unrequested pods are evicted first) and alert on node memory/disk pressure before the kubelet starts evicting."},
	},
	"pvc-stuck": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Monitor PVC capacity and provisioner health; expand volumes before 85% utilization and test the StorageClass path in a canary namespace after storage upgrades."},
	},
	"dns-failure": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Monitor CoreDNS error rates and latency, and include kube-dns egress in every NetworkPolicy template so isolation changes cannot break resolution."},
	},
	"http-5xx": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Add SLO burn-rate alerts on the edge error ratio and require endpoint-readiness gates in the deploy pipeline so traffic never routes to an empty backend."},
	},
	"db-error": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Use connection pooling with health checks and rotate database credentials via a secret manager with dual-validity windows, so rotations never break live connections."},
	},
	"unknown-unhealthy": {
		{Kind: "advice", FixType: "prevention", Risk: "low",
			Description: "Ensure the workload emits structured logs and has liveness/readiness probes — without them, every future investigation starts from less evidence."},
	},
}

// preventionFor returns the preventive actions for the matched symptoms
// (first match wins per key; deduplicated by description).
func preventionFor(symptoms []symptom) []plugin.RemediationAction {
	var out []plugin.RemediationAction
	seen := map[string]bool{}
	for _, s := range symptoms {
		for _, a := range preventionCatalog[s.Key] {
			if !seen[a.Description] {
				seen[a.Description] = true
				out = append(out, a)
			}
		}
	}
	return out
}
