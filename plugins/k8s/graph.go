package k8s

// graph.go is the Kubernetes resource-graph edge registry consumed by the
// investigation framework: the canonical Edge strings shared by the plan,
// the evidence items, and the UI tree, each with WHY the relationship
// matters — surfaced verbatim when the copilot explains its plan.

import "github.com/exalm-ai/exalm/internal/investigate"

// edgeRegistry lists every relationship the k8s copilot knows how to follow,
// ordered roughly "closest to the pod first".
var edgeRegistry = []investigate.Edge{
	{Name: "pod→logs", Collector: "previous-logs", Why: "the previous container's logs show why the last run exited"},
	{Name: "pod→ownerDeployment", Collector: "owner-chain", Why: "the owning workload declares the pod's spec — limits, probes, image — where most root causes live"},
	{Name: "pod→node", Collector: "node-detail", Why: "node pressure, taints, and capacity explain evictions and scheduling failures"},
	{Name: "pod→configmap", Collector: "configmaps", Why: "configuration referenced by the pod may have changed or be missing"},
	{Name: "pod→secret", Collector: "secrets", Why: "missing or rotated secrets break startup and image pulls (existence only — values never read)"},
	{Name: "pod→serviceAccount→rbac", Collector: "rbac", Why: "permission errors trace back to the pod's ServiceAccount grants"},
	{Name: "pod→pvc→pv→storageclass", Collector: "storage-chain", Why: "unbound claims and missing storage classes block scheduling and mounts"},
	{Name: "pod→service→endpointslice", Collector: "service-endpoints", Why: "a service with no ready endpoints means traffic never reaches the pod"},
	{Name: "pod→netpol", Collector: "netpol", Why: "network policies can silently isolate the pod from its dependencies"},
	{Name: "workload→hpa", Collector: "scaling", Why: "an autoscaler at max (or a tight disruption budget) explains saturation and stuck rollouts"},
	{Name: "ns→quota", Collector: "namespace-detail", Why: "an exhausted ResourceQuota or restrictive LimitRange starves new pods"},
	{Name: "resource→changes", Collector: "change-history", Why: "a change shortly before the first failure is the most likely trigger"},
	{Name: "pod→metrics", Collector: "metrics", Why: "resource usage trends distinguish leaks from under-provisioning"},
	{Name: "cluster→dns", Collector: "dns-heuristic", Why: "failed name resolution cascades into timeouts and dependency errors (heuristic — no real resolver)"},
	{Name: "ns→services", Collector: "related-services", Why: "sibling service issues reveal shared-dependency failures"},
	{Name: "resource→history", Collector: "history", Why: "prior investigations and incidents show whether this has happened before and what fixed it"},
}
