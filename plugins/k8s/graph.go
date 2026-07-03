package k8s

// graph.go is the canonical registry of resource-graph edges the
// investigation planner walks. It is the single source of Edge strings so the
// planner, the evidence items, and the UI tree always agree on names, and it
// records WHY each relationship matters — surfaced verbatim when the copilot
// explains its plan.

// graphEdge documents one relationship the planner can follow from a focus
// resource, and which collector inspects it.
type graphEdge struct {
	Name      string // canonical edge string, e.g. "pod→ownerDeployment"
	Collector string // key into the executePlan dispatch table
	Why       string // why this relationship matters for root-cause analysis
}

// edgeRegistry lists every relationship the copilot knows how to follow.
// Order is roughly "closest to the pod first" — the planner preserves it as
// a tie-break so plans read naturally (pod → workload → node → traffic → …).
var edgeRegistry = []graphEdge{
	{"pod→logs", "previous-logs", "the previous container's logs show why the last run exited"},
	{"pod→ownerDeployment", "owner-chain", "the owning workload declares the pod's spec — limits, probes, image — where most root causes live"},
	{"pod→node", "node-detail", "node pressure, taints, and capacity explain evictions and scheduling failures"},
	{"pod→configmap", "configmaps", "configuration referenced by the pod may have changed or be missing"},
	{"pod→secret", "secrets", "missing or rotated secrets break startup and image pulls (existence only — values never read)"},
	{"pod→serviceAccount→rbac", "rbac", "permission errors trace back to the pod's ServiceAccount grants"},
	{"pod→pvc→pv→storageclass", "storage-chain", "unbound claims and missing storage classes block scheduling and mounts"},
	{"pod→service→endpointslice", "service-endpoints", "a service with no ready endpoints means traffic never reaches the pod"},
	{"pod→netpol", "netpol", "network policies can silently isolate the pod from its dependencies"},
	{"workload→hpa", "scaling", "an autoscaler at max (or a tight disruption budget) explains saturation and stuck rollouts"},
	{"ns→quota", "namespace-detail", "an exhausted ResourceQuota or restrictive LimitRange starves new pods"},
	{"resource→changes", "change-history", "a change shortly before the first failure is the most likely trigger"},
	{"pod→metrics", "metrics", "resource usage trends distinguish leaks from under-provisioning"},
	{"cluster→dns", "dns-heuristic", "failed name resolution cascades into timeouts and dependency errors (heuristic — no real resolver)"},
	{"ns→services", "related-services", "sibling service issues reveal shared-dependency failures"},
	{"resource→history", "history", "prior investigations and incidents show whether this has happened before and what fixed it"},
}

// edgeFor returns the registered edge for a collector key ("" when the
// collector has no graph edge, e.g. purely question-driven checks).
func edgeFor(collector string) graphEdge {
	for _, e := range edgeRegistry {
		if e.Collector == collector {
			return e
		}
	}
	return graphEdge{}
}
