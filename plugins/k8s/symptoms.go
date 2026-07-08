package k8s

// symptoms.go is the KUBERNETES symptom catalog for the generic
// investigation framework (internal/investigate): what an experienced SRE
// checks FIRST for each k8s failure mode, and the candidate root causes the
// hypothesis engine ranks against the evidence. The matching helpers unwrap
// the opaque Facts bundle into k8s types.

import (
	"strings"

	"github.com/exalm-ai/exalm/internal/investigate"
)

// re is the catalog-authoring regex helper (case-insensitive).
var re = investigate.Re

// unwrap extracts the k8s facts bundle from the framework's opaque Facts.
func unwrap(f investigate.Facts) k8sFacts {
	if k, ok := f.(k8sFacts); ok {
		return k
	}
	return k8sFacts{}
}

// podHasAnomaly reports whether the pod's log anomalies include a category.
func podHasAnomaly(pod *PodSummary, categories ...string) bool {
	if pod == nil {
		return false
	}
	for _, a := range pod.LogAnomalies {
		for _, c := range categories {
			if a.Category == c {
				return true
			}
		}
	}
	return false
}

// podHasEventReason reports whether a snapshot warning event for the pod has
// a reason containing any of the substrings (case-insensitive).
func podHasEventReason(snap Snapshot, ns, name string, substrings ...string) bool {
	for _, e := range snap.Events {
		if name != "" && e.PodName != name {
			continue
		}
		if ns != "" && e.Namespace != ns {
			continue
		}
		for _, s := range substrings {
			if strings.Contains(strings.ToLower(e.Reason), strings.ToLower(s)) ||
				strings.Contains(strings.ToLower(e.Message), strings.ToLower(s)) {
				return true
			}
		}
	}
	return false
}

func reasonContains(pod *PodSummary, substrings ...string) bool {
	if pod == nil {
		return false
	}
	lower := strings.ToLower(pod.Reason)
	for _, s := range substrings {
		if strings.Contains(lower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// match adapts a k8s-typed matcher into the framework signature.
func match(fn func(pod *PodSummary, snap Snapshot, ns, name string) bool) func(investigate.Facts, investigate.Target) bool {
	return func(f investigate.Facts, t investigate.Target) bool {
		k := unwrap(f)
		return fn(k.pod, k.snap, t.Scope, t.Name)
	}
}

// symptomCatalog is evaluated in order; ALL matching symptoms contribute
// checks, but the FIRST match names the conversation fingerprint. The
// Fallback row matches any focus pod when nothing specific did.
var symptomCatalog = []investigate.Symptom{
	{
		Key: "oom-killed",
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return reasonContains(pod, "oom") || podHasEventReason(snap, ns, name, "OOMKill")
		}),
		Checks: []investigate.Check{
			{Collector: "owner-chain", Reason: "reason=OOMKilled ⇒ check the workload's memory limits and requests", Priority: 1},
			{Collector: "metrics", Reason: "memory usage trend distinguishes a leak from under-provisioning", Priority: 2},
			{Collector: "node-detail", Reason: "node memory pressure can evict/kill pods independently of limits", Priority: 3},
			{Collector: "scaling", Reason: "an HPA at max means load exceeds capacity, amplifying memory use", Priority: 4},
			{Collector: "change-history", Reason: "a deploy shortly before the first OOM is the likely trigger", Priority: 2},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Memory limit too low for the workload's real usage", Base: 70,
				For: []investigate.EvidenceMatcher{
					{Kind: "config", Pattern: re(`memLimits=false|no (cpu or memory|memory) limit`), Weight: 15},
					{Pattern: re(`oom|out of memory|exceeded.*memory`), Weight: 10},
				},
				Against: []investigate.EvidenceMatcher{{Kind: "event", Pattern: re(`memorypressure`), Weight: 10}},
			},
			{
				Title: "Memory regression introduced by a recent change", Base: 50,
				For:     []investigate.EvidenceMatcher{{Kind: "change", Pattern: re(`.`), Weight: 25}},
				Against: []investigate.EvidenceMatcher{{Kind: "change", Pattern: re(`no changes recorded`), Weight: 20}},
			},
			{
				Title: "Node memory pressure (not the container's own limit)", Base: 35,
				For:     []investigate.EvidenceMatcher{{Pattern: re(`memorypressure|node.*pressure`), Weight: 30}},
				Against: []investigate.EvidenceMatcher{{Pattern: re(`oomkilled`), Weight: 10}},
			},
		},
	},
	{
		Key: "image-pull",
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return reasonContains(pod, "imagepull", "errimagepull") || podHasEventReason(snap, ns, name, "Failed to pull", "ErrImagePull", "ImagePullBackOff")
		}),
		Checks: []investigate.Check{
			{Collector: "secrets", Reason: "an invalid or rotated imagePullSecret is the most common pull failure", Priority: 1},
			{Collector: "owner-chain", Reason: "the workload spec names the image reference being pulled", Priority: 2},
			{Collector: "change-history", Reason: "a deploy that changed the image tag or pull secret is the likely trigger", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Registry credentials (imagePullSecret) invalid or rotated", Base: 55,
				For:     []investigate.EvidenceMatcher{{Pattern: re(`403|unauthorized|authentication`), Weight: 25}, {Kind: "config", Pattern: re(`secret/`), Weight: 5}},
				Against: []investigate.EvidenceMatcher{{Pattern: re(`not found|manifest unknown`), Weight: 15}},
			},
			{
				Title: "Image reference invalid or tag missing from the registry", Base: 45,
				For:     []investigate.EvidenceMatcher{{Pattern: re(`not found|manifest unknown|no such image`), Weight: 30}},
				Against: []investigate.EvidenceMatcher{{Pattern: re(`403|unauthorized`), Weight: 15}},
			},
			{
				Title: "Registry unreachable from the node", Base: 25,
				For: []investigate.EvidenceMatcher{{Pattern: re(`timeout|i/o timeout|connection refused`), Weight: 30}},
			},
		},
	},
	{
		Key: "crashloop",
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return reasonContains(pod, "crashloop") || podHasEventReason(snap, ns, name, "BackOff", "CrashLoop")
		}),
		Checks: []investigate.Check{
			{Collector: "previous-logs", Reason: "the previous container's exit output shows why it crashed", Priority: 1},
			{Collector: "owner-chain", Reason: "the workload spec declares the command, probes, and limits in play", Priority: 2},
			{Collector: "configmaps", Reason: "a bad or missing configuration value is a classic startup-crash cause", Priority: 3},
			{Collector: "secrets", Reason: "a missing secret reference fails the container before main() runs", Priority: 4},
			{Collector: "change-history", Reason: "a change just before the first crash is the likely trigger", Priority: 2},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Application crashes on startup (bad configuration or code path)", Base: 55,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: re(`panic|fatal|error|exception`), Weight: 20}},
			},
			{
				Title: "Recent deployment introduced the crash", Base: 45,
				For:     []investigate.EvidenceMatcher{{Kind: "change", Pattern: re(`.`), Weight: 25}},
				Against: []investigate.EvidenceMatcher{{Kind: "change", Pattern: re(`no changes recorded`), Weight: 20}},
			},
			{
				Title: "Missing or invalid ConfigMap/Secret reference", Base: 35,
				For: []investigate.EvidenceMatcher{{Pattern: re(`configmap.*not found|secret.*not found|couldn't find key`), Weight: 35}},
			},
		},
	},
	{
		Key: "probe-failure",
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return podHasEventReason(snap, ns, name, "Unhealthy", "probe")
		}),
		Checks: []investigate.Check{
			{Collector: "owner-chain", Reason: "the workload spec declares the probe endpoints and thresholds", Priority: 1},
			{Collector: "service-endpoints", Reason: "failing readiness removes the pod from its service endpoints", Priority: 2},
			{Collector: "previous-logs", Reason: "logs around the probe window show whether the app was actually up", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Probe thresholds too aggressive for the app's startup time", Base: 50,
				For: []investigate.EvidenceMatcher{{Kind: "config", Pattern: re(`initialDelay=(\d)s|initialDelay=(10|15)s`), Weight: 15}},
			},
			{
				Title: "Application genuinely unready (dependency failing behind it)", Base: 45,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: re(`connection refused|timeout|unavailable`), Weight: 25}},
			},
			{
				Title: "Probe path or port misconfigured", Base: 30,
				For: []investigate.EvidenceMatcher{{Pattern: re(`404|connection refused.*probe`), Weight: 25}},
			},
		},
	},
	{
		Key: "pending-unschedulable",
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return (pod != nil && strings.EqualFold(pod.Phase, "Pending")) || podHasEventReason(snap, ns, name, "FailedScheduling")
		}),
		Checks: []investigate.Check{
			{Collector: "node-detail", Reason: "insufficient node capacity or taints block scheduling", Priority: 1},
			{Collector: "namespace-detail", Reason: "an exhausted ResourceQuota rejects new pods at admission", Priority: 2},
			{Collector: "storage-chain", Reason: "an unbound PVC blocks scheduling until the volume provisions", Priority: 3},
			{Collector: "scaling", Reason: "a tight PodDisruptionBudget can wedge rescheduling", Priority: 4},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Insufficient cluster resources for the pod's requests", Base: 50,
				For: []investigate.EvidenceMatcher{{Pattern: re(`insufficient|0/\d+ nodes`), Weight: 25}},
			},
			{
				Title: "Namespace ResourceQuota exhausted", Base: 40,
				For: []investigate.EvidenceMatcher{{Kind: "config", Pattern: re(`quota`), Weight: 25}},
			},
			{
				Title: "PVC unbound — volume not provisioning", Base: 35,
				For: []investigate.EvidenceMatcher{{Pattern: re(`unbound|pending.*pvc|storageclass.*missing`), Weight: 30}},
			},
		},
	},
	{
		Key: "evicted",
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return reasonContains(pod, "evict") || podHasEventReason(snap, ns, name, "Evicted")
		}),
		Checks: []investigate.Check{
			{Collector: "node-detail", Reason: "eviction is almost always node pressure — check conditions", Priority: 1},
			{Collector: "namespace-detail", Reason: "quota/limit context shows why THIS pod was chosen", Priority: 2},
			{Collector: "metrics", Reason: "usage trend shows whether pressure is sustained or a spike", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Node resource pressure evicted the pod", Base: 60,
				For: []investigate.EvidenceMatcher{{Pattern: re(`pressure|diskpressure|memorypressure`), Weight: 25}},
			},
			{
				Title: "Missing resource requests made this pod the first eviction candidate", Base: 35,
				For: []investigate.EvidenceMatcher{{Kind: "config", Pattern: re(`memLimits=false`), Weight: 20}},
			},
		},
	},
	{
		Key: "pvc-stuck",
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return podHasEventReason(snap, ns, name, "FailedMount", "FailedAttachVolume", "ProvisioningFailed")
		}),
		Checks: []investigate.Check{
			{Collector: "storage-chain", Reason: "walk PVC → PV → StorageClass to find the broken link", Priority: 1},
			{Collector: "namespace-detail", Reason: "storage quotas can block provisioning", Priority: 2},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "StorageClass missing or its provisioner failing", Base: 50,
				For: []investigate.EvidenceMatcher{{Pattern: re(`storageclass.*missing|provisioningfailed`), Weight: 30}},
			},
			{
				Title: "Volume attach/mount failing on the node", Base: 40,
				For: []investigate.EvidenceMatcher{{Pattern: re(`failedmount|failedattach`), Weight: 25}},
			},
		},
	},
	{
		Key: "dns-failure",
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			if pod == nil {
				return false
			}
			dnsRe := re(`no such host|could not resolve|name or service not known`)
			for _, lt := range pod.LogTails {
				if dnsRe.MatchString(lt.Lines) {
					return true
				}
			}
			for _, a := range pod.LogAnomalies {
				if dnsRe.MatchString(a.Sample) {
					return true
				}
			}
			return false
		}),
		Checks: []investigate.Check{
			{Collector: "dns-heuristic", Reason: "CoreDNS health + service/endpoint state approximate a DNS diagnosis", Priority: 1},
			{Collector: "netpol", Reason: "a NetworkPolicy blocking egress to kube-dns mimics DNS failure", Priority: 2},
			{Collector: "service-endpoints", Reason: "the 'unresolvable' name may be a service with no ready endpoints", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "DNS resolution failing (CoreDNS or upstream)", Base: 45,
				For: []investigate.EvidenceMatcher{{Pattern: re(`coredns.*unhealthy|no such host`), Weight: 25}},
			},
			{
				Title: "NetworkPolicy blocking egress to DNS", Base: 30,
				For: []investigate.EvidenceMatcher{{Kind: "config", Pattern: re(`isolatesEgress=true|default-deny`), Weight: 30}},
			},
		},
	},
	{
		Key: "http-5xx",
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return podHasAnomaly(pod, "http-5xx")
		}),
		Checks: []investigate.Check{
			{Collector: "service-endpoints", Reason: "5xx at the edge usually means no ready backends behind a service", Priority: 1},
			{Collector: "related-services", Reason: "a failing downstream dependency surfaces as 5xx upstream", Priority: 2},
			{Collector: "change-history", Reason: "a deploy shortly before the 5xx spike is the likely trigger", Priority: 2},
			{Collector: "netpol", Reason: "policy changes can cut a service off from its dependency mid-flight", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Downstream dependency failing (cascading 5xx)", Base: 45,
				For: []investigate.EvidenceMatcher{{Pattern: re(`no ready endpoints|selector mismatch|connection refused`), Weight: 25}},
			},
			{
				Title: "Recent deploy broke request handling", Base: 40,
				For: []investigate.EvidenceMatcher{{Kind: "change", Pattern: re(`.`), Weight: 25}},
			},
		},
	},
	{
		Key: "db-error",
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return podHasAnomaly(pod, "db-error")
		}),
		Checks: []investigate.Check{
			{Collector: "related-services", Reason: "locate the database service and its endpoint health", Priority: 1},
			{Collector: "netpol", Reason: "a policy isolating the pod from the database mimics DB downtime", Priority: 2},
			{Collector: "secrets", Reason: "rotated DB credentials fail connections without any infra change", Priority: 3},
			{Collector: "change-history", Reason: "config/secret changes just before the errors are the likely trigger", Priority: 2},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Database unreachable (service/network path broken)", Base: 45,
				For: []investigate.EvidenceMatcher{{Pattern: re(`connection refused|no ready endpoints|timeout`), Weight: 25}},
			},
			{
				Title: "Database credentials rotated or invalid", Base: 35,
				For: []investigate.EvidenceMatcher{{Pattern: re(`authentication|password|access denied`), Weight: 30}},
			},
		},
	},
	{
		Key:      "unknown-unhealthy",
		Fallback: true,
		Match: match(func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return pod != nil
		}),
		Checks: []investigate.Check{
			{Collector: "previous-logs", Reason: "start from what the container itself reported", Priority: 1},
			{Collector: "owner-chain", Reason: "the owning workload's spec frames every other check", Priority: 2},
			{Collector: "change-history", Reason: "whatever changed most recently is the first suspect", Priority: 3},
		},
		Causes: []investigate.CauseTemplate{
			{
				Title: "Recent change destabilized the workload", Base: 40,
				For: []investigate.EvidenceMatcher{{Kind: "change", Pattern: re(`.`), Weight: 25}},
			},
			{
				Title: "Application-level fault (see logs)", Base: 35,
				For: []investigate.EvidenceMatcher{{Kind: "log", Pattern: re(`error|panic|fatal`), Weight: 20}},
			},
		},
	},
}
