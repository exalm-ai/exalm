package k8s

// symptoms.go is the deterministic symptom catalog: what an experienced SRE
// checks FIRST for each failure mode. The planner matches the focus pod's
// state (reason, log anomalies, warning events) against this catalog to
// schedule collectors — no LLM involved. Each symptom also carries the
// candidate root causes (causeTemplates) the hypothesis engine ranks against
// the evidence that comes back.

import (
	"regexp"
	"strings"
)

// plannedCheck is one collector request contributed by a symptom or intent.
type plannedCheck struct {
	Collector string
	Reason    string // why this check matters for the symptom
	Priority  int    // lower runs earlier
}

// evidenceMatcher scores evidence for/against a cause: it matches when the
// item's Kind equals Kind (if set) and Pattern matches Source+" "+Excerpt.
type evidenceMatcher struct {
	Kind    string
	Pattern *regexp.Regexp
	Weight  int
}

// causeTemplate is one candidate root cause for a symptom.
type causeTemplate struct {
	Title   string
	Base    int // starting score 0-100 before evidence adjustment
	For     []evidenceMatcher
	Against []evidenceMatcher
}

// symptom is one row of the catalog.
type symptom struct {
	Key    string
	Match  func(pod *PodSummary, snap Snapshot, ns, name string) bool
	Checks []plannedCheck
	Causes []causeTemplate
}

func re(p string) *regexp.Regexp { return regexp.MustCompile("(?i)" + p) }

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

// symptomCatalog is evaluated in order; ALL matching symptoms contribute
// checks (a pod can be OOMKilled AND crash-looping), but the FIRST match
// names the conversation fingerprint.
var symptomCatalog = []symptom{
	{
		Key: "oom-killed",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return reasonContains(pod, "oom") || podHasEventReason(snap, ns, name, "OOMKill")
		},
		Checks: []plannedCheck{
			{"owner-chain", "reason=OOMKilled ⇒ check the workload's memory limits and requests", 1},
			{"metrics", "memory usage trend distinguishes a leak from under-provisioning", 2},
			{"node-detail", "node memory pressure can evict/kill pods independently of limits", 3},
			{"scaling", "an HPA at max means load exceeds capacity, amplifying memory use", 4},
			{"change-history", "a deploy shortly before the first OOM is the likely trigger", 2},
		},
		Causes: []causeTemplate{
			{
				Title: "Memory limit too low for the workload's real usage", Base: 70,
				For: []evidenceMatcher{
					{Kind: "config", Pattern: re(`memLimits=false|no (cpu or memory|memory) limit`), Weight: 15},
					{Pattern: re(`oom|out of memory|exceeded.*memory`), Weight: 10},
				},
				Against: []evidenceMatcher{{Kind: "event", Pattern: re(`memorypressure`), Weight: 10}},
			},
			{
				Title: "Memory regression introduced by a recent change", Base: 50,
				For:     []evidenceMatcher{{Kind: "change", Pattern: re(`.`), Weight: 25}},
				Against: []evidenceMatcher{{Kind: "change", Pattern: re(`no changes recorded`), Weight: 20}},
			},
			{
				Title: "Node memory pressure (not the container's own limit)", Base: 35,
				For:     []evidenceMatcher{{Pattern: re(`memorypressure|node.*pressure`), Weight: 30}},
				Against: []evidenceMatcher{{Pattern: re(`oomkilled`), Weight: 10}},
			},
		},
	},
	{
		Key: "image-pull",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return reasonContains(pod, "imagepull", "errimagepull") || podHasEventReason(snap, ns, name, "Failed to pull", "ErrImagePull", "ImagePullBackOff")
		},
		Checks: []plannedCheck{
			{"secrets", "an invalid or rotated imagePullSecret is the most common pull failure", 1},
			{"owner-chain", "the workload spec names the image reference being pulled", 2},
			{"change-history", "a deploy that changed the image tag or pull secret is the likely trigger", 3},
		},
		Causes: []causeTemplate{
			{
				Title: "Registry credentials (imagePullSecret) invalid or rotated", Base: 55,
				For:     []evidenceMatcher{{Pattern: re(`403|unauthorized|authentication`), Weight: 25}, {Kind: "config", Pattern: re(`secret/`), Weight: 5}},
				Against: []evidenceMatcher{{Pattern: re(`not found|manifest unknown`), Weight: 15}},
			},
			{
				Title: "Image reference invalid or tag missing from the registry", Base: 45,
				For:     []evidenceMatcher{{Pattern: re(`not found|manifest unknown|no such image`), Weight: 30}},
				Against: []evidenceMatcher{{Pattern: re(`403|unauthorized`), Weight: 15}},
			},
			{
				Title: "Registry unreachable from the node", Base: 25,
				For: []evidenceMatcher{{Pattern: re(`timeout|i/o timeout|connection refused`), Weight: 30}},
			},
		},
	},
	{
		Key: "crashloop",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return reasonContains(pod, "crashloop") || podHasEventReason(snap, ns, name, "BackOff", "CrashLoop")
		},
		Checks: []plannedCheck{
			{"previous-logs", "the previous container's exit output shows why it crashed", 1},
			{"owner-chain", "the workload spec declares the command, probes, and limits in play", 2},
			{"configmaps", "a bad or missing configuration value is a classic startup-crash cause", 3},
			{"secrets", "a missing secret reference fails the container before main() runs", 4},
			{"change-history", "a change just before the first crash is the likely trigger", 2},
		},
		Causes: []causeTemplate{
			{
				Title: "Application crashes on startup (bad configuration or code path)", Base: 55,
				For: []evidenceMatcher{{Kind: "log", Pattern: re(`panic|fatal|error|exception`), Weight: 20}},
			},
			{
				Title: "Recent deployment introduced the crash", Base: 45,
				For:     []evidenceMatcher{{Kind: "change", Pattern: re(`.`), Weight: 25}},
				Against: []evidenceMatcher{{Kind: "change", Pattern: re(`no changes recorded`), Weight: 20}},
			},
			{
				Title: "Missing or invalid ConfigMap/Secret reference", Base: 35,
				For: []evidenceMatcher{{Pattern: re(`configmap.*not found|secret.*not found|couldn't find key`), Weight: 35}},
			},
		},
	},
	{
		Key: "probe-failure",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return podHasEventReason(snap, ns, name, "Unhealthy", "probe")
		},
		Checks: []plannedCheck{
			{"owner-chain", "the workload spec declares the probe endpoints and thresholds", 1},
			{"service-endpoints", "failing readiness removes the pod from its service endpoints", 2},
			{"previous-logs", "logs around the probe window show whether the app was actually up", 3},
		},
		Causes: []causeTemplate{
			{
				Title: "Probe thresholds too aggressive for the app's startup time", Base: 50,
				For: []evidenceMatcher{{Kind: "config", Pattern: re(`initialDelay=(\d)s|initialDelay=(10|15)s`), Weight: 15}},
			},
			{
				Title: "Application genuinely unready (dependency failing behind it)", Base: 45,
				For: []evidenceMatcher{{Kind: "log", Pattern: re(`connection refused|timeout|unavailable`), Weight: 25}},
			},
			{
				Title: "Probe path or port misconfigured", Base: 30,
				For: []evidenceMatcher{{Pattern: re(`404|connection refused.*probe`), Weight: 25}},
			},
		},
	},
	{
		Key: "pending-unschedulable",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return (pod != nil && strings.EqualFold(pod.Phase, "Pending")) || podHasEventReason(snap, ns, name, "FailedScheduling")
		},
		Checks: []plannedCheck{
			{"node-detail", "insufficient node capacity or taints block scheduling", 1},
			{"namespace-detail", "an exhausted ResourceQuota rejects new pods at admission", 2},
			{"storage-chain", "an unbound PVC blocks scheduling until the volume provisions", 3},
			{"scaling", "a tight PodDisruptionBudget can wedge rescheduling", 4},
		},
		Causes: []causeTemplate{
			{
				Title: "Insufficient cluster resources for the pod's requests", Base: 50,
				For: []evidenceMatcher{{Pattern: re(`insufficient|0/\d+ nodes`), Weight: 25}},
			},
			{
				Title: "Namespace ResourceQuota exhausted", Base: 40,
				For: []evidenceMatcher{{Kind: "config", Pattern: re(`quota`), Weight: 25}},
			},
			{
				Title: "PVC unbound — volume not provisioning", Base: 35,
				For: []evidenceMatcher{{Pattern: re(`unbound|pending.*pvc|storageclass.*missing`), Weight: 30}},
			},
		},
	},
	{
		Key: "evicted",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return reasonContains(pod, "evict") || podHasEventReason(snap, ns, name, "Evicted")
		},
		Checks: []plannedCheck{
			{"node-detail", "eviction is almost always node pressure — check conditions", 1},
			{"namespace-detail", "quota/limit context shows why THIS pod was chosen", 2},
			{"metrics", "usage trend shows whether pressure is sustained or a spike", 3},
		},
		Causes: []causeTemplate{
			{
				Title: "Node resource pressure evicted the pod", Base: 60,
				For: []evidenceMatcher{{Pattern: re(`pressure|diskpressure|memorypressure`), Weight: 25}},
			},
			{
				Title: "Missing resource requests made this pod the first eviction candidate", Base: 35,
				For: []evidenceMatcher{{Kind: "config", Pattern: re(`memLimits=false`), Weight: 20}},
			},
		},
	},
	{
		Key: "pvc-stuck",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return podHasEventReason(snap, ns, name, "FailedMount", "FailedAttachVolume", "ProvisioningFailed")
		},
		Checks: []plannedCheck{
			{"storage-chain", "walk PVC → PV → StorageClass to find the broken link", 1},
			{"namespace-detail", "storage quotas can block provisioning", 2},
		},
		Causes: []causeTemplate{
			{
				Title: "StorageClass missing or its provisioner failing", Base: 50,
				For: []evidenceMatcher{{Pattern: re(`storageclass.*missing|provisioningfailed`), Weight: 30}},
			},
			{
				Title: "Volume attach/mount failing on the node", Base: 40,
				For: []evidenceMatcher{{Pattern: re(`failedmount|failedattach`), Weight: 25}},
			},
		},
	},
	{
		Key: "dns-failure",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
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
		},
		Checks: []plannedCheck{
			{"dns-heuristic", "CoreDNS health + service/endpoint state approximate a DNS diagnosis", 1},
			{"netpol", "a NetworkPolicy blocking egress to kube-dns mimics DNS failure", 2},
			{"service-endpoints", "the 'unresolvable' name may be a service with no ready endpoints", 3},
		},
		Causes: []causeTemplate{
			{
				Title: "DNS resolution failing (CoreDNS or upstream)", Base: 45,
				For: []evidenceMatcher{{Pattern: re(`coredns.*unhealthy|no such host`), Weight: 25}},
			},
			{
				Title: "NetworkPolicy blocking egress to DNS", Base: 30,
				For: []evidenceMatcher{{Kind: "config", Pattern: re(`isolatesEgress=true|default-deny`), Weight: 30}},
			},
		},
	},
	{
		Key: "http-5xx",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return podHasAnomaly(pod, "http-5xx")
		},
		Checks: []plannedCheck{
			{"service-endpoints", "5xx at the edge usually means no ready backends behind a service", 1},
			{"related-services", "a failing downstream dependency surfaces as 5xx upstream", 2},
			{"change-history", "a deploy shortly before the 5xx spike is the likely trigger", 2},
			{"netpol", "policy changes can cut a service off from its dependency mid-flight", 3},
		},
		Causes: []causeTemplate{
			{
				Title: "Downstream dependency failing (cascading 5xx)", Base: 45,
				For: []evidenceMatcher{{Pattern: re(`no ready endpoints|selector mismatch|connection refused`), Weight: 25}},
			},
			{
				Title: "Recent deploy broke request handling", Base: 40,
				For: []evidenceMatcher{{Kind: "change", Pattern: re(`.`), Weight: 25}},
			},
		},
	},
	{
		Key: "db-error",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return podHasAnomaly(pod, "db-error")
		},
		Checks: []plannedCheck{
			{"related-services", "locate the database service and its endpoint health", 1},
			{"netpol", "a policy isolating the pod from the database mimics DB downtime", 2},
			{"secrets", "rotated DB credentials fail connections without any infra change", 3},
			{"change-history", "config/secret changes just before the errors are the likely trigger", 2},
		},
		Causes: []causeTemplate{
			{
				Title: "Database unreachable (service/network path broken)", Base: 45,
				For: []evidenceMatcher{{Pattern: re(`connection refused|no ready endpoints|timeout`), Weight: 25}},
			},
			{
				Title: "Database credentials rotated or invalid", Base: 35,
				For: []evidenceMatcher{{Pattern: re(`authentication|password|access denied`), Weight: 30}},
			},
		},
	},
	{
		// Fallback: any unhealthy focus pod with no more specific match.
		Key: "unknown-unhealthy",
		Match: func(pod *PodSummary, snap Snapshot, ns, name string) bool {
			return pod != nil
		},
		Checks: []plannedCheck{
			{"previous-logs", "start from what the container itself reported", 1},
			{"owner-chain", "the owning workload's spec frames every other check", 2},
			{"change-history", "whatever changed most recently is the first suspect", 3},
		},
		Causes: []causeTemplate{
			{
				Title: "Recent change destabilized the workload", Base: 40,
				For: []evidenceMatcher{{Kind: "change", Pattern: re(`.`), Weight: 25}},
			},
			{
				Title: "Application-level fault (see logs)", Base: 35,
				For: []evidenceMatcher{{Kind: "log", Pattern: re(`error|panic|fatal`), Weight: 20}},
			},
		},
	},
}

// matchSymptoms returns every catalog row matching the focus pod, in catalog
// order. The fallback row only matches when it is the ONLY match.
func matchSymptoms(pod *PodSummary, snap Snapshot, ns, name string) []symptom {
	var out []symptom
	for _, s := range symptomCatalog {
		if s.Key == "unknown-unhealthy" {
			continue
		}
		if s.Match(pod, snap, ns, name) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		last := symptomCatalog[len(symptomCatalog)-1]
		if last.Match(pod, snap, ns, name) {
			out = append(out, last)
		}
	}
	return out
}
