package k8s

// ownerchain.go resolves a pod's workload ownership chain (pod → ReplicaSet →
// Deployment, or pod → StatefulSet/DaemonSet/Job → CronJob) via live,
// targeted GETs — the same on-demand trust class as configmaps.go. The chain
// tells the investigation planner which workload actually declares the pod's
// spec (limits, probes, image), which is where most root causes live.

import (
	"context"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// WorkloadDetail is a redaction-safe view of the workload that owns a pod.
// Images and condition messages pass through the redactor before storage
// (registry hosts and condition text can embed user-authored strings).
type WorkloadDetail struct {
	Kind            string // "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"
	Name            string
	Desired, Ready  int32
	Strategy        string
	Images          []string
	Conditions      []string // "Type=Status: message" (redacted)
	ProbeSummary    string   // readiness/liveness probe presence + initial delays
	Paused          bool     // Deployment paused / CronJob suspended
	StaleGeneration bool     // observedGeneration < generation (controller lagging)
	HasMemoryLimits bool
	HasCPULimits    bool
	// MemoryLimitDetail/CPULimitDetail carry the actual configured values per
	// container, e.g. "app=512Mi; sidecar=none" — HasMemoryLimits/HasCPULimits
	// only say whether a limit exists, not what it's set to, which left the
	// investigation chat unable to answer "what is the memory limit" questions.
	MemoryLimitDetail string
	CPULimitDetail    string
	Age               string
}

// OwnerLink is one hop of the ownership chain.
type OwnerLink struct {
	Kind string
	Name string
	Edge string // e.g. "pod→ownerReplicaSet"
}

// OwnerChain is the resolved chain plus the terminal workload's detail.
type OwnerChain struct {
	Links    []OwnerLink
	Workload *WorkloadDetail // nil when the pod has no workload owner
}

// ownerChainFor walks pod.ownerReferences upward: ReplicaSet → Deployment and
// Job → CronJob get one extra hop; StatefulSet/DaemonSet are terminal.
// Missing links (e.g. orphaned ReplicaSet) end the walk without error — the
// partial chain is itself investigation signal.
func ownerChainFor(ctx context.Context, cs kubernetes.Interface, red plugin.Redactor, ns, podName string) (OwnerChain, error) {
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return OwnerChain{}, fmt.Errorf("get pod %s/%s: %w", ns, podName, err)
	}
	var chain OwnerChain
	kind, name := controllerOwner(pod.OwnerReferences)
	if kind == "" {
		return chain, nil
	}

	switch kind {
	case "ReplicaSet":
		chain.Links = append(chain.Links, OwnerLink{Kind: kind, Name: name, Edge: "pod→ownerReplicaSet"})
		rs, err := cs.AppsV1().ReplicaSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return chain, nil
		}
		dKind, dName := controllerOwner(rs.OwnerReferences)
		if dKind == "Deployment" {
			chain.Links = append(chain.Links, OwnerLink{Kind: dKind, Name: dName, Edge: "replicaset→ownerDeployment"})
			if d, err := cs.AppsV1().Deployments(ns).Get(ctx, dName, metav1.GetOptions{}); err == nil {
				chain.Workload = deploymentDetail(d, red)
			}
		}
	case "StatefulSet":
		chain.Links = append(chain.Links, OwnerLink{Kind: kind, Name: name, Edge: "pod→ownerStatefulSet"})
		if s, err := cs.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{}); err == nil {
			chain.Workload = statefulSetDetail(s, red)
		}
	case "DaemonSet":
		chain.Links = append(chain.Links, OwnerLink{Kind: kind, Name: name, Edge: "pod→ownerDaemonSet"})
		if d, err := cs.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{}); err == nil {
			chain.Workload = daemonSetDetail(d, red)
		}
	case "Job":
		chain.Links = append(chain.Links, OwnerLink{Kind: kind, Name: name, Edge: "pod→ownerJob"})
		j, err := cs.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return chain, nil
		}
		cKind, cName := controllerOwner(j.OwnerReferences)
		if cKind == "CronJob" {
			chain.Links = append(chain.Links, OwnerLink{Kind: cKind, Name: cName, Edge: "job→ownerCronJob"})
			if cj, err := cs.BatchV1().CronJobs(ns).Get(ctx, cName, metav1.GetOptions{}); err == nil {
				chain.Workload = cronJobDetail(cj, red)
			}
		} else {
			chain.Workload = jobDetail(j, red)
		}
	default:
		chain.Links = append(chain.Links, OwnerLink{Kind: kind, Name: name, Edge: "pod→owner" + kind})
	}
	return chain, nil
}

// controllerOwner returns the kind/name of the controller ownerReference.
func controllerOwner(refs []metav1.OwnerReference) (string, string) {
	for _, r := range refs {
		if r.Controller != nil && *r.Controller {
			return r.Kind, r.Name
		}
	}
	if len(refs) > 0 {
		return refs[0].Kind, refs[0].Name
	}
	return "", ""
}

func deploymentDetail(d *appsv1.Deployment, red plugin.Redactor) *WorkloadDetail {
	w := detailFromPodSpec("Deployment", d.Name, d.Spec.Template.Spec, red)
	if d.Spec.Replicas != nil {
		w.Desired = *d.Spec.Replicas
	}
	w.Ready = d.Status.ReadyReplicas
	w.Strategy = string(d.Spec.Strategy.Type)
	w.Paused = d.Spec.Paused
	w.StaleGeneration = d.Status.ObservedGeneration < d.Generation
	for _, c := range d.Status.Conditions {
		w.Conditions = append(w.Conditions, redactStr(red, fmt.Sprintf("%s=%s: %s", c.Type, c.Status, c.Message)))
	}
	w.Age = humanizeAge(d.CreationTimestamp.Time, time.Now())
	return w
}

func statefulSetDetail(s *appsv1.StatefulSet, red plugin.Redactor) *WorkloadDetail {
	w := detailFromPodSpec("StatefulSet", s.Name, s.Spec.Template.Spec, red)
	if s.Spec.Replicas != nil {
		w.Desired = *s.Spec.Replicas
	}
	w.Ready = s.Status.ReadyReplicas
	w.Strategy = string(s.Spec.UpdateStrategy.Type)
	w.StaleGeneration = s.Status.ObservedGeneration < s.Generation
	w.Age = humanizeAge(s.CreationTimestamp.Time, time.Now())
	return w
}

func daemonSetDetail(d *appsv1.DaemonSet, red plugin.Redactor) *WorkloadDetail {
	w := detailFromPodSpec("DaemonSet", d.Name, d.Spec.Template.Spec, red)
	w.Desired = d.Status.DesiredNumberScheduled
	w.Ready = d.Status.NumberReady
	w.Strategy = string(d.Spec.UpdateStrategy.Type)
	w.StaleGeneration = d.Status.ObservedGeneration < d.Generation
	w.Age = humanizeAge(d.CreationTimestamp.Time, time.Now())
	return w
}

func jobDetail(j *batchv1.Job, red plugin.Redactor) *WorkloadDetail {
	w := detailFromPodSpec("Job", j.Name, j.Spec.Template.Spec, red)
	if j.Spec.Completions != nil {
		w.Desired = *j.Spec.Completions
	}
	w.Ready = j.Status.Succeeded
	for _, c := range j.Status.Conditions {
		w.Conditions = append(w.Conditions, redactStr(red, fmt.Sprintf("%s=%s: %s", c.Type, c.Status, c.Message)))
	}
	w.Age = humanizeAge(j.CreationTimestamp.Time, time.Now())
	return w
}

func cronJobDetail(cj *batchv1.CronJob, red plugin.Redactor) *WorkloadDetail {
	w := detailFromPodSpec("CronJob", cj.Name, cj.Spec.JobTemplate.Spec.Template.Spec, red)
	if cj.Spec.Suspend != nil {
		w.Paused = *cj.Spec.Suspend
	}
	w.Strategy = "schedule " + cj.Spec.Schedule
	w.Age = humanizeAge(cj.CreationTimestamp.Time, time.Now())
	return w
}

// detailFromPodSpec extracts the spec-level facts common to all workload
// kinds: images (redacted), limit presence, and probe configuration.
func detailFromPodSpec(kind, name string, spec corev1.PodSpec, red plugin.Redactor) *WorkloadDetail {
	w := &WorkloadDetail{Kind: kind, Name: name, HasMemoryLimits: true, HasCPULimits: true}
	var probes []string
	var memParts, cpuParts []string
	for _, c := range spec.Containers {
		w.Images = append(w.Images, redactStr(red, c.Image))
		if mem := c.Resources.Limits.Memory(); mem.IsZero() {
			w.HasMemoryLimits = false
			memParts = append(memParts, c.Name+"=none")
		} else {
			memParts = append(memParts, c.Name+"="+mem.String())
		}
		if cpu := c.Resources.Limits.Cpu(); cpu.IsZero() {
			w.HasCPULimits = false
			cpuParts = append(cpuParts, c.Name+"=none")
		} else {
			cpuParts = append(cpuParts, c.Name+"="+cpu.String())
		}
		if c.ReadinessProbe != nil {
			probes = append(probes, fmt.Sprintf("%s readiness (initialDelay=%ds)", c.Name, c.ReadinessProbe.InitialDelaySeconds))
		}
		if c.LivenessProbe != nil {
			probes = append(probes, fmt.Sprintf("%s liveness (initialDelay=%ds)", c.Name, c.LivenessProbe.InitialDelaySeconds))
		}
	}
	w.MemoryLimitDetail = strings.Join(memParts, "; ")
	w.CPULimitDetail = strings.Join(cpuParts, "; ")
	if len(probes) == 0 {
		w.ProbeSummary = "no readiness or liveness probes configured"
	} else {
		w.ProbeSummary = strings.Join(probes, "; ")
	}
	return w
}

// redactStr applies the redactor when present.
func redactStr(red plugin.Redactor, s string) string {
	if red == nil {
		return s
	}
	return red.Redact(s)
}

// gatherOwnerChain is the planner-facing wrapper: resolves the chain and
// renders it as investigation steps + topology evidence.
func gatherOwnerChain(ctx context.Context, cs kubernetes.Interface, red plugin.Redactor, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || name == "" {
		return []plugin.InvestigationStep{step("Owning workload chain inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	chain, err := ownerChainFor(ctx, cs, red, ns, name)
	if err != nil {
		return []plugin.InvestigationStep{step("Owning workload chain inspected", "unavailable", "pod fetch failed", "")}, nil
	}
	if len(chain.Links) == 0 {
		return []plugin.InvestigationStep{step("Owning workload chain inspected", "done", "pod has no workload owner (bare pod)", "")}, nil
	}
	var hops []string
	for _, l := range chain.Links {
		hops = append(hops, l.Kind+"/"+l.Name)
	}
	var evid []plugin.EvidenceItem
	evid = append(evid, plugin.EvidenceItem{
		Kind: "topology", Source: "pod/" + name, Edge: chain.Links[0].Edge,
		Excerpt: "ownership: pod → " + strings.Join(hops, " → "),
		Anchor:  "kubectl get pod " + name + " -n " + ns + " -o jsonpath='{.metadata.ownerReferences}'",
	})
	if w := chain.Workload; w != nil {
		lastEdge := chain.Links[len(chain.Links)-1].Edge
		src := strings.ToLower(w.Kind) + "/" + w.Name
		anchor := "kubectl describe " + strings.ToLower(w.Kind) + " " + w.Name + " -n " + ns
		// One atomic evidence item per fact family (rollout status, resource
		// limits, probes) instead of one dense compound line: small local
		// models misread multi-fact excerpts when answering yes/no questions
		// about a single fact, and atomic items also cite more precisely.
		evid = append(evid,
			plugin.EvidenceItem{
				Kind: "config", Source: src, Edge: lastEdge,
				Excerpt: fmt.Sprintf("ready %d/%d · strategy=%s · images=%s%s%s",
					w.Ready, w.Desired, w.Strategy, strings.Join(w.Images, ","),
					map[bool]string{true: " · PAUSED/SUSPENDED", false: ""}[w.Paused],
					map[bool]string{true: " · controller lagging (stale generation)", false: ""}[w.StaleGeneration]),
				Anchor: anchor,
			},
			plugin.EvidenceItem{
				Kind: "config", Source: src, Edge: lastEdge,
				// memLimits=%t stays verbatim: symptoms.go's confidence and
				// hypothesis matchers regex-match the "memLimits=false" literal.
				Excerpt: fmt.Sprintf("resource limits: memLimits=%t cpuLimits=%t · memory limit: %s · cpu limit: %s",
					w.HasMemoryLimits, w.HasCPULimits, w.MemoryLimitDetail, w.CPULimitDetail),
				Anchor: anchor,
			},
			plugin.EvidenceItem{
				Kind: "config", Source: src, Edge: lastEdge,
				Excerpt: "probes: " + w.ProbeSummary,
				Anchor:  anchor,
			},
		)
		for _, c := range w.Conditions {
			if strings.Contains(c, "=False") || strings.Contains(c, "Failed") {
				evid = append(evid, plugin.EvidenceItem{Kind: "event", Source: strings.ToLower(w.Kind) + "/" + w.Name, Edge: lastEdge, Excerpt: "condition: " + c})
			}
		}
	}
	return []plugin.InvestigationStep{step("Owning workload chain inspected", "done", strings.Join(hops, " → "), "")}, evid
}
