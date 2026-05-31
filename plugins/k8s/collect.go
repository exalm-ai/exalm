package k8s

import (
	"context"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// CollectOpts controls what gets gathered from the cluster.
type CollectOpts struct {
	Namespace     string
	MaxPods       int
	Since         time.Duration // time window for warning events
	IncludeNodes  bool
	LogLines      int64
	DynamicClient dynamic.Interface // optional; used for IaC change detection (ArgoCD CRDs)
}

// Collect queries the cluster and returns a Snapshot ready for formatting.
// All errors from log fetches are captured inside LogTail.Error; the caller
// always receives a usable (possibly partial) Snapshot.
func Collect(ctx context.Context, cs kubernetes.Interface, lf logFetcher, opts CollectOpts) (Snapshot, error) {
	now := time.Now()
	ns := opts.Namespace

	podList, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{Limit: 500})
	if err != nil {
		return Snapshot{}, fmt.Errorf("list pods: %w", err)
	}

	type scoredPod struct {
		pod    corev1.Pod
		result healthResult
	}
	var unhealthy []scoredPod
	for _, pod := range podList.Items {
		r := checkHealth(pod, now)
		if r.reason != "" {
			unhealthy = append(unhealthy, scoredPod{pod, r})
		}
	}

	sort.Slice(unhealthy, func(i, j int) bool {
		return unhealthy[i].result.score > unhealthy[j].result.score
	})
	if len(unhealthy) > opts.MaxPods {
		unhealthy = unhealthy[:opts.MaxPods]
	}

	podSummaries := make([]PodSummary, 0, len(unhealthy))
	for _, sp := range unhealthy {
		podSummaries = append(podSummaries, buildPodSummary(ctx, sp.pod, sp.result, lf, opts.LogLines, now))
	}

	events, err := collectEvents(ctx, cs, ns, opts.Since, now)
	if err != nil {
		return Snapshot{}, err
	}

	deployments, err := collectDeployments(ctx, cs, ns)
	if err != nil {
		return Snapshot{}, err
	}

	// Non-fatal: autoscaling/v2 not available on older clusters (< K8s 1.23).
	hpas, _ := collectHPAs(ctx, cs, ns)

	quotas, err := collectQuotas(ctx, cs, ns)
	if err != nil {
		return Snapshot{}, err
	}

	snap := Snapshot{
		Namespace:     ns,
		TotalPods:     len(podList.Items),
		UnhealthyPods: podSummaries,
		Events:        events,
		Deployments:   deployments,
		HPAs:          hpas,
		Quotas:        quotas,
	}

	if opts.IncludeNodes {
		snap.NodeIssues, _ = collectNodeIssues(ctx, cs)
	}

	// Non-fatal: some clusters restrict PVC or endpoint RBAC.
	snap.PVCIssues, _ = collectPVCIssues(ctx, cs, ns)
	snap.ServiceIssues, _ = collectServiceIssues(ctx, cs, ns)

	// Extended analyzers — all non-fatal; partial results are still useful.
	snap.IngressIssues, _ = collectIngresses(ctx, cs, ns)
	snap.ResourceGaps, _ = collectResourceGaps(ctx, cs, ns)
	snap.UncoveredNamespaces, _ = collectNetworkPolicyCoverage(ctx, cs, ns)
	snap.RBACRisks, _ = collectRBACRisks(ctx, cs)
	snap.ReplicaSetIssues, _ = collectReplicaSetIssues(ctx, cs, ns)
	snap.StatefulSetIssues, _ = collectStatefulSetIssues(ctx, cs, ns)
	snap.FailedJobs, _ = collectJobIssues(ctx, cs, ns)
	snap.CronJobIssues, _ = collectCronJobIssues(ctx, cs, ns, now)

	// Phase 2 extended analyzers.
	snap.SelectorMismatches, _ = collectSelectorMismatches(ctx, cs, ns)
	snap.CrossNamespaceIssues, _ = collectCrossNamespaceIssues(ctx, cs)

	// Phase 3 IaC change detection — best-effort; nil dynamic client is safe.
	snap.IaCChanges, _ = collectIaCChanges(ctx, cs, opts.DynamicClient, ns)

	return snap, nil
}

// collectPVCIssues returns PVCs that are not yet bound.
func collectPVCIssues(ctx context.Context, cs kubernetes.Interface, ns string) ([]PVCIssue, error) {
	list, err := cs.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list PVCs: %w", err)
	}
	var issues []PVCIssue
	for _, pvc := range list.Items {
		if pvc.Status.Phase == corev1.ClaimBound {
			continue
		}
		sc := ""
		if pvc.Spec.StorageClassName != nil {
			sc = *pvc.Spec.StorageClassName
		}
		reason := "provisioner not responding"
		for _, cond := range pvc.Status.Conditions {
			if cond.Message != "" {
				reason = cond.Message
				break
			}
		}
		issues = append(issues, PVCIssue{
			Namespace:    pvc.Namespace,
			Name:         pvc.Name,
			Phase:        string(pvc.Status.Phase),
			StorageClass: sc,
			Reason:       reason,
		})
	}
	return issues, nil
}

// collectServiceIssues returns Services that have a selector but no ready endpoints.
func collectServiceIssues(ctx context.Context, cs kubernetes.Interface, ns string) ([]ServiceIssue, error) {
	epList, err := cs.CoreV1().Endpoints(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}
	svcList, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	hasEndpoints := map[string]bool{}
	for _, ep := range epList.Items {
		for _, sub := range ep.Subsets {
			if len(sub.Addresses) > 0 {
				hasEndpoints[ep.Name] = true
				break
			}
		}
	}

	var issues []ServiceIssue
	for _, svc := range svcList.Items {
		if svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		if len(svc.Spec.Selector) == 0 {
			continue // headless or manually managed
		}
		if !hasEndpoints[svc.Name] {
			issues = append(issues, ServiceIssue{
				Namespace: svc.Namespace,
				Name:      svc.Name,
				Issue:     "no ready endpoints — pod selector may not match any running pod",
			})
		}
	}
	return issues, nil
}

func buildPodSummary(ctx context.Context, pod corev1.Pod, r healthResult, lf logFetcher, logLines int64, now time.Time) PodSummary {
	var maxRestarts int32
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.RestartCount > maxRestarts {
			maxRestarts = cs.RestartCount
		}
	}
	// Also check init containers for restart count.
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.RestartCount > maxRestarts {
			maxRestarts = cs.RestartCount
		}
	}

	tails := fetchLogs(ctx, pod, lf, logLines)

	// Scan all non-empty tails for service-level signals.
	var anomalies []LogAnomaly
	for _, t := range tails {
		if t.Error == "" && t.Lines != "" {
			anomalies = append(anomalies, scanLogPatterns(t.Lines)...)
		}
	}

	return PodSummary{
		Namespace:    pod.Namespace,
		Name:         pod.Name,
		Phase:        string(pod.Status.Phase),
		Reason:       r.reason,
		Score:        r.score,
		RestartCount: maxRestarts,
		Age:          humanAge(now.Sub(pod.CreationTimestamp.Time)),
		HasNoLimits:  hasNoLimits(pod),
		LogTails:     tails,
		LogAnomalies: anomalies,
	}
}

func fetchLogs(ctx context.Context, pod corev1.Pod, lf logFetcher, lines int64) []LogTail {
	var tails []LogTail

	// Init containers first — a stuck init blocks the whole pod.
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.Ready {
			continue
		}
		previous := cs.RestartCount > 0 && cs.LastTerminationState.Terminated != nil
		logCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		content, err := lf.Tail(logCtx, pod.Namespace, pod.Name, cs.Name, lines, previous)
		cancel()
		lt := LogTail{Container: cs.Name, Lines: content}
		if err != nil {
			lt.Error = err.Error()
		}
		tails = append(tails, lt)
	}

	// Main containers.
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Ready {
			continue
		}
		previous := cs.RestartCount > 0 && cs.LastTerminationState.Terminated != nil
		logCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		content, err := lf.Tail(logCtx, pod.Namespace, pod.Name, cs.Name, lines, previous)
		cancel()
		lt := LogTail{Container: cs.Name, Lines: content}
		if err != nil {
			lt.Error = err.Error()
		}
		tails = append(tails, lt)
	}
	return tails
}

func collectEvents(ctx context.Context, cs kubernetes.Interface, ns string, since time.Duration, now time.Time) ([]EventSummary, error) {
	evList, err := cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}

	cutoff := now.Add(-since)
	var summaries []EventSummary
	for _, e := range evList.Items {
		if e.Type != corev1.EventTypeWarning || e.InvolvedObject.Kind != "Pod" {
			continue
		}
		lastSeen := e.LastTimestamp.Time
		if lastSeen.IsZero() {
			lastSeen = e.EventTime.Time
		}
		if lastSeen.IsZero() {
			lastSeen = now // unknown time — include it
		}
		if lastSeen.Before(cutoff) {
			continue
		}

		// Density: events per second over the event's lifetime window.
		var density float64
		first := e.FirstTimestamp.Time
		if !first.IsZero() && !lastSeen.IsZero() && lastSeen.After(first) {
			window := lastSeen.Sub(first).Seconds()
			if window > 0 {
				density = float64(e.Count) / window
			}
		}

		summaries = append(summaries, EventSummary{
			Namespace: e.Namespace,
			PodName:   e.InvolvedObject.Name,
			Reason:    e.Reason,
			Message:   e.Message,
			Count:     e.Count,
			LastSeen:  humanAge(now.Sub(lastSeen)) + " ago",
			Density:   density,
		})
	}
	return summaries, nil
}

func collectNodeIssues(ctx context.Context, cs kubernetes.Interface) ([]NodeIssue, error) {
	nodeList, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	var issues []NodeIssue
	for _, node := range nodeList.Items {
		var conditions []string
		for _, c := range node.Status.Conditions {
			switch {
			case c.Type == corev1.NodeReady && c.Status != corev1.ConditionTrue:
				conditions = append(conditions, "NotReady")
			case c.Type == corev1.NodeMemoryPressure && c.Status == corev1.ConditionTrue:
				conditions = append(conditions, "MemoryPressure")
			case c.Type == corev1.NodeDiskPressure && c.Status == corev1.ConditionTrue:
				conditions = append(conditions, "DiskPressure")
			case c.Type == corev1.NodePIDPressure && c.Status == corev1.ConditionTrue:
				conditions = append(conditions, "PIDPressure")
			case c.Type == corev1.NodeNetworkUnavailable && c.Status == corev1.ConditionTrue:
				conditions = append(conditions, "NetworkUnavailable")
			}
		}
		if len(conditions) > 0 {
			issues = append(issues, NodeIssue{Name: node.Name, Conditions: conditions})
		}
	}
	return issues, nil
}
