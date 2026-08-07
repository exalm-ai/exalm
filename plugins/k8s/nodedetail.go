package k8s

// nodedetail.go is a lightweight, on-demand Node collector used by the
// conversation engine when a question implies "is this a node problem"
// (resource pressure, scheduling, taints). NodeIssue (snapshot.go) already
// captures unhealthy CONDITIONS during the main Collect() pass; this adds the
// full spec/capacity detail that's only worth fetching when a conversation
// actually asks about it.

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NodeDetail is the full picture of one node's capacity and scheduling
// constraints, beyond the unhealthy-conditions view NodeIssue already gives.
type NodeDetail struct {
	Name        string
	Capacity    map[string]string // resource name -> quantity string, e.g. "cpu" -> "4"
	Allocatable map[string]string
	Labels      map[string]string
	Taints      []string // "key=value:effect"
	Conditions  []string // "Type=Status" for every condition, not just unhealthy ones
}

// nodeNameForPod fetches the live pod to read which node it's scheduled on
// (PodSummary doesn't carry NodeName — it's only needed for node-pressure
// follow-up questions, so we fetch it on demand rather than always).
func nodeNameForPod(ctx context.Context, cs kubernetes.Interface, ns, podName string) (string, error) {
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get pod %s/%s: %w", ns, podName, err)
	}
	return pod.Spec.NodeName, nil
}

// nodeDetail fetches one node's full spec/status via a live, targeted GET.
func nodeDetail(ctx context.Context, cs kubernetes.Interface, name string) (*NodeDetail, error) {
	n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get node %s: %w", name, err)
	}
	return &NodeDetail{
		Name:        n.Name,
		Capacity:    quantityMap(n.Status.Capacity),
		Allocatable: quantityMap(n.Status.Allocatable),
		Labels:      n.Labels,
		Taints:      taintStrings(n.Spec.Taints),
		Conditions:  conditionStrings(n.Status.Conditions),
	}, nil
}

func quantityMap(rl corev1.ResourceList) map[string]string {
	out := make(map[string]string, len(rl))
	for k, v := range rl {
		out[string(k)] = v.String()
	}
	return out
}

func taintStrings(taints []corev1.Taint) []string {
	out := make([]string, 0, len(taints))
	for _, t := range taints {
		out = append(out, fmt.Sprintf("%s=%s:%s", t.Key, t.Value, t.Effect))
	}
	return out
}

func conditionStrings(conds []corev1.NodeCondition) []string {
	out := make([]string, 0, len(conds))
	for _, c := range conds {
		out = append(out, fmt.Sprintf("%s=%s", c.Type, c.Status))
	}
	return out
}
