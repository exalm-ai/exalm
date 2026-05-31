package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// collectQuotas returns ResourceQuota entries where any resource dimension is
// at or above 70% utilisation — only noisy when pressure is real.
func collectQuotas(ctx context.Context, cs kubernetes.Interface, ns string) ([]QuotaSummary, error) {
	list, err := cs.CoreV1().ResourceQuotas(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list resource quotas: %w", err)
	}

	var summaries []QuotaSummary
	for _, rq := range list.Items {
		for resourceName, hard := range rq.Status.Hard {
			used, ok := rq.Status.Used[resourceName]
			if !ok {
				continue
			}
			pct := usedPct(resourceName, used, hard)
			if pct < 70 {
				continue
			}
			summaries = append(summaries, QuotaSummary{
				Namespace: rq.Namespace,
				Resource:  string(resourceName),
				Used:      used.String(),
				Hard:      hard.String(),
				UsedPct:   pct,
			})
		}
	}
	return summaries, nil
}

// usedPct computes used/hard as an integer percentage (0–100).
// Falls back to string parsing for opaque resource names.
func usedPct(name corev1.ResourceName, used, hard resource.Quantity) int {
	hardVal := hard.MilliValue()
	if hardVal == 0 {
		return 0
	}
	pct := int(used.MilliValue() * 100 / hardVal)
	if pct > 100 {
		pct = 100
	}
	return pct
}

// hasNoLimits returns true if any container in the pod has no CPU or memory
// limit set. Unlimited containers are an OOMKill / noisy-neighbour risk.
func hasNoLimits(pod corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Resources.Limits == nil {
			return true
		}
		if _, ok := c.Resources.Limits[corev1.ResourceCPU]; !ok {
			return true
		}
		if _, ok := c.Resources.Limits[corev1.ResourceMemory]; !ok {
			return true
		}
	}
	return false
}
