package k8s

// namespacedetail.go resolves namespace-level constraints that can starve or
// block a pod: the namespace phase, ResourceQuota usage, and LimitRanges.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// NamespaceDetail summarizes a namespace's phase and constraints.
type NamespaceDetail struct {
	Name        string
	Phase       string
	Age         string
	QuotaUsage  []string // "requests.memory: 12Gi/16Gi (75%)"
	LimitRanges []string // "container default memory limit 512Mi"
}

// namespaceDetailFor fetches the namespace, its quotas, and its LimitRanges.
func namespaceDetailFor(ctx context.Context, cs kubernetes.Interface, ns string) (*NamespaceDetail, error) {
	n, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get namespace %s: %w", ns, err)
	}
	d := &NamespaceDetail{
		Name:  ns,
		Phase: string(n.Status.Phase),
		Age:   humanizeAge(n.CreationTimestamp.Time, time.Now()),
	}
	if quotas, err := cs.CoreV1().ResourceQuotas(ns).List(ctx, metav1.ListOptions{}); err == nil {
		for _, q := range quotas.Items {
			keys := make([]corev1.ResourceName, 0, len(q.Status.Hard))
			for k := range q.Status.Hard {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, k := range keys {
				hard := q.Status.Hard[k]
				used := q.Status.Used[k]
				d.QuotaUsage = append(d.QuotaUsage, fmt.Sprintf("%s: %s/%s", k, used.String(), hard.String()))
			}
		}
	}
	if lrs, err := cs.CoreV1().LimitRanges(ns).List(ctx, metav1.ListOptions{}); err == nil {
		for _, lr := range lrs.Items {
			for _, item := range lr.Spec.Limits {
				var parts []string
				for res, v := range item.Default {
					parts = append(parts, fmt.Sprintf("default %s limit %s", res, v.String()))
				}
				sort.Strings(parts)
				if len(parts) > 0 {
					d.LimitRanges = append(d.LimitRanges, fmt.Sprintf("%s (%s): %s", lr.Name, item.Type, strings.Join(parts, ", ")))
				}
			}
		}
	}
	return d, nil
}

// gatherNamespaceDetail is the planner-facing wrapper for namespace limits.
func gatherNamespaceDetail(ctx context.Context, cs kubernetes.Interface, ns string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || ns == "" {
		return []plugin.InvestigationStep{step("Namespace quotas & limits inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	d, err := namespaceDetailFor(ctx, cs, ns)
	if err != nil {
		return []plugin.InvestigationStep{step("Namespace quotas & limits inspected", "unavailable", "namespace fetch failed", "")}, nil
	}
	var evid []plugin.EvidenceItem
	if len(d.QuotaUsage) > 0 {
		evid = append(evid, plugin.EvidenceItem{
			Kind: "config", Source: "namespace/" + ns, Edge: "ns→quota",
			Excerpt: "quota usage: " + strings.Join(d.QuotaUsage, " · "),
			Anchor:  "kubectl describe quota -n " + ns,
		})
	}
	if len(d.LimitRanges) > 0 {
		evid = append(evid, plugin.EvidenceItem{
			Kind: "config", Source: "namespace/" + ns, Edge: "ns→limitrange",
			Excerpt: "limitranges: " + strings.Join(d.LimitRanges, " · "),
			Anchor:  "kubectl describe limitrange -n " + ns,
		})
	}
	detail := fmt.Sprintf("phase=%s, %d quota line(s), %d limitrange(s)", d.Phase, len(d.QuotaUsage), len(d.LimitRanges))
	return []plugin.InvestigationStep{step("Namespace quotas & limits inspected", "done", detail, "")}, evid
}
