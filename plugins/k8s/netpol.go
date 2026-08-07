package k8s

// netpol.go resolves which NetworkPolicies select a pod. Zero matches in a
// namespace that HAS policies is a strong "default-deny likely" signal —
// pods not selected by any policy in such a namespace are typically isolated
// by an implicit deny from a policy selecting everything else.

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// NetpolDetail summarizes one NetworkPolicy selecting the pod.
type NetpolDetail struct {
	Name            string
	IngressRules    int
	EgressRules     int
	IsolatesIngress bool
	IsolatesEgress  bool
}

// networkPoliciesForPod returns the policies selecting the live pod and the
// total number of policies in the namespace (for the default-deny heuristic).
func networkPoliciesForPod(ctx context.Context, cs kubernetes.Interface, ns, podName string) ([]NetpolDetail, int, error) {
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("get pod %s/%s: %w", ns, podName, err)
	}
	nps, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("list networkpolicies in %s: %w", ns, err)
	}
	var out []NetpolDetail
	for _, np := range nps.Items {
		if !labelsMatch(np.Spec.PodSelector.MatchLabels, pod.Labels) {
			continue
		}
		d := NetpolDetail{Name: np.Name, IngressRules: len(np.Spec.Ingress), EgressRules: len(np.Spec.Egress)}
		for _, t := range np.Spec.PolicyTypes {
			switch t {
			case "Ingress":
				d.IsolatesIngress = true
			case "Egress":
				d.IsolatesEgress = true
			}
		}
		out = append(out, d)
	}
	return out, len(nps.Items), nil
}

// gatherNetpol is the planner-facing wrapper for network-policy coverage.
func gatherNetpol(ctx context.Context, cs kubernetes.Interface, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || name == "" {
		return []plugin.InvestigationStep{step("NetworkPolicies inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	matched, total, err := networkPoliciesForPod(ctx, cs, ns, name)
	if err != nil {
		return []plugin.InvestigationStep{step("NetworkPolicies inspected", "unavailable", "lookup failed", "")}, nil
	}
	if total == 0 {
		return []plugin.InvestigationStep{step("NetworkPolicies inspected", "done", "namespace has no NetworkPolicies (all traffic allowed)", "")}, nil
	}
	var evid []plugin.EvidenceItem
	if len(matched) == 0 {
		evid = append(evid, plugin.EvidenceItem{
			Kind: "config", Source: "networkpolicy", Edge: "pod→netpol",
			Excerpt: fmt.Sprintf("namespace has %d NetworkPolicies but NONE selects this pod — default-deny isolation is likely if a deny-all policy exists (heuristic)", total),
			Anchor:  "kubectl get networkpolicy -n " + ns,
		})
		return []plugin.InvestigationStep{step("NetworkPolicies inspected", "done", "no policy selects this pod (possible default-deny)", "")}, evid
	}
	for _, m := range matched {
		evid = append(evid, plugin.EvidenceItem{
			Kind: "config", Source: "networkpolicy/" + m.Name, Edge: "pod→netpol",
			Excerpt: fmt.Sprintf("isolatesIngress=%t (%d rules) isolatesEgress=%t (%d rules)", m.IsolatesIngress, m.IngressRules, m.IsolatesEgress, m.EgressRules),
			Anchor:  "kubectl describe networkpolicy " + m.Name + " -n " + ns,
		})
	}
	return []plugin.InvestigationStep{step("NetworkPolicies inspected", "done", fmt.Sprintf("%d of %d policies select this pod", len(matched), total), "")}, evid
}
