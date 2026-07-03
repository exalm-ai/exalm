package k8s

// scaling.go resolves autoscaling and disruption controls for a pod's
// workload: the HPA targeting it and any PodDisruptionBudgets covering the
// pod. On-demand collector (same trust class as configmaps.go).

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// HPADetail is a redaction-safe view of the HPA targeting a workload.
type HPADetail struct {
	Name             string
	Min, Max         int32
	Current, Desired int32
	AtMax            bool
	Conditions       []string
}

// PDBDetail summarizes one PodDisruptionBudget selecting the pod.
type PDBDetail struct {
	Name               string
	DisruptionsAllowed int32
	CurrentHealthy     int32
	DesiredHealthy     int32
}

// hpaForWorkload finds the HPA whose ScaleTargetRef names the workload.
func hpaForWorkload(ctx context.Context, cs kubernetes.Interface, red plugin.Redactor, ns, kind, name string) (*HPADetail, error) {
	hpas, err := cs.AutoscalingV2().HorizontalPodAutoscalers(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list hpas in %s: %w", ns, err)
	}
	for _, h := range hpas.Items {
		if !strings.EqualFold(h.Spec.ScaleTargetRef.Kind, kind) || h.Spec.ScaleTargetRef.Name != name {
			continue
		}
		d := &HPADetail{Name: h.Name, Max: h.Spec.MaxReplicas, Current: h.Status.CurrentReplicas, Desired: h.Status.DesiredReplicas}
		if h.Spec.MinReplicas != nil {
			d.Min = *h.Spec.MinReplicas
		}
		d.AtMax = h.Status.CurrentReplicas >= h.Spec.MaxReplicas && h.Status.DesiredReplicas >= h.Spec.MaxReplicas
		for _, c := range h.Status.Conditions {
			if c.Status == "False" || c.Type == "ScalingLimited" {
				d.Conditions = append(d.Conditions, redactStr(red, fmt.Sprintf("%s=%s: %s", c.Type, c.Status, c.Message)))
			}
		}
		return d, nil
	}
	return nil, nil
}

// pdbsForPod finds PodDisruptionBudgets whose selector matches the pod.
func pdbsForPod(ctx context.Context, cs kubernetes.Interface, ns, podName string) ([]PDBDetail, error) {
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", ns, podName, err)
	}
	pdbs, err := cs.PolicyV1().PodDisruptionBudgets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pdbs in %s: %w", ns, err)
	}
	var out []PDBDetail
	for _, p := range pdbs.Items {
		if p.Spec.Selector == nil || !labelsMatch(p.Spec.Selector.MatchLabels, pod.Labels) {
			continue
		}
		out = append(out, PDBDetail{
			Name:               p.Name,
			DisruptionsAllowed: p.Status.DisruptionsAllowed,
			CurrentHealthy:     p.Status.CurrentHealthy,
			DesiredHealthy:     p.Status.DesiredHealthy,
		})
	}
	return out, nil
}

// gatherScaling is the planner-facing wrapper: resolves the pod's workload
// (via the owner chain) then its HPA and PDB coverage.
func gatherScaling(ctx context.Context, cs kubernetes.Interface, red plugin.Redactor, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || name == "" {
		return []plugin.InvestigationStep{step("Autoscaling & disruption budgets inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	var evid []plugin.EvidenceItem
	chain, err := ownerChainFor(ctx, cs, red, ns, name)
	if err == nil && chain.Workload != nil {
		if hpa, err := hpaForWorkload(ctx, cs, red, ns, chain.Workload.Kind, chain.Workload.Name); err == nil && hpa != nil {
			ex := fmt.Sprintf("min=%d max=%d current=%d desired=%d", hpa.Min, hpa.Max, hpa.Current, hpa.Desired)
			if hpa.AtMax {
				ex += " · AT MAX — no scaling headroom"
			}
			if len(hpa.Conditions) > 0 {
				ex += " · " + strings.Join(hpa.Conditions, "; ")
			}
			evid = append(evid, plugin.EvidenceItem{
				Kind: "config", Source: "hpa/" + hpa.Name, Edge: "workload→hpa",
				Excerpt: ex,
				Anchor:  "kubectl describe hpa " + hpa.Name + " -n " + ns,
			})
		}
	}
	if pdbs, err := pdbsForPod(ctx, cs, ns, name); err == nil {
		for _, p := range pdbs {
			evid = append(evid, plugin.EvidenceItem{
				Kind: "config", Source: "pdb/" + p.Name, Edge: "pod→pdb",
				Excerpt: fmt.Sprintf("disruptionsAllowed=%d healthy=%d/%d", p.DisruptionsAllowed, p.CurrentHealthy, p.DesiredHealthy),
				Anchor:  "kubectl describe pdb " + p.Name + " -n " + ns,
			})
		}
	}
	if len(evid) == 0 {
		return []plugin.InvestigationStep{step("Autoscaling & disruption budgets inspected", "done", "no HPA or PDB covers this pod's workload", "")}, nil
	}
	return []plugin.InvestigationStep{step("Autoscaling & disruption budgets inspected", "done", fmt.Sprintf("%d control(s) found", len(evid)), "")}, evid
}
