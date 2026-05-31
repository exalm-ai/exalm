package k8s

import (
	"context"
	"fmt"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// collectDeployments returns Deployments that are not fully available
// or whose rollout has stalled (Progressing condition = False).
func collectDeployments(ctx context.Context, cs kubernetes.Interface, ns string) ([]DeploymentSummary, error) {
	list, err := cs.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}

	var summaries []DeploymentSummary
	for _, d := range list.Items {
		stallReason := ""
		for _, c := range d.Status.Conditions {
			if c.Type == "Progressing" && c.Status == corev1.ConditionFalse {
				stallReason = c.Reason
				if stallReason == "" {
					stallReason = "ProgressStalled"
				}
			}
		}
		unavailable := d.Status.Replicas - d.Status.AvailableReplicas
		if unavailable <= 0 && stallReason == "" {
			continue // healthy
		}
		if unavailable < 0 {
			unavailable = 0
		}
		summaries = append(summaries, DeploymentSummary{
			Namespace:   d.Namespace,
			Name:        d.Name,
			Desired:     d.Status.Replicas,
			Available:   d.Status.AvailableReplicas,
			Unavailable: unavailable,
			StallReason: stallReason,
		})
	}
	return summaries, nil
}

// collectHPAs returns HPAs with scaling problems: unable to fetch metrics,
// scaling disabled, or desired replicas unachievable.
func collectHPAs(ctx context.Context, cs kubernetes.Interface, ns string) ([]HPASummary, error) {
	list, err := cs.AutoscalingV2().HorizontalPodAutoscalers(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list HPAs: %w", err)
	}

	var summaries []HPASummary
	for _, hpa := range list.Items {
		issue := hpaIssue(hpa.Status.Conditions)
		if issue == "" {
			continue // healthy
		}
		minReplicas := int32(1)
		if hpa.Spec.MinReplicas != nil {
			minReplicas = *hpa.Spec.MinReplicas
		}
		ref := hpa.Spec.ScaleTargetRef
		summaries = append(summaries, HPASummary{
			Namespace:       hpa.Namespace,
			Name:            hpa.Name,
			TargetKind:      ref.Kind,
			TargetName:      ref.Name,
			CurrentReplicas: hpa.Status.CurrentReplicas,
			DesiredReplicas: hpa.Status.DesiredReplicas,
			MinReplicas:     minReplicas,
			MaxReplicas:     hpa.Spec.MaxReplicas,
			Issue:           issue,
		})
	}
	return summaries, nil
}

// hpaIssue returns a human-readable issue string if the HPA has a problem,
// or empty string if healthy.
func hpaIssue(conditions []autoscalingv2.HorizontalPodAutoscalerCondition) string {
	for _, c := range conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case autoscalingv2.ScalingActive:
			// ScalingActive=False means HPA is disabled
		case autoscalingv2.AbleToScale:
			// AbleToScale=False means metrics unavailable
		default:
			continue
		}
		// These conditions being False is the problem
		_ = c
	}

	// Re-scan for False conditions that indicate problems.
	for _, c := range conditions {
		if c.Status == corev1.ConditionFalse {
			switch c.Type {
			case autoscalingv2.ScalingActive:
				return fmt.Sprintf("ScalingDisabled: %s", c.Reason)
			case autoscalingv2.AbleToScale:
				return fmt.Sprintf("CannotScale: %s", c.Reason)
			}
		}
		if c.Status == corev1.ConditionTrue && c.Type == autoscalingv2.ScalingLimited {
			return fmt.Sprintf("ScalingLimited: %s", c.Reason)
		}
	}
	return ""
}
