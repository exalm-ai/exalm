package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ApplyRemediation executes the k8s API operation described by action.
//
// Strength: komodor — "Auto-remediation closes the loop from detection to action".
// Strength: openobserve — "Python Actions enable custom remediation scripts" (we go further:
// 8 first-class K8s actions, declarative, no shell execution, audit-logged).
func ApplyRemediation(ctx context.Context, cs kubernetes.Interface, a plugin.RemediationAction) error {
	switch a.Kind {
	case "rollout-restart":
		return rolloutRestart(ctx, cs, a)
	case "resume-cronjob":
		return resumeCronJob(ctx, cs, a)
	case "delete-pod":
		return deletePod(ctx, cs, a)
	case "patch-resource":
		return patchResource(ctx, cs, a)
	case "scale-deployment":
		return scaleDeployment(ctx, cs, a)
	case "add-limits":
		return addResourceLimits(ctx, cs, a)
	case "label-resource":
		return labelResource(ctx, cs, a)
	case "cordon-node":
		return cordonNode(ctx, cs, a)
	default:
		return fmt.Errorf("unknown remediation kind %q", a.Kind)
	}
}

// rolloutRestart triggers a rolling restart by patching the pod template annotation.
// Works for both Deployments and StatefulSets.
func rolloutRestart(ctx context.Context, cs kubernetes.Interface, a plugin.RemediationAction) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`, ts)
	p := []byte(patch)

	switch a.Resource {
	case "deployment":
		_, err := cs.AppsV1().Deployments(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("patch deployment %s/%s: %w", a.Namespace, a.Name, err)
		}
	case "statefulset":
		_, err := cs.AppsV1().StatefulSets(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("patch statefulset %s/%s: %w", a.Namespace, a.Name, err)
		}
	default:
		return fmt.Errorf("rollout-restart unsupported resource %q (expected deployment or statefulset)", a.Resource)
	}
	return nil
}

// resumeCronJob un-suspends a CronJob by patching spec.suspend=false.
func resumeCronJob(ctx context.Context, cs kubernetes.Interface, a plugin.RemediationAction) error {
	patch, err := json.Marshal(map[string]any{
		"spec": map[string]any{"suspend": false},
	})
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}
	_, err = cs.BatchV1().CronJobs(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patch cronjob %s/%s: %w", a.Namespace, a.Name, err)
	}
	return nil
}

// deletePod deletes a pod so the controller reschedules it.
func deletePod(ctx context.Context, cs kubernetes.Interface, a plugin.RemediationAction) error {
	err := cs.CoreV1().Pods(a.Namespace).Delete(ctx, a.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("delete pod %s/%s: %w", a.Namespace, a.Name, err)
	}
	return nil
}

// patchResource applies a generic JSON merge patch to any resource type.
// The resource kind is taken from a.Resource (deployment, service, statefulset,
// cronjob, pvc, node, configmap).
func patchResource(ctx context.Context, cs kubernetes.Interface, a plugin.RemediationAction) error {
	p := []byte(a.PatchJSON)
	switch a.Resource {
	case "deployment":
		_, err := cs.AppsV1().Deployments(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("patch deployment %s/%s: %w", a.Namespace, a.Name, err)
		}
	case "statefulset":
		_, err := cs.AppsV1().StatefulSets(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("patch statefulset %s/%s: %w", a.Namespace, a.Name, err)
		}
	case "service":
		_, err := cs.CoreV1().Services(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("patch service %s/%s: %w", a.Namespace, a.Name, err)
		}
	case "cronjob":
		_, err := cs.BatchV1().CronJobs(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("patch cronjob %s/%s: %w", a.Namespace, a.Name, err)
		}
	case "pvc":
		_, err := cs.CoreV1().PersistentVolumeClaims(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("patch pvc %s/%s: %w", a.Namespace, a.Name, err)
		}
	case "node":
		_, err := cs.CoreV1().Nodes().Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("patch node %s: %w", a.Name, err)
		}
	default:
		return fmt.Errorf("patch-resource unsupported resource kind %q", a.Resource)
	}
	return nil
}

// scaleDeployment sets the replica count for a Deployment.
// a.PatchJSON must be a valid merge patch, e.g. {"spec":{"replicas":2}}.
func scaleDeployment(ctx context.Context, cs kubernetes.Interface, a plugin.RemediationAction) error {
	p := []byte(a.PatchJSON)
	_, err := cs.AppsV1().Deployments(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("scale deployment %s/%s: %w", a.Namespace, a.Name, err)
	}
	return nil
}

// addResourceLimits patches a Deployment's containers to add default CPU and
// memory limits using a strategic merge patch.
// a.PatchJSON must be a strategic-merge-patch that sets containers[*].resources.
func addResourceLimits(ctx context.Context, cs kubernetes.Interface, a plugin.RemediationAction) error {
	p := []byte(a.PatchJSON)
	_, err := cs.AppsV1().Deployments(a.Namespace).Patch(ctx, a.Name, types.StrategicMergePatchType, p, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("add limits to deployment %s/%s: %w", a.Namespace, a.Name, err)
	}
	return nil
}

// labelResource applies a label patch to a Deployment or Service.
// a.PatchJSON must update metadata.labels.
func labelResource(ctx context.Context, cs kubernetes.Interface, a plugin.RemediationAction) error {
	p := []byte(a.PatchJSON)
	switch a.Resource {
	case "deployment":
		_, err := cs.AppsV1().Deployments(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("label deployment %s/%s: %w", a.Namespace, a.Name, err)
		}
	case "service":
		_, err := cs.CoreV1().Services(a.Namespace).Patch(ctx, a.Name, types.MergePatchType, p, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("label service %s/%s: %w", a.Namespace, a.Name, err)
		}
	default:
		return fmt.Errorf("label-resource unsupported resource %q", a.Resource)
	}
	return nil
}

// cordonNode marks a node as unschedulable so no new pods are placed on it.
func cordonNode(ctx context.Context, cs kubernetes.Interface, a plugin.RemediationAction) error {
	patch := []byte(`{"spec":{"unschedulable":true}}`)
	_, err := cs.CoreV1().Nodes().Patch(ctx, a.Name, types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("cordon node %s: %w", a.Name, err)
	}
	return nil
}
