package k8s

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func ptr32(n int32) *int32 { return &n }

// --- Deployments ---

func TestCollectDeployments_Healthy(t *testing.T) {
	d := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
		Status: appsv1.DeploymentStatus{
			Replicas:          3,
			AvailableReplicas: 3,
		},
	}
	cs := fake.NewSimpleClientset(&d)
	got, err := collectDeployments(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 unhealthy deployments, got %d", len(got))
	}
}

func TestCollectDeployments_Unavailable(t *testing.T) {
	d := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
		Status: appsv1.DeploymentStatus{
			Replicas:          3,
			AvailableReplicas: 1,
		},
	}
	cs := fake.NewSimpleClientset(&d)
	got, err := collectDeployments(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].Unavailable != 2 {
		t.Errorf("expected unavailable=2, got %d", got[0].Unavailable)
	}
}

func TestCollectDeployments_ProgressStalled(t *testing.T) {
	d := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "prod"},
		Status: appsv1.DeploymentStatus{
			Replicas:          2,
			AvailableReplicas: 2, // fully available but stalled
			Conditions: []appsv1.DeploymentCondition{
				{
					Type:   "Progressing",
					Status: corev1.ConditionFalse,
					Reason: "ProgressDeadlineExceeded",
				},
			},
		},
	}
	cs := fake.NewSimpleClientset(&d)
	got, err := collectDeployments(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].StallReason != "ProgressDeadlineExceeded" {
		t.Errorf("expected ProgressDeadlineExceeded, got %q", got[0].StallReason)
	}
}

// --- HPAs ---

func TestCollectHPAs_Healthy(t *testing.T) {
	hpa := autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "web-hpa", Namespace: "prod"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "web"},
			MinReplicas:    ptr32(2),
			MaxReplicas:    10,
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
				{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionTrue},
				{Type: autoscalingv2.ScalingActive, Status: corev1.ConditionTrue},
			},
		},
	}
	cs := fake.NewSimpleClientset(&hpa)
	got, err := collectHPAs(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 issues, got %d", len(got))
	}
}

func TestCollectHPAs_ScalingDisabled(t *testing.T) {
	hpa := autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "api-hpa", Namespace: "prod"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "api"},
			MaxReplicas:    5,
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
				{
					Type:   autoscalingv2.ScalingActive,
					Status: corev1.ConditionFalse,
					Reason: "FailedGetScale",
				},
			},
		},
	}
	cs := fake.NewSimpleClientset(&hpa)
	got, err := collectHPAs(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].Issue == "" {
		t.Error("expected non-empty issue")
	}
}

func TestCollectHPAs_ScalingLimited(t *testing.T) {
	hpa := autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "db-hpa", Namespace: "prod"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "StatefulSet", Name: "db"},
			MaxReplicas:    3,
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
				{
					Type:   autoscalingv2.ScalingLimited,
					Status: corev1.ConditionTrue,
					Reason: "TooManyReplicas",
				},
			},
		},
	}
	cs := fake.NewSimpleClientset(&hpa)
	got, err := collectHPAs(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].Issue == "" {
		t.Error("expected non-empty issue")
	}
}
