package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNodeDetail_CapacityLabelsTaintsConditions(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "worker-3",
			Labels: map[string]string{"kubernetes.io/role": "worker"},
		},
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{{Key: "node.kubernetes.io/disk-pressure", Value: "", Effect: corev1.TaintEffectNoSchedule}},
		},
		Status: corev1.NodeStatus{
			Capacity:    corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("16Gi")},
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("3800m"), corev1.ResourceMemory: resource.MustParse("15Gi")},
			Conditions:  []corev1.NodeCondition{{Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue}, {Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}
	cs := fake.NewSimpleClientset(node)

	got, err := nodeDetail(context.Background(), cs, "worker-3")
	if err != nil {
		t.Fatalf("nodeDetail: %v", err)
	}
	if got.Capacity["cpu"] != "4" {
		t.Errorf("Capacity[cpu]: got %q want 4", got.Capacity["cpu"])
	}
	if got.Allocatable["memory"] != "15Gi" {
		t.Errorf("Allocatable[memory]: got %q want 15Gi", got.Allocatable["memory"])
	}
	if got.Labels["kubernetes.io/role"] != "worker" {
		t.Errorf("Labels: got %v", got.Labels)
	}
	if len(got.Taints) != 1 || got.Taints[0] != "node.kubernetes.io/disk-pressure=:NoSchedule" {
		t.Errorf("Taints: got %v", got.Taints)
	}
	if len(got.Conditions) != 2 {
		t.Errorf("expected 2 conditions (including healthy ones), got %v", got.Conditions)
	}
}

func TestNodeDetail_UnknownNodeErrors(t *testing.T) {
	cs := fake.NewSimpleClientset()
	if _, err := nodeDetail(context.Background(), cs, "ghost-node"); err == nil {
		t.Error("expected an error for an unknown node")
	}
}
