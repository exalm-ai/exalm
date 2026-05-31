package k8s

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func TestApplyRemediation_RolloutRestart_Deployment(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
	}
	cs := fake.NewSimpleClientset(deploy)

	action := plugin.RemediationAction{
		Kind:      "rollout-restart",
		Namespace: "default",
		Resource:  "deployment",
		Name:      "api",
	}
	if err := ApplyRemediation(context.Background(), cs, action); err != nil {
		t.Fatalf("ApplyRemediation: %v", err)
	}

	updated, err := cs.AppsV1().Deployments("default").Get(context.Background(), "api", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get deployment: %v", err)
	}
	annotations := updated.Spec.Template.Annotations
	val, ok := annotations["kubectl.kubernetes.io/restartedAt"]
	if !ok {
		t.Fatal("restartedAt annotation not set on deployment template")
	}
	if val == "" {
		t.Fatal("restartedAt annotation is empty")
	}
}

func TestApplyRemediation_RolloutRestart_StatefulSet(t *testing.T) {
	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "prod"},
	}
	cs := fake.NewSimpleClientset(ss)

	action := plugin.RemediationAction{
		Kind:      "rollout-restart",
		Namespace: "prod",
		Resource:  "statefulset",
		Name:      "db",
	}
	if err := ApplyRemediation(context.Background(), cs, action); err != nil {
		t.Fatalf("ApplyRemediation: %v", err)
	}

	updated, err := cs.AppsV1().StatefulSets("prod").Get(context.Background(), "db", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get statefulset: %v", err)
	}
	if _, ok := updated.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]; !ok {
		t.Fatal("restartedAt annotation not set on statefulset template")
	}
}

func TestApplyRemediation_ResumeCronJob(t *testing.T) {
	suspended := true
	cj := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "nightly-backup", Namespace: "ops"},
		Spec:       batchv1.CronJobSpec{Suspend: &suspended},
	}
	cs := fake.NewSimpleClientset(cj)

	action := plugin.RemediationAction{
		Kind:      "resume-cronjob",
		Namespace: "ops",
		Resource:  "cronjob",
		Name:      "nightly-backup",
	}
	if err := ApplyRemediation(context.Background(), cs, action); err != nil {
		t.Fatalf("ApplyRemediation: %v", err)
	}

	updated, err := cs.BatchV1().CronJobs("ops").Get(context.Background(), "nightly-backup", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get cronjob: %v", err)
	}
	if updated.Spec.Suspend != nil && *updated.Spec.Suspend {
		t.Fatal("cronjob is still suspended after resume-cronjob remediation")
	}
}

func TestApplyRemediation_DeletePod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "crash-pod-xyz", Namespace: "default"},
	}
	cs := fake.NewSimpleClientset(pod)

	action := plugin.RemediationAction{
		Kind:      "delete-pod",
		Namespace: "default",
		Resource:  "pod",
		Name:      "crash-pod-xyz",
	}
	if err := ApplyRemediation(context.Background(), cs, action); err != nil {
		t.Fatalf("ApplyRemediation: %v", err)
	}

	pods, err := cs.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("List pods: %v", err)
	}
	for _, p := range pods.Items {
		if p.Name == "crash-pod-xyz" {
			t.Fatal("pod was not deleted")
		}
	}
}

func TestApplyRemediation_UnknownKind(t *testing.T) {
	cs := fake.NewSimpleClientset()
	action := plugin.RemediationAction{Kind: "unknown-kind"}
	err := ApplyRemediation(context.Background(), cs, action)
	if err == nil {
		t.Fatal("expected error for unknown kind")
	}
	if !strings.Contains(err.Error(), "unknown remediation kind") {
		t.Errorf("unexpected error: %v", err)
	}
}
