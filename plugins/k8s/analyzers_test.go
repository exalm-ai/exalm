package k8s

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCollectIngresses_MissingClass(t *testing.T) {
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
		Spec:       networkingv1.IngressSpec{},
	}
	cs := fake.NewSimpleClientset(ing)
	issues, err := collectIngresses(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) == 0 {
		t.Fatal("expected ingress issue for missing class")
	}
	if !issues[0].MissingClass {
		t.Error("expected MissingClass=true")
	}
}

func TestCollectIngresses_MissingBackend(t *testing.T) {
	className := "nginx"
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			Rules: []networkingv1.IngressRule{
				{IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{Name: "missing-svc"},
							}},
						},
					},
				}},
			},
		},
	}
	ic := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "nginx"}}
	cs := fake.NewSimpleClientset(ing, ic)
	issues, err := collectIngresses(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) == 0 {
		t.Fatal("expected ingress issue for missing backend service")
	}
	if len(issues[0].MissingBackends) == 0 {
		t.Error("expected MissingBackends to be populated")
	}
}

func TestCollectIngresses_Healthy(t *testing.T) {
	className := "nginx"
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api-svc", Namespace: "prod"}}
	ic := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "nginx"}}
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			Rules: []networkingv1.IngressRule{
				{IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{
							{Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{Name: "api-svc"},
							}},
						},
					},
				}},
			},
		},
	}
	cs := fake.NewSimpleClientset(ing, svc, ic)
	issues, err := collectIngresses(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no ingress issues for healthy ingress, got %d", len(issues))
	}
}

func TestCollectResourceGaps_BestEffort(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "no-limits", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app"}, // no resources at all
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(pod)
	gaps, err := collectResourceGaps(context.Background(), cs, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) == 0 {
		t.Fatal("expected resource gap for pod with no limits")
	}
	if !gaps[0].BestEffort {
		t.Error("expected BestEffort=true when no requests or limits")
	}
}

func TestCollectResourceGaps_SkipsCompleted(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "finished", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}
	cs := fake.NewSimpleClientset(pod)
	gaps, err := collectResourceGaps(context.Background(), cs, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 {
		t.Error("expected no gaps for completed pods")
	}
}

func TestCollectRBACRisks_ClusterAdmin(t *testing.T) {
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "admin-binding"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "default", Namespace: "prod"},
		},
	}
	cs := fake.NewSimpleClientset(crb)
	risks, err := collectRBACRisks(context.Background(), cs)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) == 0 {
		t.Fatal("expected RBAC risk for cluster-admin binding")
	}
	if risks[0].Reason != "cluster-admin binding" {
		t.Errorf("unexpected reason: %q", risks[0].Reason)
	}
}

func TestCollectReplicaSetIssues_NotReady(t *testing.T) {
	desired := int32(3)
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "api-rs", Namespace: "prod"},
		Spec:       appsv1.ReplicaSetSpec{Replicas: &desired},
		Status:     appsv1.ReplicaSetStatus{Replicas: 3, ReadyReplicas: 1},
	}
	cs := fake.NewSimpleClientset(rs)
	issues, err := collectReplicaSetIssues(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) == 0 {
		t.Fatal("expected ReplicaSet issue when ready < desired")
	}
	if issues[0].Ready != 1 || issues[0].Desired != 3 {
		t.Errorf("unexpected counts: desired=%d ready=%d", issues[0].Desired, issues[0].Ready)
	}
}

func TestCollectReplicaSetIssues_Healthy(t *testing.T) {
	desired := int32(3)
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "api-rs", Namespace: "prod"},
		Spec:       appsv1.ReplicaSetSpec{Replicas: &desired},
		Status:     appsv1.ReplicaSetStatus{Replicas: 3, ReadyReplicas: 3},
	}
	cs := fake.NewSimpleClientset(rs)
	issues, err := collectReplicaSetIssues(context.Background(), cs, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Errorf("expected no issues for healthy ReplicaSet, got %d", len(issues))
	}
}

func TestCollectJobIssues_Failed(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "batch"},
		Status:     batchv1.JobStatus{Failed: 3, Active: 0},
	}
	cs := fake.NewSimpleClientset(job)
	issues, err := collectJobIssues(context.Background(), cs, "batch")
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) == 0 {
		t.Fatal("expected job issue for failed job")
	}
}

func TestCollectJobIssues_StillActive(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "running", Namespace: "batch"},
		Status:     batchv1.JobStatus{Failed: 1, Active: 1},
	}
	cs := fake.NewSimpleClientset(job)
	issues, err := collectJobIssues(context.Background(), cs, "batch")
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Error("expected no issues for still-active job")
	}
}

func TestCollectCronJobIssues_Suspended(t *testing.T) {
	suspended := true
	cj := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "cleanup", Namespace: "batch"},
		Spec:       batchv1.CronJobSpec{Suspend: &suspended, Schedule: "@daily"},
	}
	cs := fake.NewSimpleClientset(cj)
	issues, err := collectCronJobIssues(context.Background(), cs, "batch", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) == 0 {
		t.Fatal("expected CronJob issue for suspended job")
	}
	if !issues[0].Suspended {
		t.Error("expected Suspended=true")
	}
}

func TestCollectCronJobIssues_Active(t *testing.T) {
	suspended := false
	cj := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "active", Namespace: "batch"},
		Spec:       batchv1.CronJobSpec{Suspend: &suspended, Schedule: "@daily"},
	}
	cs := fake.NewSimpleClientset(cj)
	issues, err := collectCronJobIssues(context.Background(), cs, "batch", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Error("expected no issues for active CronJob")
	}
}
