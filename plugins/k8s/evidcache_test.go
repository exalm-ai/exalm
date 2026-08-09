package k8s

// evidcache_test.go — the integration guarantee that a repeated question
// within TTL does not hit the Kubernetes API again, and that an explicit
// refresh re-collects. The cache itself is engine-owned; its unit tests
// (freshness, purge, caps, nil-safety) live in internal/investigate.

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// TestConverse_RepeatedQuestionServedFromCache proves the copilot does not
// re-hit the Kubernetes API for the same question inside the TTL: the fake
// clientset's recorded action count must not grow on the second turn, and
// the second turn's plan must mark the step cached.
func TestConverse_RepeatedQuestionServedFromCache(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "payment-api", Namespace: "prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app",
			EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"},
			}}},
		}}},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "app-config", Namespace: "prod"},
		Data:       map[string]string{"LOG_LEVEL": "debug"},
	}
	cs := fake.NewSimpleClientset(pod, cm)

	p := New()
	p.newLogFetcher = func(kubernetes.Interface) logFetcher { return &fakeLogFetcher{} }
	p.setLastClient(cs)
	p.setLastSnapshot(Snapshot{UnhealthyPods: []PodSummary{{
		Namespace: "prod", Name: "payment-api", Phase: "Running", Reason: "CrashLoopBackOff", RestartCount: 5,
	}}})
	store := newTestConvoStore(t)

	first, err := p.Converse(context.Background(), "", "", "prod", "check the configmaps for payment-api", nil, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("first turn: %v", err)
	}
	actionsAfterFirst := len(cs.Actions())

	second, err := p.Converse(context.Background(), first.ID, "", "prod", "check the configmaps again", nil, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("second turn: %v", err)
	}
	actionsAfterSecond := len(cs.Actions())

	if actionsAfterSecond != actionsAfterFirst {
		t.Errorf("second identical question within TTL must not call the API: actions %d → %d",
			actionsAfterFirst, actionsAfterSecond)
	}
	lastMsg := second.Messages[len(second.Messages)-1]
	foundCached := false
	for _, ps := range lastMsg.Plan {
		if ps.Collector == "configmaps" && ps.FromCache {
			foundCached = true
		}
	}
	if !foundCached {
		t.Errorf("expected the configmaps step to be served from cache, plan=%+v", lastMsg.Plan)
	}
}

// TestConverse_RefreshBypassesCache proves an explicit "refresh" re-collects.
func TestConverse_RefreshBypassesCache(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "payment-api", Namespace: "prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app",
			EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"},
			}}},
		}}},
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "app-config", Namespace: "prod"}, Data: map[string]string{"K": "v"}}
	cs := fake.NewSimpleClientset(pod, cm)

	p := New()
	p.newLogFetcher = func(kubernetes.Interface) logFetcher { return &fakeLogFetcher{} }
	p.setLastClient(cs)
	p.setLastSnapshot(Snapshot{UnhealthyPods: []PodSummary{{
		Namespace: "prod", Name: "payment-api", Phase: "Running", Reason: "CrashLoopBackOff",
	}}})
	store := newTestConvoStore(t)

	first, err := p.Converse(context.Background(), "", "", "prod", "check the configmaps for payment-api", nil, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("first turn: %v", err)
	}
	before := len(cs.Actions())

	_, err = p.Converse(context.Background(), first.ID, "", "prod", "refresh the configmaps", nil, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("refresh turn: %v", err)
	}
	if after := len(cs.Actions()); after == before {
		t.Error("an explicit refresh must re-collect (API actions should grow)")
	}
}
