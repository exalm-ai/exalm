package k8s

// evidcache_test.go — freshness, refresh bypass, purge, caps, and the
// integration guarantee that a repeated question within TTL does not hit the
// Kubernetes API again.

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

func entryWith(label string, at time.Time) cachedEvidence {
	return cachedEvidence{
		Steps:    []plugin.InvestigationStep{{Label: label, Status: "done"}},
		Evidence: []plugin.EvidenceItem{{Kind: "config", Source: label}},
		At:       at,
	}
}

func TestEvidenceCache_FreshHitAndTTLExpiry(t *testing.T) {
	c := newEvidenceCache()
	now := time.Now()
	c.put("c1", "owner-chain", "prod/api", entryWith("x", now), now)

	if _, ok := c.get("c1", "owner-chain", "prod/api", now.Add(time.Minute)); !ok {
		t.Error("expected a fresh hit within the 5m owner-chain TTL")
	}
	if _, ok := c.get("c1", "owner-chain", "prod/api", now.Add(6*time.Minute)); ok {
		t.Error("expected a miss after the TTL expired")
	}
	if _, ok := c.get("c2", "owner-chain", "prod/api", now); ok {
		t.Error("cache must be scoped per conversation")
	}
}

func TestEvidenceCache_ShortTTLForVolatileCollectors(t *testing.T) {
	c := newEvidenceCache()
	now := time.Now()
	c.put("c1", "previous-logs", "prod/api", entryWith("logs", now), now)
	if _, ok := c.get("c1", "previous-logs", "prod/api", now.Add(2*time.Minute)); ok {
		t.Error("previous-logs should expire after 90s")
	}
}

func TestEvidenceCache_PurgeIdleConversations(t *testing.T) {
	c := newEvidenceCache()
	now := time.Now()
	c.put("idle", "owner-chain", "prod/api", entryWith("x", now), now)
	c.purge(now.Add(evidCacheIdleTTL + time.Minute))
	c.mu.Lock()
	_, exists := c.convos["idle"]
	c.mu.Unlock()
	if exists {
		t.Error("idle conversation cache should be purged")
	}
}

func TestEvidenceCache_Caps(t *testing.T) {
	c := newEvidenceCache()
	now := time.Now()
	// Conversation cap: the least-recently-used convo is evicted.
	for i := 0; i < evidCacheMaxConvos+1; i++ {
		id := string(rune('a'+i%26)) + string(rune('a'+i/26))
		c.put(id, "owner-chain", "t", entryWith("x", now), now.Add(time.Duration(i)*time.Second))
	}
	c.mu.Lock()
	nConvos := len(c.convos)
	c.mu.Unlock()
	if nConvos > evidCacheMaxConvos {
		t.Errorf("conversation cap exceeded: %d > %d", nConvos, evidCacheMaxConvos)
	}
	// Entry cap within one conversation: oldest entry evicted.
	for i := 0; i < evidCacheMaxEntries+5; i++ {
		c.put("one", "owner-chain", string(rune('A'+i%26))+string(rune('A'+i/26)), entryWith("x", now), now)
	}
	c.mu.Lock()
	nEntries := len(c.convos["one"].entries)
	c.mu.Unlock()
	if nEntries > evidCacheMaxEntries {
		t.Errorf("entry cap exceeded: %d > %d", nEntries, evidCacheMaxEntries)
	}
}

func TestEvidenceCache_NilSafe(t *testing.T) {
	var c *evidenceCache
	now := time.Now()
	c.put("c", "k", "t", cachedEvidence{}, now) // must not panic
	c.purge(now)
	if _, ok := c.get("c", "k", "t", now); ok {
		t.Error("nil cache should always miss")
	}
	if c.has("c", "k", "t", now) {
		t.Error("nil cache should never report has")
	}
}

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
	actionsAfterFirst := len(cs.Fake.Actions())

	second, err := p.Converse(context.Background(), first.ID, "", "prod", "check the configmaps again", nil, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("second turn: %v", err)
	}
	actionsAfterSecond := len(cs.Fake.Actions())

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
	before := len(cs.Fake.Actions())

	_, err = p.Converse(context.Background(), first.ID, "", "prod", "refresh the configmaps", nil, fakeRedactor{}, store, nil)
	if err != nil {
		t.Fatalf("refresh turn: %v", err)
	}
	if after := len(cs.Fake.Actions()); after == before {
		t.Error("an explicit refresh must re-collect (API actions should grow)")
	}
}
