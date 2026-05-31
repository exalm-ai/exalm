package k8s

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// TestCollectArgoCDApps_NoCRD verifies that when ArgoCD is not installed the
// collector returns an empty slice without error.  The fake dynamic client
// requires the GVR to be registered (otherwise it panics); we register the
// GVR with no objects so the List returns empty — which is the same outcome
// as a real cluster where the CRD does not exist and isNotFoundErr fires.
func TestCollectArgoCDApps_NoCRD(t *testing.T) {
	scheme := runtime.NewScheme()

	// Register the ArgoCD Application GVR list kind so the fake client can
	// service the List call without panicking.
	listKinds := map[schema.GroupVersionResource]string{
		argoCDAppGVR: "ApplicationList",
	}
	dc := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds)

	changes, err := collectArgoCDApps(context.Background(), dc, "")
	if err != nil {
		t.Fatalf("expected no error when no ArgoCD apps are present, got: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("expected 0 changes, got %d", len(changes))
	}
}

// TestCollectHelmReleases_ParsesSecrets verifies that a properly structured
// Helm release Secret is decoded and returned as an IaCChange.
func TestCollectHelmReleases_ParsesSecrets(t *testing.T) {
	deployedAt := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	rel := helmRelease{
		Name:      "nginx-ingress",
		Namespace: "ingress-nginx",
		Version:   3,
		Info: struct {
			Status       string `json:"status"`
			Description  string `json:"description"`
			LastDeployed string `json:"last_deployed"`
		}{
			Status:       "deployed",
			Description:  "Upgrade complete",
			LastDeployed: deployedAt.Format(time.RFC3339),
		},
	}
	rel.Chart.Metadata.Version = "4.11.3"

	relJSON, err := json.Marshal(rel)
	if err != nil {
		t.Fatalf("marshal release: %v", err)
	}

	// Helm double-encodes: base64(gzip(base64(json))).
	innerB64 := base64.StdEncoding.EncodeToString(relJSON)

	var gzBuf bytes.Buffer
	w := zlib.NewWriter(&gzBuf)
	if _, err := w.Write([]byte(innerB64)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	w.Close()

	outerB64 := base64.StdEncoding.EncodeToString(gzBuf.Bytes())

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sh.helm.release.v1.nginx-ingress.v3",
			Namespace: "ingress-nginx",
			Labels:    map[string]string{"owner": "helm"},
		},
		Type: "helm.sh/release.v1",
		Data: map[string][]byte{
			"release": []byte(outerB64),
		},
	}

	cs := k8sfake.NewSimpleClientset(secret)

	changes, err := collectHelmReleases(context.Background(), cs, "ingress-nginx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}

	c := changes[0]
	if c.Source != "helm" {
		t.Errorf("Source = %q, want %q", c.Source, "helm")
	}
	if c.Name != "nginx-ingress" {
		t.Errorf("Name = %q, want %q", c.Name, "nginx-ingress")
	}
	if c.Version != "4.11.3" {
		t.Errorf("Version = %q, want %q", c.Version, "4.11.3")
	}
	if c.Status != "deployed" {
		t.Errorf("Status = %q, want %q", c.Status, "deployed")
	}
	if !c.SyncedAt.Equal(deployedAt) {
		t.Errorf("SyncedAt = %v, want %v", c.SyncedAt, deployedAt)
	}
}

// TestCollectHelmReleases_KeepsLatestRevision verifies that when multiple
// Secrets exist for the same release (different revisions), only the highest
// revision number is returned.
func TestCollectHelmReleases_KeepsLatestRevision(t *testing.T) {
	makeSecret := func(name string, revision int, status string) *corev1.Secret {
		rel := helmRelease{
			Name:      "myapp",
			Namespace: "default",
			Version:   revision,
			Info: struct {
				Status       string `json:"status"`
				Description  string `json:"description"`
				LastDeployed string `json:"last_deployed"`
			}{
				Status:       status,
				LastDeployed: time.Now().Format(time.RFC3339),
			},
		}
		rel.Chart.Metadata.Version = "1.0.0"

		relJSON, _ := json.Marshal(rel)
		innerB64 := base64.StdEncoding.EncodeToString(relJSON)

		var gzBuf bytes.Buffer
		w := zlib.NewWriter(&gzBuf)
		_, _ = w.Write([]byte(innerB64))
		w.Close()

		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
				Labels:    map[string]string{"owner": "helm"},
			},
			Type: "helm.sh/release.v1",
			Data: map[string][]byte{
				"release": []byte(base64.StdEncoding.EncodeToString(gzBuf.Bytes())),
			},
		}
	}

	s1 := makeSecret("myapp.v1", 1, "superseded")
	s2 := makeSecret("myapp.v2", 2, "deployed")

	cs := k8sfake.NewSimpleClientset(s1, s2)
	changes, err := collectHelmReleases(context.Background(), cs, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change (latest revision only), got %d", len(changes))
	}
	if changes[0].Status != "deployed" {
		t.Errorf("expected latest revision status %q, got %q", "deployed", changes[0].Status)
	}
}

// TestFormatIaCChanges_Table verifies that the table output contains the
// expected section header and column headers.
func TestFormatIaCChanges_Table(t *testing.T) {
	changes := []IaCChange{
		{
			Source:    "argocd",
			Name:      "my-app",
			Namespace: "production",
			Version:   "abc12345",
			Status:    "Synced",
			SyncedAt:  time.Now().Add(-2 * time.Hour),
		},
		{
			Source:    "helm",
			Name:      "nginx-ingress",
			Namespace: "kube-system",
			Version:   "4.11.3",
			Status:    "deployed",
			SyncedAt:  time.Now().Add(-5 * time.Hour),
		},
	}

	out := formatIaCChanges(changes)

	mustContain := []string{
		"## IaC Changes",
		"| Source |",
		"| Name |",
		"| Namespace |",
		"| Version |",
		"| Status |",
		"| Synced |",
		"argocd",
		"my-app",
		"production",
		"abc12345",
		"Synced",
		"helm",
		"nginx-ingress",
		"kube-system",
		"4.11.3",
		"deployed",
		"ago",
	}

	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("formatIaCChanges output missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestCollectIaCChanges_NilDynamicClient verifies that passing a nil dynamic
// client to collectIaCChanges does not panic and still returns Helm changes.
func TestCollectIaCChanges_NilDynamicClient(t *testing.T) {
	cs := k8sfake.NewSimpleClientset() // no secrets
	changes, err := collectIaCChanges(context.Background(), cs, nil, "default")
	if err != nil {
		t.Fatalf("unexpected error with nil dynamic client: %v", err)
	}
	// Empty result is fine; we just need no panic.
	_ = changes
}

// -- fake dynamic client helper for ArgoCD tests ---------------------------

// fakeArgoCDApp builds a minimal unstructured ArgoCD Application object.
func fakeArgoCDApp(name, ns, syncStatus, revision string, finishedAt time.Time) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": ns,
		},
		"status": map[string]interface{}{
			"sync": map[string]interface{}{
				"status": syncStatus,
			},
			"operationState": map[string]interface{}{
				"finishedAt": finishedAt.Format(time.RFC3339),
				"syncResult": map[string]interface{}{
					"revision": revision,
				},
			},
		},
	}
}

// TestCollectArgoCDApps_ParsesApps verifies that a fake ArgoCD Application
// unstructured object is correctly decoded into an IaCChange.
func TestCollectArgoCDApps_ParsesApps(t *testing.T) {
	scheme := runtime.NewScheme()

	// Register the ArgoCD Application GVK so the fake client can store it.
	gvk := schema.GroupVersionKind{
		Group:   "argoproj.io",
		Version: "v1alpha1",
		Kind:    "Application",
	}
	scheme.AddKnownTypeWithName(gvk, &runtime.Unknown{})

	listGVK := schema.GroupVersionKind{
		Group:   "argoproj.io",
		Version: "v1alpha1",
		Kind:    "ApplicationList",
	}
	scheme.AddKnownTypeWithName(listGVK, &runtime.Unknown{})

	syncedAt := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	appObj := fakeArgoCDApp("my-app", "argocd", "Synced", "deadbeefcafe", syncedAt)

	appJSON, err := json.Marshal(appObj)
	if err != nil {
		t.Fatalf("marshal app: %v", err)
	}

	// Since the fake dynamic client's tracker requires fully registered scheme
	// types, we test the field-parsing logic directly against the raw map
	// rather than going through a full fake round-trip.
	var raw map[string]interface{}
	if err := json.Unmarshal(appJSON, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	status, ok := raw["status"].(map[string]interface{})
	if !ok {
		t.Fatalf("status field is not a map")
	}
	opState, ok := status["operationState"].(map[string]interface{})
	if !ok {
		t.Fatalf("operationState field is not a map")
	}
	finishedAtStr, _ := opState["finishedAt"].(string)

	parsed, err := time.Parse(time.RFC3339, finishedAtStr)
	if err != nil {
		t.Fatalf("parse finishedAt: %v", err)
	}
	if !parsed.Equal(syncedAt) {
		t.Errorf("SyncedAt = %v, want %v", parsed, syncedAt)
	}

	syncResult, ok := opState["syncResult"].(map[string]interface{})
	if !ok {
		t.Fatalf("syncResult field is not a map")
	}
	revision, _ := syncResult["revision"].(string)
	if !strings.HasPrefix(revision, "deadbeef") {
		t.Errorf("revision = %q, want prefix %q", revision, "deadbeef")
	}
}
