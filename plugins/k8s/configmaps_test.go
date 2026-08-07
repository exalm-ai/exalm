package k8s

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeRedactor (scrubs the literal "sk-secret") is defined in investigate_test.go.

func podWithConfigMapRefs(ns, name, cmName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: cmName}}}},
			}},
		},
	}
}

func TestConfigMapsFor_DiscoversAndRedactsPreview(t *testing.T) {
	pod := podWithConfigMapRefs("prod", "api-0", "api-config")
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "api-config", Namespace: "prod"},
		Data:       map[string]string{"DATABASE_URL": "postgres://user:sk-secret@db:5432/app", "LOG_LEVEL": "info"},
	}
	cs := fake.NewSimpleClientset(pod, cm)

	out, err := configMapsFor(context.Background(), cs, fakeRedactor{}, "prod", "api-0")
	if err != nil {
		t.Fatalf("configMapsFor: %v", err)
	}
	if len(out) != 1 || out[0].Name != "api-config" {
		t.Fatalf("expected 1 configmap named api-config, got %+v", out)
	}
	if len(out[0].Keys) != 2 {
		t.Errorf("expected 2 keys, got %v", out[0].Keys)
	}
	preview := out[0].Preview["DATABASE_URL"]
	if strings.Contains(preview, "sk-secret") {
		t.Errorf("preview must be redacted, got %q", preview)
	}
	if !strings.Contains(preview, "[REDACTED]") {
		t.Errorf("expected redacted marker in preview, got %q", preview)
	}
}

func TestConfigMapsFor_MissingConfigMapSkipped(t *testing.T) {
	pod := podWithConfigMapRefs("prod", "api-0", "missing-config")
	cs := fake.NewSimpleClientset(pod) // no ConfigMap object created

	out, err := configMapsFor(context.Background(), cs, fakeRedactor{}, "prod", "api-0")
	if err != nil {
		t.Fatalf("configMapsFor should not error on a missing configmap: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 results for a missing configmap, got %+v", out)
	}
}

func TestConfigMapsFor_UnknownPodErrors(t *testing.T) {
	cs := fake.NewSimpleClientset()
	if _, err := configMapsFor(context.Background(), cs, fakeRedactor{}, "prod", "ghost"); err == nil {
		t.Error("expected an error for an unknown pod")
	}
}

func TestConfigMapNamesForPod_VolumeAndEnvValueFrom(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Env: []corev1.EnvVar{{Name: "X", ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "from-env"}},
				}}},
			}},
			Volumes: []corev1.Volume{{
				Name:         "v",
				VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "from-volume"}}},
			}},
		},
	}
	names := configMapNamesForPod(pod)
	if len(names) != 2 {
		t.Fatalf("expected 2 distinct configmap names, got %v", names)
	}
}
