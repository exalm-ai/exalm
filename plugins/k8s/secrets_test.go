package k8s

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const secretValueFixture = "super-secret-database-password-12345"

func podWithSecretRefs(ns, name, secretName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				Env: []corev1.EnvVar{{Name: "DB_PASSWORD", ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: secretName}, Key: "password"},
				}}},
			}},
		},
	}
}

// TestSecretsFor_NeverLeaksValue is the critical guard: it proves that no
// matter what fields SecretMeta gains in the future, the actual secret value
// never appears anywhere in the result — not in a field, not via %+v.
func TestSecretsFor_NeverLeaksValue(t *testing.T) {
	pod := podWithSecretRefs("prod", "api-0", "db-creds")
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "prod"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"password": []byte(secretValueFixture)},
	}
	cs := fake.NewSimpleClientset(pod, sec)

	out, err := secretsFor(context.Background(), cs, "prod", "api-0")
	if err != nil {
		t.Fatalf("secretsFor: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 secret, got %+v", out)
	}

	dump := fmt.Sprintf("%+v", out)
	if strings.Contains(dump, secretValueFixture) {
		t.Fatalf("SECRET VALUE LEAKED into secretsFor() result: %s", dump)
	}

	got := out[0]
	if got.Name != "db-creds" {
		t.Errorf("Name: got %q want db-creds", got.Name)
	}
	if got.Type != string(corev1.SecretTypeOpaque) {
		t.Errorf("Type: got %q want %q", got.Type, corev1.SecretTypeOpaque)
	}
	if got.ReferencedByPod != "api-0" {
		t.Errorf("ReferencedByPod: got %q want api-0", got.ReferencedByPod)
	}
}

func TestSecretsFor_MissingSecretSkipped(t *testing.T) {
	pod := podWithSecretRefs("prod", "api-0", "missing-secret")
	cs := fake.NewSimpleClientset(pod) // no Secret object created

	out, err := secretsFor(context.Background(), cs, "prod", "api-0")
	if err != nil {
		t.Fatalf("secretsFor should not error on a missing secret: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 results for a missing secret, got %+v", out)
	}
}

func TestSecretNamesForPod_VolumeAndImagePullSecrets(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes:          []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "from-volume"}}}},
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}},
		},
	}
	names := secretNamesForPod(pod)
	if len(names) != 2 {
		t.Fatalf("expected 2 distinct secret names, got %v", names)
	}
}
