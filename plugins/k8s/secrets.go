package k8s

// secrets.go is a lightweight, on-demand Secret collector used by the
// conversation engine when a question implies "check credentials/config".
// It is intentionally minimal: SecretMeta has NO field capable of holding a
// secret value. We fetch the live Secret object (the K8s API has no
// "metadata-only" GET), but only ever read .Type/.Name/.CreationTimestamp —
// .Data and .StringData are never touched, never logged, never included in
// any LLM message or evidence text. See secrets_test.go for a guard test
// that proves a fixture secret's value never appears in the output.

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// SecretMeta is everything this collector ever exposes about a Secret:
// identity and which pod references it. No value, no key names, no size —
// those would still be a content side-channel for some investigations.
type SecretMeta struct {
	Name            string
	Type            string
	Age             string
	ReferencedByPod string
}

// secretNamesForPod returns the distinct Secret names referenced by pod via
// envFrom, env[].valueFrom.secretKeyRef, a secret volume source, or
// imagePullSecrets.
func secretNamesForPod(pod *corev1.Pod) []string {
	seen := map[string]bool{}
	var names []string
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, c := range pod.Spec.Containers {
		for _, ef := range c.EnvFrom {
			if ef.SecretRef != nil {
				add(ef.SecretRef.Name)
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				add(e.ValueFrom.SecretKeyRef.Name)
			}
		}
	}
	for _, v := range pod.Spec.Volumes {
		if v.Secret != nil {
			add(v.Secret.SecretName)
		}
	}
	for _, ips := range pod.Spec.ImagePullSecrets {
		add(ips.Name)
	}
	return names
}

// secretsFor fetches the live pod to discover which Secrets it references,
// then returns existence/type/age metadata only. Missing/inaccessible secrets
// are skipped rather than treated as a fatal error — a missing secret is
// itself useful investigation signal (e.g. "ImagePullBackOff" root cause).
func secretsFor(ctx context.Context, cs kubernetes.Interface, ns, podName string) ([]SecretMeta, error) {
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", ns, podName, err)
	}

	var out []SecretMeta
	for _, name := range secretNamesForPod(pod) {
		sec, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			continue
		}
		out = append(out, SecretMeta{
			Name:            sec.Name,
			Type:            string(sec.Type),
			Age:             humanizeAge(sec.CreationTimestamp.Time, time.Now()),
			ReferencedByPod: podName,
		})
	}
	return out, nil
}
