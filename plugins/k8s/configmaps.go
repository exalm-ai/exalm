package k8s

// configmaps.go is a lightweight, on-demand ConfigMap collector used by the
// conversation engine (converse.go) when a user question implies "check the
// configuration". It runs a live, targeted GET through the already-connected
// client — the same trust class as LogFetch (investigate.go:20-35) — rather
// than being folded into the main Collect() snapshot, since most
// conversations never need it.

import (
	"context"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ConfigMapSummary is a redaction-safe view of one ConfigMap referenced by a
// pod: key names and a short REDACTED preview of each value. Preview is
// always passed through Redactor.Redact() before this struct is built — it is
// never the raw value.
type ConfigMapSummary struct {
	Name    string
	Keys    []string
	Preview map[string]string // key -> redacted, truncated value preview
	Age     string
}

// configMapNamesForPod returns the distinct ConfigMap names referenced by pod
// via envFrom, env[].valueFrom.configMapKeyRef, or a configMap volume source.
func configMapNamesForPod(pod *corev1.Pod) []string {
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
			if ef.ConfigMapRef != nil {
				add(ef.ConfigMapRef.Name)
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.ConfigMapKeyRef != nil {
				add(e.ValueFrom.ConfigMapKeyRef.Name)
			}
		}
	}
	for _, v := range pod.Spec.Volumes {
		if v.ConfigMap != nil {
			add(v.ConfigMap.Name)
		}
	}
	return names
}

// configMapsFor fetches the live pod to discover which ConfigMaps it
// references, then lists each one's keys with a redacted value preview. Every
// value is passed through red.Redact() before it is truncated and stored —
// this struct must never carry a raw value. Missing/inaccessible ConfigMaps
// are skipped rather than treated as a fatal error: that absence is itself
// useful investigation signal.
func configMapsFor(ctx context.Context, cs kubernetes.Interface, red plugin.Redactor, ns, podName string) ([]ConfigMapSummary, error) {
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", ns, podName, err)
	}

	var out []ConfigMapSummary
	for _, name := range configMapNamesForPod(pod) {
		cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			continue
		}
		keys := make([]string, 0, len(cm.Data))
		preview := make(map[string]string, len(cm.Data))
		for k, v := range cm.Data {
			keys = append(keys, k)
			redacted := v
			if red != nil {
				redacted = red.Redact(v)
			}
			preview[k] = truncateString(redacted, 120)
		}
		sort.Strings(keys)
		out = append(out, ConfigMapSummary{
			Name:    name,
			Keys:    keys,
			Preview: preview,
			Age:     humanizeAge(cm.CreationTimestamp.Time, time.Now()),
		})
	}
	return out, nil
}

// truncateString shortens s to at most n runes, appending "…" when cut.
func truncateString(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// humanizeAge renders how long ago t was, relative to now, as a compact
// string ("3h", "2d"). Returns "" for a zero time.
func humanizeAge(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := now.Sub(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
