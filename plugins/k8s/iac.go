package k8s

import (
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// argoCDAppGVR is the GroupVersionResource for ArgoCD Application CRDs.
var argoCDAppGVR = schema.GroupVersionResource{
	Group:    "argoproj.io",
	Version:  "v1alpha1",
	Resource: "applications",
}

// collectArgoCDApps lists ArgoCD Application CRDs and extracts last-sync
// metadata. When ArgoCD is not installed the CRD won't exist; the dynamic
// client returns a not-found/no-match error which we treat as an empty
// result rather than a fatal error.
func collectArgoCDApps(ctx context.Context, dc dynamic.Interface, ns string) ([]IaCChange, error) {
	list, err := dc.Resource(argoCDAppGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		// ArgoCD is not installed — not an error condition for us.
		if isNotFoundErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list argocd applications: %w", err)
	}

	changes := make([]IaCChange, 0, len(list.Items))
	for _, item := range list.Items {
		obj := item.Object

		name, _ := obj["metadata"].(map[string]interface{})["name"].(string)
		namespace, _ := obj["metadata"].(map[string]interface{})["namespace"].(string)

		status, _ := obj["status"].(map[string]interface{})
		if status == nil {
			status = map[string]interface{}{}
		}

		// Sync status ("Synced" | "OutOfSync" | "Unknown")
		syncStatus := ""
		if sync, ok := status["sync"].(map[string]interface{}); ok {
			syncStatus, _ = sync["status"].(string)
		}

		// Health status can be "Healthy" | "Degraded" | "Progressing" | "Suspended"
		healthStatus := ""
		if health, ok := status["health"].(map[string]interface{}); ok {
			healthStatus, _ = health["status"].(string)
		}

		// Combine into a single Status field: prefer Degraded, else sync status.
		resolvedStatus := syncStatus
		if healthStatus == "Degraded" {
			resolvedStatus = "Degraded"
		}

		// operationState carries last-sync timestamp and revision.
		var syncedAt time.Time
		version := ""
		message := ""
		if opState, ok := status["operationState"].(map[string]interface{}); ok {
			if finishedAt, ok := opState["finishedAt"].(string); ok && finishedAt != "" {
				if t, err := time.Parse(time.RFC3339, finishedAt); err == nil {
					syncedAt = t
				}
			}
			if syncResult, ok := opState["syncResult"].(map[string]interface{}); ok {
				version, _ = syncResult["revision"].(string)
				// Trim to short SHA if it looks like a full Git SHA.
				if len(version) > 8 {
					version = version[:8]
				}
			}
			message, _ = opState["message"].(string)
		}

		// Fallback: first condition message.
		if message == "" {
			if conditions, ok := status["conditions"].([]interface{}); ok && len(conditions) > 0 {
				if cond, ok := conditions[0].(map[string]interface{}); ok {
					message, _ = cond["message"].(string)
				}
			}
		}

		changes = append(changes, IaCChange{
			Source:    "argocd",
			Name:      name,
			Namespace: namespace,
			SyncedAt:  syncedAt,
			Version:   version,
			Status:    resolvedStatus,
			Message:   message,
		})
	}
	return changes, nil
}

// helmRelease is the subset of a Helm release JSON we care about.
// Helm stores releases as gzip-compressed, base64-encoded JSON inside
// a Secret with label owner=helm and type helm.sh/release.v1.
type helmRelease struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Version   int    `json:"version"` // revision number
	Chart     struct {
		Metadata struct {
			Version string `json:"version"`
		} `json:"metadata"`
	} `json:"chart"`
	Info struct {
		Status       string `json:"status"`
		Description  string `json:"description"`
		LastDeployed string `json:"last_deployed"`
	} `json:"info"`
}

// collectHelmReleases reads Helm release Secrets and extracts the latest
// revision of every Helm release in the given namespace. Helm stores one
// Secret per release revision (owner=helm label, helm.sh/release.v1 type).
func collectHelmReleases(ctx context.Context, cs kubernetes.Interface, ns string) ([]IaCChange, error) {
	// List secrets owned by Helm.
	list, err := cs.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm",
	})
	if err != nil {
		return nil, fmt.Errorf("list helm release secrets: %w", err)
	}

	// Keep only the latest revision per release name.
	latest := map[string]helmRelease{}

	for _, secret := range list.Items {
		if secret.Type != "helm.sh/release.v1" {
			continue
		}
		rawB64, ok := secret.Data["release"]
		if !ok {
			continue
		}

		rel, err := decodeHelmRelease(rawB64)
		if err != nil {
			// Malformed secret — skip without failing the whole collection.
			continue
		}

		if existing, seen := latest[rel.Name]; !seen || rel.Version > existing.Version {
			latest[rel.Name] = rel
		}
	}

	changes := make([]IaCChange, 0, len(latest))
	for _, rel := range latest {
		var syncedAt time.Time
		if rel.Info.LastDeployed != "" {
			if t, err := time.Parse(time.RFC3339, rel.Info.LastDeployed); err == nil {
				syncedAt = t
			}
		}
		relNS := rel.Namespace
		if relNS == "" {
			relNS = ns
		}
		changes = append(changes, IaCChange{
			Source:    "helm",
			Name:      rel.Name,
			Namespace: relNS,
			SyncedAt:  syncedAt,
			Version:   rel.Chart.Metadata.Version,
			Status:    rel.Info.Status,
			Message:   rel.Info.Description,
		})
	}
	return changes, nil
}

// decodeHelmRelease decodes the base64 + gzip-compressed Helm release payload.
func decodeHelmRelease(rawB64 []byte) (helmRelease, error) {
	// Helm double-encodes: base64(gzip(base64(json))).
	// First base64 decode.
	outer, err := base64.StdEncoding.DecodeString(string(rawB64))
	if err != nil {
		// Try standard without padding.
		outer, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(string(rawB64), "="))
		if err != nil {
			return helmRelease{}, fmt.Errorf("base64 decode outer: %w", err)
		}
	}

	// Attempt gzip decompress.
	var jsonBytes []byte
	r, zerr := zlib.NewReader(strings.NewReader(string(outer)))
	if zerr == nil {
		defer r.Close()
		jsonBytes, err = io.ReadAll(r)
		if err != nil {
			return helmRelease{}, fmt.Errorf("gzip read: %w", err)
		}
	} else {
		// Not gzip compressed — try as-is.
		jsonBytes = outer
	}

	// Second base64 decode (Helm uses double-encoding).
	innerJSON, err := base64.StdEncoding.DecodeString(string(jsonBytes))
	if err != nil {
		// Not double-encoded — use the bytes we have directly.
		innerJSON = jsonBytes
	}

	var rel helmRelease
	if err := json.Unmarshal(innerJSON, &rel); err != nil {
		return helmRelease{}, fmt.Errorf("unmarshal helm release: %w", err)
	}
	return rel, nil
}

// collectIaCChanges merges ArgoCD Application and Helm release change events,
// sorted by SyncedAt descending (most recent first). Both collectors are
// best-effort: errors are silently dropped so a missing ArgoCD installation
// or restricted RBAC does not fail the overall analysis.
// A nil dc is safe — ArgoCD collection is simply skipped.
func collectIaCChanges(ctx context.Context, cs kubernetes.Interface, dc dynamic.Interface, ns string) ([]IaCChange, error) {
	var changes []IaCChange

	if dc != nil {
		if argoChanges, err := collectArgoCDApps(ctx, dc, ns); err == nil {
			changes = append(changes, argoChanges...)
		}
	}

	if helmChanges, err := collectHelmReleases(ctx, cs, ns); err == nil {
		changes = append(changes, helmChanges...)
	}

	sort.Slice(changes, func(i, j int) bool {
		return changes[i].SyncedAt.After(changes[j].SyncedAt)
	})

	return changes, nil
}

// isNotFoundErr returns true for the "no kind is registered for the type"
// and 404 API server errors that occur when a CRD is not installed.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no matches for kind") ||
		strings.Contains(msg, "the server could not find the requested resource") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "404")
}
