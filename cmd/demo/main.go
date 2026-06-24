// Demo server — starts the Exalm dashboard with synthetic findings for UI testing.
// Usage: go run ./cmd/demo
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/exalm-ai/exalm/internal/metrics"
	"github.com/exalm-ai/exalm/internal/web"
	"github.com/exalm-ai/exalm/pkg/plugin"
	"github.com/exalm-ai/exalm/plugins/k8s"
)

func main() {
	report := plugin.Report{
		Title:   "Exalm live dashboard — demo cluster",
		Summary: "Analysed 165 pods (14 unhealthy) across 6 namespaces using ollama.",
		Raw: `## VERDICT
**4 critical issues** require immediate attention, including a CrashLoopBackOff in production
and a PVC approaching capacity.

## TOP FINDINGS
1. **payment-api** pod in CrashLoopBackOff (22 restarts) — OOMKilled, limit 256 Mi too low.
2. **Disk pressure** on node worker-3 at 91% inode utilisation.
3. **data-pvc** in namespace analytics at 94% capacity — 6 GB remaining.
4. **auth-service** HPA at max replicas (10/10) — scaling headroom exhausted.`,
		Findings: []plugin.Finding{
			{
				Severity:   plugin.SeverityCritical,
				Category:   "Pods",
				Title:      "CrashLoopBackOff: prod/payment-api-7d8f9b-xkp2r",
				Detail:     "Pod restarted 22 times in the last hour. Last exit reason: OOMKilled. Memory limit is 256 Mi; working set peaks at 310 Mi.",
				Suggestion: "Increase memory limit to at least 512 Mi. Consider adding a readiness probe to prevent traffic during startup.",
				Source:     "k8s/prod-cluster",
				Remediation: &plugin.RemediationAction{
					Kind:        "PatchDeployment",
					Namespace:   "prod",
					Resource:    "deployment",
					Name:        "payment-api",
					PatchJSON:   `{"spec":{"template":{"spec":{"containers":[{"name":"payment-api","resources":{"limits":{"memory":"512Mi"}}}]}}}}`,
					KubectlCmd:  `kubectl patch deployment payment-api -n prod --type=merge -p '{"spec":{"template":{"spec":{"containers":[{"name":"payment-api","resources":{"limits":{"memory":"512Mi"}}}]}}}}}'`,
					Description: "Increase memory limit for payment-api to 512 Mi",
				},
				LikelyCause: &plugin.ChangeRef{
					ID:         "deploy-2026-05-23-001",
					Kind:       "Deployment",
					Namespace:  "prod",
					Name:       "payment-api",
					Actor:      "ci-bot",
					AgoSeconds: 3600,
				},
			},
			{
				Severity:   plugin.SeverityCritical,
				Category:   "Nodes",
				Title:      "DiskPressure: worker-3 at 91% inode utilisation",
				Detail:     "Node worker-3 (10.0.1.23) reports DiskPressure condition. /var/lib/docker overlay2 is 91% full. 23 pods currently scheduled on this node.",
				Suggestion: "Prune unused container images with `crictl rmi --prune`. Investigate log rotation for high-volume pods.",
				Source:     "k8s/prod-cluster",
				Evidence: []plugin.EvidenceItem{
					{Kind: "event", Source: "worker-3", Excerpt: "Node condition DiskPressure=True for 23m", Anchor: "kubectl describe node worker-3"},
					{Kind: "metric", Source: "node_disk_inodes_free", Excerpt: "inode_free=9%"},
				},
			},
			{
				Severity:   plugin.SeverityCritical,
				Category:   "Storage",
				Title:      "PVC near capacity: analytics/data-pvc (94%)",
				Detail:     "PersistentVolumeClaim data-pvc in namespace analytics is at 94% capacity (94 Gi / 100 Gi). At current write rate (+2 Gi/day) it will reach 100% in ~3 days.",
				Suggestion: "Expand the PVC to 200 Gi or archive data older than 90 days to object storage.",
				Source:     "k8s/prod-cluster",
				Remediation: &plugin.RemediationAction{
					Kind:        "ExpandPVC",
					Namespace:   "analytics",
					Resource:    "persistentvolumeclaim",
					Name:        "data-pvc",
					PatchJSON:   `{"spec":{"resources":{"requests":{"storage":"200Gi"}}}}`,
					KubectlCmd:  `kubectl patch pvc data-pvc -n analytics --type=merge -p '{"spec":{"resources":{"requests":{"storage":"200Gi"}}}}'`,
					Description: "Expand data-pvc from 100 Gi to 200 Gi",
				},
			},
			{
				Severity:   plugin.SeverityCritical,
				Category:   "Scaling",
				Title:      "HPA maxed out: prod/auth-service (10/10 replicas)",
				Detail:     "HorizontalPodAutoscaler auth-service-hpa has been at maximum replicas (10) for 47 minutes. CPU utilisation: 94%. New requests are being queued.",
				Suggestion: "Increase HPA maxReplicas to 20 or investigate the CPU spike. Check for a missing database index causing slow queries.",
				Source:     "k8s/prod-cluster",
				Evidence: []plugin.EvidenceItem{
					{Kind: "metric", Source: "kube_horizontalpodautoscaler_status_current_replicas", Excerpt: "current=10, max=10, desired=18"},
				},
			},
			{
				Severity:   plugin.SeverityHigh,
				Category:   "Pods",
				Title:      "ImagePullBackOff: staging/ml-inference-5f9c8d-wq7kp",
				Detail:     "Pod cannot pull image `ghcr.io/company/ml-inference:v2.3.1`. Error: 403 Forbidden. The imagePullSecret was rotated 2 hours ago.",
				Suggestion: "Update the deployment imagePullSecrets to reference `regcred-v2`.",
				Source:     "k8s/staging-cluster",
			},
			{
				Severity:   plugin.SeverityHigh,
				Category:   "Networking",
				Title:      "Service endpoint mismatch: prod/order-gateway has 0 ready endpoints",
				Detail:     "Service order-gateway selects pods with label `app=order-gw` but all running pods are labelled `app=order-gateway`. The selector was renamed in the last deploy.",
				Suggestion: "Update the Service selector to `app: order-gateway` or revert the pod label change.",
				Source:     "k8s/prod-cluster",
				LikelyCause: &plugin.ChangeRef{
					ID:         "deploy-2026-05-23-002",
					Kind:       "Deployment",
					Namespace:  "prod",
					Name:       "order-gateway",
					Actor:      "john.doe",
					AgoSeconds: 7200,
				},
			},
			{
				Severity:   plugin.SeverityHigh,
				Category:   "Security",
				Title:      "Pod running as root: prod/legacy-importer",
				Detail:     "Deployment legacy-importer runs containers as UID 0 without securityContext.runAsNonRoot. The container has access to host-level directories via a hostPath volume.",
				Suggestion: "Add `securityContext: {runAsNonRoot: true, runAsUser: 1000}` to the container spec.",
				Source:     "k8s/prod-cluster",
			},
			{
				Severity:   plugin.SeverityMedium,
				Category:   "Resources",
				Title:      "No resource requests/limits: monitoring/log-shipper (6 pods)",
				Detail:     "6 pods in the monitoring namespace have no resource requests or limits set. This prevents optimal scheduling and risks node overcommit.",
				Suggestion: "Add resource requests (cpu: 100m, memory: 128Mi) and limits (cpu: 500m, memory: 512Mi) to the log-shipper DaemonSet.",
				Source:     "k8s/prod-cluster",
			},
			{
				Severity:   plugin.SeverityMedium,
				Category:   "Jobs",
				Title:      "CronJob missed schedule: data/nightly-backup (4 times)",
				Detail:     "CronJob nightly-backup has missed its last 4 scheduled runs (00:00 UTC). The job controller pod was restarted during the maintenance window.",
				Suggestion: "Set `startingDeadlineSeconds: 3600` on the CronJob to allow late starts.",
				Source:     "k8s/prod-cluster",
			},
			{
				Severity:   plugin.SeverityInfo,
				Category:   "Pods",
				Title:      "Deployment rollout in progress: prod/frontend-v2 (2/5 ready)",
				Detail:     "Deployment frontend-v2 is in a rolling update. 2 of 5 replicas are running the new image v2.4.0. Expected completion in ~2 minutes.",
				Suggestion: "No action needed. Monitor: kubectl rollout status deployment/frontend-v2 -n prod",
				Source:     "k8s/prod-cluster",
			},
		},
	}

	// Classify the hand-built findings so the demo exercises the explainability
	// UI (confidence, temporary vs root-cause fixes, evidence) exactly as the
	// real k8s pipeline would via BuildAndEnrichFindings.
	for i := range report.Findings {
		k8s.Classify(&report.Findings[i])
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	updates := make(chan plugin.Report, 1)

	// Simulate a live update after 8 seconds
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(8 * time.Second):
			updated := report
			updated.Summary = "Live update: 5 critical · 3 high · 2 medium · 1 info"
			nf := plugin.Finding{
				Severity:   plugin.SeverityCritical,
				Category:   "Pods",
				Title:      "NEW: OOMKilled: prod/analytics-worker-2",
				Detail:     "analytics-worker-2 was OOMKilled 3 minutes ago. RSS peaked at 1.8 Gi against a 1 Gi limit.",
				Suggestion: "Increase memory limit to 2 Gi or optimise the batch processing job.",
				Source:     "k8s/prod-cluster",
			}
			k8s.Classify(&nf)
			updated.Findings = append(append([]plugin.Finding{}, report.Findings...), nf)
			updates <- updated
		}
	}()

	fmt.Fprintf(os.Stderr, "Demo dashboard: http://localhost:7433\n") //nolint:errcheck // startup info to stderr
	fmt.Fprintf(os.Stderr, "Press Ctrl-C to stop.\n")                 //nolint:errcheck // startup info to stderr

	// Synthetic pod inventory + a stubbed fix so the demo exercises the full
	// dashboard (namespace selector, pod-derived metrics, Fix flow).
	podInfo := web.PodInfo{
		Total:     165,
		Unhealthy: 14,
		ByNamespace: map[string]int{
			"prod": 92, "staging": 34, "monitoring": 18, "analytics": 12, "data": 6, "cluster": 3,
		},
	}

	// Stub investigation so the demo exercises the explainability UI. Mirrors
	// what the k8s plugin's deterministic engine would return.
	investigate := func(_ context.Context, id string) (*plugin.Investigation, error) {
		var f *plugin.Finding
		for i := range report.Findings {
			if report.Findings[i].ID() == id {
				f = &report.Findings[i]
				break
			}
		}
		if f == nil {
			return nil, fmt.Errorf("finding %q not found", id)
		}
		var temp, root []plugin.RemediationAction
		for _, fx := range f.Fixes {
			if fx.FixType == "root-cause" {
				root = append(root, fx)
			} else {
				temp = append(temp, fx)
			}
		}
		return &plugin.Investigation{
			Summary:    "Synthesized for the demo: " + f.Detail + " The evidence and recent change correlation point to a configuration cause, so a restart only mitigates the symptom.",
			RootCause:  f.RootCause,
			Confidence: f.Confidence,
			Steps: []plugin.InvestigationStep{
				{Label: "Pod status & container state inspected", Status: "done", Detail: f.Title},
				{Label: "Container logs inspected (current + previous)", Status: "done"},
				{Label: "Warning events inspected", Status: "done"},
				{Label: "Owning workload inspected", Status: "done"},
				{Label: "Recent changes correlated", Status: "done", Detail: "linked to a recent deploy"},
				{Label: "Prometheus metrics inspected", Status: "unavailable", Detail: "no metrics backend wired"},
			},
			Evidence:       f.Evidence,
			TemporaryFixes: temp,
			RootCauseFixes: root,
		}, nil
	}

	if err := web.Serve(ctx, report, web.ServeOpts{
		Port:          7433,
		OpenBrowser:   false,
		ReportUpdates: updates,
		Provider:      "ollama",
		PodInfo:       func() web.PodInfo { return podInfo },
		ApplyFix: func(context.Context, plugin.RemediationAction) error {
			time.Sleep(400 * time.Millisecond) // simulate the apply latency
			return nil
		},
		Investigate: investigate,
		LogFetch: func(_ context.Context, ns, pod, container string, previous bool, tail int) (string, error) {
			head := "2026-06-23T12:20:46Z INFO  starting " + pod + " (container=" + container + ")\n"
			if previous {
				head = "2026-06-23T11:58:02Z INFO  previous run of " + pod + "\n"
			}
			return head +
				"2026-06-23T12:20:47Z WARN  memory usage 298Mi approaching limit 256Mi\n" +
				"2026-06-23T12:20:48Z ERROR OOMKilled: container exceeded memory limit\n" +
				"2026-06-23T12:20:49Z INFO  restarting...\n", nil
		},
		Metrics: metrics.NewDerived(),
	}); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "serve error:", err) //nolint:errcheck // fatal error to stderr before exit
		os.Exit(1)
	}
}
