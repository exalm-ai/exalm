package k8s

import (
	"fmt"
	"strings"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// BuildFindings converts a Snapshot into a slice of structured plugin.Finding
// entries. These are emitted alongside the LLM narrative in the Report so that
// consumers (CLI renderer, future webhook dispatcher) can act on them without
// parsing free-form text.
func BuildFindings(s Snapshot) []plugin.Finding {
	cascade := detectCascade(s)
	var findings []plugin.Finding

	// Build lookup tables from events for cross-referencing below.
	schedulingMessages := map[string]string{} // pod name → FailedScheduling message
	probeFailCounts := map[string]int32{}     // pod name → Unhealthy event count
	probeFailDensity := map[string]float64{}
	probeFailMsg := map[string]string{}

	for _, e := range s.Events {
		switch e.Reason {
		case "FailedScheduling":
			schedulingMessages[e.PodName] = e.Message
		case "Unhealthy":
			probeFailCounts[e.PodName] += e.Count
			if e.Density > probeFailDensity[e.PodName] {
				probeFailDensity[e.PodName] = e.Density
				probeFailMsg[e.PodName] = e.Message
			}
		}
	}

	// --- Pods ---
	for _, pod := range s.UnhealthyPods {
		ref := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
		switch pod.Reason {
		case "CrashLoopBackOff":
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityCritical,
				Category:   "Pods",
				Title:      fmt.Sprintf("CrashLoopBackOff: %s", ref),
				Detail:     fmt.Sprintf("Pod has restarted %d times.", pod.RestartCount),
				Suggestion: "Check logs and events; fix the crash before increasing restartPolicy backoff.",
				Remediation: &plugin.RemediationAction{
					Kind:        "delete-pod",
					Namespace:   pod.Namespace,
					Resource:    "pod",
					Name:        pod.Name,
					KubectlCmd:  fmt.Sprintf("kubectl delete pod %s -n %s", pod.Name, pod.Namespace),
					Description: fmt.Sprintf("Delete pod %s so its controller reschedules it", ref),
				},
			})
		case "OOMKilled":
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityHigh,
				Category:   "Pods",
				Title:      fmt.Sprintf("OOMKilled: %s", ref),
				Detail:     fmt.Sprintf("Container exceeded its memory limit and was killed (%d restarts).", pod.RestartCount),
				Suggestion: "Increase the container memory limit or reduce heap usage.",
				Remediation: &plugin.RemediationAction{
					Kind:        "delete-pod",
					Namespace:   pod.Namespace,
					Resource:    "pod",
					Name:        pod.Name,
					KubectlCmd:  fmt.Sprintf("kubectl delete pod %s -n %s", pod.Name, pod.Namespace),
					Description: fmt.Sprintf("Delete pod %s so its controller reschedules it (also add memory limits)", ref),
				},
			})
		case "Evicted":
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityHigh,
				Category:   "Pods",
				Title:      fmt.Sprintf("Evicted: %s", ref),
				Detail:     "Pod was evicted, likely due to node resource pressure (memory or disk).",
				Suggestion: "Check node conditions with: kubectl describe node <node-name>. Add resource requests so the scheduler avoids saturated nodes.",
			})
		case "Init:Error", "Init:CrashLoopBackOff":
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityHigh,
				Category:   "Pods",
				Title:      fmt.Sprintf("Init container failure: %s (%s)", ref, pod.Reason),
				Detail:     "An init container failed, blocking the pod from starting.",
				Suggestion: "Check init container logs: kubectl logs <pod> -c <init-container> --previous",
			})
		case "ImagePullBackOff", "ErrImagePull":
			// Try to identify an imagePullPolicy fix: if the image was previously
			// pulled successfully on the node, switching to IfNotPresent avoids
			// registry round-trips and can unblock the pod immediately.
			imgPatch := `{"spec":{"template":{"spec":{"containers":[{"name":"app","imagePullPolicy":"IfNotPresent"}]}}}}`
			kubectlImg := fmt.Sprintf("kubectl rollout restart deployment -n %s", pod.Namespace)
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityHigh,
				Category:   "Pods",
				Title:      fmt.Sprintf("ImagePullBackOff: %s", ref),
				Detail:     "Kubernetes cannot pull the container image. Common causes: wrong image tag, missing imagePullSecret, registry rate limit, or private registry unreachable.",
				Suggestion: "Verify the image tag exists: docker pull <image>. Check imagePullSecret: kubectl get secret -n " + pod.Namespace,
				Remediation: &plugin.RemediationAction{
					Kind:        "rollout-restart",
					Namespace:   pod.Namespace,
					Resource:    "deployment",
					Name:        pod.Name, // best-effort: will be corrected by ownerRef resolution in collect
					PatchJSON:   imgPatch,
					KubectlCmd:  kubectlImg,
					Description: fmt.Sprintf("Restart pods in %s — verify image tag and pull secret first", pod.Namespace),
				},
			})
		case "Pending":
			if msg, ok := schedulingMessages[pod.Name]; ok {
				f := plugin.Finding{
					Severity:   plugin.SeverityHigh,
					Category:   "Pods",
					Title:      fmt.Sprintf("Scheduling failed: %s", ref),
					Detail:     msg,
					Suggestion: "Check node resources and taints: kubectl describe pod " + pod.Name + " -n " + pod.Namespace,
				}
				// Offer to cordon the most-pressured node when message mentions memory/disk pressure.
				if strings.Contains(msg, "node(s) had taint") {
					f.Suggestion += ". Also check: kubectl get nodes -o wide"
				} else if strings.Contains(msg, "Insufficient memory") || strings.Contains(msg, "memory pressure") {
					f.Suggestion += ". Consider cordoning the saturated node and draining workloads."
				}
				findings = append(findings, f)
			}
		case "NotReady":
			if cnt := probeFailCounts[pod.Name]; cnt > 20 || probeFailDensity[pod.Name] > 0.5 {
				findings = append(findings, plugin.Finding{
					Severity:   plugin.SeverityMedium,
					Category:   "Pods",
					Title:      fmt.Sprintf("Repeated probe failures: %s", ref),
					Detail:     fmt.Sprintf("%d probe failures (%.2f/s). %s", cnt, probeFailDensity[pod.Name], probeFailMsg[pod.Name]),
					Suggestion: "Investigate the failing readiness/liveness endpoint and check dependency health.",
				})
			}
		}

		// Log anomaly findings — pod-level
		for _, a := range pod.LogAnomalies {
			sev, suggestion := logAnomalySeverity(a.Category)
			findings = append(findings, plugin.Finding{
				Severity:   sev,
				Category:   "Pods",
				Title:      fmt.Sprintf("Log %s in %s", a.Category, ref),
				Detail:     fmt.Sprintf("%d occurrence(s). Sample: %s", a.Count, a.Sample),
				Suggestion: suggestion,
			})
		}

		if pod.HasNoLimits {
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityLow,
				Category:   "Resources",
				Title:      fmt.Sprintf("No resource limits: %s", ref),
				Detail:     "At least one container has no CPU or memory limit.",
				Suggestion: "Set resources.limits.cpu and resources.limits.memory to prevent noisy-neighbour issues.",
			})
		}
	}

	// --- Deployments ---
	for _, d := range s.Deployments {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityHigh,
			Category:   "Pods",
			Title:      fmt.Sprintf("Deployment stalled: %s/%s", d.Namespace, d.Name),
			Detail:     fmt.Sprintf("Desired: %d, Available: %d, Unavailable: %d. Reason: %s", d.Desired, d.Available, d.Unavailable, d.StallReason),
			Suggestion: "Check rollout events: kubectl rollout status deployment/" + d.Name + " -n " + d.Namespace,
			Remediation: &plugin.RemediationAction{
				Kind:        "rollout-restart",
				Namespace:   d.Namespace,
				Resource:    "deployment",
				Name:        d.Name,
				KubectlCmd:  fmt.Sprintf("kubectl rollout restart deployment/%s -n %s", d.Name, d.Namespace),
				Description: fmt.Sprintf("Rolling restart of deployment %s/%s", d.Namespace, d.Name),
			},
		})
	}

	// --- HPAs ---
	for _, h := range s.HPAs {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityHigh,
			Category:   "Resources",
			Title:      fmt.Sprintf("HPA cannot scale: %s/%s", h.Namespace, h.Name),
			Detail:     fmt.Sprintf("Target: %s/%s. Current: %d, Desired: %d. Issue: %s", h.TargetKind, h.TargetName, h.CurrentReplicas, h.DesiredReplicas, h.Issue),
			Suggestion: "Check HPA events and metrics-server availability.",
		})
	}

	// --- ResourceQuotas ---
	for _, q := range s.Quotas {
		sev := plugin.SeverityMedium
		if q.UsedPct >= 90 {
			sev = plugin.SeverityHigh
		}
		findings = append(findings, plugin.Finding{
			Severity:   sev,
			Category:   "Resources",
			Title:      fmt.Sprintf("Quota pressure: %s in %s (%d%%)", q.Resource, q.Namespace, q.UsedPct),
			Detail:     fmt.Sprintf("Used %s of %s hard limit.", q.Used, q.Hard),
			Suggestion: "Consider raising the ResourceQuota or reducing consumption.",
		})
	}

	// --- Node issues ---
	for _, n := range s.NodeIssues {
		for _, cond := range n.Conditions {
			sev := plugin.SeverityHigh
			if cond == "NetworkUnavailable" {
				sev = plugin.SeverityCritical
			}
			findings = append(findings, plugin.Finding{
				Severity:   sev,
				Category:   "Pods",
				Title:      fmt.Sprintf("Node %s: %s", n.Name, cond),
				Detail:     fmt.Sprintf("Node %s is reporting condition %s.", n.Name, cond),
				Suggestion: "Check node status: kubectl describe node " + n.Name,
			})
		}
	}

	// --- PVC issues ---
	for _, pvc := range s.PVCIssues {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityHigh,
			Category:   "Resources",
			Title:      fmt.Sprintf("PVC stuck: %s/%s", pvc.Namespace, pvc.Name),
			Detail:     fmt.Sprintf("Phase: %s, StorageClass: %s. %s", pvc.Phase, pvc.StorageClass, pvc.Reason),
			Suggestion: "kubectl describe storageclass " + pvc.StorageClass,
		})
	}

	// --- Service issues ---
	for _, svc := range s.ServiceIssues {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityMedium,
			Category:   "Services",
			Title:      fmt.Sprintf("Service no endpoints: %s/%s", svc.Namespace, svc.Name),
			Detail:     svc.Issue,
			Suggestion: "kubectl get endpoints " + svc.Name + " -n " + svc.Namespace,
		})
	}

	// --- Selector mismatches (service selector doesn't match any running pod) ---
	for _, sm := range s.SelectorMismatches {
		ref := fmt.Sprintf("%s/%s", sm.Namespace, sm.ServiceName)
		detail := fmt.Sprintf(
			"Service selector {%s} matches no running pods.",
			formatLabels(sm.Selector),
		)
		if sm.DeploymentName != "" {
			detail += fmt.Sprintf(
				" Deployment '%s' pods have labels: %s.",
				sm.DeploymentName, sm.MatchingLabel,
			)
		}
		kubectlFix := fmt.Sprintf(
			"kubectl patch svc %s -n %s --type merge -p '%s'",
			sm.ServiceName, sm.Namespace, sm.SuggestedPatch,
		)
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityHigh,
			Category:   "Services",
			Title:      fmt.Sprintf("Service selector mismatch: %s", ref),
			Detail:     detail,
			Suggestion: "Update the service selector to match the actual pod labels, or add missing labels to the pod template.",
			Remediation: &plugin.RemediationAction{
				Kind:        "patch-resource",
				Namespace:   sm.Namespace,
				Resource:    "service",
				Name:        sm.ServiceName,
				PatchJSON:   sm.SuggestedPatch,
				KubectlCmd:  kubectlFix,
				Description: fmt.Sprintf("Fix selector on service %s to match pod labels (%s)", ref, sm.MatchingLabel),
			},
		})
	}

	// --- Cross-namespace connectivity issues ---
	for _, cn := range s.CrossNamespaceIssues {
		findings = append(findings, plugin.Finding{
			Severity: plugin.SeverityHigh,
			Category: "Networking",
			Title: fmt.Sprintf(
				"Cross-namespace blocked: %s → %s/%s",
				cn.SourceNamespace, cn.TargetNamespace, cn.ServiceName,
			),
			Detail:     cn.Reason,
			Suggestion: fmt.Sprintf("Add a NetworkPolicy in namespace '%s' allowing egress to '%s' on port %d/%s, and add a matching ingress policy in '%s'.", cn.SourceNamespace, cn.TargetNamespace, cn.Port, cn.Protocol, cn.TargetNamespace),
		})
	}

	// --- Event spikes ---
	for _, e := range s.Events {
		if e.Density > 1.0 {
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityMedium,
				Category:   "Pods",
				Title:      fmt.Sprintf("Event spike: %s on %s/%s", e.Reason, e.Namespace, e.PodName),
				Detail:     fmt.Sprintf("%.1f events/s (%d total). Last: %s", e.Density, e.Count, e.LastSeen),
				Suggestion: "Investigate the root cause — rapid event generation often signals a control-loop failure.",
			})
		}
	}

	// --- Ingress issues ---
	for _, ing := range s.IngressIssues {
		ref := fmt.Sprintf("%s/%s", ing.Namespace, ing.Name)
		if ing.MissingClass {
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityHigh,
				Category:   "Networking",
				Title:      fmt.Sprintf("Ingress missing class: %s", ref),
				Detail:     "No spec.ingressClassName set or the referenced IngressClass does not exist.",
				Suggestion: "kubectl get ingressclass — set spec.ingressClassName to a valid class.",
			})
		}
		for _, svc := range ing.MissingBackends {
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityHigh,
				Category:   "Networking",
				Title:      fmt.Sprintf("Ingress backend missing: %s → %s", ref, svc),
				Detail:     fmt.Sprintf("Service %q referenced in Ingress rules does not exist in namespace %s.", svc, ing.Namespace),
				Suggestion: "Create the missing Service or update the Ingress backend reference.",
			})
		}
		for _, sec := range ing.MissingTLSSecret {
			findings = append(findings, plugin.Finding{
				Severity:   plugin.SeverityCritical,
				Category:   "Networking",
				Title:      fmt.Sprintf("Ingress TLS secret missing: %s → %s", ref, sec),
				Detail:     fmt.Sprintf("Secret %q referenced in Ingress TLS does not exist in namespace %s.", sec, ing.Namespace),
				Suggestion: "Create the TLS secret or update spec.tls[].secretName.",
			})
		}
	}

	// --- Resource gaps (missing limits) ---
	// Deduplicate at pod level: one finding per pod, showing worst-case containers.
	// Where a deployment name is available, offer an add-limits remediation.
	type podGapKey struct{ ns, pod string }
	podGaps := map[podGapKey][]ResourceGap{}
	for _, g := range s.ResourceGaps {
		k := podGapKey{g.Namespace, g.PodName}
		podGaps[k] = append(podGaps[k], g)
	}
	for k, gaps := range podGaps {
		hasBestEffort := false
		for _, g := range gaps {
			if g.BestEffort {
				hasBestEffort = true
				break
			}
		}
		sev := plugin.SeverityMedium
		detail := fmt.Sprintf("%d container(s) missing CPU or memory limits.", len(gaps))
		if hasBestEffort {
			sev = plugin.SeverityHigh
			detail += " Pod is BestEffort QoS — first to be evicted under node pressure."
		}

		// Build a strategic merge patch that adds safe default limits to each
		// container identified by name. Default: 100m CPU / 128Mi memory.
		var containerPatches []string
		for _, g := range gaps {
			containerPatches = append(containerPatches, fmt.Sprintf(
				`{"name":%q,"resources":{"requests":{"cpu":"50m","memory":"64Mi"},"limits":{"cpu":"200m","memory":"256Mi"}}}`,
				g.ContainerName,
			))
		}
		// Only attach remediation when we have container names to patch.
		var rem *plugin.RemediationAction
		if len(containerPatches) > 0 && gaps[0].DeploymentName != "" {
			depName := gaps[0].DeploymentName
			patchJSON := fmt.Sprintf(
				`{"spec":{"template":{"spec":{"containers":[%s]}}}}`,
				strings.Join(containerPatches, ","),
			)
			kubectlFix := fmt.Sprintf(
				"kubectl patch deployment %s -n %s --type strategic-merge-patch -p '%s'",
				depName, k.ns, patchJSON,
			)
			rem = &plugin.RemediationAction{
				Kind:        "add-limits",
				Namespace:   k.ns,
				Resource:    "deployment",
				Name:        depName,
				PatchJSON:   patchJSON,
				KubectlCmd:  kubectlFix,
				Description: fmt.Sprintf("Add default CPU/memory limits to %s/%s containers", k.ns, depName),
			}
		}

		findings = append(findings, plugin.Finding{
			Severity:    sev,
			Category:    "Resources",
			Title:       fmt.Sprintf("Resource limits missing: %s/%s", k.ns, k.pod),
			Detail:      detail,
			Suggestion:  "Set resources.requests and resources.limits on all containers.",
			Remediation: rem,
		})
	}

	// --- NetworkPolicy coverage ---
	for _, ns := range s.UncoveredNamespaces {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityMedium,
			Category:   "Security",
			Title:      fmt.Sprintf("No NetworkPolicy in namespace: %s", ns),
			Detail:     "Namespace has running pods but no NetworkPolicy — all ingress and egress is unrestricted.",
			Suggestion: "Add a default-deny NetworkPolicy and explicit allow rules for required traffic.",
		})
	}

	// --- RBAC risks ---
	for _, risk := range s.RBACRisks {
		sev := plugin.SeverityMedium
		if strings.Contains(risk.Reason, "cluster-admin") {
			sev = plugin.SeverityHigh
		}
		findings = append(findings, plugin.Finding{
			Severity:   sev,
			Category:   "Security",
			Title:      fmt.Sprintf("RBAC risk: %s", risk.Name),
			Detail:     fmt.Sprintf("%s. Subject: %s", risk.Reason, risk.Subject),
			Suggestion: "Apply least-privilege RBAC: kubectl get clusterrolebinding " + risk.Name + " -o yaml",
		})
	}

	// --- ReplicaSet issues ---
	for _, rs := range s.ReplicaSetIssues {
		detail := fmt.Sprintf("Desired: %d, Ready: %d.", rs.Desired, rs.Ready)
		if rs.Orphaned {
			detail += " ReplicaSet has no owner (not managed by a Deployment)."
		}
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityHigh,
			Category:   "Pods",
			Title:      fmt.Sprintf("ReplicaSet not ready: %s/%s", rs.Namespace, rs.Name),
			Detail:     detail,
			Suggestion: "kubectl describe rs " + rs.Name + " -n " + rs.Namespace,
		})
	}

	// --- StatefulSet issues ---
	for _, ss := range s.StatefulSetIssues {
		detail := fmt.Sprintf("Desired: %d, Ready: %d.", ss.Desired, ss.Ready)
		if ss.StuckRollout {
			detail += " Rolling update is stuck (currentRevision != updateRevision)."
		}
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityHigh,
			Category:   "Pods",
			Title:      fmt.Sprintf("StatefulSet not ready: %s/%s", ss.Namespace, ss.Name),
			Detail:     detail,
			Suggestion: "kubectl rollout status statefulset/" + ss.Name + " -n " + ss.Namespace,
			Remediation: &plugin.RemediationAction{
				Kind:        "rollout-restart",
				Namespace:   ss.Namespace,
				Resource:    "statefulset",
				Name:        ss.Name,
				KubectlCmd:  fmt.Sprintf("kubectl rollout restart statefulset/%s -n %s", ss.Name, ss.Namespace),
				Description: fmt.Sprintf("Rolling restart of statefulset %s/%s", ss.Namespace, ss.Name),
			},
		})
	}

	// --- Failed jobs ---
	for _, job := range s.FailedJobs {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityHigh,
			Category:   "Workloads",
			Title:      fmt.Sprintf("Job failed: %s/%s", job.Namespace, job.Name),
			Detail:     fmt.Sprintf("Failed attempts: %d. Reason: %s", job.Failed, job.Reason),
			Suggestion: "kubectl describe job " + job.Name + " -n " + job.Namespace + " && kubectl logs -l job-name=" + job.Name + " -n " + job.Namespace,
		})
	}

	// --- Suspended CronJobs ---
	for _, cj := range s.CronJobIssues {
		findings = append(findings, plugin.Finding{
			Severity:   plugin.SeverityMedium,
			Category:   "Workloads",
			Title:      fmt.Sprintf("CronJob suspended: %s/%s", cj.Namespace, cj.Name),
			Detail:     fmt.Sprintf("CronJob is suspended (spec.suspend=true). Last schedule: %s.", cj.LastSchedule),
			Suggestion: "kubectl patch cronjob " + cj.Name + " -n " + cj.Namespace + ` -p '{"spec":{"suspend":false}}'`,
			Remediation: &plugin.RemediationAction{
				Kind:        "resume-cronjob",
				Namespace:   cj.Namespace,
				Resource:    "cronjob",
				Name:        cj.Name,
				KubectlCmd:  fmt.Sprintf(`kubectl patch cronjob %s -n %s -p '{"spec":{"suspend":false}}'`, cj.Name, cj.Namespace),
				Description: fmt.Sprintf("Resume suspended CronJob %s/%s", cj.Namespace, cj.Name),
			},
		})
	}

	return append(cascade, findings...)
}

// detectCascade scans all pod log anomalies for cross-cutting failure patterns.
// When 3+ pods share the same anomaly category it signals a cascade — a single
// root cause propagating across the fleet. Cascade findings are prepended so
// they appear before per-pod findings in the report.
func detectCascade(s Snapshot) []plugin.Finding {
	counts := map[string]int{}
	pods := map[string][]string{}

	for _, pod := range s.UnhealthyPods {
		seen := map[string]bool{}
		for _, a := range pod.LogAnomalies {
			if !seen[a.Category] {
				seen[a.Category] = true
				counts[a.Category]++
				ref := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
				pods[a.Category] = append(pods[a.Category], ref)
			}
		}
	}

	type rule struct {
		minPods  int
		severity plugin.Severity
		title    string
		hint     string
	}
	rules := map[string]rule{
		"db-error":       {3, plugin.SeverityCritical, "Database cascade failure", "Investigate the database primary: check OOMKilled pods, connection limits, and network policies."},
		"dependency":     {3, plugin.SeverityHigh, "Dependency cascade", "Identify the failing upstream service and restore it before addressing downstream symptoms."},
		"cert-expiry":    {2, plugin.SeverityCritical, "Certificate expiry cascade", "Renew the shared TLS certificate immediately. All affected pods will recover on restart."},
		"rbac-forbidden": {2, plugin.SeverityHigh, "RBAC misconfiguration cascade", "Audit the ServiceAccount ClusterRoleBinding: kubectl get clusterrolebinding | grep <sa-name>."},
		"http-5xx":       {4, plugin.SeverityHigh, "HTTP 5XX cascade", "Check the common upstream dependency causing 5XX responses across the fleet."},
	}

	var findings []plugin.Finding
	for cat, r := range rules {
		if counts[cat] < r.minPods {
			continue
		}
		podList := strings.Join(pods[cat], ", ")
		if len(podList) > 200 {
			podList = podList[:200] + "..."
		}
		findings = append(findings, plugin.Finding{
			Severity:   r.severity,
			Title:      fmt.Sprintf("%s: %d pods affected", r.title, counts[cat]),
			Detail:     fmt.Sprintf("Pods: %s", podList),
			Suggestion: r.hint,
		})
	}
	return findings
}

// formatLabels converts a label map to a human-readable k=v string.
func formatLabels(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ", ")
}

// logAnomalySeverity maps a log category to a Finding severity and a fix hint.
func logAnomalySeverity(category string) (plugin.Severity, string) {
	switch category {
	case "db-error":
		return plugin.SeverityHigh, "Investigate database connectivity: check network policies, connection pool limits, and credentials."
	case "disk-error":
		return plugin.SeverityHigh, "Node or volume is out of disk space. Check PVC usage and node disk pressure: kubectl describe nodes."
	case "dependency":
		return plugin.SeverityMedium, "A downstream service is unreachable or returning 5XX. Check circuit-breaker state and service health."
	case "http-5xx":
		return plugin.SeverityMedium, "HTTP 5XX responses detected. Check error rates in your APM/metrics dashboard."
	case "latency":
		return plugin.SeverityMedium, "High latency detected in logs. Profile slow endpoints and check resource saturation."
	case "cpu-throttle":
		return plugin.SeverityMedium, "Container is CPU-throttled. Increase the CPU limit or optimise the workload to reduce usage."
	case "rbac-forbidden":
		return plugin.SeverityHigh, "Check SA bindings: kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>"
	case "cert-expiry":
		return plugin.SeverityCritical, "Renew TLS certificates immediately. Check cert-manager CertificateRequest resources."
	case "oom-system":
		return plugin.SeverityHigh, "Node-level OOM detected. Check: kubectl describe node <node-name>."
	case "probe-failure":
		return plugin.SeverityHigh, "Health probe repeatedly failing in logs. Check probe endpoint reachability, increase initialDelaySeconds or failureThreshold."
	case "latency-p99":
		return plugin.SeverityMedium, "P95/P99 tail latency spike detected. Profile hot paths, check downstream dependencies, and review CPU throttling."
	default:
		return plugin.SeverityInfo, ""
	}
}
