package k8s

import (
	"fmt"
	"strings"
	"time"
)

// Format renders a Snapshot into a compact text block for the LLM.
// Pods are already sorted by score descending; if the running total
// exceeds maxBytes, extra pods are omitted and a trailer note is added.
func Format(s Snapshot, maxBytes int) string {
	var b strings.Builder

	scope := s.Namespace
	if scope == "" {
		scope = "cluster-wide"
	}
	fmt.Fprintf(&b, "Scope: %s | Total pods: %d | Unhealthy: %d\n\n", scope, s.TotalPods, len(s.UnhealthyPods))

	if len(s.NodeIssues) > 0 {
		b.WriteString("## NODE ISSUES\n")
		for _, n := range s.NodeIssues {
			fmt.Fprintf(&b, "- %s: %s\n", n.Name, strings.Join(n.Conditions, ", "))
		}
		b.WriteString("\n")
	}

	if len(s.Quotas) > 0 {
		b.WriteString("## RESOURCE QUOTAS\n")
		for _, q := range s.Quotas {
			fmt.Fprintf(&b, "- %s/%s: %s / %s (%d%%)\n", q.Namespace, q.Resource, q.Used, q.Hard, q.UsedPct)
		}
		b.WriteString("\n")
	}

	if len(s.Deployments) > 0 {
		b.WriteString("## DEPLOYMENTS\n")
		for _, d := range s.Deployments {
			line := fmt.Sprintf("- %s/%s: desired=%d available=%d unavailable=%d", d.Namespace, d.Name, d.Desired, d.Available, d.Unavailable)
			if d.StallReason != "" {
				line += " stall=" + d.StallReason
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}

	if len(s.HPAs) > 0 {
		b.WriteString("## HPAs\n")
		for _, h := range s.HPAs {
			fmt.Fprintf(&b, "- %s/%s → %s/%s: current=%d desired=%d min=%d max=%d issue=%s\n",
				h.Namespace, h.Name, h.TargetKind, h.TargetName,
				h.CurrentReplicas, h.DesiredReplicas, h.MinReplicas, h.MaxReplicas, h.Issue)
		}
		b.WriteString("\n")
	}

	if len(s.PVCIssues) > 0 {
		b.WriteString("## PVC ISSUES\n")
		for _, pvc := range s.PVCIssues {
			fmt.Fprintf(&b, "- %s/%s: %s | storageClass=%s | reason=%s\n",
				pvc.Namespace, pvc.Name, pvc.Phase, pvc.StorageClass, pvc.Reason)
		}
		b.WriteString("\n")
	}

	if len(s.ServiceIssues) > 0 {
		b.WriteString("## SERVICE ISSUES\n")
		for _, svc := range s.ServiceIssues {
			fmt.Fprintf(&b, "- %s/%s: %s\n", svc.Namespace, svc.Name, svc.Issue)
		}
		b.WriteString("\n")
	}

	if len(s.IngressIssues) > 0 {
		b.WriteString("## INGRESS ISSUES\n")
		for _, ing := range s.IngressIssues {
			line := fmt.Sprintf("- %s/%s:", ing.Namespace, ing.Name)
			if ing.MissingClass {
				line += " missing-class"
			}
			if len(ing.MissingBackends) > 0 {
				line += fmt.Sprintf(" missing-backends=%s", strings.Join(ing.MissingBackends, ","))
			}
			if len(ing.MissingTLSSecret) > 0 {
				line += fmt.Sprintf(" missing-tls-secrets=%s", strings.Join(ing.MissingTLSSecret, ","))
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}

	if len(s.ResourceGaps) > 0 {
		b.WriteString("## RESOURCE GAPS (missing limits)\n")
		for _, g := range s.ResourceGaps {
			qos := ""
			if g.BestEffort {
				qos = " [BestEffort QoS]"
			}
			missing := ""
			if g.MissingCPU && g.MissingMemory {
				missing = "cpu+memory"
			} else if g.MissingCPU {
				missing = "cpu"
			} else {
				missing = "memory"
			}
			fmt.Fprintf(&b, "- %s/%s[%s]: missing=%s%s\n", g.Namespace, g.PodName, g.ContainerName, missing, qos)
		}
		b.WriteString("\n")
	}

	if len(s.UncoveredNamespaces) > 0 {
		b.WriteString("## NAMESPACES WITHOUT NETWORKPOLICY\n")
		for _, ns := range s.UncoveredNamespaces {
			fmt.Fprintf(&b, "- %s\n", ns)
		}
		b.WriteString("\n")
	}

	if len(s.RBACRisks) > 0 {
		b.WriteString("## RBAC RISKS\n")
		for _, r := range s.RBACRisks {
			fmt.Fprintf(&b, "- %s/%s: %s | subject=%s\n", r.Kind, r.Name, r.Reason, r.Subject)
		}
		b.WriteString("\n")
	}

	if len(s.ReplicaSetIssues) > 0 {
		b.WriteString("## REPLICASET ISSUES\n")
		for _, rs := range s.ReplicaSetIssues {
			orphan := ""
			if rs.Orphaned {
				orphan = " orphaned"
			}
			fmt.Fprintf(&b, "- %s/%s: desired=%d ready=%d%s\n", rs.Namespace, rs.Name, rs.Desired, rs.Ready, orphan)
		}
		b.WriteString("\n")
	}

	if len(s.StatefulSetIssues) > 0 {
		b.WriteString("## STATEFULSET ISSUES\n")
		for _, ss := range s.StatefulSetIssues {
			stuck := ""
			if ss.StuckRollout {
				stuck = " stuck-rollout"
			}
			fmt.Fprintf(&b, "- %s/%s: desired=%d ready=%d%s\n", ss.Namespace, ss.Name, ss.Desired, ss.Ready, stuck)
		}
		b.WriteString("\n")
	}

	if len(s.FailedJobs) > 0 {
		b.WriteString("## FAILED JOBS\n")
		for _, j := range s.FailedJobs {
			fmt.Fprintf(&b, "- %s/%s: failed=%d reason=%s\n", j.Namespace, j.Name, j.Failed, j.Reason)
		}
		b.WriteString("\n")
	}

	if len(s.CronJobIssues) > 0 {
		b.WriteString("## SUSPENDED CRONJOBS\n")
		for _, cj := range s.CronJobIssues {
			fmt.Fprintf(&b, "- %s/%s: suspended=true last-schedule=%s\n", cj.Namespace, cj.Name, cj.LastSchedule)
		}
		b.WriteString("\n")
	}

	if len(s.IaCChanges) > 0 {
		b.WriteString(formatIaCChanges(s.IaCChanges))
	}

	if len(s.UnhealthyPods) == 0 {
		b.WriteString("No unhealthy pods found.\n")
		return b.String()
	}

	// Index events by pod name for O(1) lookup.
	eventsByPod := make(map[string][]EventSummary, len(s.Events))
	for _, e := range s.Events {
		eventsByPod[e.PodName] = append(eventsByPod[e.PodName], e)
	}

	omitted := 0
	for _, pod := range s.UnhealthyPods {
		section := formatPod(pod, eventsByPod[pod.Name])
		if b.Len()+len(section) > maxBytes {
			omitted++
			continue
		}
		b.WriteString(section)
	}

	if omitted > 0 {
		fmt.Fprintf(&b, "\n... %d more unhealthy pod(s) omitted. Rerun with --namespace for a narrower scope.\n", omitted)
	}

	result := b.String()
	if len(result) > maxBytes {
		return result[:maxBytes] + "\n... [truncated]"
	}
	return result
}

func formatPod(pod PodSummary, events []EventSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "--- %s/%s ---\n", pod.Namespace, pod.Name)
	fmt.Fprintf(&b, "Phase: %s | Reason: %s | Restarts: %d | Age: %s\n",
		pod.Phase, pod.Reason, pod.RestartCount, pod.Age)

	if pod.HasNoLimits {
		b.WriteString("Warning: one or more containers have no CPU/memory limits.\n")
	}

	if len(events) > 0 {
		b.WriteString("\nEvents:\n")
		for _, e := range events {
			line := fmt.Sprintf("  [%s] %s (x%d, %s)", e.Reason, e.Message, e.Count, e.LastSeen)
			if e.Density > 1.0 {
				line += fmt.Sprintf(" [spike: %.1f/s]", e.Density)
			}
			b.WriteString(line + "\n")
		}
	}

	if len(pod.LogAnomalies) > 0 {
		b.WriteString("\nLog signals:\n")
		for _, a := range pod.LogAnomalies {
			fmt.Fprintf(&b, "  [%s] x%d — %s\n", a.Category, a.Count, a.Sample)
		}
	}

	for _, lt := range pod.LogTails {
		if lt.Error != "" {
			fmt.Fprintf(&b, "\nLogs (%s): [fetch error: %s]\n", lt.Container, lt.Error)
			continue
		}
		if strings.TrimSpace(lt.Lines) == "" {
			fmt.Fprintf(&b, "\nLogs (%s): [empty]\n", lt.Container)
			continue
		}
		fmt.Fprintf(&b, "\nLogs (%s):\n```\n%s\n```\n", lt.Container, strings.TrimRight(lt.Lines, "\n"))
	}

	b.WriteString("\n")
	return b.String()
}

// humanAge converts a duration to a short human-readable string (e.g. "3h", "45m").
func humanAge(d time.Duration) string {
	d = d.Truncate(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// formatIaCChanges renders the IaC change table for the LLM context block.
// Each row shows the source tool, release/application name, namespace,
// chart/revision version, sync status, and a relative synced-at age.
func formatIaCChanges(changes []IaCChange) string {
	var b strings.Builder
	b.WriteString("## IaC Changes\n")
	b.WriteString("| Source | Name | Namespace | Version | Status | Synced |\n")
	b.WriteString("|--------|------|-----------|---------|--------|--------|\n")
	now := time.Now()
	for _, c := range changes {
		syncedStr := "unknown"
		if !c.SyncedAt.IsZero() {
			syncedStr = humanAge(now.Sub(c.SyncedAt)) + " ago"
		}
		version := c.Version
		if version == "" {
			version = "-"
		}
		status := c.Status
		if status == "" {
			status = "unknown"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
			c.Source, c.Name, c.Namespace, version, status, syncedStr)
	}
	b.WriteString("\n")
	return b.String()
}
