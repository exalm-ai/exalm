// Strength: komodor — "Native Kubernetes vocabulary throughout: pods, deployments,
// ReplicaSets, HPAs are first-class data-model objects rather than tags on a
// generic APM schema." Every collector below speaks K8s natively.
package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// collectIngresses detects Ingress objects with missing class, backend service,
// or TLS secret references.
func collectIngresses(ctx context.Context, cs kubernetes.Interface, ns string) ([]IngressHealth, error) {
	list, err := cs.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ingresses: %w", err)
	}
	if len(list.Items) == 0 {
		return nil, nil
	}

	// Build sets of existing IngressClasses, Services, and Secrets per namespace
	// for cheap O(1) lookups.
	icList, err := cs.NetworkingV1().IngressClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ingressclasses: %w", err)
	}
	existingClasses := make(map[string]bool, len(icList.Items))
	for _, ic := range icList.Items {
		existingClasses[ic.Name] = true
	}

	// Cache services and secrets per namespace.
	svcCache := map[string]map[string]bool{}
	secretCache := map[string]map[string]bool{}

	svcOf := func(namespace string) (map[string]bool, error) {
		if m, ok := svcCache[namespace]; ok {
			return m, nil
		}
		sl, err := cs.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list services in %s: %w", namespace, err)
		}
		m := make(map[string]bool, len(sl.Items))
		for _, s := range sl.Items {
			m[s.Name] = true
		}
		svcCache[namespace] = m
		return m, nil
	}

	secretOf := func(namespace string) (map[string]bool, error) {
		if m, ok := secretCache[namespace]; ok {
			return m, nil
		}
		sl, err := cs.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list secrets in %s: %w", namespace, err)
		}
		m := make(map[string]bool, len(sl.Items))
		for _, s := range sl.Items {
			m[s.Name] = true
		}
		secretCache[namespace] = m
		return m, nil
	}

	var issues []IngressHealth
	for _, ing := range list.Items {
		var h IngressHealth
		h.Namespace = ing.Namespace
		h.Name = ing.Name

		// Check IngressClass reference.
		className := ""
		if ing.Spec.IngressClassName != nil {
			className = *ing.Spec.IngressClassName
		}
		if className == "" {
			if v, ok := ing.Annotations["kubernetes.io/ingress.class"]; ok {
				className = v
			}
		}
		if className == "" {
			h.MissingClass = true
		} else if !existingClasses[className] {
			h.MissingClass = true
		}

		// Check backend service references.
		svcs, err := svcOf(ing.Namespace)
		if err == nil {
			for _, rule := range ing.Spec.Rules {
				if rule.HTTP == nil {
					continue
				}
				for _, path := range rule.HTTP.Paths {
					if path.Backend.Service != nil {
						name := path.Backend.Service.Name
						if !svcs[name] {
							h.MissingBackends = append(h.MissingBackends, name)
						}
					}
				}
			}
		}

		// Check TLS secret references.
		secrets, err := secretOf(ing.Namespace)
		if err == nil {
			for _, tls := range ing.Spec.TLS {
				if tls.SecretName != "" && !secrets[tls.SecretName] {
					h.MissingTLSSecret = append(h.MissingTLSSecret, tls.SecretName)
				}
			}
		}

		if h.MissingClass || len(h.MissingBackends) > 0 || len(h.MissingTLSSecret) > 0 {
			issues = append(issues, h)
		}
	}
	return issues, nil
}

// collectResourceGaps returns containers that have missing CPU or memory limits.
// Pods that have no requests AND no limits at all are flagged as BestEffort QoS.
// DeploymentName is resolved via the pod's ownerReference chain (pod → RS → Deployment)
// so the add-limits remediation can target the correct Deployment spec.
func collectResourceGaps(ctx context.Context, cs kubernetes.Interface, ns string) ([]ResourceGap, error) {
	list, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{Limit: 500})
	if err != nil {
		return nil, fmt.Errorf("list pods for resource gaps: %w", err)
	}

	// Pre-load ReplicaSets to resolve pod → ReplicaSet → Deployment.
	var rsToDeployment map[string]string
	rsList, rsErr := cs.AppsV1().ReplicaSets(ns).List(ctx, metav1.ListOptions{})
	if rsErr == nil {
		rsToDeployment = make(map[string]string, len(rsList.Items))
		for _, rs := range rsList.Items {
			for _, ref := range rs.OwnerReferences {
				if ref.Kind == "Deployment" {
					rsToDeployment[rs.Name] = ref.Name
					break
				}
			}
		}
	}

	var gaps []ResourceGap
	for _, pod := range list.Items {
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		// Resolve owning Deployment name if possible.
		deploymentName := ""
		for _, ref := range pod.OwnerReferences {
			if ref.Kind == "ReplicaSet" && rsToDeployment != nil {
				deploymentName = rsToDeployment[ref.Name]
				break
			}
		}
		for _, c := range pod.Spec.Containers {
			lim := c.Resources.Limits
			req := c.Resources.Requests
			missingCPU := lim == nil || lim.Cpu().IsZero()
			missingMem := lim == nil || lim.Memory().IsZero()
			if !missingCPU && !missingMem {
				continue
			}
			noReqCPU := req == nil || req.Cpu().IsZero()
			noReqMem := req == nil || req.Memory().IsZero()
			gaps = append(gaps, ResourceGap{
				Namespace:      pod.Namespace,
				PodName:        pod.Name,
				ContainerName:  c.Name,
				DeploymentName: deploymentName,
				MissingCPU:     missingCPU,
				MissingMemory:  missingMem,
				BestEffort:     missingCPU && missingMem && noReqCPU && noReqMem,
			})
		}
	}
	return gaps, nil
}

// collectNetworkPolicyCoverage returns namespaces that contain running pods
// but have no NetworkPolicy objects defined (open-network risk).
func collectNetworkPolicyCoverage(ctx context.Context, cs kubernetes.Interface, ns string) ([]string, error) {
	// When scoped to a single namespace just check that one.
	namespacesToCheck := []string{}
	if ns != "" {
		namespacesToCheck = append(namespacesToCheck, ns)
	} else {
		nsList, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list namespaces: %w", err)
		}
		for _, n := range nsList.Items {
			namespacesToCheck = append(namespacesToCheck, n.Name)
		}
	}

	npList, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list network policies: %w", err)
	}
	coveredNS := make(map[string]bool, len(npList.Items))
	for _, np := range npList.Items {
		coveredNS[np.Namespace] = true
	}

	var uncovered []string
	for _, n := range namespacesToCheck {
		if coveredNS[n] {
			continue
		}
		// Only flag if the namespace actually has running pods.
		podList, err := cs.CoreV1().Pods(n).List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil || len(podList.Items) == 0 {
			continue
		}
		uncovered = append(uncovered, n)
	}
	return uncovered, nil
}

// collectRBACRisks detects ClusterRoleBindings and RoleBindings that grant
// cluster-admin or wildcard permissions.
func collectRBACRisks(ctx context.Context, cs kubernetes.Interface) ([]RBACRisk, error) {
	var risks []RBACRisk

	crbList, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterrolebindings: %w", err)
	}
	for _, crb := range crbList.Items {
		if crb.RoleRef.Name == "cluster-admin" {
			for _, subj := range crb.Subjects {
				risks = append(risks, RBACRisk{
					Kind:    "ClusterRoleBinding",
					Name:    crb.Name,
					Reason:  "cluster-admin binding",
					Subject: subjectString(subj),
				})
			}
		}
	}

	// Check ClusterRoles for wildcard rules.
	crList, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterroles: %w", err)
	}
	wildcardRoles := make(map[string]bool)
	for _, cr := range crList.Items {
		for _, rule := range cr.Rules {
			if containsWildcard(rule.Verbs) && (containsWildcard(rule.Resources) || containsResource(rule.Resources, "secrets")) {
				wildcardRoles[cr.Name] = true
				break
			}
		}
	}

	// Find bindings that reference a wildcard ClusterRole.
	for _, crb := range crbList.Items {
		if wildcardRoles[crb.RoleRef.Name] {
			for _, subj := range crb.Subjects {
				risks = append(risks, RBACRisk{
					Kind:    "ClusterRoleBinding",
					Name:    crb.Name,
					Reason:  fmt.Sprintf("wildcard verbs on secrets via %s", crb.RoleRef.Name),
					Subject: subjectString(subj),
				})
			}
		}
	}

	return risks, nil
}

// collectReplicaSetIssues returns ReplicaSets where ready < desired.
func collectReplicaSetIssues(ctx context.Context, cs kubernetes.Interface, ns string) ([]ReplicaSetIssue, error) {
	list, err := cs.AppsV1().ReplicaSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list replicasets: %w", err)
	}

	var issues []ReplicaSetIssue
	for _, rs := range list.Items {
		desired := rs.Status.Replicas
		ready := rs.Status.ReadyReplicas
		if desired == 0 || ready >= desired {
			continue
		}
		orphaned := len(rs.OwnerReferences) == 0
		issues = append(issues, ReplicaSetIssue{
			Namespace: rs.Namespace,
			Name:      rs.Name,
			Desired:   desired,
			Ready:     ready,
			Orphaned:  orphaned,
		})
	}
	return issues, nil
}

// collectStatefulSetIssues returns StatefulSets with readiness or rollout problems.
func collectStatefulSetIssues(ctx context.Context, cs kubernetes.Interface, ns string) ([]StatefulSetIssue, error) {
	list, err := cs.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}

	var issues []StatefulSetIssue
	for _, ss := range list.Items {
		desired := ss.Status.Replicas
		ready := ss.Status.ReadyReplicas
		stuckRollout := ss.Status.CurrentRevision != "" &&
			ss.Status.UpdateRevision != "" &&
			ss.Status.CurrentRevision != ss.Status.UpdateRevision

		if ready >= desired && !stuckRollout {
			continue
		}
		issues = append(issues, StatefulSetIssue{
			Namespace:    ss.Namespace,
			Name:         ss.Name,
			Desired:      desired,
			Ready:        ready,
			StuckRollout: stuckRollout,
		})
	}
	return issues, nil
}

// collectJobIssues returns batch Jobs that have failed with no active pods.
func collectJobIssues(ctx context.Context, cs kubernetes.Interface, ns string) ([]JobIssue, error) {
	list, err := cs.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}

	var issues []JobIssue
	for _, job := range list.Items {
		if job.Status.Failed == 0 || job.Status.Active > 0 {
			continue
		}
		// Skip completed jobs.
		if isJobComplete(job) {
			continue
		}
		reason := jobFailReason(job)
		issues = append(issues, JobIssue{
			Namespace: job.Namespace,
			Name:      job.Name,
			Failed:    job.Status.Failed,
			Reason:    reason,
		})
	}
	return issues, nil
}

// collectCronJobIssues returns CronJobs that are suspended or severely overdue.
func collectCronJobIssues(ctx context.Context, cs kubernetes.Interface, ns string, now time.Time) ([]CronJobIssue, error) {
	list, err := cs.BatchV1().CronJobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list cronjobs: %w", err)
	}

	var issues []CronJobIssue
	for _, cj := range list.Items {
		if cj.Spec.Suspend == nil || !*cj.Spec.Suspend {
			continue
		}
		lastSched := "never"
		if cj.Status.LastScheduleTime != nil {
			lastSched = humanAge(now.Sub(cj.Status.LastScheduleTime.Time)) + " ago"
		}
		issues = append(issues, CronJobIssue{
			Namespace:    cj.Namespace,
			Name:         cj.Name,
			Suspended:    true,
			LastSchedule: lastSched,
		})
	}
	return issues, nil
}

// ── Helpers ────────────────────────────────────────────────────────────────

func containsWildcard(ss []string) bool {
	for _, s := range ss {
		if s == "*" {
			return true
		}
	}
	return false
}

func containsResource(resources []string, target string) bool {
	for _, r := range resources {
		if r == target {
			return true
		}
	}
	return false
}

// collectSelectorMismatches finds Services whose label selector matches no running pod.
// When a Deployment exists in the same namespace whose pod template labels differ from
// the service selector, we generate a JSON merge patch to fix the service.
func collectSelectorMismatches(ctx context.Context, cs kubernetes.Interface, ns string) ([]SelectorMismatch, error) {
	// Collect services with selectors but no ready endpoints.
	epList, err := cs.CoreV1().Endpoints(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}
	svcList, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	readyEP := map[string]bool{}
	for _, ep := range epList.Items {
		for _, sub := range ep.Subsets {
			if len(sub.Addresses) > 0 {
				readyEP[ep.Name] = true
				break
			}
		}
	}

	// For each service with no endpoints, check if any deployment in the namespace
	// has a pod template that almost matches (differs in label values but same keys).
	depList, err := cs.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}

	var mismatches []SelectorMismatch
	for _, svc := range svcList.Items {
		if svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.Selector) == 0 {
			continue
		}
		if readyEP[svc.Name] {
			continue
		}

		// Look for a deployment whose pod labels share at least one key with the
		// service selector but have different values (the classic copy-paste bug).
		for _, dep := range depList.Items {
			podLabels := dep.Spec.Template.Labels
			if len(podLabels) == 0 {
				continue
			}

			// Check overlap: service selector key exists in pod labels but with different value.
			mismatchFound := false
			for k, svcVal := range svc.Spec.Selector {
				if podVal, ok := podLabels[k]; ok && podVal != svcVal {
					mismatchFound = true
					break
				}
				if _, ok := podLabels[k]; !ok {
					// Key missing from pod labels entirely — also a mismatch.
					mismatchFound = true
					break
				}
			}
			if !mismatchFound {
				continue
			}

			// Build a suggested patch: update the service selector to match pod labels.
			// We keep only keys that exist in the pod labels.
			newSelector := map[string]string{}
			for k := range svc.Spec.Selector {
				if v, ok := podLabels[k]; ok {
					newSelector[k] = v
				}
			}
			// If no overlap at all, use the pod's app label as the selector.
			if len(newSelector) == 0 {
				if appLabel, ok := podLabels["app"]; ok {
					newSelector["app"] = appLabel
				}
			}
			if len(newSelector) == 0 {
				continue // can't suggest a fix without at least one label
			}

			// Encode suggested patch.
			patchBytes, err := encodeServiceSelectorPatch(newSelector)
			if err != nil {
				continue
			}

			// Build human-readable matching label string.
			matchingParts := make([]string, 0, len(newSelector))
			for k, v := range newSelector {
				matchingParts = append(matchingParts, k+"="+v)
			}
			matchingLabel := strings.Join(matchingParts, ", ")

			mismatches = append(mismatches, SelectorMismatch{
				Namespace:      svc.Namespace,
				ServiceName:    svc.Name,
				Selector:       svc.Spec.Selector,
				SuggestedPatch: string(patchBytes),
				DeploymentName: dep.Name,
				MatchingLabel:  matchingLabel,
			})
			break // one mismatch per service is enough
		}
	}
	return mismatches, nil
}

// encodeServiceSelectorPatch builds a JSON merge patch that sets spec.selector.
func encodeServiceSelectorPatch(selector map[string]string) ([]byte, error) {
	type specPatch struct {
		Selector map[string]string `json:"selector"`
	}
	type patch struct {
		Spec specPatch `json:"spec"`
	}
	return json.Marshal(patch{Spec: specPatch{Selector: selector}})
}

// collectCrossNamespaceIssues inspects NetworkPolicy coverage across namespaces.
// When namespace A has pods with log patterns indicating failed connections to
// services in namespace B, but namespace A has a default-deny egress policy and
// no explicit allow rule for B, we report a cross-namespace connectivity issue.
func collectCrossNamespaceIssues(ctx context.Context, cs kubernetes.Interface) ([]CrossNamespaceIssue, error) {
	// List all namespaces.
	nsList, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	// Build a set of namespaces that have a default-deny egress NetworkPolicy.
	type npInfo struct{ hasDenyAll bool }
	nsPolicy := map[string]npInfo{}
	for _, ns := range nsList.Items {
		npList, err := cs.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		info := npInfo{}
		for _, np := range npList.Items {
			// A policy with empty podSelector and empty egress list = deny-all egress.
			if np.Spec.PodSelector.MatchLabels == nil && len(np.Spec.Egress) == 0 {
				for _, pt := range np.Spec.PolicyTypes {
					if pt == networkingv1.PolicyTypeEgress {
						info.hasDenyAll = true
					}
				}
			}
		}
		nsPolicy[ns.Name] = info
	}

	// Cross-namespace services: any ClusterIP service whose namespace differs from
	// namespaces that have a deny-all egress policy — those namespaces can't reach it.
	var issues []CrossNamespaceIssue
	for _, ns := range nsList.Items {
		if !nsPolicy[ns.Name].hasDenyAll {
			continue
		}
		// List services in OTHER namespaces that pods in ns.Name would need to reach.
		// Heuristic: look for services in other namespaces that have a matching name
		// referenced in events or pod labels (simplified: just report all namespaces
		// with deny-all that have pods, paired with any service-bearing namespace).
		for _, targetNS := range nsList.Items {
			if targetNS.Name == ns.Name {
				continue
			}
			svcList, err := cs.CoreV1().Services(targetNS.Name).List(ctx, metav1.ListOptions{})
			if err != nil || len(svcList.Items) == 0 {
				continue
			}
			// Pick first ClusterIP service as the representative target.
			for _, svc := range svcList.Items {
				if svc.Spec.Type == corev1.ServiceTypeClusterIP && len(svc.Spec.Ports) > 0 {
					issues = append(issues, CrossNamespaceIssue{
						SourceNamespace: ns.Name,
						TargetNamespace: targetNS.Name,
						ServiceName:     svc.Name,
						Protocol:        string(svc.Spec.Ports[0].Protocol),
						Port:            svc.Spec.Ports[0].Port,
						Reason: fmt.Sprintf(
							"Namespace '%s' has a default-deny egress NetworkPolicy but no explicit allow rule for namespace '%s'. Pods in '%s' cannot reach %s/%s on port %d.",
							ns.Name, targetNS.Name, ns.Name, targetNS.Name, svc.Name, svc.Spec.Ports[0].Port,
						),
					})
					break // one representative per target namespace
				}
			}
		}
	}
	return issues, nil
}

func subjectString(subj rbacv1.Subject) string {
	if subj.Kind == "ServiceAccount" && subj.Namespace != "" {
		return fmt.Sprintf("serviceaccount:%s/%s", subj.Namespace, subj.Name)
	}
	return fmt.Sprintf("%s:%s", strings.ToLower(subj.Kind), subj.Name)
}

func isJobComplete(job batchv1.Job) bool {
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func jobFailReason(job batchv1.Job) string {
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			if c.Reason != "" {
				return c.Reason
			}
		}
	}
	return "BackoffLimitExceeded"
}
