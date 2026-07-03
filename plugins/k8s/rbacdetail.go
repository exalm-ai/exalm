package k8s

// rbacdetail.go resolves the pod's ServiceAccount and the RBAC bindings that
// grant it permissions. Names and role references ONLY — this collector never
// touches ServiceAccount token Secrets or any Secret values.

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// RBACBinding is one Role/ClusterRoleBinding granting the ServiceAccount.
type RBACBinding struct {
	Kind    string // "RoleBinding" | "ClusterRoleBinding"
	Name    string
	RoleRef string // "ClusterRole/admin", "Role/config-reader"
}

// RBACDetail is the pod's identity and its grants.
type RBACDetail struct {
	ServiceAccount string
	Bindings       []RBACBinding
}

// serviceAccountFor reads the live pod's serviceAccountName ("default" when
// unset, matching kubelet behavior).
func serviceAccountFor(ctx context.Context, cs kubernetes.Interface, ns, podName string) (string, error) {
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get pod %s/%s: %w", ns, podName, err)
	}
	if pod.Spec.ServiceAccountName == "" {
		return "default", nil
	}
	return pod.Spec.ServiceAccountName, nil
}

// rbacForServiceAccount lists RoleBindings in ns and ClusterRoleBindings,
// keeping those whose subjects include the ServiceAccount.
func rbacForServiceAccount(ctx context.Context, cs kubernetes.Interface, ns, saName string) (RBACDetail, error) {
	detail := RBACDetail{ServiceAccount: saName}
	if rbs, err := cs.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{}); err == nil {
		for _, rb := range rbs.Items {
			if subjectsInclude(rb.Subjects, ns, saName) {
				detail.Bindings = append(detail.Bindings, RBACBinding{
					Kind: "RoleBinding", Name: rb.Name,
					RoleRef: rb.RoleRef.Kind + "/" + rb.RoleRef.Name,
				})
			}
		}
	}
	if crbs, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{}); err == nil {
		for _, crb := range crbs.Items {
			if subjectsInclude(crb.Subjects, ns, saName) {
				detail.Bindings = append(detail.Bindings, RBACBinding{
					Kind: "ClusterRoleBinding", Name: crb.Name,
					RoleRef: crb.RoleRef.Kind + "/" + crb.RoleRef.Name,
				})
			}
		}
	}
	return detail, nil
}

// subjectsInclude reports whether any subject is the given ServiceAccount.
func subjectsInclude(subjects []rbacv1.Subject, ns, saName string) bool {
	for _, s := range subjects {
		if s.Kind == "ServiceAccount" && s.Name == saName && (s.Namespace == "" || s.Namespace == ns) {
			return true
		}
	}
	return false
}

// gatherRBAC is the planner-facing wrapper for the pod's identity + grants.
func gatherRBAC(ctx context.Context, cs kubernetes.Interface, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || name == "" {
		return []plugin.InvestigationStep{step("ServiceAccount & RBAC inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	sa, err := serviceAccountFor(ctx, cs, ns, name)
	if err != nil {
		return []plugin.InvestigationStep{step("ServiceAccount & RBAC inspected", "unavailable", "pod fetch failed", "")}, nil
	}
	detail, _ := rbacForServiceAccount(ctx, cs, ns, sa)
	evid := []plugin.EvidenceItem{{
		Kind: "config", Source: "serviceaccount/" + sa, Edge: "pod→serviceAccount→rbac",
		Excerpt: fmt.Sprintf("pod runs as serviceaccount/%s with %d RBAC binding(s)", sa, len(detail.Bindings)),
		Anchor:  "kubectl get rolebindings,clusterrolebindings -A -o wide | grep " + sa,
	}}
	for _, b := range detail.Bindings {
		evid = append(evid, plugin.EvidenceItem{
			Kind: "config", Source: b.Kind + "/" + b.Name, Edge: "pod→serviceAccount→rbac",
			Excerpt: "grants " + b.RoleRef,
		})
	}
	return []plugin.InvestigationStep{step("ServiceAccount & RBAC inspected (names/roles only — token secrets never read)", "done",
		fmt.Sprintf("serviceaccount/%s, %d binding(s)", sa, len(detail.Bindings)), "")}, evid
}
