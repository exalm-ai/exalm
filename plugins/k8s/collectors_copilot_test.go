package k8s

// collectors_copilot_test.go covers the copilot's on-demand collectors:
// owner chain, service chain, storage chain, scaling, netpol, RBAC, and
// namespace detail — all against the fake clientset (hermetic, no cluster).

import (
	"context"
	"fmt"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func boolPtr(b bool) *bool    { return &b }
func int32Ptr(i int32) *int32 { return &i }

func TestOwnerChainFor_PodToDeployment(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "payment-api-7d8-xkp", Namespace: "prod",
			Labels:          map[string]string{"app": "payment-api"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "payment-api-7d8", Controller: boolPtr(true)}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry.example.com/payment-api:v2"}}},
	}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "payment-api-7d8", Namespace: "prod",
			OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "payment-api", Controller: boolPtr(true)}},
		},
	}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "payment-api", Namespace: "prod"},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(3),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "app", Image: "registry.example.com/payment-api:v2",
			}}}},
		},
		Status: appsv1.DeploymentStatus{ReadyReplicas: 1},
	}
	cs := fake.NewSimpleClientset(pod, rs, dep)

	chain, err := ownerChainFor(context.Background(), cs, nil, "prod", "payment-api-7d8-xkp")
	if err != nil {
		t.Fatalf("ownerChainFor: %v", err)
	}
	if len(chain.Links) != 2 {
		t.Fatalf("expected 2 links (rs, deployment), got %+v", chain.Links)
	}
	if chain.Links[0].Edge != "pod→ownerReplicaSet" || chain.Links[1].Edge != "replicaset→ownerDeployment" {
		t.Errorf("unexpected edges: %+v", chain.Links)
	}
	if chain.Workload == nil || chain.Workload.Kind != "Deployment" || chain.Workload.Name != "payment-api" {
		t.Fatalf("expected Deployment workload detail, got %+v", chain.Workload)
	}
	if chain.Workload.Desired != 3 || chain.Workload.Ready != 1 {
		t.Errorf("replica counts: got %d/%d want 1/3", chain.Workload.Ready, chain.Workload.Desired)
	}
	if chain.Workload.HasMemoryLimits {
		t.Error("fixture has no limits; HasMemoryLimits should be false")
	}
	if !strings.Contains(chain.Workload.ProbeSummary, "no readiness or liveness probes") {
		t.Errorf("probe summary: %q", chain.Workload.ProbeSummary)
	}
}

func TestOwnerChainFor_BarePod(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "solo", Namespace: "prod"}}
	cs := fake.NewSimpleClientset(pod)
	chain, err := ownerChainFor(context.Background(), cs, nil, "prod", "solo")
	if err != nil {
		t.Fatalf("ownerChainFor: %v", err)
	}
	if len(chain.Links) != 0 || chain.Workload != nil {
		t.Errorf("bare pod should yield an empty chain, got %+v", chain)
	}
}

func TestGatherOwnerChain_NoClient(t *testing.T) {
	steps, evid := gatherOwnerChain(context.Background(), nil, nil, "prod", "x")
	if len(steps) != 1 || steps[0].Status != "unavailable" {
		t.Errorf("expected a single unavailable step, got %+v", steps)
	}
	if evid != nil {
		t.Errorf("expected no evidence, got %+v", evid)
	}
}

func TestServicesForPod_SelectorAndEndpointSlices(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "payment-api-1", Namespace: "prod", Labels: map[string]string{"app": "payment-api"},
	}}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "payment-api", Namespace: "prod"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "payment-api"}, Type: corev1.ServiceTypeClusterIP},
	}
	otherSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "prod"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "other"}},
	}
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "payment-api-abc", Namespace: "prod",
			Labels: map[string]string{"kubernetes.io/service-name": "payment-api"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Conditions: discoveryv1.EndpointConditions{Ready: boolPtr(true)}},
			{Conditions: discoveryv1.EndpointConditions{Ready: boolPtr(false)}},
		},
	}
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "prod"},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: "pay.internal.example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Path:    "/pay",
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "payment-api"}},
				}},
			}},
		}}},
	}
	cs := fake.NewSimpleClientset(pod, svc, otherSvc, slice, ing)

	out, err := servicesForPod(context.Background(), cs, nil, "prod", "payment-api-1")
	if err != nil {
		t.Fatalf("servicesForPod: %v", err)
	}
	if len(out) != 1 || out[0].Name != "payment-api" {
		t.Fatalf("expected only the matching service, got %+v", out)
	}
	if !out[0].Endpoints.Found || out[0].Endpoints.Ready != 1 || out[0].Endpoints.NotReady != 1 {
		t.Errorf("endpoint health: %+v", out[0].Endpoints)
	}
	if len(out[0].Ingresses) != 1 || out[0].Ingresses[0].Name != "edge" {
		t.Errorf("ingress routes: %+v", out[0].Ingresses)
	}
}

func TestStorageChainForPod_FullChainAndMissingSC(t *testing.T) {
	mode := storagev1.VolumeBindingWaitForFirstConsumer
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "db-0", Namespace: "prod"},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{
			{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data-pvc"}}},
			{Name: "orphan", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "orphan-pvc"}}},
		}},
	}
	scName := "fast-ssd"
	missingSC := "gone-sc"
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "data-pvc", Namespace: "prod"},
		Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: &scName, VolumeName: "pv-123"},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase:    corev1.ClaimBound,
			Capacity: corev1.ResourceList{"storage": resource.MustParse("100Gi")},
		},
	}
	orphanPVC := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan-pvc", Namespace: "prod"},
		Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: &missingSC},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-123"},
		Spec: corev1.PersistentVolumeSpec{
			StorageClassName:              scName,
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}
	sc := &storagev1.StorageClass{
		ObjectMeta:        metav1.ObjectMeta{Name: scName},
		Provisioner:       "ebs.csi.aws.com",
		VolumeBindingMode: &mode,
	}
	cs := fake.NewSimpleClientset(pod, pvc, orphanPVC, pv, sc)

	links, err := storageChainForPod(context.Background(), cs, "prod", "db-0")
	if err != nil {
		t.Fatalf("storageChainForPod: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %+v", links)
	}
	full := links[0]
	if full.PVCName != "data-pvc" || full.PVName != "pv-123" || full.SCName != scName {
		t.Errorf("full chain: %+v", full)
	}
	if full.Provisioner != "ebs.csi.aws.com" || full.ReclaimPolicy != "Retain" {
		t.Errorf("PV/SC detail: %+v", full)
	}
	orphan := links[1]
	if orphan.PVName != "" || !orphan.SCMissing {
		t.Errorf("orphan link should be unbound with a missing SC: %+v", orphan)
	}
}

func TestHPAForWorkload_MatchAndAtMax(t *testing.T) {
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "payment-hpa", Namespace: "prod"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "payment-api"},
			MinReplicas:    int32Ptr(2),
			MaxReplicas:    10,
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{CurrentReplicas: 10, DesiredReplicas: 18},
	}
	cs := fake.NewSimpleClientset(hpa)

	d, err := hpaForWorkload(context.Background(), cs, nil, "prod", "Deployment", "payment-api")
	if err != nil || d == nil {
		t.Fatalf("hpaForWorkload: d=%v err=%v", d, err)
	}
	if !d.AtMax {
		t.Errorf("expected AtMax with current=10 max=10 desired=18: %+v", d)
	}
	none, err := hpaForWorkload(context.Background(), cs, nil, "prod", "Deployment", "unrelated")
	if err != nil || none != nil {
		t.Errorf("expected no HPA for unrelated workload, got %+v err=%v", none, err)
	}
}

func TestNetworkPoliciesForPod_DefaultDenySignal(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "api-1", Namespace: "prod", Labels: map[string]string{"app": "api"},
	}}
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "db-only", Namespace: "prod"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}
	cs := fake.NewSimpleClientset(pod, np)

	matched, total, err := networkPoliciesForPod(context.Background(), cs, "prod", "api-1")
	if err != nil {
		t.Fatalf("networkPoliciesForPod: %v", err)
	}
	if total != 1 || len(matched) != 0 {
		t.Errorf("expected 0 matches of 1 total, got %d of %d", len(matched), total)
	}
	_, evid := gatherNetpol(context.Background(), cs, "prod", "api-1")
	if len(evid) != 1 || !strings.Contains(evid[0].Excerpt, "default-deny") {
		t.Errorf("expected a default-deny heuristic evidence item, got %+v", evid)
	}
}

func TestRBACForServiceAccount_NamesOnlyNeverTokens(t *testing.T) {
	tokenValue := "eyJhbGciOiJSUzI1NiJ9.super-secret-token"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "prod"},
		Spec:       corev1.PodSpec{ServiceAccountName: "api-sa"},
	}
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "api-sa-token", Namespace: "prod"},
		Type:       corev1.SecretTypeServiceAccountToken,
		Data:       map[string][]byte{"token": []byte(tokenValue)},
	}
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "api-reader", Namespace: "prod"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "api-sa", Namespace: "prod"}},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "config-reader"},
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "api-cluster-view"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "api-sa", Namespace: "prod"}},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
	}
	cs := fake.NewSimpleClientset(pod, tokenSecret, rb, crb)

	steps, evid := gatherRBAC(context.Background(), cs, "prod", "api-1")
	if len(steps) != 1 || steps[0].Status != "done" {
		t.Fatalf("steps: %+v", steps)
	}
	dump := fmt.Sprintf("%+v %+v", steps, evid)
	if strings.Contains(dump, tokenValue) {
		t.Fatalf("SERVICE ACCOUNT TOKEN LEAKED into RBAC evidence: %s", dump)
	}
	if len(evid) != 3 { // 1 identity + 2 bindings
		t.Fatalf("expected 3 evidence items, got %+v", evid)
	}
	if !strings.Contains(dump, "Role/config-reader") || !strings.Contains(dump, "ClusterRole/view") {
		t.Errorf("expected role refs in evidence: %s", dump)
	}
}

func TestNamespaceDetailFor_QuotaAndLimitRange(t *testing.T) {
	nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}}
	quota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: "prod-quota", Namespace: "prod"},
		Status: corev1.ResourceQuotaStatus{
			Hard: corev1.ResourceList{"requests.memory": resource.MustParse("16Gi")},
			Used: corev1.ResourceList{"requests.memory": resource.MustParse("12Gi")},
		},
	}
	lr := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Name: "defaults", Namespace: "prod"},
		Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
			Type:    corev1.LimitTypeContainer,
			Default: corev1.ResourceList{"memory": resource.MustParse("512Mi")},
		}}},
	}
	cs := fake.NewSimpleClientset(nsObj, quota, lr)

	d, err := namespaceDetailFor(context.Background(), cs, "prod")
	if err != nil {
		t.Fatalf("namespaceDetailFor: %v", err)
	}
	if d.Phase != "Active" {
		t.Errorf("phase: %q", d.Phase)
	}
	if len(d.QuotaUsage) != 1 || !strings.Contains(d.QuotaUsage[0], "12Gi/16Gi") {
		t.Errorf("quota usage: %+v", d.QuotaUsage)
	}
	if len(d.LimitRanges) != 1 || !strings.Contains(d.LimitRanges[0], "512Mi") {
		t.Errorf("limit ranges: %+v", d.LimitRanges)
	}
}
