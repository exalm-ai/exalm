package k8s

// servicechain.go resolves the traffic path for a pod: which Services select
// it, how healthy each Service's EndpointSlices are, and which Ingresses
// route to those Services. On-demand collector (same trust class as
// configmaps.go).

import (
	"context"
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ServiceDetail is a redaction-safe view of one Service selecting the pod.
type ServiceDetail struct {
	Name      string
	Type      string
	Ports     []string
	Endpoints EndpointHealth
	Ingresses []IngressRoute
}

// EndpointHealth summarizes readiness across a Service's EndpointSlices.
type EndpointHealth struct {
	Ready    int
	NotReady int
	Found    bool // false when no EndpointSlice exists at all
}

// IngressRoute is one Ingress rule that routes to a Service (host redacted —
// hostnames are user-authored and can identify internal systems).
type IngressRoute struct {
	Name string
	Host string
	Path string
	TLS  bool
}

// servicesForPod finds Services in ns whose selector matches the live pod's
// labels, then resolves each one's EndpointSlices and Ingress routes.
func servicesForPod(ctx context.Context, cs kubernetes.Interface, red plugin.Redactor, ns, podName string) ([]ServiceDetail, error) {
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", ns, podName, err)
	}
	svcs, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services in %s: %w", ns, err)
	}

	var out []ServiceDetail
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if len(svc.Spec.Selector) == 0 || !labelsMatch(svc.Spec.Selector, pod.Labels) {
			continue
		}
		d := ServiceDetail{Name: svc.Name, Type: string(svc.Spec.Type)}
		for _, p := range svc.Spec.Ports {
			d.Ports = append(d.Ports, fmt.Sprintf("%d→%s", p.Port, p.TargetPort.String()))
		}
		d.Endpoints = endpointSlicesFor(ctx, cs, ns, svc.Name)
		d.Ingresses = ingressesForService(ctx, cs, red, ns, svc.Name)
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// labelsMatch reports whether every selector key/value is present in labels.
func labelsMatch(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// endpointSlicesFor counts ready vs not-ready endpoints across the Service's
// EndpointSlices (label kubernetes.io/service-name). A missing slice — or a
// slice with zero ready endpoints — is a classic selector-mismatch signal.
func endpointSlicesFor(ctx context.Context, cs kubernetes.Interface, ns, svcName string) EndpointHealth {
	slices, err := cs.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "kubernetes.io/service-name=" + svcName,
	})
	if err != nil || len(slices.Items) == 0 {
		return EndpointHealth{}
	}
	h := EndpointHealth{Found: true}
	for _, sl := range slices.Items {
		for _, ep := range sl.Endpoints {
			if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				h.Ready++
			} else {
				h.NotReady++
			}
		}
	}
	return h
}

// ingressesForService returns the Ingress rules whose backend names svcName.
func ingressesForService(ctx context.Context, cs kubernetes.Interface, red plugin.Redactor, ns, svcName string) []IngressRoute {
	ings, err := cs.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	var out []IngressRoute
	for _, ing := range ings.Items {
		tlsHosts := map[string]bool{}
		for _, t := range ing.Spec.TLS {
			for _, h := range t.Hosts {
				tlsHosts[h] = true
			}
		}
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, p := range rule.HTTP.Paths {
				if p.Backend.Service == nil || p.Backend.Service.Name != svcName {
					continue
				}
				out = append(out, IngressRoute{
					Name: ing.Name,
					Host: redactStr(red, rule.Host),
					Path: p.Path,
					TLS:  tlsHosts[rule.Host],
				})
			}
		}
	}
	return out
}

// gatherServiceChain is the planner-facing wrapper for the pod's traffic path.
func gatherServiceChain(ctx context.Context, cs kubernetes.Interface, red plugin.Redactor, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || name == "" {
		return []plugin.InvestigationStep{step("Service routing inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	svcs, err := servicesForPod(ctx, cs, red, ns, name)
	if err != nil {
		return []plugin.InvestigationStep{step("Service routing inspected", "unavailable", "service lookup failed", "")}, nil
	}
	if len(svcs) == 0 {
		return []plugin.InvestigationStep{step("Service routing inspected", "done", "no Service selects this pod", "")}, nil
	}
	var evid []plugin.EvidenceItem
	for _, s := range svcs {
		epTxt := "no EndpointSlice found"
		if s.Endpoints.Found {
			epTxt = fmt.Sprintf("%d ready / %d not-ready endpoints", s.Endpoints.Ready, s.Endpoints.NotReady)
		}
		evid = append(evid, plugin.EvidenceItem{
			Kind: "topology", Source: "service/" + s.Name, Edge: "pod→service→endpointslice",
			Excerpt: fmt.Sprintf("type=%s ports=%s · %s", s.Type, strings.Join(s.Ports, ","), epTxt),
			Anchor:  "kubectl get endpointslices -n " + ns + " -l kubernetes.io/service-name=" + s.Name,
		})
		for _, ing := range s.Ingresses {
			evid = append(evid, plugin.EvidenceItem{
				Kind: "topology", Source: "ingress/" + ing.Name, Edge: "service→ingress",
				Excerpt: fmt.Sprintf("host=%s path=%s tls=%t → service/%s", ing.Host, ing.Path, ing.TLS, s.Name),
				Anchor:  "kubectl describe ingress " + ing.Name + " -n " + ns,
			})
		}
	}
	return []plugin.InvestigationStep{step("Service routing inspected", "done", fmt.Sprintf("%d service(s) select this pod", len(svcs)), "")}, evid
}
