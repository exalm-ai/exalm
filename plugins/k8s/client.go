package k8s

import (
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// logFetcher abstracts log streaming so tests can inject a fake without
// needing a real kubelet. The fake.Clientset's GetLogs().Stream() panics,
// so this interface is what makes collect.go hermetically testable.
type logFetcher interface {
	Tail(ctx context.Context, ns, pod, container string, lines int64, previous bool) (string, error)
}

// restLogFetcher is the production implementation backed by the k8s REST API.
type restLogFetcher struct {
	clientset kubernetes.Interface
}

func (f *restLogFetcher) Tail(ctx context.Context, ns, pod, container string, lines int64, previous bool) (string, error) {
	req := f.clientset.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{
		Container: container,
		TailLines: &lines,
		Previous:  previous,
	})
	stream, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("stream logs %s/%s/%s: %w", ns, pod, container, err)
	}
	defer stream.Close()
	b, err := io.ReadAll(io.LimitReader(stream, 16*1024))
	if err != nil {
		return "", fmt.Errorf("read logs %s/%s/%s: %w", ns, pod, container, err)
	}
	return string(b), nil
}

// newKubeClient builds a kubernetes.Interface using standard kubeconfig
// discovery: explicit path > KUBECONFIG env > ~/.kube/config > in-cluster.
func newKubeClient(kubeconfigPath, contextName string) (kubernetes.Interface, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, overrides,
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build k8s client: %w", err)
	}
	return cs, nil
}

// newDynamicClient builds a dynamic.Interface for CRD queries (e.g. ArgoCD
// Applications) using the same kubeconfig discovery as newKubeClient.
func newDynamicClient(kubeconfigPath, contextName string) (dynamic.Interface, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, overrides,
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig for dynamic client: %w", err)
	}
	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}
	return dc, nil
}
