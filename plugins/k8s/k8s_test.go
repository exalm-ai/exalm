package k8s

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/exalm-ai/exalm/internal/redact"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// fakeLLM records what it was asked and returns a canned response.
type fakeLLM struct {
	lastSystem  string
	lastUserMsg string
}

func (f *fakeLLM) Name() string { return "fake" }
func (f *fakeLLM) Complete(_ context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
	f.lastSystem = req.System
	if len(req.Messages) > 0 {
		f.lastUserMsg = req.Messages[0].Content
	}
	return plugin.CompleteResponse{Content: "## VERDICT\nTest response."}, nil
}

// fakeLogFetcher returns canned log content keyed by "ns/pod/container".
type fakeLogFetcher struct {
	logs map[string]string
}

func (f *fakeLogFetcher) Tail(_ context.Context, ns, pod, container string, _ int64, _ bool) (string, error) {
	if f.logs == nil {
		return "", nil
	}
	return f.logs[ns+"/"+pod+"/"+container], nil
}

// newTestPlugin builds a Plugin with injected fakes.
func newTestPlugin(clientset kubernetes.Interface, logs map[string]string) *Plugin {
	lf := &fakeLogFetcher{logs: logs}
	return &Plugin{
		clientFactory: func(_, _ string) (kubernetes.Interface, error) { return clientset, nil },
		newLogFetcher: func(kubernetes.Interface) logFetcher { return lf },
	}
}

func TestPlugin_Metadata(t *testing.T) {
	p := New()
	if p.Name() != "k8s" {
		t.Errorf("Name() = %q, want k8s", p.Name())
	}
	if p.Mutates() {
		t.Error("k8s plugin should be read-only (Mutates() = false)")
	}
	subs := p.Subcommands()
	if len(subs) == 0 {
		t.Fatal("expected at least one subcommand")
	}
	if subs[0].Name != "analyze" {
		t.Errorf("first subcommand = %q, want analyze", subs[0].Name)
	}
}

func TestAnalyze_RedactsBeforeLLM(t *testing.T) {
	crashPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "crash-pod", Namespace: "default"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", Ready: false, RestartCount: 3,
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
					}},
			},
		},
	}
	logs := map[string]string{
		"default/crash-pod/app": "error: credentials AKIAIOSFODNN7EXAMPLE rejected\n",
	}
	p := newTestPlugin(fake.NewSimpleClientset(crashPod), logs)
	llm := &fakeLLM{}
	_, err := p.Subcommands()[0].Run(context.Background(), plugin.RunArgs{
		Flags:    map[string]string{"namespace": "default"},
		LLM:      llm,
		Redactor: redact.New(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(llm.lastUserMsg, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("AWS key reached LLM unredacted")
	}
	if !strings.Contains(llm.lastUserMsg, "[REDACTED:") {
		t.Fatal("expected redaction marker in LLM input")
	}
}

func TestAnalyze_BearerTokenRedacted(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: "default"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "api", Ready: false, State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
				}},
			},
		},
	}
	event := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "evt1", Namespace: "default"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "api-pod"},
		Type:           corev1.EventTypeWarning,
		Reason:         "Unauthorized",
		Message:        "unauthorized: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature",
		Count:          1,
	}
	p := newTestPlugin(fake.NewSimpleClientset(pod, event), nil)
	llm := &fakeLLM{}
	_, err := p.Subcommands()[0].Run(context.Background(), plugin.RunArgs{
		Flags:    map[string]string{"namespace": "default"},
		LLM:      llm,
		Redactor: redact.New(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(llm.lastUserMsg, "eyJhbGciOiJSUzI1NiIs") {
		t.Fatal("JWT in event message reached LLM unredacted")
	}
}

func TestAnalyze_HealthyPodsNotInPayload(t *testing.T) {
	healthyPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "healthy-pod", Namespace: "default"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", Ready: true},
			},
		},
	}
	p := newTestPlugin(fake.NewSimpleClientset(healthyPod), nil)
	llm := &fakeLLM{}
	_, err := p.Subcommands()[0].Run(context.Background(), plugin.RunArgs{
		Flags:    map[string]string{"namespace": "default"},
		LLM:      llm,
		Redactor: redact.New(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(llm.lastUserMsg, "healthy-pod") {
		t.Fatal("healthy pod name appeared in LLM payload")
	}
}

func TestAnalyze_EmptyCluster(t *testing.T) {
	p := newTestPlugin(fake.NewSimpleClientset(), nil)
	llm := &fakeLLM{}
	_, err := p.Subcommands()[0].Run(context.Background(), plugin.RunArgs{
		Flags:    map[string]string{},
		LLM:      llm,
		Redactor: redact.New(),
	})
	if err != nil {
		t.Fatalf("Run on empty cluster: %v", err)
	}
	// LLM must still be called even with no unhealthy pods.
	if llm.lastUserMsg == "" {
		t.Fatal("LLM was not called for empty cluster")
	}
	if !strings.Contains(llm.lastUserMsg, "No unhealthy pods") {
		t.Errorf("expected 'No unhealthy pods' message, got: %q", llm.lastUserMsg)
	}
}

func TestAnalyze_UnhealthyPodNameReachesLLM(t *testing.T) {
	// The LLM needs pod names for correlation — they must NOT be stripped.
	crashPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-api-7d9f", Namespace: "prod"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", Ready: false, State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
				}},
			},
		},
	}
	p := newTestPlugin(fake.NewSimpleClientset(crashPod), nil)
	llm := &fakeLLM{}
	_, err := p.Subcommands()[0].Run(context.Background(), plugin.RunArgs{
		Flags:    map[string]string{"namespace": "prod"},
		LLM:      llm,
		Redactor: redact.New(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(llm.lastUserMsg, "payments-api-7d9f") {
		t.Error("unhealthy pod name must appear in LLM payload for correlation")
	}
}
