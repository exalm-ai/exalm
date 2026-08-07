package k8s

import (
	"os"
	"path/filepath"
	"testing"
)

// A minimal but valid kubeconfig. The server address is deliberately bogus
// (no such host) — building a client never dials it (kubernetes.NewForConfig
// is lazy), so this only exercises config loading, not real connectivity.
const fakeKubeconfig = `
apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: https://127.0.0.1:1
current-context: test-context
contexts:
- name: test-context
  context:
    cluster: test-cluster
    user: test-user
users:
- name: test-user
  user:
    token: fake-token
`

func writeFakeKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(fakeKubeconfig), 0o600); err != nil {
		t.Fatalf("write fake kubeconfig: %v", err)
	}
	return path
}

func TestNewClient_ValidKubeconfig(t *testing.T) {
	path := writeFakeKubeconfig(t)
	cs, err := NewClient(path, "")
	if err != nil {
		t.Fatalf("NewClient with a valid (if unreachable) kubeconfig should not error: %v", err)
	}
	if cs == nil {
		t.Error("expected a non-nil clientset")
	}
}

func TestNewClient_ExplicitContext(t *testing.T) {
	path := writeFakeKubeconfig(t)
	if _, err := NewClient(path, "test-context"); err != nil {
		t.Errorf("NewClient with an existing context name should not error: %v", err)
	}
	if _, err := NewClient(path, "no-such-context"); err == nil {
		t.Error("NewClient with an unknown context name should error")
	}
}

func TestNewClient_MissingKubeconfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := NewClient(missing, ""); err == nil {
		t.Error("NewClient with a nonexistent kubeconfig path should error, not silently succeed")
	}
}
