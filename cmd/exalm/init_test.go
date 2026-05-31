package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestLlmKeyCheck_KnownProviders verifies the env-var names returned for
// each supported provider.
func TestLlmKeyCheck_KnownProviders(t *testing.T) {
	cases := []struct {
		provider string
		wantEnv  string
	}{
		{"claude", "ANTHROPIC_API_KEY"},
		{"openai", "OPENAI_API_KEY"},
		{"openrouter", "OPENROUTER_API_KEY"},
		{"ollama", "EXALM_OLLAMA_URL"}, // no key required; always "present"
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			envVar, _ := llmKeyCheck(tc.provider)
			if envVar != tc.wantEnv {
				t.Errorf("provider=%s: got env %q, want %q", tc.provider, envVar, tc.wantEnv)
			}
		})
	}
}

// TestLlmKeyCheck_Ollama_AlwaysPresent verifies that Ollama is always
// considered "present" since it requires no API key.
func TestLlmKeyCheck_Ollama_AlwaysPresent(t *testing.T) {
	_, present := llmKeyCheck("ollama")
	if !present {
		t.Error("ollama should always report keyPresent=true (no API key required)")
	}
}

// TestLlmKeyCheck_Claude_Absent verifies that Claude reports absent when the
// env var is not set.
func TestLlmKeyCheck_Claude_Absent(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	_, present := llmKeyCheck("claude")
	if present {
		t.Error("expected keyPresent=false when ANTHROPIC_API_KEY is unset")
	}
}

// TestLlmKeyCheck_Claude_Present verifies that Claude reports present when
// the env var is set.
func TestLlmKeyCheck_Claude_Present(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
	_, present := llmKeyCheck("claude")
	if !present {
		t.Error("expected keyPresent=true when ANTHROPIC_API_KEY is set")
	}
}

// TestEnsureDataDir_Creates verifies that ensureDataDir creates the directory
// when it does not exist.
func TestEnsureDataDir_Creates(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, ".exalm")

	// Point UserHomeDir at our temp dir by overriding HOME.
	t.Setenv("HOME", tmp)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tmp)
	}

	path, ok, msg := ensureDataDir()
	if !ok {
		t.Fatalf("ensureDataDir failed: %s", msg)
	}
	if path != target {
		t.Errorf("path: got %q, want %q", path, target)
	}
	if _, err := os.Stat(target); os.IsNotExist(err) {
		t.Error("directory was not created")
	}
}

// TestEnsureDataDir_AlreadyExists verifies that ensureDataDir succeeds when
// the directory already exists.
func TestEnsureDataDir_AlreadyExists(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, ".exalm")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("setup: %v", err)
	}

	t.Setenv("HOME", tmp)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tmp)
	}

	_, ok, msg := ensureDataDir()
	if !ok {
		t.Fatalf("ensureDataDir failed on existing dir: %s", msg)
	}
}

// TestDetectKubeContext_Missing verifies that detectKubeContext returns ""
// when no kubeconfig exists.
func TestDetectKubeContext_Missing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KUBECONFIG", filepath.Join(tmp, "nonexistent"))
	ctx := detectKubeContext()
	if ctx != "" {
		t.Errorf("expected empty context for missing kubeconfig, got %q", ctx)
	}
}

// TestDetectKubeContext_Present verifies that detectKubeContext reads the
// current-context line from a minimal kubeconfig file.
func TestDetectKubeContext_Present(t *testing.T) {
	tmp := t.TempDir()
	kc := filepath.Join(tmp, "config")
	content := "apiVersion: v1\ncurrent-context: my-cluster\nclusters: []\n"
	if err := os.WriteFile(kc, []byte(content), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	t.Setenv("KUBECONFIG", kc)

	ctx := detectKubeContext()
	if ctx != "my-cluster" {
		t.Errorf("expected my-cluster, got %q", ctx)
	}
}
