package main

import (
	"runtime"
	"testing"
)

// setInitHome points os.UserHomeDir at a temp dir on every OS so runInit's
// data-directory check operates on disposable state.
func setInitHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
}

// runInit should succeed when a no-key provider (mock) is configured and the
// data directory is writable. Kubernetes/token are non-critical so their state
// does not affect the result.
func TestRunInit_HealthyMock(t *testing.T) {
	setInitHome(t, t.TempDir())
	t.Setenv("EXALM_LLM_PROVIDER", "mock")
	if err := runInit(); err != nil {
		t.Errorf("runInit() = %v, want nil for a healthy mock environment", err)
	}
}

// runInit should fail when a key-requiring provider has no key — that is a
// critical failure.
func TestRunInit_MissingCriticalKey(t *testing.T) {
	setInitHome(t, t.TempDir())
	t.Setenv("EXALM_LLM_PROVIDER", "claude")
	t.Setenv("ANTHROPIC_API_KEY", "")
	if err := runInit(); err == nil {
		t.Error("runInit() = nil, want error when ANTHROPIC_API_KEY is missing for claude")
	}
}

// runInit should succeed for a healthy claude environment (key present).
func TestRunInit_ClaudeWithKey(t *testing.T) {
	setInitHome(t, t.TempDir())
	t.Setenv("EXALM_LLM_PROVIDER", "claude")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-EXAMPLE-EXAMPLE")
	if err := runInit(); err != nil {
		t.Errorf("runInit() = %v, want nil when the API key is present", err)
	}
}
