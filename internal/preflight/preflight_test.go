package preflight

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/exalm-ai/exalm/internal/config"
)

// setHome points os.UserHomeDir at a temp dir on every OS.
func setHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
}

// ─── Provider ─────────────────────────────────────────────────────────────────

func TestProvider_Known(t *testing.T) {
	for _, p := range []string{"claude", "anthropic", "openai", "openrouter", "ollama", "mock"} {
		t.Run(p, func(t *testing.T) {
			r := Provider(config.Config{LLMProvider: p})
			if !r.OK {
				t.Errorf("Provider(%q).OK = false, want true (msg=%q)", p, r.Message)
			}
			if !r.Critical {
				t.Errorf("Provider(%q).Critical = false, want true", p)
			}
		})
	}
}

func TestProvider_Empty(t *testing.T) {
	r := Provider(config.Config{LLMProvider: ""})
	if r.OK {
		t.Error("Provider(\"\").OK = true, want false")
	}
	if !r.Critical {
		t.Error("empty provider must be critical")
	}
	if r.Hint == "" {
		t.Error("empty provider should carry a hint")
	}
}

func TestProvider_Unknown(t *testing.T) {
	r := Provider(config.Config{LLMProvider: "gpt5-turbo-ultra"})
	if r.OK {
		t.Error("unknown provider should not be OK")
	}
	if !strings.Contains(r.Message, "unknown provider") {
		t.Errorf("message = %q, want it to mention unknown provider", r.Message)
	}
}

// ─── APIKey ───────────────────────────────────────────────────────────────────

func TestAPIKey_Matrix(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.Config
		wantOK  bool
		wantEnv string // substring that must appear in Message (env var name)
	}{
		{"claude present", config.Config{LLMProvider: "claude", AnthropicAPIKey: "sk-ant-x"}, true, "ANTHROPIC_API_KEY"},
		{"claude absent", config.Config{LLMProvider: "claude"}, false, "ANTHROPIC_API_KEY"},
		{"openai present", config.Config{LLMProvider: "openai", OpenAIAPIKey: "sk-x"}, true, "OPENAI_API_KEY"},
		{"openai absent", config.Config{LLMProvider: "openai"}, false, "OPENAI_API_KEY"},
		{"openrouter present", config.Config{LLMProvider: "openrouter", OpenRouterAPIKey: "sk-or-x"}, true, "OPENROUTER_API_KEY"},
		{"openrouter absent", config.Config{LLMProvider: "openrouter"}, false, "OPENROUTER_API_KEY"},
		{"ollama needs no key", config.Config{LLMProvider: "ollama"}, true, "Ollama"},
		{"mock needs no key", config.Config{LLMProvider: "mock"}, true, "mock"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := APIKey(tc.cfg)
			if r.OK != tc.wantOK {
				t.Errorf("APIKey(%+v).OK = %v, want %v (msg=%q)", tc.cfg, r.OK, tc.wantOK, r.Message)
			}
			if !strings.Contains(r.Message, tc.wantEnv) {
				t.Errorf("APIKey message = %q, want substring %q", r.Message, tc.wantEnv)
			}
			if !tc.wantOK && r.Hint == "" {
				t.Error("a failing API-key check should carry a hint")
			}
		})
	}
}

// ─── Kubeconfig ───────────────────────────────────────────────────────────────

func TestKubeconfig_Missing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("KUBECONFIG", filepath.Join(tmp, "nonexistent"))
	setHome(t, tmp) // so the ~/.kube/config fallback also misses
	r := Kubeconfig()
	if r.OK {
		t.Errorf("Kubeconfig().OK = true for missing config, want false")
	}
	if r.Critical {
		t.Error("Kubernetes check must be non-critical")
	}
}

func TestKubeconfig_Present(t *testing.T) {
	tmp := t.TempDir()
	kc := filepath.Join(tmp, "config")
	content := "apiVersion: v1\ncurrent-context: my-cluster\nclusters: []\n"
	if err := os.WriteFile(kc, []byte(content), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	t.Setenv("KUBECONFIG", kc)
	r := Kubeconfig()
	if !r.OK {
		t.Errorf("Kubeconfig().OK = false, want true (msg=%q)", r.Message)
	}
	if !strings.Contains(r.Message, "my-cluster") {
		t.Errorf("message = %q, want it to name the context", r.Message)
	}
}

// ─── DataDir ──────────────────────────────────────────────────────────────────

func TestDataDir_Creates(t *testing.T) {
	tmp := t.TempDir()
	setHome(t, tmp)
	target := filepath.Join(tmp, ".exalm")

	r := DataDir()
	if !r.OK {
		t.Fatalf("DataDir().OK = false: %q", r.Message)
	}
	if !r.Critical {
		t.Error("Data directory must be critical")
	}
	if _, err := os.Stat(target); os.IsNotExist(err) {
		t.Error("DataDir did not create ~/.exalm")
	}
}

func TestDataDir_AlreadyExists(t *testing.T) {
	tmp := t.TempDir()
	setHome(t, tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".exalm"), 0o700); err != nil {
		t.Fatalf("setup: %v", err)
	}
	r := DataDir()
	if !r.OK {
		t.Fatalf("DataDir().OK = false on existing dir: %q", r.Message)
	}
}

// ─── DashboardToken ───────────────────────────────────────────────────────────

func TestDashboardToken_Set(t *testing.T) {
	t.Setenv("EXALM_TOKEN", "secret")
	r := DashboardToken()
	if !r.OK {
		t.Error("DashboardToken().OK = false when EXALM_TOKEN is set")
	}
	if r.Critical {
		t.Error("Dashboard token must be non-critical")
	}
}

func TestDashboardToken_Unset(t *testing.T) {
	t.Setenv("EXALM_TOKEN", "")
	r := DashboardToken()
	if r.OK {
		t.Error("DashboardToken().OK = true when EXALM_TOKEN is unset")
	}
	if r.Hint == "" {
		t.Error("unset token should carry a hint")
	}
}

// ─── RunAll / aggregation ─────────────────────────────────────────────────────

func TestRunAll_HealthyMock(t *testing.T) {
	tmp := t.TempDir()
	setHome(t, tmp)
	t.Setenv("EXALM_TOKEN", "tok")
	results := RunAll(config.Config{LLMProvider: "mock"})
	if len(results) != 5 {
		t.Fatalf("RunAll returned %d results, want 5", len(results))
	}
	if !AllCriticalOK(results) {
		t.Error("AllCriticalOK = false for a healthy mock environment")
	}
}

func TestAllCriticalOK_FailsOnCritical(t *testing.T) {
	results := []Result{
		{Name: "ok-noncrit", OK: true, Critical: false},
		{Name: "fail-crit", OK: false, Critical: true},
	}
	if AllCriticalOK(results) {
		t.Error("AllCriticalOK = true despite a failed critical check")
	}
	if got := CountOK(results); got != 1 {
		t.Errorf("CountOK = %d, want 1", got)
	}
}
