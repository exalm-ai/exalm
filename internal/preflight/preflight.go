// Package preflight runs the environment readiness checks shared by
// `exalm init`, `exalm serve`, and the global `--dry-run` preview.
//
// Each check returns a Result describing what was inspected, whether it passed,
// whether failing it is fatal (Critical), and — when it fails — a one-line Hint
// the caller can print as the next step. Checks never mutate state except
// DataDir(), which creates ~/.exalm if absent (the same behaviour `init` always
// had). Nothing here calls an LLM or touches the network.
package preflight

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/exalm-ai/exalm/internal/config"
)

// Result is the outcome of a single readiness check.
type Result struct {
	// Name is the short label shown in the readiness summary (e.g. "LLM provider").
	Name string
	// OK reports whether the check passed.
	OK bool
	// Critical reports whether failing this check blocks core functionality.
	// init/serve treat a failed critical check as a hard error.
	Critical bool
	// Message is the human-readable status (shown next to the check name).
	Message string
	// Hint is an actionable next step, shown only when the check fails.
	Hint string
}

// RunAll runs every readiness check in display order and returns their results.
func RunAll(cfg config.Config) []Result {
	return []Result{
		Provider(cfg),
		APIKey(cfg),
		Kubeconfig(),
		DataDir(),
		DashboardToken(),
	}
}

// AllCriticalOK reports whether every critical check in results passed.
func AllCriticalOK(results []Result) bool {
	for _, r := range results {
		if r.Critical && !r.OK {
			return false
		}
	}
	return true
}

// CountOK returns how many of the given checks passed.
func CountOK(results []Result) int {
	n := 0
	for _, r := range results {
		if r.OK {
			n++
		}
	}
	return n
}

// Provider validates that a recognised LLM provider is selected. Critical: with
// no valid provider Exalm cannot call a model at all.
func Provider(cfg config.Config) Result {
	p := strings.ToLower(strings.TrimSpace(cfg.LLMProvider))
	switch p {
	case "claude", "anthropic", "openai", "openrouter", "ollama", "mock":
		return Result{Name: "LLM provider", OK: true, Critical: true, Message: p}
	case "":
		return Result{
			Name: "LLM provider", OK: false, Critical: true,
			Message: "no provider selected",
			Hint:    "set EXALM_LLM_PROVIDER=claude (or openai/openrouter/ollama), or pass --provider",
		}
	default:
		return Result{
			Name: "LLM provider", OK: false, Critical: true,
			Message: fmt.Sprintf("unknown provider %q", cfg.LLMProvider),
			Hint:    "valid providers: claude, openai, openrouter, ollama",
		}
	}
}

// APIKey checks that the credential the selected provider needs is present.
// Local providers (ollama) and the test mock need no key and always pass.
// Reads from cfg, which config.Load() has already populated from the environment.
func APIKey(cfg config.Config) Result {
	switch strings.ToLower(strings.TrimSpace(cfg.LLMProvider)) {
	case "claude", "anthropic":
		return keyResult("ANTHROPIC_API_KEY", cfg.AnthropicAPIKey)
	case "openai":
		return keyResult("OPENAI_API_KEY", cfg.OpenAIAPIKey)
	case "openrouter":
		return keyResult("OPENROUTER_API_KEY", cfg.OpenRouterAPIKey)
	case "ollama":
		return Result{Name: "API key", OK: true, Critical: true, Message: "not required for local Ollama"}
	case "mock":
		return Result{Name: "API key", OK: true, Critical: true, Message: "not required for the mock provider"}
	default:
		// Provider() already reports the unknown/empty provider as a critical
		// failure; keep this non-critical so we don't double-count it.
		return Result{
			Name: "API key", OK: false, Critical: false,
			Message: "no provider selected",
			Hint:    "choose a provider first (see above)",
		}
	}
}

// keyResult builds an API-key Result from the expected env var and its value.
func keyResult(envVar, value string) Result {
	if strings.TrimSpace(value) != "" {
		return Result{Name: "API key", OK: true, Critical: true, Message: envVar + " is set"}
	}
	return Result{
		Name: "API key", OK: false, Critical: true,
		Message: envVar + " is not set",
		Hint:    "export " + envVar + "=… or switch to a local model with --provider ollama",
	}
}

// Kubeconfig reports whether an active kube context is reachable. Non-critical:
// the log plugins work fine without a cluster.
func Kubeconfig() Result {
	if ctx := detectKubeContext(); ctx != "" {
		return Result{Name: "Kubernetes", OK: true, Message: "active context: " + ctx}
	}
	return Result{
		Name: "Kubernetes", OK: false, Critical: false,
		Message: "no KUBECONFIG or ~/.kube/config found",
		Hint:    "the k8s plugin needs a cluster; log plugins work without one",
	}
}

// DataDir ensures ~/.exalm exists with safe permissions, creating it if absent.
// Critical: Exalm persists incidents and deployments there.
func DataDir() Result {
	path, ok, msg := ensureDataDir()
	r := Result{Name: "Data directory", OK: ok, Critical: true, Message: path + " — " + msg}
	if !ok {
		r.Hint = "Exalm stores incidents and deployments here; resolve the issue above and re-run"
	}
	return r
}

// DashboardToken reports whether EXALM_TOKEN is set for `exalm serve` auth.
// Non-critical: solo localhost use is fine without a token.
func DashboardToken() Result {
	if os.Getenv("EXALM_TOKEN") != "" {
		return Result{Name: "Dashboard token", OK: true, Message: "EXALM_TOKEN is set — serve will require auth"}
	}
	return Result{
		Name: "Dashboard token", OK: false, Critical: false,
		Message: "EXALM_TOKEN is not set — serve will run without auth",
		Hint:    "export EXALM_TOKEN=… before exposing the dashboard beyond localhost",
	}
}

// detectKubeContext reads the active kube context from KUBECONFIG or
// ~/.kube/config. Returns an empty string if none is found.
func detectKubeContext() string {
	kc := os.Getenv("KUBECONFIG")
	if kc == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		kc = filepath.Join(home, ".kube", "config")
	}

	// If the file doesn't exist, no context is available.
	if _, err := os.Stat(kc); err != nil { //nolint:gosec // G703: kc derives from KUBECONFIG env or ~/.kube/config, not arbitrary input
		return ""
	}

	// Read the file just enough to find the current-context line.
	data, err := os.ReadFile(kc) //nolint:gosec // G304: kc derives from KUBECONFIG env or ~/.kube/config, not arbitrary input
	if err != nil {
		return kc + " (unreadable)"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "current-context:") {
			ctx := strings.TrimSpace(strings.TrimPrefix(line, "current-context:"))
			if ctx == "" || ctx == "null" {
				return ""
			}
			return ctx
		}
	}
	return "" // valid kubeconfig but no current-context set
}

// ensureDataDir creates ~/.exalm if it does not exist. Returns the path, a
// success flag, and a human-readable message.
func ensureDataDir() (path string, ok bool, msg string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "~/.exalm", false, fmt.Sprintf("cannot determine home dir: %v", err)
	}
	dir := filepath.Join(home, ".exalm")

	info, statErr := os.Stat(dir)
	if statErr == nil {
		if !info.IsDir() {
			return dir, false, "exists but is not a directory — remove it and re-run"
		}
		// Verify permission bits (skip on Windows where they're not enforced).
		if runtime.GOOS != "windows" {
			mode := info.Mode().Perm()
			if mode&0o077 != 0 {
				return dir, false, fmt.Sprintf("permissions too open (%04o) — run: chmod 700 %s", mode, dir)
			}
		}
		return dir, true, "exists"
	}

	if !os.IsNotExist(statErr) {
		return dir, false, fmt.Sprintf("cannot stat: %v", statErr)
	}

	// Create it.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return dir, false, fmt.Sprintf("cannot create: %v", err)
	}
	return dir, true, "created"
}
