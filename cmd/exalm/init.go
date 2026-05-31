package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/exalm-ai/exalm/internal/config"
)

// newInitCmd returns the `exalm init` cobra command.
//
// init performs a one-time setup check:
//  1. Detects the configured (or default) LLM provider and validates its API key.
//  2. Checks for a reachable kubeconfig context.
//  3. Creates ~/.exalm/ with correct permissions if it does not exist.
//  4. Prints a ready-summary so the user knows what is working.
//
// It is intentionally non-mutating: it never writes config files or modifies
// kubeconfig. It only reads the environment and checks that the expected
// prerequisites are in place.
func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Check Exalm prerequisites and print a readiness summary",
		Long: `init validates that your environment is correctly configured for Exalm.

It checks:
  • LLM provider and API key presence
  • KUBECONFIG / active kube context
  • ~/.exalm/ data directory (creates it if missing)
  • Dashboard auth token (warns if unset)

No changes are made to your system beyond creating ~/.exalm/ if it is absent.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit()
		},
	}
}

// check holds the result of a single readiness check.
type check struct {
	name    string
	ok      bool
	message string
}

func runInit() error {
	var checks []check
	allOK := true

	// ── 1. LLM provider ─────────────────────────────────────────────────────
	cfg := config.Load()
	provider := cfg.LLMProvider
	if provider == "" {
		provider = "claude" // default
	}
	apiKeyEnv, keyPresent := llmKeyCheck(provider)
	if keyPresent {
		checks = append(checks, check{
			name:    "LLM provider",
			ok:      true,
			message: fmt.Sprintf("%s (%s is set)", provider, apiKeyEnv),
		})
	} else {
		allOK = false
		checks = append(checks, check{
			name:    "LLM provider",
			ok:      false,
			message: fmt.Sprintf("%s — %s is not set; set it or use --provider=ollama for a local model", provider, apiKeyEnv),
		})
	}

	// ── 2. Kubernetes context ────────────────────────────────────────────────
	kubeCtx := detectKubeContext()
	if kubeCtx != "" {
		checks = append(checks, check{
			name:    "Kubernetes",
			ok:      true,
			message: fmt.Sprintf("active context: %s", kubeCtx),
		})
	} else {
		checks = append(checks, check{
			name:    "Kubernetes",
			ok:      false,
			message: "no KUBECONFIG or ~/.kube/config found — k8s plugin will not work",
		})
		// Not fatal: user might only use log plugins.
	}

	// ── 3. Data directory ────────────────────────────────────────────────────
	dataDir, dirOK, dirMsg := ensureDataDir()
	checks = append(checks, check{
		name:    "Data directory",
		ok:      dirOK,
		message: fmt.Sprintf("%s — %s", dataDir, dirMsg),
	})
	if !dirOK {
		allOK = false
	}

	// ── 4. Dashboard auth token ──────────────────────────────────────────────
	if os.Getenv("EXALM_TOKEN") != "" {
		checks = append(checks, check{
			name:    "Dashboard token",
			ok:      true,
			message: "EXALM_TOKEN is set — exalm serve will require authentication",
		})
	} else {
		checks = append(checks, check{
			name:    "Dashboard token",
			ok:      false,
			message: "EXALM_TOKEN is not set — run 'exalm serve' will warn about missing auth",
		})
		// Not fatal: solo developer use case is fine without a token.
	}

	// ── Print summary ────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("  Exalm readiness check")
	fmt.Println("  ─────────────────────")
	for _, c := range checks {
		icon := "✓"
		if !c.ok {
			icon = "✗"
		}
		fmt.Printf("  %s  %-20s %s\n", icon, c.name, c.message)
	}
	fmt.Println()

	if allOK {
		fmt.Println("  ✓ All critical checks passed. Run 'exalm k8s analyze' to start.")
		fmt.Println()
		return nil
	}

	failedCritical := false
	for _, c := range checks {
		if !c.ok && (c.name == "LLM provider" || c.name == "Data directory") {
			failedCritical = true
			break
		}
	}
	if failedCritical {
		return errors.New("one or more critical checks failed — see output above")
	}

	fmt.Println("  Some optional checks failed (see above). Core functionality will work.")
	fmt.Println()
	return nil
}

// llmKeyCheck returns the expected env var name and whether it is set for
// the given provider.
func llmKeyCheck(provider string) (envVar string, present bool) {
	switch strings.ToLower(provider) {
	case "claude":
		v := "ANTHROPIC_API_KEY"
		return v, os.Getenv(v) != ""
	case "openai":
		v := "OPENAI_API_KEY"
		return v, os.Getenv(v) != ""
	case "openrouter":
		v := "OPENROUTER_API_KEY"
		return v, os.Getenv(v) != ""
	case "ollama":
		// Ollama runs locally — no key required.
		return "EXALM_OLLAMA_URL", true // always OK — Ollama needs no API key
	default:
		return "EXALM_LLM_PROVIDER", false
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
	if _, err := os.Stat(kc); err != nil { //nolint:gosec // G703: kc is derived from KUBECONFIG env or ~/.kube/config, not arbitrary user input
		return ""
	}

	// Read the file just enough to find the current-context line.
	data, err := os.ReadFile(kc) //nolint:gosec // G304: kc is derived from KUBECONFIG env or ~/.kube/config, not arbitrary user input
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

// ensureDataDir creates ~/.exalm if it does not exist.
// Returns the path, a success flag, and a human-readable message.
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
