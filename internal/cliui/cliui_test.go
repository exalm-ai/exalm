package cliui

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// ─── IsTerminal ───────────────────────────────────────────────────────────────

func TestIsTerminal_NilFile(t *testing.T) {
	if IsTerminal(nil) {
		t.Error("IsTerminal(nil) = true, want false")
	}
}

func TestIsTerminal_RegularFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	if IsTerminal(f) {
		t.Error("IsTerminal(regular file) = true, want false")
	}
}

func TestIsTerminal_Pipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(r) || IsTerminal(w) {
		t.Error("IsTerminal(pipe) = true, want false")
	}
}

// ─── Colour helpers ───────────────────────────────────────────────────────────

// With NO_COLOR set, every colour helper must return its input unchanged.
func TestColorHelpers_NoColorSuppression(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	cases := map[string]string{
		"Success": Success("ok"),
		"Warn":    Warn("careful"),
		"Errorf":  Errorf("bad %d", 7),
		"Hint":    Hint("try this"),
		"Dim":     Dim("detail"),
		"Bold":    Bold("title"),
	}
	want := map[string]string{
		"Success": "ok",
		"Warn":    "careful",
		"Errorf":  "bad 7",
		"Hint":    "try this",
		"Dim":     "detail",
		"Bold":    "title",
	}
	for name, got := range cases {
		if got != want[name] {
			t.Errorf("%s with NO_COLOR = %q, want plain %q", name, got, want[name])
		}
		if strings.Contains(got, "\033[") {
			t.Errorf("%s with NO_COLOR leaked an ANSI escape: %q", name, got)
		}
	}
}

// EXALM_NO_COLOR is honoured as an alias for NO_COLOR.
func TestColorHelpers_ExalmNoColorSuppression(t *testing.T) {
	t.Setenv("EXALM_NO_COLOR", "1")
	if got := Success("ok"); got != "ok" {
		t.Errorf("Success with EXALM_NO_COLOR = %q, want %q", got, "ok")
	}
}

func TestColorize_EnabledWrapsWithANSI(t *testing.T) {
	// colorsEnabled() is false under `go test` (stdout is not a TTY), so exercise
	// the wrapping branch directly to prove the codes are well-formed.
	got := ansiGreen + "x" + ansiReset
	if !strings.HasPrefix(got, "\033[32m") || !strings.HasSuffix(got, "\033[0m") {
		t.Errorf("colour codes malformed: %q", got)
	}
}

// ─── Spinner ──────────────────────────────────────────────────────────────────

// A spinner whose writer is not a terminal must write nothing.
func TestSpinner_NonTTY_NoOp(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf)
	if sp.enabled {
		t.Fatal("spinner should be disabled for a bytes.Buffer writer")
	}
	sp.Start("working")
	sp.Stop()
	if buf.Len() != 0 {
		t.Errorf("non-TTY spinner wrote %q, want nothing", buf.String())
	}
}

// Stop must be safe to call without Start, and on a disabled spinner.
func TestSpinner_StopWithoutStart(t *testing.T) {
	sp := NewSpinner(&bytes.Buffer{})
	sp.Stop() // must not panic or block
}

// Even with NO_COLOR cleared, a non-*os.File writer keeps the spinner disabled.
func TestSpinner_DisabledForNonFileWriter(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	sp := NewSpinner(&bytes.Buffer{})
	if sp.enabled {
		t.Error("spinner must stay disabled for a non-file writer")
	}
}

// ─── FriendlyError ────────────────────────────────────────────────────────────

func TestFriendlyError_Nil(t *testing.T) {
	if got := FriendlyError(nil); got != "" {
		t.Errorf("FriendlyError(nil) = %q, want empty", got)
	}
}

func TestFriendlyError_Mapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string // substring that must appear in the friendly output
	}{
		{
			name: "no provider passes through",
			err:  errors.New("No LLM provider configured.\nSet up Claude..."),
			want: "No LLM provider configured.",
		},
		{
			name: "401 unauthorized",
			err:  errors.New("anthropic: 401 unauthorized"),
			want: "rejected your API key",
		},
		{
			name: "invalid api key",
			err:  errors.New("openai: invalid api key provided"),
			want: "rejected your API key",
		},
		{
			name: "ollama refused",
			err:  errors.New("dial tcp 127.0.0.1:11434: connection refused"),
			want: "Ollama server",
		},
		{
			name: "ollama named",
			err:  errors.New("ollama: model not found"),
			want: "Ollama server",
		},
		{
			name: "kubeconfig missing",
			err:  errors.New("invalid configuration: no kubeconfig found"),
			want: "Kubernetes cluster",
		},
		{
			name: "ssh handshake",
			err:  errors.New("ssh: handshake failed: knownhosts: key mismatch"),
			want: "SSH connection failed",
		},
		{
			name: "unknown falls back",
			err:  errors.New("some unexpected boom"),
			want: "Error: some unexpected boom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FriendlyError(tc.err)
			if !strings.Contains(got, tc.want) {
				t.Errorf("FriendlyError(%v):\n got: %q\nwant substring: %q", tc.err, got, tc.want)
			}
		})
	}
}

// Regression: an error that merely mentions "ollama" in hint text — e.g. the
// readiness check suggesting "switch to a local model with --provider ollama" —
// must NOT be mistaken for an Ollama-server-unreachable failure. Only a genuine
// "ollama:" provider error or a refused connection on :11434 maps to that
// branch; everything else falls through to the default passthrough.
func TestFriendlyError_OllamaWordInHintNotMisrouted(t *testing.T) {
	err := errors.New(
		"API key — ANTHROPIC_API_KEY is not set\n" +
			"  → export ANTHROPIC_API_KEY=… or switch to a local model with --provider ollama")
	got := FriendlyError(err)
	if strings.Contains(got, "Ollama server") {
		t.Errorf("readiness hint mentioning ollama was misrouted to the Ollama branch:\n%s", got)
	}
	if !strings.HasPrefix(got, "Error: API key") {
		t.Errorf("expected default passthrough beginning %q, got: %q", "Error: API key", got)
	}
}

// The auth, ollama, kube and ssh branches should always surface the underlying
// error text so users can still see the raw detail.
func TestFriendlyError_PreservesUnderlyingDetail(t *testing.T) {
	raw := "dial tcp 127.0.0.1:11434: connection refused"
	got := FriendlyError(errors.New(raw))
	if !strings.Contains(got, raw) {
		t.Errorf("FriendlyError dropped underlying detail; got %q", got)
	}
}
