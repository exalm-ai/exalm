// Package cliui provides small, dependency-free terminal presentation helpers
// for the Exalm CLI: TTY detection, a stderr progress spinner, ANSI colour
// helpers, and a FriendlyError mapper that turns common failure signatures into
// actionable next steps.
//
// Everything degrades cleanly. Colour and the spinner become no-ops when the
// target stream is not a terminal or when the user opts out via NO_COLOR /
// EXALM_NO_COLOR (https://no-color.org), so piped and CI output stays clean.
// Nothing here imports beyond the standard library — the CLI layer must stay
// lightweight and not pull lipgloss in for plain text.
package cliui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ─── TTY detection ────────────────────────────────────────────────────────────

// IsTerminal reports whether f refers to a character device (a real terminal),
// as opposed to a pipe or a regular file. It uses only the standard library: a
// Stat() on the descriptor followed by a check of the os.ModeCharDevice bit.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// ─── Colour ───────────────────────────────────────────────────────────────────

// ANSI escape codes. Every coloured string is built via colorize(), which
// respects NO_COLOR / EXALM_NO_COLOR and the stdout TTY check.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// colorDisabledByEnv reports whether the user has opted out of colour via the
// well-known NO_COLOR convention or Exalm's own EXALM_NO_COLOR override.
func colorDisabledByEnv() bool {
	return os.Getenv("NO_COLOR") != "" || os.Getenv("EXALM_NO_COLOR") != ""
}

// colorsEnabled mirrors internal/output: colour is on only when the user has
// not opted out and stdout looks like a real terminal.
func colorsEnabled() bool {
	if colorDisabledByEnv() {
		return false
	}
	if fi, err := os.Stdout.Stat(); err == nil {
		return fi.Mode()&os.ModeCharDevice != 0
	}
	return false
}

func colorize(code, text string) string {
	if !colorsEnabled() {
		return text
	}
	return code + text + ansiReset
}

// Success returns s in green (e.g. for a passing check). Plain when colour is
// disabled.
func Success(s string) string { return colorize(ansiGreen, s) }

// Warn returns s in yellow (e.g. for a non-fatal warning). Plain when colour is
// disabled.
func Warn(s string) string { return colorize(ansiYellow, s) }

// Errorf returns a red message built from format + args (e.g. for a failing
// check). Plain when colour is disabled.
func Errorf(format string, a ...any) string {
	return colorize(ansiRed, fmt.Sprintf(format, a...))
}

// Hint returns s in cyan, intended for next-step guidance. Plain when colour is
// disabled.
func Hint(s string) string { return colorize(ansiCyan, s) }

// Dim returns s dimmed, intended for secondary detail. Plain when colour is
// disabled.
func Dim(s string) string { return colorize(ansiDim, s) }

// Bold returns s in bold, intended for headers. Plain when colour is disabled.
func Bold(s string) string { return colorize(ansiBold, s) }

// ─── Spinner ──────────────────────────────────────────────────────────────────

// spinnerFrames is the Braille animation used by the stderr spinner.
var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// spinnerInterval controls the animation cadence.
const spinnerInterval = 90 * time.Millisecond

// Spinner is a minimal progress spinner driven by a background goroutine. It is
// a no-op when its writer is not a terminal or when colour is disabled, so
// piped/CI output never accumulates carriage-return spam.
//
// Typical use:
//
//	sp := cliui.NewSpinner(os.Stderr)
//	sp.Start("Analyzing with claude…")
//	defer sp.Stop()
type Spinner struct {
	w       io.Writer
	enabled bool

	mu     sync.Mutex
	active bool
	stopCh chan struct{}
	doneCh chan struct{}
}

// NewSpinner returns a Spinner that animates on w (typically os.Stderr). The
// spinner is enabled only when w is a terminal and colour is not disabled.
func NewSpinner(w io.Writer) *Spinner {
	return &Spinner{w: w, enabled: spinnerEnabled(w)}
}

// spinnerEnabled decides whether a spinner on w should animate.
func spinnerEnabled(w io.Writer) bool {
	if colorDisabledByEnv() {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return IsTerminal(f)
}

// Start begins animating with msg. A second call while already active is
// ignored. No-op when the spinner is disabled.
func (s *Spinner) Start(msg string) {
	if !s.enabled {
		return
	}
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return
	}
	s.active = true
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	stop, done := s.stopCh, s.doneCh
	s.mu.Unlock()

	go func() {
		defer close(done)
		t := time.NewTicker(spinnerInterval)
		defer t.Stop()
		i := 0
		// Paint the first frame immediately so feedback is instant.
		s.paint(msg, i)
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				i++
				s.paint(msg, i)
			}
		}
	}()
}

// paint writes a single spinner frame, overwriting the current line.
func (s *Spinner) paint(msg string, i int) {
	frame := string(spinnerFrames[i%len(spinnerFrames)])
	// enabled already implies colour is on, so apply ANSI directly.
	fmt.Fprintf(s.w, "\r%s%s%s %s ", ansiCyan, frame, ansiReset, msg) //nolint:errcheck // best-effort UI write to stderr
}

// Stop halts the animation and clears the spinner line. Safe to call even when
// Start was a no-op or never ran.
func (s *Spinner) Stop() {
	if !s.enabled {
		return
	}
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	s.active = false
	close(s.stopCh)
	done := s.doneCh
	s.mu.Unlock()

	<-done
	// Clear the whole line and return the cursor to column 0.
	fmt.Fprint(s.w, "\r\033[K") //nolint:errcheck // best-effort UI write to stderr
}

// ─── FriendlyError ────────────────────────────────────────────────────────────

// FriendlyError maps common failure signatures to actionable, multi-line
// guidance. Unrecognised errors fall back to "Error: <message>". The already
// helpful "no LLM provider" text (built in cmd/exalm) flows through unchanged.
//
// It intentionally matches on substrings rather than concrete error types so it
// stays decoupled from the provider/SSH/k8s packages and keeps working when an
// upstream wraps the error with extra context.
func FriendlyError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	low := strings.ToLower(msg)

	switch {
	// No provider configured. cmd/exalm already turns this into multi-line help
	// text; pass it through verbatim so we don't double-wrap or shorten it.
	case strings.Contains(low, "no llm provider"):
		return msg

	// Authentication failures (401 / invalid key) across providers.
	case strings.Contains(low, "401") ||
		strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid_api_key") ||
		strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "authentication failed"):
		return "Error: the LLM provider rejected your API key (HTTP 401).\n" +
			"  • Check the key is current and has not been revoked.\n" +
			"  • Claude:     export ANTHROPIC_API_KEY=sk-ant-...\n" +
			"  • OpenAI:     export OPENAI_API_KEY=sk-...\n" +
			"  • OpenRouter: export OPENROUTER_API_KEY=sk-or-...\n" +
			"  • Or run a local model with no key: --provider ollama\n" +
			"  • Details: " + msg

	// Ollama / local model not reachable. Match the "ollama:" error prefix that
	// the provider always wraps with (fmt.Errorf("ollama: …")) or a refused
	// connection on the default port — NOT the bare word "ollama", which also
	// appears in hint text like "switch to a local model with --provider ollama".
	// Checked before the generic kubeconfig/connection cases so this hint wins.
	case strings.Contains(low, "ollama:") ||
		(strings.Contains(low, "connection refused") && strings.Contains(low, "11434")):
		return "Error: cannot reach the local Ollama server (default http://localhost:11434).\n" +
			"  • Start it:     ollama serve\n" +
			"  • Pull a model: ollama pull llama3\n" +
			"  • Point Exalm elsewhere: export EXALM_OLLAMA_URL=http://host:11434\n" +
			"  • Details: " + msg

	// Missing / unreadable kubeconfig or no reachable cluster.
	case strings.Contains(low, "kubeconfig") ||
		strings.Contains(low, "no configuration has been provided") ||
		(strings.Contains(low, "kube") && strings.Contains(low, "could not find")):
		return "Error: could not reach a Kubernetes cluster.\n" +
			"  • Check the active context: kubectl config current-context\n" +
			"  • Point Exalm at a file:    --kubeconfig /path/to/config\n" +
			"  • Scope to a namespace:     -n <namespace>\n" +
			"  • Details: " + msg

	// SSH auth / host-key mismatch during remote log collection.
	case strings.Contains(low, "host key") ||
		strings.Contains(low, "host-key") ||
		strings.Contains(low, "knownhosts") ||
		strings.Contains(low, "ssh: handshake failed") ||
		strings.Contains(low, "unable to authenticate") ||
		(strings.Contains(low, "ssh") && strings.Contains(low, "permission denied")):
		return "Error: SSH connection failed.\n" +
			"  • Verify host and credentials: --host <h> --ssh-user <u> --ssh-key <path>\n" +
			"  • Host key changed? Remove the stale entry from ~/.exalm/known_hosts.\n" +
			"  • Details: " + msg

	default:
		return "Error: " + msg
	}
}
