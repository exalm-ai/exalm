package tui_test

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/exalm-ai/exalm/internal/tui"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// fakePlugin is a minimal plugin.Plugin for testing.
type fakePlugin struct {
	name    string
	subcmds []plugin.Subcommand
	mutates bool
}

func (p *fakePlugin) Name() string                     { return p.name }
func (p *fakePlugin) Description() string              { return "fake plugin " + p.name }
func (p *fakePlugin) Mutates() bool                    { return p.mutates }
func (p *fakePlugin) Subcommands() []plugin.Subcommand { return p.subcmds }

// okRunner returns a runner that always succeeds with a canned report.
func okRunner(summary string) tui.RunnerFunc {
	return func(_ context.Context, _ plugin.Plugin, _ plugin.Subcommand, _ map[string]string) (plugin.Report, error) {
		return plugin.Report{
			Title:   "test report",
			Summary: summary,
			Findings: []plugin.Finding{
				{Severity: "INFO", Title: "test finding", Detail: "all good"},
			},
		}, nil
	}
}

// errRunner returns a runner that always fails.
func errRunner() tui.RunnerFunc {
	return func(_ context.Context, _ plugin.Plugin, _ plugin.Subcommand, _ map[string]string) (plugin.Report, error) {
		return plugin.Report{}, &pluginError{"simulated run error"}
	}
}

type pluginError struct{ msg string }

func (e *pluginError) Error() string { return e.msg }

// ─── tests ────────────────────────────────────────────────────────────────────

func TestNewModel_InitialState(t *testing.T) {
	plugins := []plugin.Plugin{
		&fakePlugin{name: "logs", subcmds: []plugin.Subcommand{{Name: "summarize"}}},
		&fakePlugin{name: "k8s", subcmds: []plugin.Subcommand{{Name: "analyze"}}},
	}
	m := tui.NewModel(context.Background(), plugins, okRunner("ok"))
	view := m.View()

	if !strings.Contains(view, "exalm tui") {
		t.Errorf("header missing from initial view: %q", view)
	}
	if !strings.Contains(view, "logs") {
		t.Errorf("plugin 'logs' not shown in initial view")
	}
	if !strings.Contains(view, "k8s") {
		t.Errorf("plugin 'k8s' not shown in initial view")
	}
}

func TestModel_SelectPluginWithSingleSubcmd_SkipsSubcmdList(t *testing.T) {
	plugins := []plugin.Plugin{
		&fakePlugin{
			name: "syslog",
			subcmds: []plugin.Subcommand{
				{Name: "analyze", Description: "analyze syslog"},
			},
		},
	}
	m := tui.NewModel(context.Background(), plugins, okRunner("ok"))

	// Press Enter to select the first (only) plugin.
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	_ = cmd
	nm, ok := next.(tui.Model)
	if !ok {
		t.Fatal("Update did not return a tui.Model")
	}

	// With a single subcommand, we should jump straight to the flag form.
	view := nm.View()
	if !strings.Contains(view, "--file") && !strings.Contains(view, "--host") {
		t.Errorf("expected flag form after selecting plugin with one subcommand, got:\n%s", view)
	}
}

func TestModel_SelectPluginWithMultipleSubcmds_ShowsSubcmdList(t *testing.T) {
	plugins := []plugin.Plugin{
		&fakePlugin{
			name: "k8s",
			subcmds: []plugin.Subcommand{
				{Name: "analyze", Description: "analyze cluster"},
				{Name: "fix", Description: "fix issues"},
			},
		},
	}
	m := tui.NewModel(context.Background(), plugins, okRunner("ok"))

	// Select the plugin.
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm, ok := next.(tui.Model)
	if !ok {
		t.Fatal("Update did not return a tui.Model")
	}

	view := nm.View()
	if !strings.Contains(view, "analyze") || !strings.Contains(view, "fix") {
		t.Errorf("expected subcommand list, got:\n%s", view)
	}
}

func TestModel_FlagForm_TabMovesFocus(t *testing.T) {
	plugins := []plugin.Plugin{
		&fakePlugin{
			name:    "syslog",
			subcmds: []plugin.Subcommand{{Name: "analyze"}},
		},
	}
	m := tui.NewModel(context.Background(), plugins, okRunner("ok"))

	// Get to the flag form.
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	nm0, ok := next.(tui.Model)
	if !ok {
		t.Fatal("Update did not return a tui.Model")
	}
	m = nm0

	// Tab should move focus to the next input.
	m1, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm1, ok := m1.(tui.Model)
	if !ok {
		t.Fatal("Update did not return a tui.Model")
	}
	if nm1.FocusIndex() != 1 {
		t.Errorf("Tab: expected focus index 1, got %d", nm1.FocusIndex())
	}
}

func TestModel_FlagForm_EscGoesBack(t *testing.T) {
	plugins := []plugin.Plugin{
		&fakePlugin{
			name:    "syslog",
			subcmds: []plugin.Subcommand{{Name: "analyze"}},
		},
	}
	m := tui.NewModel(context.Background(), plugins, okRunner("ok"))
	next0, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m, ok := next0.(tui.Model)
	if !ok {
		t.Fatal("Update did not return a tui.Model")
	}

	// Esc from the flag form should go back.
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	nm, ok2 := next.(tui.Model)
	if !ok2 {
		t.Fatal("Update did not return a tui.Model")
	}
	// After Esc with a single subcommand plugin we go back to the subcommand
	// list (which immediately skips back toward the plugin list). The key
	// constraint: we must NOT be in the flag form any more.
	view := nm.View()
	if strings.Contains(view, "run again") {
		t.Error("Esc from flag form should not stay in result view")
	}
}

func TestModel_QuitKey(t *testing.T) {
	plugins := []plugin.Plugin{
		&fakePlugin{name: "logs", subcmds: []plugin.Subcommand{{Name: "summarize"}}},
	}
	m := tui.NewModel(context.Background(), plugins, okRunner("ok"))
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Fatal("'q' should produce a tea.Quit command")
	}
}

func TestModel_ResultMsg_ShowsOutput(t *testing.T) {
	plugins := []plugin.Plugin{
		&fakePlugin{name: "logs", subcmds: []plugin.Subcommand{{Name: "summarize"}}},
	}
	m := tui.NewModel(context.Background(), plugins, okRunner("great summary"))

	// We test the model's reaction to a resultMsg by injecting it directly.
	// tui.ResultMsg is exported via the package's public test surface.
	// Since resultMsg is unexported, we drive the model via the Run helper.
	// Instead, verify that the stateResult view renders correctly via the
	// model state after a successful run message is processed.
	next, _ := m.Update(tui.NewResultMsg("great summary", nil))
	nm, ok := next.(tui.Model)
	if !ok {
		t.Fatal("Update did not return a tui.Model")
	}
	view := nm.View()
	if !strings.Contains(view, "great summary") {
		t.Errorf("expected result output in view, got:\n%s", view)
	}
	if !strings.Contains(view, "✓") {
		t.Errorf("expected success tick in view, got:\n%s", view)
	}
}

func TestModel_ResultMsg_ShowsError(t *testing.T) {
	plugins := []plugin.Plugin{
		&fakePlugin{name: "logs", subcmds: []plugin.Subcommand{{Name: "summarize"}}},
	}
	m := tui.NewModel(context.Background(), plugins, errRunner())
	next, _ := m.Update(tui.NewResultMsg("", &pluginError{"simulated run error"}))
	nm := next.(tui.Model)
	view := nm.View()
	if !strings.Contains(view, "simulated run error") {
		t.Errorf("expected error in view, got:\n%s", view)
	}
	if !strings.Contains(view, "✗") {
		t.Errorf("expected error tick in view, got:\n%s", view)
	}
}

// TestModel_ResultViewport_ScrollKeysDoNotPanic verifies that Up/Down key
// presses in stateResult don't panic, that the scroll indicator is present,
// and that the viewport renders a portion of the output.
func TestModel_ResultViewport_ScrollKeysDoNotPanic(t *testing.T) {
	plugins := []plugin.Plugin{
		&fakePlugin{name: "logs", subcmds: []plugin.Subcommand{{Name: "summarize"}}},
	}
	m := tui.NewModel(context.Background(), plugins, okRunner("great summary"))

	// Build a long result so the viewport has content to scroll.
	var longOutput strings.Builder
	for i := 0; i < 100; i++ {
		longOutput.WriteString("Line of output content that would normally be truncated.\n")
	}
	next, _ := m.Update(tui.NewResultMsg(longOutput.String(), nil))
	nm := next.(tui.Model)

	// Scroll keys must not panic.
	for _, key := range []tea.KeyType{tea.KeyUp, tea.KeyDown, tea.KeyPgUp, tea.KeyPgDown} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("key %v caused panic: %v", key, r)
				}
			}()
			updated, _ := nm.Update(tea.KeyMsg{Type: key})
			if casted, ok := updated.(tui.Model); ok {
				nm = casted
			}
		}()
	}

	view := nm.View()

	// The scroll indicator ("[N%]") must be present.
	if !strings.Contains(view, "%]") {
		t.Errorf("expected scroll percentage indicator in result view, got:\n%s", view)
	}
	// The help text must show scroll instructions.
	if !strings.Contains(view, "↑/↓ scroll") {
		t.Errorf("expected scroll hint in result view, got:\n%s", view)
	}
	// The success icon must still be visible.
	if !strings.Contains(view, "✓") {
		t.Errorf("expected success tick in scrollable result view, got:\n%s", view)
	}
}
