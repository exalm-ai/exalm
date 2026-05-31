package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ─── state machine ─────────────────────────────────────────────────────────

type appState int

const (
	statePluginList appState = iota // choose a plugin
	stateSubcmdList                 // choose a subcommand
	stateFlagForm                   // fill in flags
	stateRunning                    // plugin executing
	stateResult                     // show result / error
	stateQuit                       // bye
)

// ─── list item helpers ──────────────────────────────────────────────────────

// pluginItem adapts plugin.Plugin to bubbles/list.Item.
type pluginItem struct{ p plugin.Plugin }

func (i pluginItem) FilterValue() string { return i.p.Name() }
func (i pluginItem) Title() string       { return i.p.Name() }
func (i pluginItem) Description() string { return i.p.Description() }

// subcmdItem adapts plugin.Subcommand to bubbles/list.Item.
type subcmdItem struct{ sc plugin.Subcommand }

func (i subcmdItem) FilterValue() string { return i.sc.Name }
func (i subcmdItem) Title() string       { return i.sc.Name }
func (i subcmdItem) Description() string { return i.sc.Description }

// ─── flag form helpers ──────────────────────────────────────────────────────

// flagDef describes one user-visible flag input.
type flagDef struct {
	name        string // flag key sent to plugin
	label       string // display label
	placeholder string // hint text
}

// concurrentFlagDefs are shown for plugins that accept --file / SSH collection.
var concurrentFlagDefs = []flagDef{
	{"file", "--file", "path or glob (optional if --host set)"},
	{"host", "--host", "user@host or IP (SSH remote collection)"},
	{"ssh-user", "--ssh-user", "SSH username (default: OS user)"},
	{"ssh-key", "--ssh-key", "~/.ssh/id_rsa or path to PEM key"},
	{"log-lines", "--log-lines", "lines to fetch (default: 5000)"},
}

var k8sFlagDefs = []flagDef{
	{"namespace", "--namespace", "Kubernetes namespace (default: all)"},
	{"kubeconfig", "--kubeconfig", "path to kubeconfig file"},
}

var simpleFlagDefs = []flagDef{
	{"file", "--file", "path to input file"},
}

// flagDefsFor returns the flag inputs appropriate for the given plugin name.
func flagDefsFor(pluginName string) []flagDef {
	switch pluginName {
	case "eventlog", "iis", "syslog", "httplog":
		return concurrentFlagDefs
	case "k8s":
		return k8sFlagDefs
	default:
		return simpleFlagDefs
	}
}

// ─── messages ───────────────────────────────────────────────────────────────

// resultMsg is sent by the runner tea.Cmd when the plugin finishes.
type resultMsg struct {
	output string
	err    error
}

// ─── RunnerFunc ─────────────────────────────────────────────────────────────

// RunnerFunc is called to execute a plugin subcommand with the collected flags.
// Injected via NewModel to keep the model testable (no real LLM in tests).
type RunnerFunc func(
	ctx context.Context,
	p plugin.Plugin,
	sc plugin.Subcommand,
	flags map[string]string,
) (plugin.Report, error)

// ─── Model ──────────────────────────────────────────────────────────────────

// Model is the Bubble Tea application model.
type Model struct {
	ctx     context.Context
	runner  RunnerFunc
	plugins []plugin.Plugin

	state appState

	// ── list components ──────────────────────────────────────────────────
	pluginList list.Model
	subcmdList list.Model

	// ── selected items ───────────────────────────────────────────────────
	selectedPlugin plugin.Plugin
	selectedSubcmd plugin.Subcommand

	// ── flag form ────────────────────────────────────────────────────────
	flagDefs   []flagDef
	inputs     []textinput.Model
	focusIndex int // which input is focused

	// ── running / result ─────────────────────────────────────────────────
	spin      spinner.Model
	result    string
	runErr    error
	resultVP  viewport.Model // scrollable output panel for the result screen
	startedAt time.Time      // when the current run began (drives the elapsed timer)

	// ── help overlay ─────────────────────────────────────────────────────
	showHelp bool // toggled by "?"; renders the keybinding reference panel

	// ── terminal dimensions ──────────────────────────────────────────────
	width  int
	height int
}

// NewModel constructs the initial model. plugins is the full list; runner is
// called when the user submits the flag form.
func NewModel(ctx context.Context, plugins []plugin.Plugin, runner RunnerFunc) Model {
	// Build the plugin list.
	items := make([]list.Item, len(plugins))
	for i, p := range plugins {
		items[i] = pluginItem{p}
	}
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	pList := list.New(items, delegate, 60, 16)
	pList.Title = "Plugins"
	pList.SetShowStatusBar(false)
	pList.SetFilteringEnabled(true)
	pList.Styles.Title = titleStyle

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = selectedStyle

	// Result viewport: sensible default size — resized on first WindowSizeMsg.
	vp := viewport.New(76, 14)
	vp.Style = resultViewportStyle

	return Model{
		ctx:        ctx,
		runner:     runner,
		plugins:    plugins,
		state:      statePluginList,
		pluginList: pList,
		spin:       sp,
		resultVP:   vp,
		width:      80,
		height:     24,
	}
}

// ─── tea.Model implementation ───────────────────────────────────────────────

// Init sets up the initial command (none — we wait for user input).
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles all incoming messages and key events.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.pluginList.SetSize(min(msg.Width-4, 70), msg.Height-8)
		m.subcmdList.SetSize(min(msg.Width-4, 70), msg.Height-8)
		// Reserve ~10 rows for header (2) + help bar (2) + error/status (2) + margins.
		vpHeight := msg.Height - 10
		if vpHeight < 4 {
			vpHeight = 4
		}
		m.resultVP.Width = msg.Width - 4
		m.resultVP.Height = vpHeight

	case tea.KeyMsg:
		return m.handleKey(msg)

	case resultMsg:
		m.state = stateResult
		m.result = msg.output
		m.runErr = msg.err
		// Populate the scrollable viewport with the new result and jump to top
		// so every fresh result starts at the beginning.
		m.resultVP.SetContent(m.formatResultContent())
		m.resultVP.GotoTop()

	case spinner.TickMsg:
		if m.state == stateRunning {
			var cmd tea.Cmd
			m.spin, cmd = m.spin.Update(msg)
			return m, cmd
		}
	}

	// Delegate to the active component.
	return m.updateActiveComponent(msg)
}

// View renders the current UI.
func (m Model) View() string {
	header := headerStyle.Render("  exalm tui  —  interactive ops assistant")

	// The "?" help overlay takes over the body when active.
	if m.showHelp {
		return header + "\n\n" + m.viewHelp()
	}

	var body string

	switch m.state {
	case statePluginList:
		body = m.viewPluginList()
	case stateSubcmdList:
		body = m.viewSubcmdList()
	case stateFlagForm:
		body = m.viewFlagForm()
	case stateRunning:
		body = m.viewRunning()
	case stateResult:
		body = m.viewResult()
	case stateQuit:
		return "Goodbye!\n"
	}

	return header + "\n\n" + body
}

// ─── per-state views ────────────────────────────────────────────────────────

func (m Model) viewPluginList() string {
	return m.pluginList.View() +
		helpStyle.Render("\n  ↑/↓ navigate  •  Enter select  •  / filter  •  ? help  •  q quit")
}

func (m Model) viewSubcmdList() string {
	return subtitleStyle.Render("Plugin: "+m.selectedPlugin.Name()) + "\n\n" +
		m.subcmdList.View() +
		helpStyle.Render("\n  ↑/↓ navigate  •  Enter select  •  Esc back  •  ? help  •  q quit")
}

func (m Model) viewFlagForm() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n\n",
		subtitleStyle.Render("Plugin:"),
		selectedStyle.Render(m.selectedPlugin.Name()+" "+m.selectedSubcmd.Name),
	)
	for i, inp := range m.inputs {
		label := inputLabelStyle.Render(m.flagDefs[i].label)
		b.WriteString("  " + label + " " + inp.View() + "\n")
	}
	b.WriteString(helpStyle.Render("\n  Tab/↓ next field  •  Shift+Tab/↑ prev  •  Enter run  •  Esc back"))
	return b.String()
}

func (m Model) viewRunning() string {
	// The spinner ticks every frame, so re-deriving elapsed here keeps the
	// counter live without a separate timer goroutine.
	elapsed := ""
	if !m.startedAt.IsZero() {
		elapsed = subtitleStyle.Render(fmt.Sprintf(" %ds", int(time.Since(m.startedAt).Seconds())))
	}
	return fmt.Sprintf("\n  %s  Running %s %s …%s\n",
		m.spin.View(),
		selectedStyle.Render(m.selectedPlugin.Name()),
		m.selectedSubcmd.Name,
		elapsed,
	)
}

// viewHelp renders the bordered keybinding reference toggled by "?".
func (m Model) viewHelp() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Keyboard shortcuts") + "\n\n")
	rows := [][2]string{
		{"↑ / ↓", "Navigate lists · scroll results"},
		{"Enter", "Select · run the command"},
		{"Tab / Shift+Tab", "Move between flag fields"},
		{"/", "Filter the current list"},
		{"PgUp / PgDn", "Page through results"},
		{"r", "Run the last command again"},
		{"Esc", "Go back one step"},
		{"?", "Toggle this help"},
		{"q / Ctrl+C", "Quit"},
	}
	for _, kv := range rows {
		key := helpKeyStyle.Render(fmt.Sprintf("%-16s", kv[0]))
		fmt.Fprintf(&b, "  %s  %s\n", key, kv[1])
	}
	b.WriteString("\n" + subtitleStyle.Render("Press ? or Esc to close"))
	return helpPanelStyle.Render(b.String())
}

func (m Model) viewResult() string {
	var b strings.Builder
	if m.runErr != nil {
		b.WriteString(errorStyle.Render("  ✗  Error: "+m.runErr.Error()) + "\n\n")
		b.WriteString(helpStyle.Render("  r run again  •  Esc back to plugins  •  ? help  •  q quit"))
	} else {
		b.WriteString(successStyle.Render("  ✓  Complete") + "\n\n")
		b.WriteString(m.resultVP.View() + "\n")
		// Scroll position indicator.
		pct := 100
		if m.resultVP.TotalLineCount() > 0 {
			pct = int(m.resultVP.ScrollPercent() * 100)
		}
		b.WriteString(helpStyle.Render(fmt.Sprintf(
			"  ↑/↓ scroll  •  PgUp/PgDn page  •  r run again  •  Esc back  •  ? help  •  q quit  [%d%%]",
			pct,
		)))
	}
	return b.String()
}

// formatResultContent builds the viewport content string from m.result,
// indenting each line for visual separation from the border.
func (m Model) formatResultContent() string {
	if m.result == "" {
		return "  No findings. Everything looks healthy.\n"
	}
	var b strings.Builder
	for _, line := range strings.Split(m.result, "\n") {
		b.WriteString("  " + line + "\n")
	}
	return b.String()
}

// ─── event handling ─────────────────────────────────────────────────────────

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Global help overlay. While it is up, "?" / Esc dismiss it and Ctrl+C / q
	// still quit; every other key is swallowed so the panel stays put.
	if m.showHelp {
		switch msg.String() {
		case "ctrl+c", "q":
			m.state = stateQuit
			return m, tea.Quit
		case "?", "esc":
			m.showHelp = false
		}
		return m, nil
	}
	// Open the overlay with "?" — but only when it would not shadow a text input
	// or an active list filter, where "?" is a literal character.
	if msg.String() == "?" && m.canToggleHelp() {
		m.showHelp = true
		return m, nil
	}

	switch m.state {

	case statePluginList:
		switch msg.String() {
		case "q", "ctrl+c":
			m.state = stateQuit
			return m, tea.Quit
		case "enter":
			if i, ok := m.pluginList.SelectedItem().(pluginItem); ok {
				return m.selectPlugin(i.p)
			}
		}

	case stateSubcmdList:
		switch msg.String() {
		case "q", "ctrl+c":
			m.state = stateQuit
			return m, tea.Quit
		case "esc":
			m.state = statePluginList
			return m, nil
		case "enter":
			if i, ok := m.subcmdList.SelectedItem().(subcmdItem); ok {
				return m.selectSubcmd(i.sc)
			}
		}

	case stateFlagForm:
		switch msg.String() {
		case "ctrl+c":
			m.state = stateQuit
			return m, tea.Quit
		case "esc":
			m.state = stateSubcmdList
			return m, nil
		case "tab", "down":
			return m.moveFocus(1), nil
		case "shift+tab", "up":
			return m.moveFocus(-1), nil
		case "enter":
			// On last input, or if Enter pressed anywhere with --host filled,
			// submit the form.
			if m.focusIndex == len(m.inputs)-1 || m.isReadyToRun() {
				return m.submitForm()
			}
			return m.moveFocus(1), nil
		}

	case stateResult:
		switch msg.String() {
		case "q", "ctrl+c":
			m.state = stateQuit
			return m, tea.Quit
		case "esc", "r":
			// Esc → back to plugin list; r → re-run same config.
			if msg.String() == "esc" {
				m.state = statePluginList
				return m, nil
			}
			return m.submitForm()
		}
	}

	return m.updateActiveComponent(msg)
}

// canToggleHelp reports whether "?" should open the help overlay rather than be
// handled as literal text. It is suppressed while typing into a flag input or
// while a list's filter is actively being edited.
func (m Model) canToggleHelp() bool {
	switch m.state {
	case stateFlagForm:
		return false
	case statePluginList:
		return m.pluginList.FilterState() != list.Filtering
	case stateSubcmdList:
		return m.subcmdList.FilterState() != list.Filtering
	default:
		return true
	}
}

// ─── state transitions ───────────────────────────────────────────────────────

func (m Model) selectPlugin(p plugin.Plugin) (Model, tea.Cmd) {
	m.selectedPlugin = p
	scs := p.Subcommands()
	if len(scs) == 1 {
		// Only one subcommand — skip the list and go straight to the form.
		return m.selectSubcmd(scs[0])
	}
	items := make([]list.Item, len(scs))
	for i, sc := range scs {
		items[i] = subcmdItem{sc}
	}
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	l := list.New(items, delegate, min(m.width-4, 70), m.height-8)
	l.Title = p.Name() + " — choose an action"
	l.SetShowStatusBar(false)
	l.Styles.Title = titleStyle
	m.subcmdList = l
	m.state = stateSubcmdList
	return m, nil
}

func (m Model) selectSubcmd(sc plugin.Subcommand) (Model, tea.Cmd) {
	m.selectedSubcmd = sc
	defs := flagDefsFor(m.selectedPlugin.Name())
	m.flagDefs = defs
	m.inputs = make([]textinput.Model, len(defs))
	for i, d := range defs {
		inp := textinput.New()
		inp.Placeholder = d.placeholder
		inp.CharLimit = 256
		if i == 0 {
			inp.Focus()
		}
		m.inputs[i] = inp
	}
	m.focusIndex = 0
	m.state = stateFlagForm
	return m, textinput.Blink
}

func (m Model) moveFocus(delta int) Model {
	if len(m.inputs) == 0 {
		return m
	}
	// Blur current.
	m.inputs[m.focusIndex].Blur()
	// Move.
	m.focusIndex = (m.focusIndex + delta + len(m.inputs)) % len(m.inputs)
	m.inputs[m.focusIndex].Focus()
	return m
}

// isReadyToRun returns true when enough flags are filled to attempt a run.
// A non-empty --file or --host is sufficient; no flags is also valid for
// plugins that read from stdin.
func (m Model) isReadyToRun() bool {
	return true // always allow submission; plugin validates inputs
}

func (m Model) submitForm() (Model, tea.Cmd) {
	flags := m.collectFlags()
	p := m.selectedPlugin
	sc := m.selectedSubcmd
	runner := m.runner
	ctx := m.ctx

	m.state = stateRunning
	m.startedAt = time.Now()
	return m, tea.Batch(
		m.spin.Tick,
		func() tea.Msg {
			report, err := runner(ctx, p, sc, flags)
			if err != nil {
				return resultMsg{err: err}
			}
			// Build a concise text summary from the report.
			var sb strings.Builder
			if report.Summary != "" {
				sb.WriteString(report.Summary + "\n\n")
			}
			for _, f := range report.Findings {
				sb.WriteString(fmt.Sprintf("[%s] %s\n  %s\n\n", f.Severity, f.Title, f.Detail)) //nolint:staticcheck // QF1012: fmt.Fprintf alternative would need errcheck suppression too
			}
			if sb.Len() == 0 {
				sb.WriteString("No findings. Everything looks healthy.\n")
			}
			return resultMsg{output: sb.String()}
		},
	)
}

// collectFlags reads each text input and returns a flag map.
func (m Model) collectFlags() map[string]string {
	flags := make(map[string]string, len(m.inputs))
	for i, inp := range m.inputs {
		v := strings.TrimSpace(inp.Value())
		if v != "" {
			flags[m.flagDefs[i].name] = v
		}
	}
	return flags
}

// ─── component delegation ───────────────────────────────────────────────────

// updateActiveComponent forwards messages to whichever sub-component is
// currently visible so scrolling, filtering, etc. continue to work.
func (m Model) updateActiveComponent(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch m.state {
	case statePluginList:
		m.pluginList, cmd = m.pluginList.Update(msg)
	case stateSubcmdList:
		m.subcmdList, cmd = m.subcmdList.Update(msg)
	case stateFlagForm:
		if m.focusIndex < len(m.inputs) {
			m.inputs[m.focusIndex], cmd = m.inputs[m.focusIndex].Update(msg)
		}
	case stateResult:
		// Route all unhandled messages (scroll keys, mouse wheel) to the viewport.
		m.resultVP, cmd = m.resultVP.Update(msg)
	}
	return m, cmd
}

// ─── exported helpers for testing ───────────────────────────────────────────

// FocusIndex returns the index of the currently-focused text input.
// Exported for use in unit tests.
func (m Model) FocusIndex() int { return m.focusIndex }

// NewResultMsg constructs a resultMsg tea.Msg that can be injected in tests
// without needing to run the real plugin runner. Exported for testing.
func NewResultMsg(output string, err error) tea.Msg {
	return resultMsg{output: output, err: err}
}
