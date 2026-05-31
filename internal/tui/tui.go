package tui

import (
	"context"
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// Run starts the interactive TUI, blocks until the user quits, and returns
// any fatal error. plugins is the list registered in the binary; runner is
// called when the user submits the flag form.
//
// output is where the Bubble Tea program writes its rendered frames; pass
// os.Stdout in production and a *bytes.Buffer in tests.
func Run(ctx context.Context, plugins []plugin.Plugin, runner RunnerFunc, output io.Writer) error {
	if len(plugins) == 0 {
		return fmt.Errorf("tui: no plugins registered")
	}

	m := NewModel(ctx, plugins, runner)

	opts := []tea.ProgramOption{tea.WithOutput(output)}
	// When running in a real terminal, enable the alternate screen.
	// When output is not a TTY (e.g. in tests) the program still runs but
	// without the alternate screen so test output stays readable.
	if isTerminal(output) {
		opts = append(opts, tea.WithAltScreen())
	}

	prog := tea.NewProgram(m, opts...)
	finalModel, err := prog.Run()
	if err != nil {
		return fmt.Errorf("tui: %w", err)
	}

	// If the user got to a result, print it one more time to stdout so it
	// persists after the alternate-screen clears.
	if fm, ok := finalModel.(Model); ok && fm.state == stateResult {
		if fm.runErr != nil {
			fmt.Fprintf(output, "\nError: %v\n", fm.runErr) //nolint:errcheck
		} else if fm.result != "" {
			fmt.Fprintf(output, "\n%s\n", fm.result) //nolint:errcheck
		}
	}

	return nil
}
