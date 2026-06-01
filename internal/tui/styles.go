// Package tui implements the `exalm tui` interactive terminal interface.
// It uses Bubble Tea for the event loop and Lipgloss for styling.
package tui

import "github.com/charmbracelet/lipgloss"

// Color palette — matches the navy/cyan theme of the web dashboard.
const (
	colorCyan    = lipgloss.Color("#00b4d8")
	colorNavy    = lipgloss.Color("#03045e")
	colorSky     = lipgloss.Color("#caf0f8")
	colorMuted   = lipgloss.Color("#8d99ae")
	colorAccent  = lipgloss.Color("#48cae4")
	colorError   = lipgloss.Color("#e63946")
	colorSuccess = lipgloss.Color("#2dc653")
	colorWarn    = lipgloss.Color("#f4a261")
)

var (
	// headerStyle renders the top title bar.
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Background(colorNavy).
			Foreground(colorSky).
			Padding(0, 2).
			Width(70)

	// titleStyle renders section headings inside the TUI.
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyan)

	// subtitleStyle renders secondary labels.
	subtitleStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	// selectedStyle highlights the focused list item.
	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyan)

	// inputLabelStyle renders flag name labels in the form.
	inputLabelStyle = lipgloss.NewStyle().
			Foreground(colorAccent).
			Width(18)

	// helpStyle renders the key-binding hint at the bottom.
	helpStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			MarginTop(1)

	// errorStyle renders error messages.
	errorStyle = lipgloss.NewStyle().
			Foreground(colorError).
			Bold(true)

	// successStyle renders success messages.
	successStyle = lipgloss.NewStyle().
			Foreground(colorSuccess).
			Bold(true)

	// resultViewportStyle wraps the scrollable result viewport in a subtle
	// rounded border so it is visually distinct from the surrounding UI chrome.
	resultViewportStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorMuted).
				Padding(0, 1)

	// helpKeyStyle renders the key column of the "?" help overlay.
	helpKeyStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent)

	// helpPanelStyle renders the bordered "?" help overlay panel.
	helpPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorCyan).
			Padding(1, 3).
			MarginLeft(2)
)
