// Package output renders plugin.Report values for the terminal.
package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// ─── ANSI colour helpers ──────────────────────────────────────────────────────

// colorsEnabled returns true when stdout looks like a real terminal and the
// user hasn't opted out via NO_COLOR (https://no-color.org).
func colorsEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("EXALM_NO_COLOR") != "" {
		return false
	}
	// Check if stdout is a character device (real terminal), not a pipe/file.
	if fi, err := os.Stdout.Stat(); err == nil {
		return (fi.Mode() & os.ModeCharDevice) != 0
	}
	return false
}

// ANSI escape codes. All writes go through colorize() which respects NO_COLOR.
const (
	ansiReset      = "\033[0m"
	ansiBold       = "\033[1m"
	ansiDim        = "\033[2m"
	ansiCyan       = "\033[36m"
	ansiGreen      = "\033[32m"
	ansiYellow     = "\033[33m"
	ansiRed        = "\033[31m"
	ansiMagenta    = "\033[35m"
	ansiBlue       = "\033[34m"
	ansiWhite      = "\033[97m"
	ansiBgDarkGray = "\033[100m"
)

func colorize(code, text string) string {
	if !colorsEnabled() {
		return text
	}
	return code + text + ansiReset
}

func bold(s string) string    { return colorize(ansiBold, s) }
func dim(s string) string     { return colorize(ansiDim, s) }
func cyan(s string) string    { return colorize(ansiCyan, s) }
func green(s string) string   { return colorize(ansiGreen, s) }
func yellow(s string) string  { return colorize(ansiYellow, s) }
func red(s string) string     { return colorize(ansiRed, s) }
func magenta(s string) string { return colorize(ansiMagenta, s) }

// ─── Section detection ────────────────────────────────────────────────────────

// knownSection maps normalised ## HEADING lines to their display config.
type sectionStyle struct {
	label string
	color func(string) string
	icon  string
}

var sectionStyles = map[string]sectionStyle{
	"VERDICT":    {label: "VERDICT", color: bold, icon: "◆"},
	"EVIDENCE":   {label: "EVIDENCE", color: cyan, icon: "▸"},
	"CAUSES":     {label: "LIKELY CAUSES", color: yellow, icon: "▸"},
	"NEXT STEPS": {label: "NEXT STEPS", color: green, icon: "▸"},
	// Fallback for models that use slightly different headings.
	"LIKELY CAUSES":     {label: "LIKELY CAUSES", color: yellow, icon: "▸"},
	"SUGGESTED ACTIONS": {label: "NEXT STEPS", color: green, icon: "▸"},
	"ROOT CAUSE":        {label: "VERDICT", color: bold, icon: "◆"},
}

// ─── Markdown renderer ────────────────────────────────────────────────────────

// Markdown writes a terminal-rendered report to w.
//
// It detects the ## SECTION headers produced by the log system prompt and
// renders each section with a colour-coded bar. Falls back to plain-text
// pass-through for reports that don't follow the structured format.
func Markdown(w io.Writer, r plugin.Report) error {
	colors := colorsEnabled()
	_ = colors

	var b strings.Builder

	// ── Header bar ──────────────────────────────────────────────────────────
	writeHeaderBar(&b, r)

	// ── Body ────────────────────────────────────────────────────────────────
	if r.Raw != "" {
		writeFormattedRaw(&b, r.Raw)
	} else if len(r.Findings) > 0 {
		writeFindings(&b, r.Findings)
	}

	// ── Footer ──────────────────────────────────────────────────────────────
	writeFooter(&b, r)

	_, err := io.WriteString(w, b.String())
	return err
}

func writeHeaderBar(b *strings.Builder, r plugin.Report) {
	title := r.Title
	if title == "" {
		title = "Analysis"
	}

	line := strings.Repeat("─", 60)
	b.WriteString("\n")
	b.WriteString(bold(cyan("  exalm  ")) + dim("│") + "  " + bold(strings.ToUpper(title)) + "\n")
	b.WriteString(dim(line) + "\n")

	if r.Summary != "" {
		b.WriteString(dim("  "+r.Summary) + "\n")
		b.WriteString(dim(line) + "\n")
	}
	b.WriteString("\n")
}

func writeFooter(b *strings.Builder, r plugin.Report) {
	line := strings.Repeat("─", 60)
	b.WriteString("\n" + dim(line) + "\n")
	b.WriteString(dim(fmt.Sprintf("  %s  ·  exalm.com\n", time.Now().Format("2006-01-02 15:04:05 UTC"))))
	b.WriteString("\n")
}

// writeFormattedRaw parses the LLM raw output and renders sections with
// colour-coded headers. Lines that don't match a section header are
// rendered as body text with minor formatting improvements.
func writeFormattedRaw(b *strings.Builder, raw string) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	inCodeBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Code fence toggle.
		if strings.HasPrefix(trimmed, "```") {
			inCodeBlock = !inCodeBlock
			if inCodeBlock {
				b.WriteString(dim("  ┌──────────────────────────────────────────\n"))
			} else {
				b.WriteString(dim("  └──────────────────────────────────────────\n"))
			}
			continue
		}

		// Lines inside code blocks get a subtle left border.
		if inCodeBlock {
			b.WriteString(dim("  │ ") + colorize(ansiWhite, trimmed) + "\n")
			continue
		}

		// ## SECTION HEADER
		if strings.HasPrefix(trimmed, "## ") {
			heading := strings.ToUpper(strings.TrimPrefix(trimmed, "## "))
			if style, ok := sectionStyles[heading]; ok {
				b.WriteString("\n")
				b.WriteString(style.color(bold("  "+style.icon+" "+style.label)) + "\n")
				b.WriteString(dim("  "+strings.Repeat("·", 40)) + "\n")
				continue
			}
			// Unknown ## heading — render it visibly but without special color.
			b.WriteString("\n" + bold("  ▸ "+strings.TrimPrefix(trimmed, "## ")) + "\n")
			continue
		}

		// Bullet points.
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			content := strings.TrimPrefix(strings.TrimPrefix(trimmed, "- "), "* ")
			b.WriteString("  " + yellow("•") + " " + content + "\n")
			continue
		}

		// Numbered list items.
		if len(trimmed) > 2 && trimmed[1] == '.' && trimmed[0] >= '1' && trimmed[0] <= '9' {
			num := string(trimmed[0])
			content := strings.TrimSpace(trimmed[2:])
			b.WriteString("  " + green(num+".") + " " + content + "\n")
			continue
		}

		// Bold **text** — render the asterisks as bold without the markers.
		if strings.Contains(trimmed, "**") {
			rendered := renderInlineBold(trimmed)
			b.WriteString("  " + rendered + "\n")
			continue
		}

		// Blank lines become a single blank line.
		if trimmed == "" {
			b.WriteString("\n")
			continue
		}

		// Regular line.
		b.WriteString("  " + trimmed + "\n")
	}
}

// renderInlineBold replaces **text** markers with bold ANSI codes.
func renderInlineBold(s string) string {
	var out strings.Builder
	parts := strings.Split(s, "**")
	for i, p := range parts {
		if i%2 == 1 {
			out.WriteString(bold(p))
		} else {
			out.WriteString(p)
		}
	}
	return out.String()
}

// writeFindings renders structured Findings (for plugins that parse the LLM
// response into Finding objects rather than returning Raw text).
func writeFindings(b *strings.Builder, findings []plugin.Finding) {
	b.WriteString(bold("  ▸ FINDINGS\n"))
	b.WriteString(dim("  "+strings.Repeat("·", 40)) + "\n\n")

	for i, f := range findings {
		severityColor := severityColor(f.Severity)
		b.WriteString(fmt.Sprintf("  %s  %s\n", //nolint:staticcheck // QF1012: fmt.Fprintf alternative would need errcheck suppression too
			severityColor(fmt.Sprintf("[%-8s]", strings.ToUpper(string(f.Severity)))),
			bold(f.Title),
		))
		if f.Detail != "" {
			for _, line := range strings.Split(f.Detail, "\n") {
				b.WriteString("       " + line + "\n")
			}
		}
		if f.Suggestion != "" {
			b.WriteString("       " + green("→ ") + f.Suggestion + "\n")
		}
		if i < len(findings)-1 {
			b.WriteString("\n")
		}
	}
}

func severityColor(s plugin.Severity) func(string) string {
	switch s {
	case plugin.SeverityCritical:
		return red
	case plugin.SeverityHigh:
		return magenta
	case plugin.SeverityMedium:
		return yellow
	case plugin.SeverityLow:
		return cyan
	default:
		return dim
	}
}
