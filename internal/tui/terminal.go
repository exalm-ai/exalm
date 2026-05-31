package tui

import (
	"io"
	"os"
)

// isTerminal reports whether w is a real TTY (i.e. os.Stdout or a *os.File
// connected to a terminal). Non-TTY writers (buffers, pipes) run the program
// without alt-screen mode so test output stays readable.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
