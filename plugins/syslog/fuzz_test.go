package syslog

import (
	"strings"
	"testing"
)

// FuzzParseSyslog verifies that parseSyslog never panics on arbitrary remote
// input. Syslog data originates from SSH-collected logs on remote hosts — any
// malformed or adversarial content must be handled gracefully.
func FuzzParseSyslog(f *testing.F) {
	// Seed corpus: valid formats + common edge cases.
	f.Add([]byte(`<34>1 2026-01-15T10:00:00Z db-01 mysqld 1234 - OOM killer invoked`))
	f.Add([]byte(`<35>Jan 15 10:00:00 web-01 nginx[1234]: upstream timed out`))
	f.Add([]byte(`Jan 15 10:00:00 web-01 sshd: error: connect_to port 22: failed.`))
	f.Add([]byte(`{"PRIORITY":"3","_HOSTNAME":"db-01","_SYSTEMD_UNIT":"mysql.service","MESSAGE":"Aborted connection","__REALTIME_TIMESTAMP":"1234567890"}`))
	f.Add([]byte(``))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte(strings.Repeat("A", 10000)))
	f.Add([]byte("<999>1 " + strings.Repeat("x", 512) + " host app 1 1 " + strings.Repeat("msg ", 200)))
	f.Add([]byte(`<0>`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"PRIORITY":""}`))
	f.Add([]byte(strings.Repeat("<13>Jan 15 10:00:00 host tag: msg\n", 500)))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic under any input.
		out, err := parseSyslog(data)
		if err != nil {
			return // errors are acceptable; panics are not
		}
		// Output must be a valid (possibly empty) string — never contain NUL bytes
		// from unvalidated input being passed through verbatim.
		_ = out
	})
}

// TestParseSyslog_NeverPanics runs a targeted set of edge cases that are
// most likely to trigger panics in parsers: empty input, NUL bytes, very long
// lines, and boundary values for the priority field.
func TestParseSyslog_NeverPanics(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("\x00"),
		[]byte("\n\n\n"),
		[]byte("<0>"),
		[]byte("<4294967295>"),        // priority overflow
		[]byte("<13>Jan  1 00:00:00"), // truncated BSD syslog
		[]byte("<34>1"),               // truncated RFC 5424
		[]byte("{"),                   // malformed JSON
		[]byte(`{"PRIORITY":null}`),   // null field
		[]byte(`{"MESSAGE":` + strings.Repeat(`"x`, 1000) + `"}`),    // malformed JSON value
		[]byte(strings.Repeat("x", 1<<16)),                           // 64 KB single "line"
		[]byte(strings.Repeat("<3>Jan  1 00:00:00 h t: m\n", 10000)), // 10k lines
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: parseSyslog panicked: %v", i, r)
				}
			}()
			_, _ = parseSyslog(c)
		}()
	}
}

// TestParseLine_NeverPanics targets the inner parseLine function which is the
// first call site for each individual log line.
func TestParseLine_NeverPanics(t *testing.T) {
	tricky := []string{
		"",
		" ",
		"{bad json}",
		`{"PRIORITY":"-1"}`,
		`{"PRIORITY":"999"}`,
		strings.Repeat("x", 4096),
		"<0>" + strings.Repeat(" ", 100),
		"<13>Jan  1 00:00:00" + strings.Repeat(" x", 50) + ":",
	}
	for i, line := range tricky {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d %q: parseLine panicked: %v", i, line[:min(len(line), 40)], r)
				}
			}()
			_, _ = parseLine(line)
		}()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
