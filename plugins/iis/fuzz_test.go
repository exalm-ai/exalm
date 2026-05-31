package iis

import (
	"strings"
	"testing"
)

// FuzzParseW3C verifies that parseW3C never panics on arbitrary remote input.
// IIS W3C logs are collected over SSH from Windows hosts — malformed, truncated,
// or adversarially crafted content must never crash the exalm process.
func FuzzParseW3C(f *testing.F) {
	// Seed corpus: valid W3C log, edge cases, adversarial inputs.
	f.Add([]byte("#Version: 1.0\n#Fields: date time c-ip cs-method cs-uri-stem sc-status time-taken\n2026-01-15 10:00:00 192.168.1.1 GET /api/health 200 123\n"))
	f.Add([]byte("#Fields: date time c-ip cs-method cs-uri-stem sc-status time-taken\n2026-01-15 10:00:01 10.0.0.5 POST /login 500 9876\n"))
	f.Add([]byte("#Fields: date time sc-status\n2026-01-15 10:00:02 404\n"))
	f.Add([]byte(`#Software: Microsoft Internet Information Services 10.0` + "\n"))
	f.Add([]byte(``))
	f.Add([]byte("\x00\x01\x02\x03\xff"))
	f.Add([]byte(strings.Repeat("A", 10000)))
	f.Add([]byte("#Fields: " + strings.Repeat("field-x ", 200) + "\n" + strings.Repeat("val ", 200) + "\n"))
	f.Add([]byte("#Fields:\n")) // empty fields header
	f.Add([]byte("no-fields-header-at-all 200 GET / 192.0.2.1\n"))
	f.Add([]byte(strings.Repeat("#Fields: sc-status\n2026-01-15 10:00:00 500\n", 500)))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic under any input.
		out, err := parseW3C(data)
		if err != nil {
			return
		}
		_ = out
	})
}

// TestParseW3C_NeverPanics runs targeted edge cases most likely to trigger
// panics in the IIS W3C parser: empty input, NUL bytes, mismatched field
// counts, empty status codes, and very large inputs.
func TestParseW3C_NeverPanics(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("\x00"),
		[]byte("#"),
		[]byte("#Fields:"),
		[]byte("#Fields:\n\n"),
		[]byte("#Fields: sc-status\n"), // fields declared, no data rows
		[]byte("#Fields: sc-status\n500\n"),
		[]byte("#Fields: sc-status time-taken\n500\n"), // fewer columns than fields
		// Status with no first byte (shouldn't happen, but guard against it):
		[]byte("#Fields: sc-status\n\n\n"),
		// Fields header appearing multiple times (IIS can rotate mid-file):
		[]byte("#Fields: sc-status\n200\n#Fields: sc-status time-taken\n500 100\n"),
		// Very long single field value:
		[]byte("#Fields: cs-uri-stem\n" + strings.Repeat("x", 8192) + "\n"),
		// Many rows with 5xx status to exercise errPerMin and errorLines:
		[]byte("#Fields: date time cs-method cs-uri-stem c-ip sc-status time-taken\n" +
			strings.Repeat("2026-01-15 10:00:00 GET / 10.0.0.1 500 100\n", 1000)),
		// Rows with non-numeric time-taken to exercise the Atoi path:
		[]byte("#Fields: sc-status time-taken\n500 NaN\n200 -1\n"),
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: parseW3C panicked: %v", i, r)
				}
			}()
			_, _ = parseW3C(c)
		}()
	}
}
