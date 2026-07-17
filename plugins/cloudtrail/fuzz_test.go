package cloudtrail

import (
	"strings"
	"testing"
)

// FuzzParseCloudTrail verifies that parseCloudTrail never panics on arbitrary
// input. NDJSON input can be malformed, truncated, or adversarial (a
// downloaded log file, a bad conversion) — it must be handled gracefully.
func FuzzParseCloudTrail(f *testing.F) {
	f.Add([]byte(`{"eventTime":"2026-05-13T09:00:00Z","eventName":"DeleteUser","userIdentity":{"userName":"alice"},"awsRegion":"us-east-1","errorCode":"AccessDenied","errorMessage":"denied"}`))
	f.Add([]byte(`{"eventTime":"2026-05-13T09:00:00Z","eventName":"CreateUser","userIdentity":{"type":"Root"},"awsRegion":"us-east-1"}`))
	f.Add([]byte(`{"eventName":"ConsoleLogin","responseElements":{"ConsoleLogin":"Failure"}}`))
	f.Add([]byte(``))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte(strings.Repeat("A", 10000)))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"userIdentity":null}`))
	f.Add([]byte(`{"errorCode":123}`)) // wrong type for a string field
	f.Add([]byte(strings.Repeat(`{"eventName":"DeleteUser"}`+"\n", 500)))

	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := parseCloudTrail(data)
		if err != nil {
			return // errors are acceptable; panics are not
		}
		_ = out
		_ = parseEvents(0, data) // must not panic either
	})
}

// TestParseCloudTrail_NeverPanics runs a targeted set of edge cases most
// likely to trigger panics: empty input, NUL bytes, truncated/malformed
// JSON, and type-mismatched fields.
func TestParseCloudTrail_NeverPanics(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("\x00"),
		[]byte("\n\n\n"),
		[]byte("{"),
		[]byte(`{"userIdentity":`),
		[]byte(`{"userIdentity":null}`),
		[]byte(`{"errorCode":123}`),
		[]byte(`{"eventTime":12345}`),
		[]byte(`{"responseElements":"not an object"}`),
		[]byte(strings.Repeat("x", 1<<16)),
		[]byte(strings.Repeat(`{"eventName":"DeleteUser","userIdentity":{"userName":"a"}}`+"\n", 5000)),
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: parseCloudTrail panicked: %v", i, r)
				}
			}()
			_, _ = parseCloudTrail(c)
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: parseEvents panicked: %v", i, r)
				}
			}()
			_ = parseEvents(0, c)
		}()
	}
}
