package httplog

import (
	"strings"
	"testing"
)

// FuzzParseHTTP verifies that parseHTTP never panics on arbitrary remote
// input. HTTP access and error logs originate from SSH-collected files on
// remote hosts — any malformed or adversarial content must be handled
// gracefully without crashing the exalm process.
func FuzzParseHTTP(f *testing.F) {
	// Seed corpus: combined access log, Apache/nginx error log, edge cases.
	f.Add([]byte(`192.168.1.1 - alice [15/Jan/2026:10:00:00 +0000] "GET /api/v1/health HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0" 0.123`))
	f.Add([]byte(`10.0.0.5 - - [15/Jan/2026:10:00:01 +0000] "POST /login HTTP/2.0" 500 0`))
	f.Add([]byte(`[Wed Jan 15 10:00:00 2026] [error] [pid 12345] [client 10.0.0.1:54321] PHP Fatal error: Allowed memory size exhausted`))
	f.Add([]byte(`2026/01/15 10:00:00 [crit] 8765#8765: *1 connect() failed (111: Connection refused) while connecting to upstream`))
	f.Add([]byte(``))
	f.Add([]byte("\x00\x01\x02\x03\xff"))
	f.Add([]byte(strings.Repeat("A", 10000)))
	f.Add([]byte(`- - - [] "" 0 -`))
	f.Add([]byte(`127.0.0.1 - - [` + strings.Repeat("x", 256) + `] "GET / HTTP/1.1" 200 0`))
	f.Add([]byte(strings.Repeat(`192.0.2.1 - - [15/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 500 100`+"\n", 300)))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic under any input.
		out, err := parseHTTP(data)
		if err != nil {
			return
		}
		_ = out
	})
}

// TestParseHTTP_NeverPanics runs targeted edge cases most likely to trigger
// panics in the HTTP log parser.
func TestParseHTTP_NeverPanics(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("\x00"),
		[]byte(`""`),
		[]byte(`[] "" 500 0 "" ""`),
		[]byte(`127.0.0.1 - - [] "" 500 0`), // empty date bracket
		[]byte(`127.0.0.1 - - [x] "GET /` + strings.Repeat("x", 2048) + `" 200`),              // long URI
		[]byte(strings.Repeat("GET / HTTP/1.1\n", 10000)),                                     // 10k non-matching lines
		[]byte(`[` + strings.Repeat("x", 256) + `] [error] msg`),                              // long Apache error date
		[]byte(`2026/01/15 10:00:00 [] 0#0: error`),                                           // empty nginx level
		[]byte(`127.0.0.1 - - [d] "GET / HTTP/1.1" 500 0 "` + strings.Repeat(`"`, 100) + `"`), // quotes in referer
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: parseHTTP panicked: %v", i, r)
				}
			}()
			_, _ = parseHTTP(c)
		}()
	}
}
