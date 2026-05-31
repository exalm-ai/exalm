package k8s

import (
	"testing"
)

func TestScanLogPatterns_DBError(t *testing.T) {
	content := `2026-05-10T07:30:11Z INFO  starting
2026-05-10T07:30:12Z ERROR connection refused to postgres:5432
2026-05-10T07:30:13Z ERROR connection refused again`

	got := scanLogPatterns(content)
	if len(got) == 0 {
		t.Fatal("expected at least one anomaly, got none")
	}
	if got[0].Category != "db-error" {
		t.Errorf("expected db-error, got %q", got[0].Category)
	}
	if got[0].Count != 2 {
		t.Errorf("expected count 2, got %d", got[0].Count)
	}
}

func TestScanLogPatterns_HTTP5XX(t *testing.T) {
	lines := []struct {
		log      string
		category string
	}{
		{`10.0.0.1 - - "GET / HTTP/1.1" 503 1234`, "http-5xx"},
		{`{"status": 502, "path": "/api"}`, "http-5xx"},
		{`status=500 path=/health`, "http-5xx"},
	}
	for _, tc := range lines {
		got := scanLogPatterns(tc.log)
		if len(got) == 0 {
			t.Errorf("no match for %q", tc.log)
			continue
		}
		if got[0].Category != tc.category {
			t.Errorf("log %q: expected %s, got %s", tc.log, tc.category, got[0].Category)
		}
	}
}

func TestScanLogPatterns_Latency(t *testing.T) {
	cases := []struct {
		log     string
		matches bool
	}{
		{`took 2341ms to process request`, true},
		{`duration=3.2s for /api/v1/search`, true},
		{`latency: 1500ms`, true},
		{`response_time=2.1s`, true},
		{`took 200ms`, false}, // under threshold
		{`duration=0.9s`, false},
	}
	for _, tc := range cases {
		got := scanLogPatterns(tc.log)
		found := false
		for _, a := range got {
			if a.Category == "latency" {
				found = true
				break
			}
		}
		if found != tc.matches {
			t.Errorf("log %q: want match=%v got match=%v", tc.log, tc.matches, found)
		}
	}
}

func TestScanLogPatterns_Dependency(t *testing.T) {
	cases := []string{
		`circuit breaker open for user-events-svc`,
		`ECONNREFUSED connecting to redis:6379`,
		`upstream unavailable: payments-svc`,
		`HTTP 503 from gateway`,
	}
	for _, c := range cases {
		got := scanLogPatterns(c)
		found := false
		for _, a := range got {
			if a.Category == "dependency" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected dependency match for %q", c)
		}
	}
}

func TestScanLogPatterns_Empty(t *testing.T) {
	if got := scanLogPatterns(""); got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
}

func TestScanLogPatterns_RBACForbidden(t *testing.T) {
	cases := []string{
		`forbidden: User "system:serviceaccount:ops:syncer" cannot list resource "configmaps"`,
		`403 Forbidden: insufficient permissions`,
		`kubernetes API error: configmaps is forbidden: User "system:serviceaccount:ns:sa" cannot list resource "configmaps"`,
	}
	for _, c := range cases {
		got := scanLogPatterns(c)
		found := false
		for _, a := range got {
			if a.Category == "rbac-forbidden" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected rbac-forbidden match for %q", c)
		}
	}
}

func TestScanLogPatterns_CertExpiry(t *testing.T) {
	cases := []string{
		`x509: certificate has expired or is not yet valid: current time 2026-05-11`,
		`ERROR TLS handshake failed: certificate has expired`,
		`certificate has expired`,
	}
	for _, c := range cases {
		got := scanLogPatterns(c)
		found := false
		for _, a := range got {
			if a.Category == "cert-expiry" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected cert-expiry match for %q", c)
		}
	}
}

func TestScanLogPatterns_OOMSystem(t *testing.T) {
	cases := []string{
		`memory cgroup out of memory: Killed process 891 (postgres)`,
		`Out of memory: Killed process 1234`,
	}
	for _, c := range cases {
		got := scanLogPatterns(c)
		found := false
		for _, a := range got {
			if a.Category == "oom-system" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected oom-system match for %q", c)
		}
	}
}

func TestScanLogPatterns_NoMatch(t *testing.T) {
	content := `2026-05-10T07:30:11Z INFO  all systems nominal
2026-05-10T07:30:12Z INFO  heartbeat ok`
	got := scanLogPatterns(content)
	if len(got) != 0 {
		t.Errorf("expected no anomalies, got %v", got)
	}
}

func TestScanLogPatterns_SampleTruncated(t *testing.T) {
	long := "a"
	for i := 0; i < 200; i++ {
		long += "x"
	}
	content := "connection refused: " + long
	got := scanLogPatterns(content)
	if len(got) == 0 {
		t.Fatal("expected a match")
	}
	if len(got[0].Sample) > 123 { // 120 ASCII bytes + "…" (3 UTF-8 bytes)
		t.Errorf("sample not truncated: len=%d", len(got[0].Sample))
	}
}
