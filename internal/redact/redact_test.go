package redact

import (
	"strings"
	"testing"
)

// These tests are non-negotiable: redaction is the trust boundary of Exalm.
// Add a test case for every new pattern. Never lower a test's strictness
// to make code pass; lower it only if you've replaced it with a stricter check.

func TestRedact_AWSAccessKey(t *testing.T) {
	e := New()
	in := "use AKIAIOSFODNN7EXAMPLE here"
	got := e.Redact(in)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("AWS key leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:AWS_ACCESS_KEY]") {
		t.Fatalf("expected redaction marker, got %q", got)
	}
}

func TestRedact_AnthropicKey(t *testing.T) {
	e := New()
	in := "ANTHROPIC_API_KEY=sk-ant-abc123def456ghi789jkl012mno345pqr678"
	got := e.Redact(in)
	if strings.Contains(got, "sk-ant-abc123") {
		t.Fatalf("Anthropic key leaked: %q", got)
	}
}

func TestRedact_OpenAIKey(t *testing.T) {
	e := New()
	in := "key=sk-abcdefghijklmnopqrstuvwxyz123456"
	got := e.Redact(in)
	if strings.Contains(got, "sk-abcdefghij") {
		t.Fatalf("OpenAI key leaked: %q", got)
	}
}

func TestRedact_GitHubToken(t *testing.T) {
	e := New()
	in := "token: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	got := e.Redact(in)
	if strings.Contains(got, "ghp_aaaaaaa") {
		t.Fatalf("GitHub token leaked: %q", got)
	}
}

func TestRedact_JWT(t *testing.T) {
	e := New()
	in := "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	got := e.Redact(in)
	if strings.Contains(got, "eyJhbGciOiJIUzI1NiIs") {
		t.Fatalf("JWT leaked: %q", got)
	}
}

func TestRedact_BearerToken(t *testing.T) {
	e := New()
	in := "Authorization: Bearer abc123def456ghi789jkl012mno345pqr678"
	got := e.Redact(in)
	if strings.Contains(got, "abc123def456ghi789") {
		t.Fatalf("bearer token leaked: %q", got)
	}
}

func TestRedact_PrivateKey(t *testing.T) {
	e := New()
	in := `before
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvQ...
fake key bytes here
-----END RSA PRIVATE KEY-----
after`
	got := e.Redact(in)
	if strings.Contains(got, "MIIEpAIBAAKCAQEAvQ") {
		t.Fatalf("private key block leaked: %q", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("redaction nuked surrounding context: %q", got)
	}
}

func TestRedact_Password(t *testing.T) {
	e := New()
	cases := []string{
		`password=hunter2isgood`,
		`PASSWORD: "supersecret123"`,
		`pwd=correcthorsebatterystaple`,
	}
	for _, in := range cases {
		got := e.Redact(in)
		if strings.Contains(got, "hunter2") || strings.Contains(got, "supersecret") || strings.Contains(got, "correcthorse") {
			t.Errorf("password leaked from %q -> %q", in, got)
		}
	}
}

func TestRedact_ConnectionString(t *testing.T) {
	e := New()
	in := "DATABASE_URL=postgres://app:s3cr3t-pass@db.internal:5432/prod"
	got := e.Redact(in)
	if strings.Contains(got, "s3cr3t-pass") {
		t.Fatalf("connection password leaked: %q", got)
	}
	if !strings.Contains(got, "postgres://app") {
		t.Fatalf("redaction nuked the URL prefix: %q", got)
	}
}

func TestRedact_OptionalEmail(t *testing.T) {
	plain := New()
	if !strings.Contains(plain.Redact("contact me at user@example.com"), "user@example.com") {
		t.Fatalf("default engine should NOT redact email")
	}
	with := New("email")
	if strings.Contains(with.Redact("contact me at user@example.com"), "user@example.com") {
		t.Fatalf("email should be redacted with optional pattern enabled")
	}
}

func TestRedact_NoLeakOnEmpty(t *testing.T) {
	e := New()
	if got := e.Redact(""); got != "" {
		t.Fatalf("empty input should return empty, got %q", got)
	}
}

func TestRedact_PreservesBenignText(t *testing.T) {
	e := New()
	in := "GET /api/users 200 in 23ms"
	got := e.Redact(in)
	if got != in {
		t.Fatalf("benign text should be preserved unchanged: in=%q out=%q", in, got)
	}
}

func TestRedact_DockerConfigJSON(t *testing.T) {
	e := New()
	in := `.dockerconfigjson: eyJhdXRocyI6eyJyZWdpc3RyeS5leGFtcGxlLmNvbSI6eyJ1c2VybmFtZSI6InVzZXIiLCJwYXNzd29yZCI6InNlY3JldCJ9fX0=`
	got := e.Redact(in)
	if strings.Contains(got, "eyJhdXRocyI6") {
		t.Fatalf("docker config JSON leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:DOCKER_CONFIG]") {
		t.Fatalf("expected redaction marker, got: %q", got)
	}
	if !strings.Contains(got, ".dockerconfigjson") {
		t.Fatalf("redaction nuked the key name: %q", got)
	}
}

func TestRedact_WindowsSID(t *testing.T) {
	e := New()
	in := "User S-1-5-21-1234567890-1111111111-2222222222-1001 logged in"
	got := e.Redact(in)
	if strings.Contains(got, "S-1-5-21-1234567890") {
		t.Fatalf("Windows SID leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:WINDOWS_SID]") {
		t.Fatalf("expected SID marker, got %q", got)
	}
	if !strings.Contains(got, "logged in") {
		t.Fatalf("redaction nuked surrounding context: %q", got)
	}
}

func TestRedact_NTLMHash(t *testing.T) {
	e := New()
	in := "hash: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 dumped"
	got := e.Redact(in)
	if strings.Contains(got, "aad3b435b51404ee") {
		t.Fatalf("NTLM hash leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:NTLM_HASH]") {
		t.Fatalf("expected NTLM marker, got %q", got)
	}
}

func TestRedact_OptionalInternalIPv4(t *testing.T) {
	plain := New()
	if !strings.Contains(plain.Redact("from 10.0.5.12 to 192.168.1.7"), "10.0.5.12") {
		t.Fatalf("default engine should NOT redact internal IPv4")
	}
	with := New("internal-ipv4")
	got := with.Redact("from 10.0.5.12 to 192.168.1.7 and 172.20.0.4 and 8.8.8.8")
	if strings.Contains(got, "10.0.5.12") || strings.Contains(got, "192.168.1.7") || strings.Contains(got, "172.20.0.4") {
		t.Fatalf("internal IPs should be redacted: %q", got)
	}
	if !strings.Contains(got, "8.8.8.8") {
		t.Fatalf("public IPs must NOT be redacted: %q", got)
	}
}

func TestRedact_OptionalWindowsAccount(t *testing.T) {
	plain := New()
	if !strings.Contains(plain.Redact("logon from CORP\\jdoe"), "CORP\\jdoe") {
		t.Fatalf("default engine should NOT redact windows account")
	}
	with := New("windows-account")
	got := with.Redact("logon from CORP\\jdoe at workstation WS-001")
	if strings.Contains(got, "CORP\\jdoe") {
		t.Fatalf("windows account should be redacted: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:WINDOWS_ACCOUNT]") {
		t.Fatalf("expected account marker, got %q", got)
	}
}

func TestRedact_OptionalLinuxUsername(t *testing.T) {
	plain := New()
	if !strings.Contains(plain.Redact("sshd[1234]: Accepted password for root from 10.0.0.1"), "for root") {
		t.Fatalf("default engine should NOT redact linux username")
	}
	with := New("linux-username")
	got := with.Redact("sshd[1234]: Accepted password for root from 10.0.0.1")
	if strings.Contains(got, "for root") {
		t.Fatalf("linux username should be redacted: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:LINUX_USER]") {
		t.Fatalf("expected linux user marker, got %q", got)
	}
}

func TestDiff_ReportsMatches(t *testing.T) {
	e := New()
	in := "AKIAIOSFODNN7EXAMPLE and ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	d := e.Diff(in)
	if len(d) != 2 {
		t.Fatalf("expected 2 redactions, got %d", len(d))
	}
}
