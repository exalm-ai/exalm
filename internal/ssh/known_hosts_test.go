package ssh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gocrypto "golang.org/x/crypto/ssh"
)

// makeECKey generates a fresh ECDSA P-256 key pair and returns the
// gocrypto.Signer and the corresponding gocrypto.PublicKey.
func makeECKey(t *testing.T) (gocrypto.Signer, gocrypto.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	signer, err := gocrypto.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer, signer.PublicKey()
}

// fakeAddr is a minimal net.Addr for use in callback tests.
type fakeAddr struct{ s string }

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return a.s }

// withTempKnownHosts sets knownHostsPathOverride to a fresh file in t.TempDir
// and restores the original value after the test.
func withTempKnownHosts(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	orig := knownHostsPathOverride
	knownHostsPathOverride = path
	t.Cleanup(func() { knownHostsPathOverride = orig })
	return path
}

func TestTOFU_AcceptsFirstConnection(t *testing.T) {
	withTempKnownHosts(t)

	_, pub := makeECKey(t)
	cb, err := TOFUCallback(false)
	if err != nil {
		t.Fatalf("TOFUCallback: %v", err)
	}

	addr := fakeAddr{"192.0.2.1:22"}
	if err := cb("192.0.2.1:22", addr, pub); err != nil {
		t.Fatalf("first connection should be accepted, got: %v", err)
	}
}

func TestTOFU_AcceptsFirstConnection_KeyStored(t *testing.T) {
	path := withTempKnownHosts(t)

	_, pub := makeECKey(t)
	cb, err := TOFUCallback(false)
	if err != nil {
		t.Fatalf("TOFUCallback: %v", err)
	}

	addr := fakeAddr{"192.0.2.2:22"}
	if err := cb("192.0.2.2:22", addr, pub); err != nil {
		t.Fatalf("first connection: %v", err)
	}

	// Verify the key was written to the file.
	data, err := readFile(path)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	fp := fingerprint(pub)
	if !strings.Contains(data, fp) {
		t.Errorf("expected fingerprint %s to appear in known_hosts, got:\n%s", fp, data)
	}
}

func TestTOFU_AcceptsKnownKey(t *testing.T) {
	withTempKnownHosts(t)

	_, pub := makeECKey(t)
	cb, err := TOFUCallback(false)
	if err != nil {
		t.Fatalf("TOFUCallback: %v", err)
	}

	addr := fakeAddr{"10.0.0.1:22"}

	// First connection — TOFU persist.
	if err := cb("10.0.0.1:22", addr, pub); err != nil {
		t.Fatalf("first connection: %v", err)
	}

	// Second connection with the same key must succeed.
	cb2, err := TOFUCallback(false)
	if err != nil {
		t.Fatalf("TOFUCallback (2): %v", err)
	}
	if err := cb2("10.0.0.1:22", addr, pub); err != nil {
		t.Fatalf("second connection with same key should be accepted, got: %v", err)
	}
}

func TestTOFU_RejectsMismatch(t *testing.T) {
	withTempKnownHosts(t)

	_, pubA := makeECKey(t)
	_, pubB := makeECKey(t)

	addr := fakeAddr{"10.0.0.2:22"}

	// First connection with key A.
	cb, err := TOFUCallback(false)
	if err != nil {
		t.Fatalf("TOFUCallback: %v", err)
	}
	if err := cb("10.0.0.2:22", addr, pubA); err != nil {
		t.Fatalf("first connection: %v", err)
	}

	// Second connection with key B — must be rejected.
	cb2, err := TOFUCallback(false)
	if err != nil {
		t.Fatalf("TOFUCallback (2): %v", err)
	}
	err = cb2("10.0.0.2:22", addr, pubB)
	if err == nil {
		t.Fatal("mismatch connection should be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "host key mismatch") {
		t.Errorf("expected 'host key mismatch' in error, got: %v", err)
	}
	// Error should include both fingerprints.
	fpA := fingerprint(pubA)
	fpB := fingerprint(pubB)
	if !strings.Contains(err.Error(), fpA) {
		t.Errorf("expected old fingerprint %s in error, got: %v", fpA, err)
	}
	if !strings.Contains(err.Error(), fpB) {
		t.Errorf("expected new fingerprint %s in error, got: %v", fpB, err)
	}
	// Recovery hint must mention known_hosts.
	if !strings.Contains(err.Error(), "known_hosts") {
		t.Errorf("expected recovery hint mentioning known_hosts in error, got: %v", err)
	}
}

func TestTOFU_StrictRejectsUnknown(t *testing.T) {
	withTempKnownHosts(t)

	_, pub := makeECKey(t)
	cb, err := TOFUCallback(true) // strict = true
	if err != nil {
		t.Fatalf("TOFUCallback: %v", err)
	}

	addr := fakeAddr{"10.0.0.3:22"}
	err = cb("10.0.0.3:22", addr, pub)
	if err == nil {
		t.Fatal("strict mode should reject unknown host, got nil error")
	}
	if !strings.Contains(err.Error(), "unknown host") {
		t.Errorf("expected 'unknown host' in error, got: %v", err)
	}
}

func TestTOFU_StrictAcceptsKnownKey(t *testing.T) {
	withTempKnownHosts(t)

	_, pub := makeECKey(t)
	addr := fakeAddr{"10.0.0.4:22"}

	// Seed via non-strict callback.
	cbNonStrict, err := TOFUCallback(false)
	if err != nil {
		t.Fatalf("TOFUCallback (non-strict): %v", err)
	}
	if err := cbNonStrict("10.0.0.4:22", addr, pub); err != nil {
		t.Fatalf("seed connection: %v", err)
	}

	// Now strict mode should accept the already-known key.
	cbStrict, err := TOFUCallback(true)
	if err != nil {
		t.Fatalf("TOFUCallback (strict): %v", err)
	}
	if err := cbStrict("10.0.0.4:22", addr, pub); err != nil {
		t.Fatalf("strict mode should accept known key, got: %v", err)
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	_, pub := makeECKey(t)

	fp1 := fingerprint(pub)
	fp2 := fingerprint(pub)

	if fp1 != fp2 {
		t.Errorf("fingerprint not deterministic: %s vs %s", fp1, fp2)
	}
	if fp1 == "" {
		t.Error("fingerprint must not be empty")
	}
}

func TestFingerprint_DifferentKeys(t *testing.T) {
	_, pubA := makeECKey(t)
	_, pubB := makeECKey(t)

	if fingerprint(pubA) == fingerprint(pubB) {
		t.Error("distinct keys should produce distinct fingerprints")
	}
}

func TestTOFU_HostWithoutPort(t *testing.T) {
	withTempKnownHosts(t)

	_, pub := makeECKey(t)

	// Some SSH implementations pass hostname without port to the callback.
	cb, err := TOFUCallback(false)
	if err != nil {
		t.Fatalf("TOFUCallback: %v", err)
	}

	addr := fakeAddr{"192.0.2.10:22"}
	// Hostname without port.
	if err := cb("192.0.2.10", addr, pub); err != nil {
		t.Fatalf("hostname without port should be accepted on first use, got: %v", err)
	}

	// Second connection with the same hostname-without-port must also pass.
	cb2, err := TOFUCallback(false)
	if err != nil {
		t.Fatalf("TOFUCallback (2): %v", err)
	}
	if err := cb2("192.0.2.10", addr, pub); err != nil {
		t.Fatalf("same key, hostname without port, second connection: %v", err)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// readFile reads the file at path and returns its contents as a string.
func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
