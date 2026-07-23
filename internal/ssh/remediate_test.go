package ssh

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRemediationCommand_ValidPerOS(t *testing.T) {
	cases := []struct {
		name, os, param, want string
	}{
		{"svc-restart-linux", "linux", "nginx.service", "systemctl restart 'nginx.service'"},
		{"svc-restart-windows", "windows", "Spooler", "Restart-Service -Name 'Spooler'"},
		{"iis-pool-recycle", "windows", "shop", "Import-Module WebAdministration; Restart-WebAppPool -Name 'shop'"},
	}
	for _, c := range cases {
		got, _, err := RemediationCommand(c.name, c.os, c.param)
		if err != nil {
			t.Errorf("%s/%s: unexpected error %v", c.name, c.os, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s/%s: got %q, want %q", c.name, c.os, got, c.want)
		}
	}
}

func TestRemediationCommand_UnknownNameRefused(t *testing.T) {
	if _, _, err := RemediationCommand("rm-rf-slash", "linux", "x"); err == nil {
		t.Error("unknown remediation name must be refused")
	}
}

func TestRemediationCommand_InjectionRefused(t *testing.T) {
	// Every one of these is a shell-injection or metacharacter attempt; the
	// param must be REFUSED, never quoted-and-run.
	bad := []string{
		"nginx; rm -rf /",
		"nginx && reboot",
		"$(reboot)",
		"`reboot`",
		"nginx service", // space
		"a'b",           // quote
		"a|b",
		"a\nb",
		"../../etc/passwd",
		"", // empty
	}
	for _, p := range bad {
		if _, _, err := RemediationCommand("svc-restart-linux", "linux", p); err == nil {
			t.Errorf("param %q must be refused as an injection risk", p)
		}
	}
}

func TestRemediationCommand_WrongOSRefused(t *testing.T) {
	// svc-restart-linux has no Windows variant, and vice-versa.
	if _, _, err := RemediationCommand("svc-restart-linux", "windows", "nginx"); err == nil {
		t.Error("svc-restart-linux must not be available on windows")
	}
	if _, _, err := RemediationCommand("svc-restart-windows", "linux", "Spooler"); err == nil {
		t.Error("svc-restart-windows must not be available on linux")
	}
	if _, _, err := RemediationCommand("svc-restart-linux", "plan9", "nginx"); err == nil {
		t.Error("unknown OS family must be refused")
	}
}

func TestIsRemediationKind(t *testing.T) {
	for _, k := range []string{"svc-restart-linux", "svc-restart-windows", "iis-pool-recycle"} {
		if !IsRemediationKind(k) {
			t.Errorf("%q should be a known remediation kind", k)
		}
	}
	for _, k := range []string{"rollout-restart", "delete-pod", "shell", ""} {
		if IsRemediationKind(k) {
			t.Errorf("%q must NOT be an SSH remediation kind", k)
		}
	}
}

// fakeRunner records the command it was handed and returns canned output.
type fakeRunner struct {
	gotCmd string
	out    string
	runErr error
	closed bool
}

func (f *fakeRunner) RunCommand(_ context.Context, cmd string) (io.Reader, error) {
	f.gotCmd = cmd
	if f.runErr != nil {
		return nil, f.runErr
	}
	return strings.NewReader(f.out), nil
}
func (f *fakeRunner) Close() error { f.closed = true; return nil }

// withFakeDialer swaps the package dialer for the duration of a test.
func withFakeDialer(t *testing.T, fr *fakeRunner, dialErr error) {
	t.Helper()
	prev := dialForRemediation
	dialForRemediation = func(_ context.Context, _ Options) (commandRunner, error) {
		if dialErr != nil {
			return nil, dialErr
		}
		return fr, nil
	}
	t.Cleanup(func() { dialForRemediation = prev })
}

func TestRunRemediation_RunsExactAllowlistedCommand(t *testing.T) {
	fr := &fakeRunner{out: "ok"}
	withFakeDialer(t, fr, nil)

	out, _, err := RunRemediation(context.Background(), Options{Host: "h"}, "svc-restart-linux", "linux", "nginx.service", true)
	if err != nil {
		t.Fatalf("RunRemediation: %v", err)
	}
	if fr.gotCmd != "systemctl restart 'nginx.service'" {
		t.Errorf("executed command was not the allowlist template: %q", fr.gotCmd)
	}
	if out != "ok" {
		t.Errorf("output: %q", out)
	}
	if !fr.closed {
		t.Error("client should be closed after use")
	}
}

func TestRunRemediation_WriteGateBlocksWhenNotAllowed(t *testing.T) {
	fr := &fakeRunner{out: "ok"}
	withFakeDialer(t, fr, nil)

	_, _, err := RunRemediation(context.Background(), Options{Host: "h"}, "svc-restart-linux", "linux", "nginx.service", false)
	if err == nil {
		t.Fatal("allow=false must refuse")
	}
	if fr.gotCmd != "" {
		t.Errorf("no command should have been dialed/run when write mode is off, ran %q", fr.gotCmd)
	}
}

func TestRunRemediation_BadParamNeverDials(t *testing.T) {
	fr := &fakeRunner{out: "ok"}
	withFakeDialer(t, fr, nil)

	if _, _, err := RunRemediation(context.Background(), Options{Host: "h"}, "svc-restart-linux", "linux", "nginx; rm -rf /", true); err == nil {
		t.Fatal("injection param must be refused")
	}
	if fr.gotCmd != "" {
		t.Errorf("refused param must not reach the host, ran %q", fr.gotCmd)
	}
}

func TestRunRemediation_DialErrorSurfaces(t *testing.T) {
	withFakeDialer(t, nil, errors.New("connection refused"))
	if _, _, err := RunRemediation(context.Background(), Options{Host: "h"}, "svc-restart-linux", "linux", "nginx", true); err == nil {
		t.Error("a dial failure should surface as an error")
	}
}
