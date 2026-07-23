package ssh

// remediate.go is the ONLY source of remote MUTATING command strings. It is
// the write-side mirror of diagnostics.go and enforces the identical trust
// model — with one deliberate difference: there is no "tier" that enables
// mutations implicitly. A mutating command runs only when the caller passes an
// explicit allow flag (wired to the CLI --apply gate, the dashboard token +
// CSRF check, or MCP --mcp-write). Everything else is refused, never
// sanitized-and-run:
//
//   - Commands are keyed by a fixed remediation name (svc-restart-linux,
//     svc-restart-windows, iis-pool-recycle); the LLM never chooses them and
//     never supplies the command string.
//   - The single %s slot accepts only paramRe-validated values (the same
//     regexp diagnostics.go uses: no quotes, spaces, or shell metacharacters),
//     substituted inside single quotes. A bad param is refused.
//   - The command string is ALWAYS built from the compile-time template here,
//     NEVER from a RemediationAction's display command (KubectlCmd is
//     display/copy only and is never executed).
//
// Adding a row is a reviewed change: every command must be a minimal,
// well-understood service action with a clear rollback.

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// RemediationSpec is one allowlisted mutating command.
type RemediationSpec struct {
	Name     string // remediation key, e.g. "svc-restart-linux"
	Linux    string // POSIX sh command; "" = not available on linux
	Windows  string // PowerShell command; "" = not available on windows
	Param    bool   // true when the command has one validated %s slot
	MaxBytes int    // output cap; 0 => defaultRemediationMaxBytes
	Describe string // human description of what the command does
}

const defaultRemediationMaxBytes = 16 * 1024

// remediationTable is the complete write allowlist. It is intentionally tiny:
// one safe, reversible service action per supported OS/domain. The %s slot is
// the service/unit/app-pool name, single-quoted and paramRe-validated.
var remediationTable = []RemediationSpec{
	{
		Name:     "svc-restart-linux",
		Linux:    "systemctl restart '%s'",
		Param:    true,
		Describe: "Restart a failed systemd unit",
	},
	{
		Name:     "svc-restart-windows",
		Windows:  "Restart-Service -Name '%s'",
		Param:    true,
		Describe: "Restart a crashed Windows service",
	},
	{
		Name:     "iis-pool-recycle",
		Windows:  "Import-Module WebAdministration; Restart-WebAppPool -Name '%s'",
		Param:    true,
		Describe: "Recycle an IIS application pool",
	},
}

// RemediationSpecFor returns the allowlist row for a remediation name.
func RemediationSpecFor(name string) (RemediationSpec, bool) {
	for _, r := range remediationTable {
		if r.Name == name {
			return r, true
		}
	}
	return RemediationSpec{}, false
}

// IsRemediationKind reports whether name is a known SSH remediation kind. Used
// by the ApplyFix router to decide between the k8s executor and the SSH
// executor without hard-coding the kind list at every call site.
func IsRemediationKind(name string) bool {
	_, ok := RemediationSpecFor(name)
	return ok
}

// RemediationCommand resolves the command string for (name, osFamily),
// substituting the validated param. Refusal — never sanitize-and-run. The
// returned string is built from the compile-time template, not from any
// caller-supplied command text.
func RemediationCommand(name, osFamily, param string) (string, RemediationSpec, error) {
	spec, ok := RemediationSpecFor(name)
	if !ok {
		return "", RemediationSpec{}, fmt.Errorf("unknown remediation %q", name)
	}
	var tmpl string
	switch strings.ToLower(osFamily) {
	case "linux":
		tmpl = spec.Linux
	case "windows":
		tmpl = spec.Windows
	default:
		return "", spec, fmt.Errorf("remediation %q: unknown OS family %q", name, osFamily)
	}
	if tmpl == "" {
		return "", spec, fmt.Errorf("remediation %q is not available on %s", name, osFamily)
	}
	if spec.Param {
		if !paramRe.MatchString(param) {
			return "", spec, fmt.Errorf("remediation %q: parameter %q refused (letters, digits, ._@:- only)", name, param)
		}
		tmpl = fmt.Sprintf(tmpl, param)
	} else if param != "" {
		return "", spec, fmt.Errorf("remediation %q takes no parameter", name)
	}
	return tmpl, spec, nil
}

// commandRunner is the minimal SSH surface RunRemediation needs. *Client
// satisfies it; tests inject a fake so the executor is verifiable without a
// live host.
type commandRunner interface {
	RunCommand(ctx context.Context, cmd string) (io.Reader, error)
	Close() error
}

// dialForRemediation is the client factory RunRemediation uses. Package-level
// so tests can swap in a fake dialer without a real SSH server. Production
// dials via Dial with TOFU host verification.
var dialForRemediation = func(ctx context.Context, opts Options) (commandRunner, error) {
	return Dial(ctx, opts)
}

// RunRemediation dials the host and runs one allowlisted mutating command.
// This is the ONLY path that executes a remote mutation. allow MUST be true —
// it is the explicit write gate (from --apply / dashboard auth / --mcp-write);
// a false allow is refused before any connection is made, so a
// misconfiguration fails closed.
func RunRemediation(ctx context.Context, opts Options, name, osFamily, param string, allow bool) (string, RemediationSpec, error) {
	cmd, spec, err := RemediationCommand(name, osFamily, param)
	if err != nil {
		return "", spec, err
	}
	if !allow {
		return "", spec, fmt.Errorf("remediation %q refused: write mode not enabled", name)
	}
	client, err := dialForRemediation(ctx, opts)
	if err != nil {
		return "", spec, fmt.Errorf("remediation %q: %w", name, err)
	}
	defer client.Close() //nolint:errcheck // best-effort close
	out, err := client.RunCommand(ctx, cmd)
	if err != nil {
		return "", spec, fmt.Errorf("remediation %q: %w", name, err)
	}
	maxBytes := spec.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultRemediationMaxBytes
	}
	data, err := io.ReadAll(io.LimitReader(out, int64(maxBytes)))
	if err != nil {
		return "", spec, fmt.Errorf("remediation %q: read: %w", name, err)
	}
	return string(data), spec, nil
}
