package investigate

// diagrunner.go adapts the SSH diagnostics allowlist (internal/ssh) into the
// DiagFn shape profiles register. This is the ONLY bridge from the
// investigation framework to remote command execution — commands are always
// selected by allowlist name, tier-gated, and parameter-validated inside
// internal/ssh/diagnostics.go.

import (
	"context"
	"fmt"

	exassh "github.com/exalm-ai/exalm/internal/ssh"
)

// SSHDiagRunner runs one allowlisted diagnostic against the session's
// remote host. Profiles pass it to DiagCollector; tests inject fakes.
func SSHDiagRunner(ctx context.Context, s *LogSession, name, param string) (string, string, error) {
	if s == nil || s.SSH == nil {
		return "", "", fmt.Errorf("no remote host attached to this analysis")
	}
	tier, err := exassh.ParseDiagTier(s.DiagTier)
	if err != nil {
		return "", "", err
	}
	out, spec, err := exassh.RunDiag(ctx, exassh.Options{
		Host:     s.SSH.Host,
		User:     s.SSH.User,
		KeyPath:  s.SSH.KeyPath,
		Port:     s.SSH.Port,
		Password: s.SSH.Password,
	}, name, s.SSH.OSFamily, tier, param)
	if err != nil {
		return "", "", err
	}
	return out, spec.Describe, nil
}
