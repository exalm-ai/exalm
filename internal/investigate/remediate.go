package investigate

// remediate.go is the write-side counterpart of diagrunner.go: it adapts the
// SSH mutation allowlist (internal/ssh/remediate.go) into an ApplyFix closure
// —  func(ctx, plugin.RemediationAction) error — that the web dashboard, the
// CLI fix subcommands, and the MCP server all use to apply an analyzer's
// proposed shell remediation. Commands are always selected by allowlist name
// and parameter-validated inside internal/ssh; the RemediationAction's display
// command (KubectlCmd) is never executed.

import (
	"context"
	"fmt"

	exassh "github.com/exalm-ai/exalm/internal/ssh"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// osFamilyForShell maps a RemediationAction.Shell to the SSH allowlist OS
// family. The finding's Remediate hook sets Shell ("bash"/"powershell") to
// match the domain, so this selects the correct command variant.
func osFamilyForShell(shell string) string {
	if shell == "powershell" {
		return "windows"
	}
	return "linux"
}

// SSHRemediator returns an ApplyFix closure that executes SSH remediations
// (svc-restart-linux, svc-restart-windows, iis-pool-recycle) against the host
// in rp. allow is the write gate (from --apply / dashboard auth / --mcp-write);
// RunRemediation refuses before dialing when it is false. A nil rp or a
// non-SSH kind is rejected — the ApplyFix router must not route k8s kinds here.
func SSHRemediator(rp *RemoteParams, allow bool) func(context.Context, plugin.RemediationAction) error {
	return func(ctx context.Context, a plugin.RemediationAction) error {
		if rp == nil {
			return fmt.Errorf("no remote host is attached to this analysis; SSH remediation needs --host")
		}
		if !exassh.IsRemediationKind(a.Kind) {
			return fmt.Errorf("unsupported SSH remediation kind %q", a.Kind)
		}
		_, _, err := exassh.RunRemediation(ctx, exassh.Options{
			Host:     rp.Host,
			User:     rp.User,
			KeyPath:  rp.KeyPath,
			Port:     rp.Port,
			Password: rp.Password,
		}, a.Kind, osFamilyForShell(a.Shell), a.Name, allow)
		return err
	}
}
