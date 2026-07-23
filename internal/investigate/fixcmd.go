package investigate

// fixcmd.go implements the shared `<analyzer> fix` subcommand body so syslog,
// eventlog, and iis don't each re-implement the list → --apply gate →
// per-fix confirmation → SSH-apply loop. It mirrors the k8s `fix` subcommand
// (plugins/k8s/k8s.go): without --apply it lists the applicable fixes and
// exits; with --apply it prompts y/N per fix and executes the confirmed ones
// through the allowlisted SSH remediator.

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	exassh "github.com/exalm-ai/exalm/internal/ssh"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// RunFixSubcommand drives the interactive fix flow over the analyzer report's
// findings. rep is the report from the plugin's analyze() (its Findings carry
// the proposed remediations); rp is the SSH connection for the analyzed host
// (nil for a local file). domainTitle names the report (e.g. "syslog fix").
func RunFixSubcommand(ctx context.Context, args plugin.RunArgs, rep plugin.Report, domainTitle string, rp *RemoteParams) (plugin.Report, error) {
	var fixable []plugin.Finding
	for _, f := range rep.Findings {
		if f.Remediation != nil && exassh.IsRemediationKind(f.Remediation.Kind) {
			fixable = append(fixable, f)
		}
	}

	if len(fixable) == 0 {
		fmt.Fprintln(args.Stdout, "No auto-applicable fixes found (findings without a remote-executable remediation are advice-only).") //nolint:errcheck // plugin stdout
		return plugin.Report{Title: domainTitle, Summary: "No auto-applicable fixes.", Findings: rep.Findings}, nil
	}

	fmt.Fprintf(args.Stdout, "\n%d auto-applicable fix(es):\n\n", len(fixable)) //nolint:errcheck // plugin stdout
	for i, f := range fixable {
		fmt.Fprintf(args.Stdout, "  [%d] [%s] %s\n      %s\n", i+1, strings.ToUpper(string(f.Severity)), f.Title, f.Remediation.KubectlCmd) //nolint:errcheck // plugin stdout
		if f.Remediation.Warning != "" {
			fmt.Fprintf(args.Stdout, "      ⚠ %s\n", f.Remediation.Warning) //nolint:errcheck // plugin stdout
		}
		fmt.Fprintln(args.Stdout) //nolint:errcheck // plugin stdout
	}

	if args.Flags["dry-run"] == "true" {
		fmt.Fprintln(args.Stdout, "Dry-run: no changes applied.") //nolint:errcheck // plugin stdout
		return plugin.Report{Title: domainTitle + " (dry-run)", Findings: rep.Findings}, nil
	}

	if args.Flags["apply"] != "true" {
		fmt.Fprintln(args.Stderr, "Pass --apply to execute these fixes over SSH.") //nolint:errcheck // plugin stderr
		return plugin.Report{Title: domainTitle, Findings: rep.Findings}, nil
	}

	if rp == nil {
		return plugin.Report{}, fmt.Errorf("--apply needs a remote host: re-run with --host <host> (and --ssh-user/--ssh-key as needed)")
	}

	apply := SSHRemediator(rp, true)
	scanner := bufio.NewScanner(args.Stdin)
	var applied, skipped int
	for _, f := range fixable {
		fmt.Fprintf(args.Stdout, "Apply fix for [%s] %s on %s? [y/N] ", strings.ToUpper(string(f.Severity)), f.Title, rp.Host) //nolint:errcheck // plugin stdout
		scanner.Scan()
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer != "y" && answer != "yes" {
			skipped++
			continue
		}
		if err := apply(ctx, *f.Remediation); err != nil {
			fmt.Fprintf(args.Stderr, "  Error: %v\n", err) //nolint:errcheck // plugin stderr
		} else {
			fmt.Fprintf(args.Stdout, "  ✓ Applied: %s\n", f.Remediation.Description) //nolint:errcheck // plugin stdout
			applied++
		}
	}

	return plugin.Report{
		Title:    domainTitle,
		Summary:  fmt.Sprintf("Applied %d fix(es), skipped %d.", applied, skipped),
		Findings: rep.Findings,
	}, nil
}
