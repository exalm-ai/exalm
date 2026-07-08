package ssh

// diagnostics.go is the ONLY source of remote diagnostic command strings for
// the investigation framework. Commands are keyed by collector name, fixed
// at compile time, read-only, and tier-gated:
//
//   off      — no remote diagnostics at all (log collection still works)
//   readonly — basic system state (disk, memory, uptime, services, kernel
//              ring, journal); the default
//   full     — adds security-sensitive READS (auth logs, login history,
//              firewall state, certificate expiry, scheduled tasks); opt-in
//              via --remote-diag full or EXALM_REMOTE_DIAG=full
//
// The planner selects commands by NAME only — neither the user's free text
// nor the LLM can inject a command string. The single parameterized slot
// (%s) accepts only paramRe-validated values (no quotes, spaces, or shell
// metacharacters) inside single quotes, refused otherwise — never sanitized
// and run.

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// DiagTier is the remote-diagnostics permission level.
type DiagTier string

const (
	TierOff      DiagTier = "off"
	TierReadonly DiagTier = "readonly"
	TierFull     DiagTier = "full"
)

// ParseDiagTier normalizes a tier string ("" => readonly, the default).
func ParseDiagTier(s string) (DiagTier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "readonly":
		return TierReadonly, nil
	case "off":
		return TierOff, nil
	case "full":
		return TierFull, nil
	default:
		return "", fmt.Errorf("invalid remote-diag tier %q (use off, readonly, or full)", s)
	}
}

// allows reports whether a tier permits commands requiring min.
func (t DiagTier) allows(min DiagTier) bool {
	rank := map[DiagTier]int{TierOff: 0, TierReadonly: 1, TierFull: 2}
	return rank[t] >= rank[min]
}

// DiagSpec is one allowlisted diagnostic.
type DiagSpec struct {
	Name     string   // collector key, e.g. "sys-disk"
	Tier     DiagTier // minimum tier required
	Linux    string   // POSIX sh command; "" = not available on linux
	Windows  string   // PowerShell command; "" = not available on windows
	Param    bool     // true when the command has one validated %s slot
	MaxBytes int      // output cap
	Describe string   // human description, shown in InvestigationStep details
}

// paramRe is the ONLY shape a runtime value may take inside a diagnostic
// command: unit/service/provider names. Anything else is refused.
var paramRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:\-]{0,127}$`)

const defaultDiagMaxBytes = 64 * 1024

// diagTable is the complete allowlist. Adding a row is a reviewed change —
// every command must be read-only and must never read credential material.
var diagTable = []DiagSpec{
	// ── readonly tier: basic system state ──
	{Name: "sys-disk", Tier: TierReadonly,
		Linux:    "df -h | head -n 30",
		Windows:  "Get-Volume | Select-Object DriveLetter,FileSystemLabel,SizeRemaining,Size | Format-Table -AutoSize",
		Describe: "filesystem usage"},
	{Name: "sys-memory", Tier: TierReadonly,
		Linux:    "free -m 2>/dev/null || vm_stat",
		Windows:  "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory",
		Describe: "memory usage"},
	{Name: "sys-uptime", Tier: TierReadonly,
		Linux:    "uptime",
		Windows:  "Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime",
		Describe: "uptime / last boot"},
	{Name: "svc-failed", Tier: TierReadonly,
		Linux:    "systemctl --failed --no-pager --plain 2>/dev/null | head -n 50",
		Windows:  "Get-Service | Where-Object {$_.Status -ne 'Running' -and $_.StartType -eq 'Automatic'} | Select-Object Name,Status,StartType",
		Describe: "failed services"},
	{Name: "svc-status", Tier: TierReadonly, Param: true,
		Linux:    "systemctl status '%s' --no-pager -l -n 20 2>/dev/null",
		Windows:  "Get-Service -Name '%s' | Select-Object Name,Status,StartType",
		Describe: "service status"},
	{Name: "journal-unit", Tier: TierReadonly, Param: true,
		Linux:    "journalctl -u '%s' -n 200 --no-pager 2>/dev/null",
		Windows:  "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='%s'} -MaxEvents 100 | Format-List TimeCreated,Id,LevelDisplayName,Message",
		Describe: "recent journal/provider entries"},
	{Name: "kernel-ring", Tier: TierReadonly,
		Linux:    "dmesg --ctime 2>/dev/null | tail -n 200",
		Windows:  "Get-WinEvent -LogName System -MaxEvents 100 | Where-Object {$_.Level -le 3} | Format-List TimeCreated,ProviderName,Id,Message",
		Describe: "kernel ring buffer / system errors"},
	{Name: "iis-apppools", Tier: TierReadonly,
		Windows:  "Get-IISAppPool 2>$null | Select-Object Name,State",
		Describe: "IIS application pool states"},
	{Name: "http-error-log", Tier: TierReadonly,
		Linux:    "tail -n 500 /var/log/nginx/error.log 2>/dev/null || tail -n 500 /var/log/apache2/error.log 2>/dev/null || tail -n 500 /var/log/httpd/error_log 2>/dev/null",
		Describe: "web server error log tail"},

	// ── full tier: security-sensitive reads (opt-in) ──
	{Name: "auth-log", Tier: TierFull,
		Linux:    "tail -n 300 /var/log/auth.log 2>/dev/null || tail -n 300 /var/log/secure 2>/dev/null || journalctl _COMM=sshd -n 300 --no-pager 2>/dev/null",
		Windows:  "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 2>$null | Format-List TimeCreated,Id,Message",
		Describe: "authentication log tail"},
	{Name: "login-history", Tier: TierFull,
		Linux:    "last -n 25 2>/dev/null",
		Windows:  "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50 2>$null | Format-List TimeCreated,Id,Message",
		Describe: "recent login history"},
	{Name: "firewall-state", Tier: TierFull,
		Linux:    "nft list ruleset 2>/dev/null | head -n 100 || iptables -S 2>/dev/null | head -n 100",
		Windows:  "Get-NetFirewallProfile | Select-Object Name,Enabled",
		Describe: "firewall state"},
	{Name: "cert-expiry", Tier: TierFull,
		Windows:  "Get-ChildItem Cert:\\LocalMachine\\My | Select-Object Subject,NotAfter",
		Describe: "machine certificate expiry"},
	{Name: "scheduled-tasks", Tier: TierFull,
		Linux:    "crontab -l 2>/dev/null | head -n 40; ls /etc/cron.d 2>/dev/null",
		Windows:  "Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object TaskName,State -First 30",
		Describe: "scheduled tasks / cron entries"},
}

// DiagSpecFor returns the allowlist row for a collector name.
func DiagSpecFor(name string) (DiagSpec, bool) {
	for _, d := range diagTable {
		if d.Name == name {
			return d, true
		}
	}
	return DiagSpec{}, false
}

// DiagCommand resolves the command string for (name, osFamily) under tier,
// substituting the validated param when the spec takes one. Refusal — never
// sanitize-and-run.
func DiagCommand(name, osFamily string, tier DiagTier, param string) (string, DiagSpec, error) {
	spec, ok := DiagSpecFor(name)
	if !ok {
		return "", DiagSpec{}, fmt.Errorf("unknown diagnostic %q", name)
	}
	if !tier.allows(spec.Tier) {
		return "", spec, fmt.Errorf("diagnostic %q requires --remote-diag %s (current tier: %s)", name, spec.Tier, tier)
	}
	var tmpl string
	switch strings.ToLower(osFamily) {
	case "linux":
		tmpl = spec.Linux
	case "windows":
		tmpl = spec.Windows
	default:
		return "", spec, fmt.Errorf("diagnostic %q: unknown OS family %q", name, osFamily)
	}
	if tmpl == "" {
		return "", spec, fmt.Errorf("diagnostic %q is not available on %s", name, osFamily)
	}
	if spec.Param {
		if !paramRe.MatchString(param) {
			return "", spec, fmt.Errorf("diagnostic %q: parameter %q refused (letters, digits, ._@:- only)", name, param)
		}
		tmpl = fmt.Sprintf(tmpl, param)
	} else if param != "" {
		return "", spec, fmt.Errorf("diagnostic %q takes no parameter", name)
	}
	return tmpl, spec, nil
}

// RunDiag dials the host and runs one allowlisted diagnostic, truncating the
// output at the spec's cap. The ONLY call path from the investigation
// framework into remote command execution.
func RunDiag(ctx context.Context, opts Options, name, osFamily string, tier DiagTier, param string) (string, DiagSpec, error) {
	cmd, spec, err := DiagCommand(name, osFamily, tier, param)
	if err != nil {
		return "", spec, err
	}
	client, err := Dial(ctx, opts)
	if err != nil {
		return "", spec, fmt.Errorf("diagnostic %q: %w", name, err)
	}
	defer client.Close() //nolint:errcheck // best-effort close on a read-only session
	out, err := client.RunCommand(ctx, cmd)
	if err != nil {
		return "", spec, fmt.Errorf("diagnostic %q: %w", name, err)
	}
	maxBytes := spec.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultDiagMaxBytes
	}
	data, err := io.ReadAll(io.LimitReader(out, int64(maxBytes)))
	if err != nil {
		return "", spec, fmt.Errorf("diagnostic %q: read: %w", name, err)
	}
	return string(data), spec, nil
}
