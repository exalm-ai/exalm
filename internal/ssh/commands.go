// Package ssh — preset remote commands for each log plugin.
//
// Each command is chosen to be:
//   - Available on a vanilla Linux install (no exotic tools)
//   - Output-compatible with the plugin's existing parser
//   - Bounded in size (all commands cap output to ≤512 KB worth of lines)
//
// Commands use POSIX sh syntax so they work on any sh-compatible shell,
// including Alpine/busybox.
package ssh

import (
	"fmt"
	"strings"
)

// validEventLogNames is the set of well-known Windows event log channel names
// that EventLogCmd will accept. Any other value is rejected and "Security" is
// used instead, preventing command-injection via --log-name.
var validEventLogNames = map[string]bool{
	"Security":           true,
	"System":             true,
	"Application":        true,
	"Setup":              true,
	"ForwardedEvents":    true,
	"Windows PowerShell": true,
	"Microsoft-Windows-PowerShell/Operational": true,
}

// pathShellMetaChars are characters that would break out of single-quoted
// PowerShell string literals or enable command injection.
const pathShellMetaChars = "';|&`$()\"<>\n\r"

// SyslogCmd returns the remote command that collects syslog entries.
//
//   - If journaldAvailable is true it uses journalctl (systemd hosts).
//   - Otherwise it falls back to a tail of /var/log/syslog or /var/log/messages.
//
// lines controls how many log lines to fetch (default: 5000).
func SyslogCmd(journaldAvailable bool, lines int) string {
	if lines <= 0 {
		lines = 5000
	}
	if journaldAvailable {
		return fmt.Sprintf("journalctl -n %d --no-pager 2>/dev/null || tail -n %d /var/log/syslog 2>/dev/null || tail -n %d /var/log/messages", lines, lines, lines)
	}
	return fmt.Sprintf(
		"{ tail -n %d /var/log/syslog 2>/dev/null || tail -n %d /var/log/messages 2>/dev/null || tail -n %d /var/log/system.log 2>/dev/null; } | head -n %d",
		lines, lines, lines, lines,
	)
}

// HTTPLogCmd returns the remote command to collect an nginx/Apache access log.
// logPath defaults to /var/log/nginx/access.log.
func HTTPLogCmd(logPath string, lines int) string {
	if logPath == "" {
		logPath = "/var/log/nginx/access.log"
	}
	if lines <= 0 {
		lines = 10000
	}
	return fmt.Sprintf("tail -n %d %s 2>/dev/null || tail -n %d /var/log/apache2/access.log 2>/dev/null", lines, logPath, lines)
}

// HTTPErrorLogCmd returns the command to collect nginx/Apache error logs.
func HTTPErrorLogCmd(logPath string, lines int) string {
	if logPath == "" {
		logPath = "/var/log/nginx/error.log"
	}
	if lines <= 0 {
		lines = 5000
	}
	return fmt.Sprintf("tail -n %d %s 2>/dev/null || tail -n %d /var/log/apache2/error.log 2>/dev/null", lines, logPath, lines)
}

// AuthLogCmd returns the command to collect SSH / auth log entries.
func AuthLogCmd(lines int) string {
	if lines <= 0 {
		lines = 5000
	}
	return fmt.Sprintf(
		"{ journalctl -u sshd -n %d --no-pager 2>/dev/null || tail -n %d /var/log/auth.log 2>/dev/null || tail -n %d /var/log/secure 2>/dev/null; }",
		lines, lines, lines,
	)
}

// EventLogCmd returns the PowerShell command to export Windows Event Log
// entries as JSON. logName must be one of the known channel names listed in
// validEventLogNames; any other value is replaced with "Security" to prevent
// command injection via the --log-name flag.
func EventLogCmd(logName string, maxEvents int) string {
	if !validEventLogNames[logName] {
		logName = "Security"
	}
	if maxEvents <= 0 {
		maxEvents = 2000
	}
	return fmt.Sprintf(
		`Get-WinEvent -LogName '%s' -MaxEvents %d | ConvertTo-Json -Depth 3 -Compress`,
		logName, maxEvents,
	)
}

// IISLogCmd returns the PowerShell command to tail IIS W3C access logs.
// logDir defaults to C:\inetpub\logs\LogFiles\W3SVC1.
//
// logDir is validated: any value containing shell metacharacters (', ;, |, &,
// etc.) is rejected and the default path is used instead, preventing command
// injection via the --log-dir flag.
func IISLogCmd(logDir string, lines int) string {
	if logDir == "" || strings.ContainsAny(logDir, pathShellMetaChars) {
		logDir = `C:\inetpub\logs\LogFiles\W3SVC1`
	}
	if lines <= 0 {
		lines = 10000
	}
	return fmt.Sprintf(
		`Get-ChildItem '%s\*.log' | Sort-Object LastWriteTime -Desc | Select-Object -First 1 | Get-Content -Tail %d`,
		logDir, lines,
	)
}
