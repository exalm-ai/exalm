// Demo server — starts the Exalm dashboard with synthetic Windows and Linux
// log analysis findings for UI testing without a live cluster or LLM key.
// Usage: go run ./cmd/demo-logs
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/exalm-ai/exalm/internal/web"
	"github.com/exalm-ai/exalm/pkg/plugin"
)

// simulateApplyFix is the demo ApplyFix handler. It does NOT execute shell
// commands on the local machine — it logs the action and returns success after
// a realistic pause to let the UI show the confirmation flow.
func simulateApplyFix(_ context.Context, action plugin.RemediationAction) error {
	shell := action.Shell
	if shell == "" {
		shell = "kubectl"
	}
	fmt.Fprintf(os.Stderr, "[DEMO applyFix] shell=%s cmd=%q\n", shell, action.KubectlCmd) //nolint:errcheck // demo output to stderr
	time.Sleep(600 * time.Millisecond)                                                    // simulate round-trip
	return nil
}

func main() {
	report := plugin.Report{
		Title:   "Exalm log analysis — win-prod + linux-prod",
		Summary: "Analysed 4 servers · 17 log sources · 5 critical · 4 high · 4 medium · 2 info",

		// Raw uses \n escapes to avoid backtick conflicts with markdown inline code.
		Raw: "## VERDICT\n" +
			"**5 critical issues** across two Windows servers (win-dc-01, win-web-01) and two Linux servers\n" +
			"(linux-db-01, linux-nginx-01). The audit log clear on win-dc-01 combined with four new service\n" +
			"installs in ten minutes is a strong indicator of active compromise. The IIS 502 burst on win-web-01\n" +
			"correlates directly with the app pool crash event at 13:42. On Linux, the PostgreSQL OOM kill on\n" +
			"linux-db-01 is the upstream cause of the nginx 503 surge — 3,140 upstream errors over eight minutes.\n\n" +
			"## INCIDENTS\n" +
			"**Windows Compromise (win-dc-01) — investigate immediately:**\n" +
			"1. **Audit log cleared** (Event 1102) at 13:41 — attacker covering tracks after 847 failed logons\n" +
			"   and one successful logon from 10.20.5.100\n" +
			"2. **4 new services installed** (Event 7045) by SYSTEM within 10 minutes — persistence mechanism\n" +
			"   or lateral-movement tooling likely deployed\n" +
			"3. **SeDebugPrivilege** used by CORP\\\\svc-deploy (Event 4672) — unusual for a CI service account;\n" +
			"   may indicate credential theft\n\n" +
			"**Infrastructure Failures:**\n" +
			"4. IIS app pool crash on win-web-01 caused 1,247 x 502 errors in 3 min (Event 1000 at 13:42)\n" +
			"5. PostgreSQL OOM kill on linux-db-01 (RSS 7.8 Gi vs 8 Gi limit) triggered the nginx 503 surge\n\n" +
			"## PREVENTION\n" +
			"1. **Isolate win-dc-01 immediately** — audit log tamper + service installs = active compromise.\n" +
			"   Disconnect from network; start forensic imaging before any remediation.\n" +
			"2. Block 185.220.101.0/24 at the perimeter firewall — Tor exit-node range scanning both\n" +
			"   Windows (Event 4625 source) and Linux endpoints concurrently.\n" +
			"3. Increase PostgreSQL work_mem and tune max_connections on linux-db-01; add memory alert\n" +
			"   at 80% RSS to catch pressure before OOM kill triggers.\n" +
			"4. Configure IIS application pool auto-restart health monitoring and alert on consecutive failures.\n" +
			"5. Enable Windows Advanced Audit Policy for Process Creation (Event 4688) on all servers.\n",

		Findings: []plugin.Finding{

			// ── Windows EventLog ───────────────────────────────────────────
			{
				Severity: plugin.SeverityCritical,
				Category: "EventLog",
				Title:    "Audit log cleared on win-dc-01 (Event 1102)",
				Detail: "The Windows Security audit log on win-dc-01 was cleared at 13:41:03 UTC by " +
					"CORP\\Administrator (Logon ID: 0x3E7). This follows 847 failed logon attempts (Event 4625) " +
					"and one successful logon from 10.20.5.100 in the preceding 22 minutes. Clearing the audit " +
					"log is standard attacker tradecraft to destroy forensic evidence.",
				Suggestion: "Isolate win-dc-01 from the network immediately. Do not reboot — a forensic memory " +
					"dump may contain attacker artefacts. Restore the audit log from your SIEM (Splunk, Sentinel) " +
					"before it rolls.",
				Source: "eventlog/win-dc-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:   "log",
						Source: "Security",
						Excerpt: "2026-05-24T13:41:03Z | EventID=1102 | Provider=Microsoft-Windows-Eventlog\n" +
							"The audit log was cleared.\n" +
							"Subject: Security ID: CORP\\Administrator | Logon ID: 0x3E7",
						Anchor: "Get-WinEvent -LogName Security -FilterHashtable @{Id=1102} | Format-List",
					},
					{
						Kind:   "log",
						Source: "Security",
						Excerpt: "2026-05-24T13:19:14Z | EventID=4625 | Source: 10.20.5.100\n" +
							"An account failed to log on. Count: 847 attempts in 22 min",
						Anchor: "Get-WinEvent -LogName Security -FilterHashtable @{Id=4625} | Format-List",
					},
					{
						Kind:   "event",
						Source: "Security",
						Excerpt: "2026-05-24T13:40:51Z | EventID=4624 | Logon Type: 3 (Network)\n" +
							"Account: CORP\\Administrator | Source: 10.20.5.100\n" +
							"SUCCESSFUL logon — 12 seconds before audit log cleared",
					},
				},
				LikelyCause: &plugin.ChangeRef{
					ID:         "breach-2026-05-24-001",
					Kind:       "SecurityEvent",
					Namespace:  "win-dc-01",
					Name:       "AuditLogClear",
					Actor:      "10.20.5.100",
					AgoSeconds: 1800,
				},
			},
			{
				Severity: plugin.SeverityCritical,
				Category: "EventLog",
				Title:    "4 new services installed in 10 min: win-dc-01 (Event 7045)",
				Detail: "Four new Windows services were registered on win-dc-01 within a 10-minute window " +
					"(13:41–13:51 UTC) by the SYSTEM account. Service names follow randomised patterns: svc-7f3a, " +
					"nethlpr64, winsvc32, lsaext. Binary paths point to %TEMP% and %APPDATA% — classic indicators " +
					"of malware persistence or lateral-movement tooling (e.g., Cobalt Strike service stager).",
				Suggestion: "Do not restart or interact with these services. Capture binary hashes immediately " +
					"and submit to your AV/EDR. Use Sysinternals Autoruns to enumerate all persistence vectors. " +
					"Isolate the host if not already done.",
				Source: "eventlog/win-dc-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:   "log",
						Source: "System",
						Excerpt: "13:41:12 | EventID=7045 | ServiceName=svc-7f3a\n" +
							"           ImagePath=C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\svc7f3a.exe\n" +
							"13:43:02 | EventID=7045 | ServiceName=nethlpr64\n" +
							"           ImagePath=C:\\Windows\\Temp\\nethlpr64.dll\n" +
							"13:48:19 | EventID=7045 | ServiceName=winsvc32\n" +
							"           ImagePath=C:\\Users\\Public\\winsvc32.exe\n" +
							"13:51:44 | EventID=7045 | ServiceName=lsaext\n" +
							"           ImagePath=C:\\Windows\\Temp\\lsaext.dll",
						Anchor: "Get-WinEvent -LogName System -FilterHashtable @{Id=7045} | Select-Object TimeCreated,Message | Format-List",
					},
				},
				Remediation: &plugin.RemediationAction{
					Kind:        "WindowsServiceStop",
					Namespace:   "win-dc-01",
					Resource:    "Service",
					Name:        "svc-7f3a,nethlpr64,winsvc32,lsaext",
					PatchJSON:   `{"action":"stop-disable","services":["svc-7f3a","nethlpr64","winsvc32","lsaext"]}`,
					KubectlCmd:  `@("svc-7f3a","nethlpr64","winsvc32","lsaext") | ForEach-Object { Stop-Service $_ -Force -ErrorAction SilentlyContinue; Set-Service $_ -StartupType Disabled }`,
					Description: "Stop and disable the four suspicious services on win-dc-01. Run in an elevated PowerShell session.",
					Shell:       "powershell",
					Warning:     "⚠ DANGER: Only do this AFTER capturing binary hashes and memory. Stopping the services may trigger anti-forensic self-deletion in some malware families.",
				},
			},
			{
				Severity: plugin.SeverityHigh,
				Category: "EventLog",
				Title:    "Brute force: 847 failed logons from 10.20.5.100 (Event 4625)",
				Detail: "win-dc-01 recorded 847 consecutive failed logon attempts (Event 4625) targeting " +
					"the Administrator account from 10.20.5.100 between 13:18 and 13:40 UTC (38/min). " +
					"Logon type 3 (Network). The attack succeeded at 13:40:51 UTC. No lockout policy is " +
					"configured for the Administrator account.",
				Suggestion: "Enable Account Lockout Policy for privileged accounts. Block 10.20.5.100 at the " +
					"network layer. Enable MFA for all RDP/WinRM access. Review whether the Administrator " +
					"account should have network logon rights.",
				Source: "eventlog/win-dc-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:    "metric",
						Source:  "Security/4625",
						Excerpt: "failed_logons_per_minute=38 | target=Administrator | source_ip=10.20.5.100 | duration=22m",
					},
					{
						Kind:   "event",
						Source: "Security/4624",
						Excerpt: "13:40:51Z — SUCCESSFUL logon after 847 failures\n" +
							"Account: CORP\\Administrator | Logon Type: 3 | Source: 10.20.5.100",
					},
				},
				Remediation: &plugin.RemediationAction{
					Kind:        "WindowsFirewallBlock",
					Namespace:   "win-dc-01",
					Resource:    "NetFirewallRule",
					Name:        "Block-Attacker-10.20.5.100",
					PatchJSON:   `{"action":"block","direction":"inbound","remoteAddress":"10.20.5.100"}`,
					KubectlCmd:  `New-NetFirewallRule -DisplayName "Block-Attacker" -Direction Inbound -Action Block -RemoteAddress "10.20.5.100"`,
					Description: "Block inbound traffic from attacker IP 10.20.5.100 on win-dc-01. Run in an elevated PowerShell session on win-dc-01.",
					Shell:       "powershell",
					Warning:     "This blocks 10.20.5.100 at the Windows Firewall layer. The attacker already logged in — isolate the host first.",
				},
			},
			{
				Severity: plugin.SeverityHigh,
				Category: "EventLog",
				Title:    "App pool crash: IIS DefaultAppPool stopped (Event 1000) on win-web-01",
				Detail: "IIS Worker Process (w3wp.exe) for DefaultAppPool on win-web-01 crashed at " +
					"13:42:07 UTC with a fatal error (Event 1000: Application Error). " +
					"Exception code: 0xC0000005 (ACCESS_VIOLATION). This triggered the 5xx burst on the IIS site. " +
					"The app pool failed twice before stabilising at 13:43:44 UTC.",
				Suggestion: "Review the Windows Error Reporting crash dump at C:\\Windows\\Minidump\\. " +
					"Check recent .NET application deployments — the access violation may indicate a null " +
					"pointer from a bad deploy. Enable app pool recycling triggers to reduce blast radius.",
				Source: "eventlog/win-web-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:   "log",
						Source: "Application/1000",
						Excerpt: "13:42:07Z | EventID=1000 | Faulting application: w3wp.exe\n" +
							"Faulting module: clr.dll | Exception code: 0xC0000005 (ACCESS_VIOLATION)\n" +
							"Fault offset: 0x00000000004a21f3",
					},
					{
						Kind:   "event",
						Source: "System/1074",
						Excerpt: "13:42:19Z | App pool DefaultAppPool restart attempt 1 — FAILED\n" +
							"13:42:39Z | App pool DefaultAppPool restart attempt 2 — FAILED\n" +
							"13:43:44Z | App pool DefaultAppPool restarted successfully",
					},
				},
			},
			{
				Severity: plugin.SeverityMedium,
				Category: "EventLog",
				Title:    "SeDebugPrivilege used by CORP\\svc-deploy (Event 4672) on win-dc-01",
				Detail: "Special privilege SeDebugPrivilege was assigned to CORP\\svc-deploy (Event 4672) " +
					"at 13:39:44 UTC on win-dc-01 — 72 seconds before the failed logon spike. " +
					"SeDebugPrivilege allows attaching to any process including LSASS, enabling credential " +
					"dumping. This account is a CI/CD service account and should not require debug privileges.",
				Suggestion: "Revoke SeDebugPrivilege from svc-deploy immediately via Group Policy " +
					"(Security Settings > Local Policies > User Rights Assignment). " +
					"Rotate the svc-deploy credentials and audit its recent activity.",
				Source: "eventlog/win-dc-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:   "log",
						Source: "Security/4672",
						Excerpt: "13:39:44Z | EventID=4672 | Subject: CORP\\svc-deploy\n" +
							"Privileges: SeDebugPrivilege SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege",
					},
				},
			},

			// ── IIS findings ──────────────────────────────────────────────
			{
				Severity: plugin.SeverityCritical,
				Category: "IIS",
				Title:    "5xx burst: 1,247 x 502 errors in 3 min on /api/ (13:42–13:45)",
				Detail: "IIS access logs on win-web-01 show 1,247 HTTP 502 Bad Gateway errors between " +
					"13:42:07 and 13:45:12 UTC, peaking at 487 errors/minute at 13:43:00. The spike onset " +
					"is within 2 seconds of the DefaultAppPool crash (Event 1000 at 13:42:07). " +
					"All errors are on the /api/ path group. Normal 502 rate is <1/hour.",
				Suggestion: "Configure IIS application pool Rapid-Fail Protection (max 5 failures in 5 minutes). " +
					"Set up a static 503 maintenance page as failover. Alert on 502-rate > 10/min.",
				Source: "iis/win-web-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:    "metric",
						Source:  "iis/win-web-01",
						Excerpt: "5xx_per_minute=487 (peak 13:43:00) | total_5xx=1247 | window=3m | path_prefix=/api/",
					},
					{
						Kind:   "log",
						Source: "W3SVC1/access.log",
						Excerpt: "2026-05-24 13:42:08 POST /api/checkout 502 0 0 847\n" +
							"2026-05-24 13:42:09 GET  /api/orders   502 0 0 312\n" +
							"2026-05-24 13:42:09 POST /api/payment  502 0 0 891\n" +
							"... (1,244 more 502 lines between 13:42:07 and 13:45:12)",
					},
				},
				Remediation: &plugin.RemediationAction{
					Kind:        "IISAppPoolRestart",
					Namespace:   "win-web-01",
					Resource:    "AppPool",
					Name:        "DefaultAppPool",
					PatchJSON:   `{"action":"restart","appPool":"DefaultAppPool"}`,
					KubectlCmd:  `Restart-WebAppPool -Name "DefaultAppPool"`,
					Description: "Restart IIS DefaultAppPool on win-web-01. Run in an elevated PowerShell session (requires WebAdministration module).",
					Shell:       "powershell",
				},
				LikelyCause: &plugin.ChangeRef{
					ID:         "deploy-2026-05-24-win-001",
					Kind:       "AppDeploy",
					Namespace:  "win-web-01",
					Name:       "api-service-v3.2.1",
					Actor:      "svc-deploy",
					AgoSeconds: 5400,
				},
			},
			{
				Severity: plugin.SeverityHigh,
				Category: "IIS",
				Title:    "Slow endpoint: POST /api/checkout avg 8.2 s (SLA: 2 s)",
				Detail: "IIS access logs show POST /api/checkout with average time-taken of 8,247 ms " +
					"(p50: 6.1 s, p95: 14.3 s, p99: 22 s). SLA is 2 s. 82% of slow requests correlate " +
					"with query param promo=true, suggesting the promotional pricing query path is unindexed. " +
					"SQL Server shows a matching long-running query avg 7.9 s with 0 index seeks.",
				Suggestion: "Add a composite index on promotions(code, valid_from, valid_to). " +
					"Cache the promo lookup in Redis with a 60-second TTL. " +
					"Set an IIS request timeout of 30 s to prevent thread-pool starvation.",
				Source: "iis/win-web-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:    "metric",
						Source:  "iis/win-web-01",
						Excerpt: "endpoint=POST /api/checkout | avg_ms=8247 | p95_ms=14300 | sla_ms=2000 | sla_breaches=100%",
					},
					{
						Kind:   "log",
						Source: "W3SVC1/access.log",
						Excerpt: "2026-05-24 09:17:34 POST /api/checkout?promo=true  200 0 0 14293\n" +
							"2026-05-24 09:19:02 POST /api/checkout?promo=true  200 0 0 11841\n" +
							"2026-05-24 09:21:15 POST /api/checkout?promo=false 200 0 0 1124",
					},
				},
			},
			{
				Severity: plugin.SeverityHigh,
				Category: "IIS",
				Title:    "Security scan: 523 probes for /.env, /wp-login from 185.220.101.x",
				Detail: "IIS logs show 523 sequential 404 requests from 185.220.101.47 (Tor exit node) " +
					"probing: /.env (180), /wp-login.php (94), /phpinfo.php (72), /admin/config.php (61), " +
					"path traversal attempts (40), and 76 other paths. Some probes returned 200 for " +
					"/web.config — investigate immediately if IIS is serving it.",
				Suggestion: "Block 185.220.101.0/24 at the WAF or IIS IP Restrictions. " +
					"Review the /web.config 200 response — if served, sensitive connection strings may " +
					"be exposed. Enable IIS Dynamic IP Restrictions to auto-block scanners.",
				Source: "iis/win-web-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:    "metric",
						Source:  "iis/win-web-01",
						Excerpt: "scanner_ip=185.220.101.47 | total_probes=523 | duration=60m | avg_rps=8.7\ntop_paths: /.env(180) /wp-login.php(94) /phpinfo.php(72)",
					},
					{
						Kind:   "log",
						Source: "W3SVC1/access.log",
						Excerpt: "185.220.101.47 GET /.env               404  0  0  2\n" +
							"185.220.101.47 GET /wp-login.php       404  0  0  1\n" +
							"185.220.101.47 GET /web.config         200  0  0  3  <- EXPOSED",
					},
				},
				Remediation: &plugin.RemediationAction{
					Kind:        "IISIPBlock",
					Namespace:   "win-web-01",
					Resource:    "NetFirewallRule",
					Name:        "Block-TorScanner-185.220.101.0",
					PatchJSON:   `{"action":"block","direction":"inbound","remoteAddress":"185.220.101.0/24"}`,
					KubectlCmd:  `New-NetFirewallRule -DisplayName "Block-TorScan" -Direction Inbound -Action Block -RemoteAddress "185.220.101.0/24"`,
					Description: "Block Tor exit-node range 185.220.101.0/24 at Windows Firewall on win-web-01. Run in elevated PowerShell.",
					Shell:       "powershell",
					Warning:     "Apply this at the perimeter firewall too — 185.220.101.0/24 is scanning all servers concurrently.",
				},
			},
			{
				Severity: plugin.SeverityMedium,
				Category: "IIS",
				Title:    "Request flood: 10.0.1.50 made 4,400 requests in 5 min to /api/healthz",
				Detail: "A single internal IP (10.0.1.50 — staging load-balancer) made 4,400 requests " +
					"to /api/healthz and /api/status in 5 minutes at 14:00–14:05 UTC, averaging 14.7 req/s. " +
					"This is 7x the expected health-check rate (2 req/s). Harmless now but becomes a " +
					"bottleneck if the backend slows.",
				Suggestion: "Increase the staging load-balancer health-check interval from 2 s to 15 s. " +
					"Add Cache-Control: max-age=10 to /api/healthz to reduce IIS thread usage.",
				Source: "iis/win-web-01",
			},

			// ── Linux Syslog findings ──────────────────────────────────────
			{
				Severity: plugin.SeverityCritical,
				Category: "Syslog",
				Title:    "OOM killer: postgres killed on linux-db-01 (RSS 7.8 Gi vs 8 Gi limit)",
				Detail: "The Linux OOM killer terminated PID 14432 (postgres: worker process) on linux-db-01 " +
					"at 13:40:02 UTC. Resident Set Size was 7.8 Gi against a cgroup memory limit of 8 Gi. " +
					"The database restarted within 4 seconds (PID 14501), immediately climbing to 5.2 Gi RSS. " +
					"This is the upstream cause of the nginx 503 surge (13:42–13:50 UTC) — the 2-minute gap " +
					"is the postgres crash-recovery window.",
				Suggestion: "Increase the cgroup memory limit for postgres to 12 Gi, or enable PostgreSQL " +
					"huge pages to reduce RSS. Add PgBouncer connection pooling to cap concurrent queries. " +
					"Set a memory alert at 80% to catch this before OOM triggers.",
				Source: "syslog/linux-db-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:   "log",
						Source: "kern.log",
						Excerpt: "2026-05-24T13:40:02+00:00 linux-db-01 kernel:\n" +
							"  Out of memory: Kill process 14432 (postgres) score 912 or sacrifice child\n" +
							"  Killed process 14432 (postgres) total-vm:9437184kB, anon-rss:8180736kB",
						Anchor: "dmesg | grep -i 'oom\\|killed process' | tail -20",
					},
					{
						Kind:    "metric",
						Source:  "node/linux-db-01",
						Excerpt: "postgres_rss_gib=7.8 | cgroup_limit_gib=8.0 | utilisation=97.5%",
					},
				},
			},
			{
				Severity: plugin.SeverityHigh,
				Category: "Syslog",
				Title:    "SSH brute force: 1,239 failed attempts from 185.220.101.47 in 22 min",
				Detail: "sshd on linux-db-01 recorded 1,239 'Failed password' events from 185.220.101.47 " +
					"between 13:17 and 13:39 UTC, averaging 56 attempts/min — the same Tor exit node " +
					"concurrently scanning win-dc-01 via RDP. Targets: root (812), ubuntu (241), postgres (186). " +
					"No successful logon recorded. fail2ban is not installed. SSH exposed on 0.0.0.0:22.",
				Suggestion: "Install and configure fail2ban with maxretry=5. Restrict SSH to management VPN. " +
					"Disable password authentication — require SSH keys. " +
					"Consider moving SSH to a non-standard port as a noise reducer.",
				Source: "syslog/linux-db-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:    "metric",
						Source:  "syslog/sshd",
						Excerpt: "attacker_ip=185.220.101.47 | total_attempts=1239 | duration=22m | rate=56/min\ntargets: root(812) ubuntu(241) postgres(186)",
					},
					{
						Kind:   "log",
						Source: "/var/log/auth.log",
						Excerpt: "May 24 13:17:04 linux-db-01 sshd[9321]: Failed password for root from 185.220.101.47 port 42183 ssh2\n" +
							"May 24 13:17:05 linux-db-01 sshd[9322]: Failed password for root from 185.220.101.47 port 42184 ssh2\n" +
							"... (1,237 more lines)",
						Anchor: "journalctl -u sshd --since '1 hour ago' --no-pager | grep 'Failed password' | awk '{print $11}' | sort | uniq -c | sort -rn",
					},
				},
				Remediation: &plugin.RemediationAction{
					Kind:        "IPTablesBlock",
					Namespace:   "linux-db-01",
					Resource:    "iptables",
					Name:        "block-185.220.101.47",
					PatchJSON:   `{"chain":"INPUT","action":"DROP","source":"185.220.101.47"}`,
					KubectlCmd:  `sudo iptables -A INPUT -s 185.220.101.47 -j DROP && sudo iptables-save > /etc/iptables/rules.v4`,
					Description: "Drop all inbound traffic from attacker IP 185.220.101.47 on linux-db-01. Requires root.",
					Shell:       "bash",
					Warning:     "Also block 185.220.101.0/24 at the perimeter — this Tor range is scanning all servers simultaneously.",
				},
			},
			{
				Severity: plugin.SeverityHigh,
				Category: "Syslog",
				Title:    "Service crash loop: nginx.service failed 5x in 10 min on linux-app-01",
				Detail: "systemd on linux-app-01 reports nginx.service entering a restart loop starting " +
					"at 11:20 UTC — 5 consecutive failures within 10 minutes. ExecStartPre (nginx -t) returns " +
					"exit code 1 each time: invalid directive 'proxy_cache_pathh' at line 47. The config change " +
					"was pushed by deploy@linux-app-01 via a failed Ansible playbook run at 11:18:15 UTC. " +
					"The service is in 'failed' state and is not serving traffic.",
				Suggestion: "Roll back nginx config: git checkout HEAD~1 -- /etc/nginx/nginx.conf && " +
					"nginx -t && systemctl start nginx. Fix the Ansible playbook to run nginx -t before reloading. " +
					"Add a CI step that validates config before deploying.",
				Source: "syslog/linux-app-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:   "log",
						Source: "journald/nginx",
						Excerpt: "May 24 11:20:44 linux-app-01 systemd[1]: nginx.service: Start request repeated too quickly.\n" +
							"May 24 11:20:44 linux-app-01 systemd[1]: Failed to start A high performance web server.\n" +
							"May 24 11:20:44 linux-app-01 systemd[1]: nginx.service: Entered failed state.",
						Anchor: "journalctl -u nginx.service --since '2 hours ago' --no-pager",
					},
					{
						Kind:   "log",
						Source: "nginx -t",
						Excerpt: "nginx: [emerg] unknown directive \"proxy_cache_pathh\" in /etc/nginx/nginx.conf:47\n" +
							"nginx: configuration file /etc/nginx/nginx.conf test failed",
					},
				},
				LikelyCause: &plugin.ChangeRef{
					ID:         "ansible-2026-05-24-001",
					Kind:       "ConfigChange",
					Namespace:  "linux-app-01",
					Name:       "nginx.conf",
					Actor:      "deploy",
					AgoSeconds: 7800,
				},
				Remediation: &plugin.RemediationAction{
					Kind:        "NginxConfigRollback",
					Namespace:   "linux-app-01",
					Resource:    "nginx-conf",
					Name:        "nginx.conf",
					PatchJSON:   `{"action":"rollback","file":"/etc/nginx/nginx.conf"}`,
					KubectlCmd:  `sudo git -C /etc/nginx checkout HEAD~1 -- nginx.conf && sudo nginx -t && sudo systemctl start nginx`,
					Description: "Roll back nginx.conf to the previous commit and restart nginx on linux-app-01. Requires root and git-managed /etc/nginx.",
					Shell:       "bash",
					Warning:     "Verify nginx -t passes before starting. If /etc/nginx is not git-managed, restore from your config backup instead.",
				},
			},
			{
				Severity: plugin.SeverityMedium,
				Category: "Syslog",
				Title:    "Disk I/O saturation: /dev/sdb at 100% util for 14 min on linux-db-01",
				Detail: "iostat shows /dev/sdb (PostgreSQL data volume) at 100% I/O utilisation from " +
					"13:32 to 13:46 UTC — a 14-minute window that preceded and overlapped the OOM kill. " +
					"Average service time: 124 ms (normal: 2–5 ms). The I/O spike was caused by a full " +
					"table scan on the events table (743 million rows, no index on created_at).",
				Suggestion: "Add an index on events(created_at) using CREATE INDEX CONCURRENTLY to avoid locking. " +
					"Schedule creation during off-peak hours. Enable log_min_duration_statement = 1000 to " +
					"catch future long queries before they saturate I/O.",
				Source: "syslog/linux-db-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:    "metric",
						Source:  "iostat/linux-db-01",
						Excerpt: "device=/dev/sdb | util=100% | await_ms=124 | normal_await_ms=2-5 | duration=14m",
					},
				},
			},

			// ── nginx / HTTPLog findings ───────────────────────────────────
			{
				Severity: plugin.SeverityCritical,
				Category: "HTTPLog",
				Title:    "503 surge: 3,140 upstream errors in 8 min on linux-nginx-01 (13:42–13:50)",
				Detail: "nginx access logs on linux-nginx-01 show 3,140 HTTP 503 responses between " +
					"13:42:14 and 13:50:07 UTC. nginx error log confirms upstream connect() failed " +
					"(111: Connection refused) for app-backend:8080 during the postgres crash-recovery window. " +
					"Peak rate: 712 errors/minute at 13:43:00. Zero successful responses during the window.",
				Suggestion: "Configure nginx upstream health checks (health_check interval=5s fails=2 passes=1) " +
					"and a static 503.html maintenance page as fallback. Add a circuit-breaker with " +
					"proxy_next_upstream to prevent retry storms. Alert on 5xx-rate > 50/min.",
				Source: "httplog/linux-nginx-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:    "metric",
						Source:  "httplog/linux-nginx-01",
						Excerpt: "5xx_per_minute=712 (peak) | total_503=3140 | window=8m | upstream=app-backend:8080",
					},
					{
						Kind:   "log",
						Source: "/var/log/nginx/error.log",
						Excerpt: "2026/05/24 13:42:14 [error] 9012#0: *18423 connect() failed (111: Connection refused)\n" +
							"  while connecting to upstream: \"http://app-backend:8080/api\"\n" +
							"2026/05/24 13:42:14 [error] 9012#0: *18424 connect() failed (111: Connection refused)\n" +
							"  while connecting to upstream: \"http://app-backend:8080/api\"\n" +
							"... (3,138 more lines until 13:50:07)",
						Anchor: "tail -200 /var/log/nginx/error.log | grep 'upstream'",
					},
					{
						Kind:   "log",
						Source: "/var/log/nginx/access.log",
						Excerpt: "192.168.1.100 [24/May/2026:13:42:14] \"POST /api/checkout\" 503 0 upstream_time=30.001\n" +
							"192.168.1.101 [24/May/2026:13:42:14] \"GET /api/orders\"   503 0 upstream_time=30.001",
					},
				},
				Remediation: &plugin.RemediationAction{
					Kind:        "NginxRestart",
					Namespace:   "linux-nginx-01",
					Resource:    "systemd-service",
					Name:        "nginx",
					PatchJSON:   `{"action":"restart","service":"nginx"}`,
					KubectlCmd:  `sudo systemctl restart nginx && sudo systemctl status nginx`,
					Description: "Restart nginx on linux-nginx-01 to clear upstream connection state. Note: this treats the symptom — the root cause is the postgres OOM kill on linux-db-01.",
					Shell:       "bash",
					Warning:     "This is a symptom fix. Restart postgres on linux-db-01 first and confirm it is healthy before restarting nginx.",
				},
			},
			{
				Severity: plugin.SeverityHigh,
				Category: "HTTPLog",
				Title:    "Slow endpoint: GET /api/reports P95=12.3 s, P50=4.1 s (SLA: 1 s)",
				Detail: "nginx access logs show GET /api/reports with P50 latency 4.1 s and P95 12.3 s " +
					"over 6 hours. SLA is 1 s. The upstream_response_time field confirms the latency " +
					"originates in the app backend. PostgreSQL slow query log shows SELECT * FROM reports " +
					"WHERE org_id = $1 ORDER BY created_at DESC taking 4–14 s (2.3 M rows, sequential scan — " +
					"no index on org_id, created_at).",
				Suggestion: "Run: CREATE INDEX CONCURRENTLY idx_reports_org_created ON reports(org_id, created_at DESC). " +
					"Expected query time after index: <10 ms. Add query result caching for repeat requests within 60 s.",
				Source: "httplog/linux-nginx-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:    "metric",
						Source:  "httplog/linux-nginx-01",
						Excerpt: "endpoint=GET /api/reports | p50_ms=4100 | p95_ms=12300 | p99_ms=24100 | sla_ms=1000",
					},
					{
						Kind:   "log",
						Source: "/var/log/postgresql/slow.log",
						Excerpt: "2026-05-24 09:15:22 UTC [14501] LOG: duration: 14312.441 ms\n" +
							"  statement: SELECT * FROM reports WHERE org_id='42' ORDER BY created_at DESC LIMIT 100\n" +
							"2026-05-24 09:16:04 UTC [14502] LOG: duration: 11847.203 ms\n" +
							"  statement: SELECT * FROM reports WHERE org_id='17' ORDER BY created_at DESC LIMIT 100",
						Anchor: "psql -c \"EXPLAIN ANALYZE SELECT * FROM reports WHERE org_id='42' ORDER BY created_at DESC LIMIT 100;\"",
					},
				},
			},
			{
				Severity: plugin.SeverityHigh,
				Category: "HTTPLog",
				Title:    "Botnet scan: 23 IPs probing /admin, /.git — 8,400 requests",
				Detail: "nginx logs show a coordinated scan from 23 distinct IPs (all 185.220.101.x/24 — " +
					"same Tor range scanning win-web-01) probing /admin, /.git/config, /.env, /config.php, " +
					"/backup.sql, /wp-admin. Total: 8,400 requests over 2 hours. The /.git/config path " +
					"returned 403 (directory exists but listing disabled) — the .git directory should not " +
					"be accessible from the web root.",
				Suggestion: "Block the entire 185.220.101.0/24 range. Add an nginx rule returning 444 " +
					"(connection close) for sensitive paths. Restrict the .git directory: add 'deny all;' " +
					"in a location block matching /\\.git.",
				Source: "httplog/linux-nginx-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:    "metric",
						Source:  "httplog/linux-nginx-01",
						Excerpt: "scanner_ips=23 | cidr=185.220.101.0/24 | total_probes=8400 | duration=120m\ntop_paths: /admin(2100) /.git/config(1800) /.env(1500)",
					},
					{
						Kind:   "log",
						Source: "/var/log/nginx/access.log",
						Excerpt: "185.220.101.23 GET /.git/config     403 162  <- directory exists!\n" +
							"185.220.101.47 GET /.env             404   0\n" +
							"185.220.101.12 GET /backup.sql       404   0\n" +
							"185.220.101.31 GET /admin/           404   0",
					},
				},
				Remediation: &plugin.RemediationAction{
					Kind:        "NginxIPBlock",
					Namespace:   "linux-nginx-01",
					Resource:    "nginx-conf",
					Name:        "block-185.220.101.0-24",
					PatchJSON:   `{"directive":"deny","value":"185.220.101.0/24"}`,
					KubectlCmd:  `echo 'deny 185.220.101.0/24;' | sudo tee -a /etc/nginx/conf.d/blocklist.conf && sudo nginx -t && sudo systemctl reload nginx`,
					Description: "Block Tor scanner range 185.220.101.0/24 in nginx on linux-nginx-01. Requires root.",
					Shell:       "bash",
					Warning:     "Also restrict /.git location in nginx config — the directory returned 403, not 404. It should not be web-accessible.",
				},
			},
			{
				Severity: plugin.SeverityMedium,
				Category: "HTTPLog",
				Title:    "Upstream keepalive exhaustion: 14 requests with response time >30 s",
				Detail: "nginx upstream_response_time shows 14 requests exceeding 30 seconds in the " +
					"past hour, all targeting app-backend:8080. These long-held connections exhaust the " +
					"upstream keepalive pool (configured at 32 connections) and force new connections, " +
					"adding 200–500 ms overhead for concurrent requests.",
				Suggestion: "Set proxy_read_timeout 15s in the nginx upstream block to kill stalled backend " +
					"connections. Reduce keepalive_timeout to 30. Add proxy_next_upstream timeout so nginx " +
					"retries on a different upstream before returning 504.",
				Source: "httplog/linux-nginx-01",
				Evidence: []plugin.EvidenceItem{
					{
						Kind:    "metric",
						Source:  "httplog/linux-nginx-01",
						Excerpt: "upstream_response_time_gt_30s=14 | window=1h | upstream=app-backend:8080",
					},
					{
						Kind:   "log",
						Source: "/var/log/nginx/access.log",
						Excerpt: "192.168.1.200 GET /api/export 200 - upstream_time=34.821\n" +
							"192.168.1.201 GET /api/export 200 - upstream_time=31.047\n" +
							"192.168.1.202 GET /api/export 504 - upstream_time=60.001",
					},
				},
			},

			// ── Info ──────────────────────────────────────────────────────────
			{
				Severity: plugin.SeverityInfo,
				Category: "Syslog",
				Title:    "Log rotation completed on linux-db-01 — all within retention",
				Detail: "logrotate ran successfully at 00:00 UTC. Rotated: postgresql-2026-05-23.log " +
					"(4.2 GB → compressed 310 MB), nginx-access.log.1 (1.1 GB → 87 MB), auth.log.1 " +
					"(220 MB → 18 MB). All logs within the 14-day retention policy.",
				Suggestion: "Confirm backup of compressed logs to object storage is running.",
				Source:     "syslog/linux-db-01",
			},
			{
				Severity: plugin.SeverityInfo,
				Category: "IIS",
				Title:    "IIS log rotation completed on win-web-01 — W3SVC1 logs archived",
				Detail: "IIS log rotation ran at 00:00 UTC. Today's archive: W3SVC1-20260524.log " +
					"(2.1 GB, 14.2 M requests). Archived to \\\\fileserver\\logs\\iis\\. " +
					"Retention: 30 days. Oldest log deleted: W3SVC1-20260424.log.",
				Suggestion: "No action needed.",
				Source:     "iis/win-web-01",
			},
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	updates := make(chan plugin.Report, 1)

	// Simulate a live update: SSL expiry finding arrives after 10 seconds.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
			updated := report
			updated.Summary = "Live update: 6 critical · 4 high · 4 medium · 2 info"
			updated.Findings = append(updated.Findings, plugin.Finding{
				Severity: plugin.SeverityCritical,
				Category: "HTTPLog",
				Title:    "NEW: SSL cert expires in 3 days on linux-nginx-01 (exalm.com)",
				Detail: "nginx TLS certificate for exalm.com and *.exalm.com expires at " +
					"2026-05-27T00:00:00Z — 3 days from now. Certificate is issued by Let's Encrypt. " +
					"certbot auto-renewal cron has been failing silently for 28 days " +
					"(permission error on /etc/letsencrypt/). Manual renewal required.",
				Suggestion: "Run: certbot renew --force-renewal && systemctl reload nginx. " +
					"Fix certbot cron permission: chown -R root:root /etc/letsencrypt && " +
					"chmod 700 /etc/letsencrypt/live.",
				Source: "httplog/linux-nginx-01",
				Remediation: &plugin.RemediationAction{
					Kind:        "CertbotRenew",
					Namespace:   "linux-nginx-01",
					Resource:    "tls-cert",
					Name:        "exalm.com",
					PatchJSON:   `{"action":"renew","domain":"exalm.com"}`,
					KubectlCmd:  `sudo chown -R root:root /etc/letsencrypt && sudo chmod 700 /etc/letsencrypt/live && sudo certbot renew --force-renewal && sudo systemctl reload nginx`,
					Description: "Fix certbot permissions and force-renew the TLS certificate for exalm.com on linux-nginx-01. Requires root.",
					Shell:       "bash",
				},
			})
			updates <- updated
		}
	}()

	fmt.Fprintf(os.Stderr, "Demo logs dashboard: http://localhost:7434\n") //nolint:errcheck // startup info to stderr
	fmt.Fprintf(os.Stderr, "Press Ctrl-C to stop.\n")                      //nolint:errcheck // startup info to stderr

	if err := web.Serve(ctx, report, web.ServeOpts{
		Port:          7434,
		OpenBrowser:   false,
		ReportUpdates: updates,
		ApplyFix:      simulateApplyFix,
	}); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "serve error:", err) //nolint:errcheck // fatal error to stderr before exit
		os.Exit(1)
	}
}
