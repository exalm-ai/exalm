'use strict';

// ── Constants ─────────────────────────────────────────────────────────────
const SEV_COLORS = {
  critical: '#da3633',
  high:     '#d29922',
  medium:   '#e3b341',
  low:      '#388bfd',
  info:     '#484f58',
};
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// ── Root cause correlation ────────────────────────────────────────────────
// Scans findings array and builds a map: podRef → {rootCause, fixWarning, related[]}
// "podRef" is the "namespace/pod-name" portion extracted from finding titles.

function extractPodRef(title) {
  // Titles follow patterns like:
  //   "CrashLoopBackOff: ns/pod-name"
  //   "Log db-error in ns/pod-name"
  //   "OOMKilled: ns/pod-name"
  const m = title.match(/:\s+([\w-]+\/[\w.-]+)$/) ||
             title.match(/\bin\s+([\w-]+\/[\w.-]+)$/);
  return m ? m[1] : null;
}

// Strength: openobserve — "AI SRE Agent shows complete evidence chain (exact
// log lines, metric values, trace IDs) for every RCA finding — verifiable, not
// a black box." buildRootCauseMap correlates co-located log anomalies with pod
// failures so the UI can show "Root cause: DB connectivity failure" rather than
// just "CrashLoopBackOff", with the evidence (the db-error log line) visible
// in the expanded card. Find/Investigate/Fix is one keystroke each.
function buildRootCauseMap(findings) {
  const map = {}; // podRef → {rootCause, fixWarning, related[]}

  // First pass: index log anomaly findings by pod.
  const anomaliesByPod = {}; // podRef → [title, ...]
  findings.forEach(function(f) {
    if (f.title && f.title.startsWith('Log ')) {
      const ref = extractPodRef(f.title);
      if (ref) {
        if (!anomaliesByPod[ref]) anomaliesByPod[ref] = [];
        anomaliesByPod[ref].push(f.title);
      }
    }
  });

  // Second pass: annotate primary findings.
  findings.forEach(function(f) {
    const ref = extractPodRef(f.title);
    if (!ref) return;

    const anomalies = anomaliesByPod[ref] || [];
    const hasDB   = anomalies.some(function(t) { return t.includes('db-error'); });
    const hasDisk = anomalies.some(function(t) { return t.includes('disk-error'); });
    const hasCert = anomalies.some(function(t) { return t.includes('cert-expiry'); });

    if (f.title.startsWith('CrashLoopBackOff')) {
      if (hasDB) {
        map[f.title] = {
          rootCause: 'Database connectivity failure',
          fixWarning: 'Deleting this pod will NOT fix the root cause — it restarts and crashes again because the database at the address in the logs is unreachable. Fix DB connectivity first.',
          related: anomalies,
        };
      } else if (hasDisk) {
        map[f.title] = {
          rootCause: 'Disk I/O or storage failure',
          fixWarning: 'Deleting the pod may not help if the underlying disk or PVC is the problem. Check node disk pressure and PVC status first.',
          related: anomalies,
        };
      } else if (hasCert) {
        map[f.title] = {
          rootCause: 'TLS certificate expiry',
          fixWarning: 'The pod is crashing because a certificate expired. Renew the certificate before restarting — the pod will crash again immediately otherwise.',
          related: anomalies,
        };
      } else if (anomalies.length > 0) {
        map[f.title] = { rootCause: 'Application-level error (see log anomalies)', fixWarning: '', related: anomalies };
      }
    }

    if (f.title.startsWith('Scheduling failed')) {
      const cpuInsufficient = f.detail && f.detail.includes('Insufficient cpu');
      const memInsufficient = f.detail && f.detail.includes('Insufficient memory');
      if (cpuInsufficient) {
        map[f.title] = {
          rootCause: 'Node CPU exhaustion',
          fixWarning: 'Restarting the deployment will not help — no node has enough free CPU to schedule this pod. Free up CPU on existing nodes or add more nodes first.',
          related: [],
        };
      } else if (memInsufficient) {
        map[f.title] = {
          rootCause: 'Node memory exhaustion',
          fixWarning: 'No node has sufficient free memory. Add memory or remove other workloads before rescheduling.',
          related: [],
        };
      }
    }

    if (f.title.startsWith('OOMKilled')) {
      map[f.title] = {
        rootCause: 'Container exceeded its memory limit',
        fixWarning: '',  // delete is a valid temp fix here; no extra warning
        related: [],
      };
    }
  });

  return map;
}

// ── Investigation step generator ──────────────────────────────────────────
function buildInvestigationSteps(card) {
  const title    = card.dataset.title    || '';
  const category = card.dataset.category || '';
  const detail   = card.dataset.detail   || '';

  const steps = [];

  // Extract namespace/name from title where possible.
  const refMatch = title.match(/:\s+([\w-]+)\/([\w.-]+)$/);
  const ns  = refMatch ? refMatch[1] : '';
  const pod = refMatch ? refMatch[2] : '';

  if (title.startsWith('CrashLoopBackOff') && pod) {
    steps.push({ desc: 'View crash logs (current and previous container):', cmd: 'kubectl logs ' + pod + ' -n ' + ns + ' --previous' });
    steps.push({ desc: 'Inspect pod events and conditions:', cmd: 'kubectl describe pod ' + pod + ' -n ' + ns });
    steps.push({ desc: 'Check all warning events in the namespace:', cmd: 'kubectl get events -n ' + ns + ' --field-selector type=Warning' });
    steps.push({ desc: 'Verify service endpoints (DB, dependencies):', cmd: 'kubectl get endpoints -n ' + ns });
    steps.push({ desc: 'Check network policies allowing egress:', cmd: 'kubectl get networkpolicy -n ' + ns });
  } else if (title.startsWith('OOMKilled') && pod) {
    steps.push({ desc: 'View previous container logs before OOM kill:', cmd: 'kubectl logs ' + pod + ' -n ' + ns + ' --previous' });
    steps.push({ desc: 'Inspect resource limits and current usage:', cmd: 'kubectl describe pod ' + pod + ' -n ' + ns });
    steps.push({ desc: 'Check node-level resource usage:', cmd: 'kubectl top nodes' });
    steps.push({ desc: 'Check pod resource consumption:', cmd: 'kubectl top pod -n ' + ns });
  } else if (title.startsWith('Scheduling failed') && pod) {
    steps.push({ desc: 'Inspect scheduling events on the pod:', cmd: 'kubectl describe pod ' + pod + ' -n ' + ns });
    steps.push({ desc: 'View node resource capacity and allocatable:', cmd: 'kubectl describe nodes' });
    steps.push({ desc: 'Check current node resource utilisation:', cmd: 'kubectl top nodes' });
    steps.push({ desc: 'List node taints that may prevent scheduling:', cmd: 'kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints' });
  } else if (title.startsWith('Deployment stalled')) {
    const depMatch = title.match(/:\s+([\w-]+)\/([\w.-]+)$/);
    if (depMatch) {
      steps.push({ desc: 'Check rollout status and events:', cmd: 'kubectl rollout status deployment/' + depMatch[2] + ' -n ' + depMatch[1] });
      steps.push({ desc: 'Describe deployment to see failure reason:', cmd: 'kubectl describe deployment ' + depMatch[2] + ' -n ' + depMatch[1] });
      steps.push({ desc: 'List pods owned by this deployment:', cmd: 'kubectl get pods -n ' + depMatch[1] + ' -l app=' + depMatch[2] });
    }
  } else if (title.startsWith('Log db-error') && pod) {
    steps.push({ desc: 'Confirm database pod is running:', cmd: 'kubectl get pods -n ' + ns + ' | grep -i postgres' });
    steps.push({ desc: 'Check database service and endpoints:', cmd: 'kubectl get svc,endpoints -n ' + ns });
    steps.push({ desc: 'Verify network policy allows DB access:', cmd: 'kubectl get networkpolicy -n ' + ns + ' -o yaml' });
  } else if (category === 'Security' && title.startsWith('RBAC risk')) {
    const nameMatch = title.match(/RBAC risk:\s+(.+)$/);
    if (nameMatch) {
      steps.push({ desc: 'Inspect the ClusterRoleBinding in full:', cmd: 'kubectl get clusterrolebinding ' + nameMatch[1] + ' -o yaml' });
      steps.push({ desc: 'List all cluster-admin bindings:', cmd: 'kubectl get clusterrolebindings -o json | jq \'.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name\'' });
    }
  } else if (title.startsWith('Service no endpoints')) {
    const svcMatch = title.match(/:\s+([\w-]+)\/([\w.-]+)$/);
    if (svcMatch) {
      steps.push({ desc: 'Inspect service selector and endpoints:', cmd: 'kubectl describe svc ' + svcMatch[2] + ' -n ' + svcMatch[1] });
      steps.push({ desc: 'Check if any pods match the selector:', cmd: 'kubectl get endpoints ' + svcMatch[2] + ' -n ' + svcMatch[1] });
    }
  } else if (category === 'Resources' || title.includes('Resource limits')) {
    if (pod) {
      steps.push({ desc: 'View current resource requests/limits:', cmd: 'kubectl describe pod ' + pod + ' -n ' + ns + ' | grep -A5 Limits' });
      steps.push({ desc: 'Check current pod resource usage:', cmd: 'kubectl top pod ' + pod + ' -n ' + ns });
    }
  } else if (title.startsWith('ImagePullBackOff') && pod) {
    steps.push({ desc: 'Check image pull events and errors:', cmd: 'kubectl describe pod ' + pod + ' -n ' + ns + ' | grep -A5 "Failed\\|BackOff"' });
    steps.push({ desc: 'Verify the image tag exists in the registry:', cmd: 'kubectl get pod ' + pod + ' -n ' + ns + ' -o jsonpath=\'{.spec.containers[*].image}\'' });
    steps.push({ desc: 'Check imagePullSecrets on the pod:', cmd: 'kubectl get pod ' + pod + ' -n ' + ns + ' -o jsonpath=\'{.spec.imagePullSecrets}\'' });
    steps.push({ desc: 'Check events in namespace:', cmd: 'kubectl get events -n ' + ns + ' --field-selector reason=Failed' });
  } else if (title.startsWith('Selector mismatch')) {
    var smatch = title.match(/:\s+([\w-]+)\/([\w.-]+)$/);
    if (smatch) {
      steps.push({ desc: 'Inspect service selector vs pod labels:', cmd: 'kubectl describe svc ' + smatch[2] + ' -n ' + smatch[1] });
      steps.push({ desc: 'List pods with labels in namespace:', cmd: 'kubectl get pods -n ' + smatch[1] + ' --show-labels' });
      steps.push({ desc: 'Check current endpoints (expect none):', cmd: 'kubectl get endpoints ' + smatch[2] + ' -n ' + smatch[1] });
    }
  } else if (title.startsWith('Cross-namespace blocked')) {
    var cnMatch = title.match(/blocked:\s+([\w-]+)\s*→\s*([\w-]+)/);
    if (cnMatch) {
      var srcNs = cnMatch[1], tgtNs = cnMatch[2];
      steps.push({ desc: 'Check egress NetworkPolicy in source namespace:', cmd: 'kubectl get networkpolicy -n ' + srcNs + ' -o yaml' });
      steps.push({ desc: 'Verify target service and endpoints exist:', cmd: 'kubectl get svc,endpoints -n ' + tgtNs });
      steps.push({ desc: 'Test cross-namespace connectivity:', cmd: 'kubectl run net-debug --image=busybox --rm -it --restart=Never -n ' + srcNs + ' -- nc -zv <target-svc>.' + tgtNs + '.svc.cluster.local <port>' });
      steps.push({ desc: 'View ingress policy on target namespace:', cmd: 'kubectl get networkpolicy -n ' + tgtNs + ' -o yaml' });
    }
  } else if (title.includes('PVC') || title.includes('PersistentVolumeClaim')) {
    var pvcMatch = title.match(/:\s+([\w-]+)\/([\w.-]+)$/);
    if (pvcMatch) {
      steps.push({ desc: 'Describe PVC for provisioner events:', cmd: 'kubectl describe pvc ' + pvcMatch[2] + ' -n ' + pvcMatch[1] });
      steps.push({ desc: 'List available StorageClasses:', cmd: 'kubectl get storageclass' });
      steps.push({ desc: 'Check provisioner failure events:', cmd: 'kubectl get events -n ' + pvcMatch[1] + ' --field-selector reason=ProvisioningFailed' });
    }
  } else if (title.startsWith('CronJob suspended')) {
    var cjMatch = title.match(/:\s+([\w-]+)\/([\w.-]+)$/);
    if (cjMatch) {
      steps.push({ desc: 'Inspect CronJob for suspension reason:', cmd: 'kubectl describe cronjob ' + cjMatch[2] + ' -n ' + cjMatch[1] });
      steps.push({ desc: 'Check recent job runs:', cmd: 'kubectl get jobs -n ' + cjMatch[1] + ' --sort-by=.metadata.creationTimestamp' });
    }
  } else if (title.startsWith('StatefulSet')) {
    var ssMatch = title.match(/:\s+([\w-]+)\/([\w.-]+)$/);
    if (ssMatch) {
      steps.push({ desc: 'Check StatefulSet rollout status:', cmd: 'kubectl rollout status statefulset/' + ssMatch[2] + ' -n ' + ssMatch[1] });
      steps.push({ desc: 'Describe StatefulSet for stuck pods:', cmd: 'kubectl describe statefulset ' + ssMatch[2] + ' -n ' + ssMatch[1] });
      steps.push({ desc: 'List PVCs for this StatefulSet:', cmd: 'kubectl get pvc -n ' + ssMatch[1] + ' | grep ' + ssMatch[2] });
    }
  } else if (category === 'EventLog') {
    // Windows Event Log investigation steps
    var evIdMatch = title.match(/Event\s+(\d+)/i) || detail.match(/Event\s+(\d+)/i);
    var evId = evIdMatch ? evIdMatch[1] : '';
    if (title.toLowerCase().includes('audit log') || evId === '1102') {
      steps.push({ desc: 'Find audit log clear events (requires admin):', cmd: "Get-WinEvent -LogName Security -FilterHashtable @{Id=1102} | Select-Object TimeCreated,Message | Format-List" });
      steps.push({ desc: 'Who logged on just before the clear:', cmd: "Get-WinEvent -LogName Security -FilterHashtable @{Id=4624; StartTime=(Get-Date).AddHours(-2)} | Select-Object TimeCreated,Message | Format-List" });
      steps.push({ desc: 'Check new services installed around same time:', cmd: "Get-WinEvent -LogName System -FilterHashtable @{Id=7045} | Select-Object TimeCreated,Message | Format-List" });
    } else if (title.toLowerCase().includes('service') || evId === '7045') {
      steps.push({ desc: 'List all recently installed services:', cmd: "Get-WinEvent -LogName System -FilterHashtable @{Id=7045; StartTime=(Get-Date).AddHours(-1)} | Select-Object TimeCreated,Message | Format-List" });
      steps.push({ desc: 'Inspect suspicious service binary paths:', cmd: "Get-Service | Where-Object {$_.StartType -eq 'Automatic'} | Select-Object Name,DisplayName,Status" });
      steps.push({ desc: 'Check service registry for persistence keys:', cmd: "Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Services\\* | Where-Object {$_.ImagePath -match 'temp|appdata|public'}" });
    } else if (title.toLowerCase().includes('logon') || title.toLowerCase().includes('logon') || evId === '4625') {
      steps.push({ desc: 'Count failed logons by source IP in last hour:', cmd: "Get-WinEvent -LogName Security -FilterHashtable @{Id=4625; StartTime=(Get-Date).AddHours(-1)} | Group-Object {$_.Properties[19].Value} | Sort Count -Desc" });
      steps.push({ desc: 'Check for successful logon after failed attempts:', cmd: "Get-WinEvent -LogName Security -FilterHashtable @{Id=4624; StartTime=(Get-Date).AddHours(-1)} | Select-Object TimeCreated,Message | Format-List" });
      steps.push({ desc: 'List all locked accounts:', cmd: "Search-ADAccount -LockedOut | Select-Object SamAccountName,LockedOut,LastLogonDate" });
    } else if (evId === '4672') {
      steps.push({ desc: 'Check privilege usage context:', cmd: "Get-WinEvent -LogName Security -FilterHashtable @{Id=4672; StartTime=(Get-Date).AddHours(-2)} | Select-Object TimeCreated,Message | Format-List" });
      steps.push({ desc: 'Verify the account belongs to expected groups:', cmd: "Get-ADGroupMember -Identity 'Domain Admins' | Select-Object Name,SamAccountName" });
    } else {
      if (evId) {
        steps.push({ desc: 'Retrieve recent occurrences of this event:', cmd: "Get-WinEvent -LogName Security -FilterHashtable @{Id=" + evId + "; StartTime=(Get-Date).AddHours(-2)} | Select-Object TimeCreated,Message | Format-List" });
      }
      steps.push({ desc: 'Check all error/critical events in last 2h:', cmd: "Get-WinEvent -LogName System -FilterHashtable @{Level=1,2; StartTime=(Get-Date).AddHours(-2)} | Select-Object TimeCreated,Id,Message | Format-List" });
      steps.push({ desc: 'Export Security log for forensics:', cmd: "wevtutil epl Security C:\\forensics\\security-export.evtx" });
    }
  } else if (category === 'IIS') {
    // IIS investigation steps
    if (title.toLowerCase().includes('5xx') || title.toLowerCase().includes('502') || title.toLowerCase().includes('503')) {
      steps.push({ desc: 'Check IIS application pool state:', cmd: "Get-WebConfiguration system.applicationHost/applicationPools/add | Where-Object {$_.state -ne 'Started'} | Select-Object name,state" });
      steps.push({ desc: 'Tail the most recent IIS error log:', cmd: "Get-ChildItem 'C:\\inetpub\\logs\\LogFiles' -Recurse -Filter '*.log' | Sort LastWriteTime -Desc | Select -First 1 | Get-Content -Tail 100 | Select-String '50[0-9]'" });
      steps.push({ desc: 'Restart the failed application pool:', cmd: "Restart-WebAppPool -Name 'DefaultAppPool'" });
      steps.push({ desc: 'Review Windows Event Log for app pool failures:', cmd: "Get-WinEvent -LogName Application -FilterHashtable @{Id=1000,1002; StartTime=(Get-Date).AddHours(-1)} | Format-List" });
    } else if (title.toLowerCase().includes('slow') || title.toLowerCase().includes('latency')) {
      steps.push({ desc: 'Find slow requests in IIS logs (>5000ms):', cmd: "Get-ChildItem 'C:\\inetpub\\logs\\LogFiles' -Recurse -Filter '*.log' | Sort LastWriteTime -Desc | Select -First 1 | Get-Content | Where-Object {($_ -split ' ')[-1] -gt 5000}" });
      steps.push({ desc: 'Check SQL Server wait statistics:', cmd: "Invoke-Sqlcmd -Query \"SELECT TOP 10 wait_type, wait_time_ms FROM sys.dm_os_wait_stats ORDER BY wait_time_ms DESC\"" });
      steps.push({ desc: 'Review IIS request queue length:', cmd: "Get-Counter '\\Web Service(_Total)\\Current Connections'" });
    } else if (title.toLowerCase().includes('scan') || title.toLowerCase().includes('suspicious') || title.toLowerCase().includes('probe')) {
      steps.push({ desc: 'Find top requesting IPs in last hour:', cmd: "Get-ChildItem 'C:\\inetpub\\logs\\LogFiles' -Recurse -Filter '*.log' | Sort LastWriteTime -Desc | Select -First 1 | Get-Content | Where-Object {$_ -notmatch '^#'} | Group-Object {($_ -split ' ')[2]} | Sort Count -Desc | Select -First 10" });
      steps.push({ desc: 'Block the offending IP at Windows Firewall:', cmd: "New-NetFirewallRule -DisplayName 'Block Scanner' -Direction Inbound -Action Block -RemoteAddress '185.220.101.0/24'" });
      steps.push({ desc: 'Enable Dynamic IP Restrictions in IIS:', cmd: "Set-WebConfigurationProperty -Filter system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests -Name enabled -Value True" });
    } else {
      steps.push({ desc: 'List IIS sites and their status:', cmd: "Get-WebSite | Select-Object Name,State,PhysicalPath" });
      steps.push({ desc: 'Check IIS error log:', cmd: "Get-ChildItem 'C:\\inetpub\\logs\\LogFiles' -Recurse -Filter '*.log' | Sort LastWriteTime -Desc | Select -First 1 | Get-Content -Tail 50" });
    }
  } else if (category === 'Syslog') {
    // Linux syslog investigation steps
    var unitMatch = title.match(/(\S+\.service)/) || detail.match(/(\S+\.service)/);
    var unit = unitMatch ? unitMatch[1] : '';
    if (title.toLowerCase().includes('oom') || title.toLowerCase().includes('killed')) {
      steps.push({ desc: 'Confirm OOM kill in kernel ring buffer:', cmd: "dmesg | grep -i 'oom\\|killed process\\|out of memory' | tail -20" });
      steps.push({ desc: 'Check process memory usage now:', cmd: "ps aux --sort=-%mem | head -15" });
      steps.push({ desc: 'View journalctl OOM events:', cmd: "journalctl -k --since '2 hours ago' | grep -i 'oom\\|kill' | tail -30" });
      steps.push({ desc: 'Check current memory pressure:', cmd: "free -h && cat /proc/meminfo | grep -E 'MemAvailable|Dirty|Writeback'" });
    } else if (title.toLowerCase().includes('ssh') || title.toLowerCase().includes('brute')) {
      steps.push({ desc: 'Count failed SSH attempts by IP:', cmd: "journalctl -u sshd --since '1 hour ago' --no-pager | grep 'Failed password' | awk '{print $11}' | sort | uniq -c | sort -rn | head -10" });
      steps.push({ desc: 'Block attacking IP with iptables:', cmd: "iptables -A INPUT -s 185.220.101.47 -j DROP && iptables-save > /etc/iptables/rules.v4" });
      steps.push({ desc: 'Check for successful auth from attacker IPs:', cmd: "journalctl -u sshd --since '2 hours ago' | grep 'Accepted' | tail -20" });
      steps.push({ desc: 'Install and configure fail2ban if not present:', cmd: "apt-get install -y fail2ban && systemctl enable fail2ban && systemctl start fail2ban" });
    } else if (title.toLowerCase().includes('crash') || title.toLowerCase().includes('failed') || unit) {
      var target = unit || 'nginx';
      steps.push({ desc: 'Check service status and last failure reason:', cmd: "systemctl status " + target + " --no-pager -l" });
      steps.push({ desc: 'View full service journal (last 100 lines):', cmd: "journalctl -u " + target + " --no-pager -n 100" });
      steps.push({ desc: 'Check ExecStartPre failure details:', cmd: "journalctl -u " + target + " --since '1 hour ago' | grep -i 'error\\|fail\\|fatal'" });
      steps.push({ desc: 'Reset failed counter and restart service:', cmd: "systemctl reset-failed " + target + " && systemctl start " + target });
    } else if (title.toLowerCase().includes('disk') || title.toLowerCase().includes('i/o')) {
      steps.push({ desc: 'Check current disk I/O utilisation:', cmd: "iostat -x 1 5 | grep -v '^$'" });
      steps.push({ desc: 'Find processes with highest I/O:', cmd: "iotop -b -n 3 -o | head -20" });
      steps.push({ desc: 'Check disk usage by directory:', cmd: "du -sh /* 2>/dev/null | sort -rh | head -15" });
      steps.push({ desc: 'Check for disk errors in kernel log:', cmd: "dmesg | grep -i 'error\\|reset\\|timeout\\|I/O error' | tail -20" });
    } else {
      steps.push({ desc: 'Check error-level syslog entries (last 2h):', cmd: "journalctl -p err --since '2 hours ago' --no-pager | tail -50" });
      steps.push({ desc: 'View kernel messages for hardware issues:', cmd: "dmesg --level=err,crit,alert,emerg | tail -30" });
      steps.push({ desc: 'Check system uptime and load average:', cmd: "uptime && cat /proc/loadavg" });
    }
  } else if (category === 'HTTPLog') {
    // nginx / Apache access+error log investigation steps
    if (title.toLowerCase().includes('503') || title.toLowerCase().includes('upstream')) {
      steps.push({ desc: 'Check upstream backend connectivity:', cmd: "curl -sv http://app-backend:8080/health 2>&1 | tail -20" });
      steps.push({ desc: 'Count 503 errors in last 200 log lines:', cmd: "tail -200 /var/log/nginx/access.log | awk '$9 == 503' | wc -l" });
      steps.push({ desc: 'View recent nginx error log for upstream failures:', cmd: "tail -100 /var/log/nginx/error.log | grep 'upstream'" });
      steps.push({ desc: 'Check nginx upstream health and worker count:', cmd: "nginx -T | grep -E 'upstream|worker_processes|keepalive'" });
      steps.push({ desc: 'Reload nginx config after fix:', cmd: "nginx -t && systemctl reload nginx" });
    } else if (title.toLowerCase().includes('slow') || title.toLowerCase().includes('latency') || title.toLowerCase().includes('p95')) {
      steps.push({ desc: 'Find slowest endpoints in access log (>5s):', cmd: "awk '$NF > 5000000 {print $NF, $7}' /var/log/nginx/access.log | sort -rn | head -20" });
      steps.push({ desc: 'Check database slow query log:', cmd: "tail -100 /var/log/postgresql/postgresql-*.log | grep 'duration' | sort -t'=' -k2 -rn | head -10" });
      steps.push({ desc: 'Profile running queries in PostgreSQL:', cmd: "psql -c \"SELECT pid, now()-query_start AS duration, query FROM pg_stat_activity WHERE state='active' ORDER BY duration DESC LIMIT 10;\"" });
      steps.push({ desc: 'Check for missing DB indexes (explain analyze):', cmd: "psql -c \"EXPLAIN ANALYZE SELECT * FROM reports WHERE created_at > NOW() - INTERVAL '1 day';\"" });
    } else if (title.toLowerCase().includes('scan') || title.toLowerCase().includes('bot') || title.toLowerCase().includes('probe')) {
      steps.push({ desc: 'Find top attacker IPs in access log:', cmd: "awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20" });
      steps.push({ desc: 'Block scanner range at nginx level:', cmd: "echo 'deny 185.220.101.0/24;' >> /etc/nginx/conf.d/blocklist.conf && nginx -t && systemctl reload nginx" });
      steps.push({ desc: 'Check which paths are being probed:', cmd: "grep '185.220.101' /var/log/nginx/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -20" });
      steps.push({ desc: 'Install fail2ban nginx jail if not present:', cmd: "fail2ban-client status nginx-http-auth" });
    } else {
      steps.push({ desc: 'Check recent HTTP error distribution:', cmd: "awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn" });
      steps.push({ desc: 'View nginx error log tail:', cmd: "tail -50 /var/log/nginx/error.log" });
      steps.push({ desc: 'Verify nginx config is valid:', cmd: "nginx -t 2>&1" });
    }
  } else {
    // Generic fallback.
    if (pod) {
      steps.push({ desc: 'Describe the affected resource:', cmd: 'kubectl describe pod ' + pod + ' -n ' + ns });
      steps.push({ desc: 'Check related events:', cmd: 'kubectl get events -n ' + ns + ' --field-selector type=Warning' });
    }
  }

  return steps;
}

// ── Health score ──────────────────────────────────────────────────────────
// Score 0-100 based on severity counts.  Heavy penalty for critical, diminishing.
function buildHealthScore(sevCounts) {
  var crit = sevCounts.critical || 0;
  var high = sevCounts.high     || 0;
  var med  = sevCounts.medium   || 0;
  var low  = sevCounts.low      || 0;
  var score = Math.round(Math.max(0, Math.min(100,
    100
    - Math.min(crit * 12, 50)
    - Math.min(high * 3,  28)
    - Math.min(med  * 1,   8)
    - Math.min(low  * 0.3, 4)
  )));
  return score;
}

function buildHealthRing(container, score) {
  if (!container) return;
  var R = 28, cx = 34, cy = 34;
  var circ = 2 * Math.PI * R;
  var filled = (score / 100) * circ;
  var color = score >= 75 ? '#3fb950' :
              score >= 50 ? '#e3b341' :
              score >= 25 ? '#d29922' : '#da3633';
  container.innerHTML =
    '<svg viewBox="0 0 68 68" xmlns="http://www.w3.org/2000/svg">' +
      '<circle cx="' + cx + '" cy="' + cy + '" r="' + R + '" fill="none" stroke="#21262d" stroke-width="6"/>' +
      '<circle cx="' + cx + '" cy="' + cy + '" r="' + R + '" fill="none"' +
        ' stroke="' + color + '" stroke-width="6" stroke-linecap="round"' +
        ' stroke-dasharray="' + filled.toFixed(1) + ' ' + circ.toFixed(1) + '">' +
        '<title>Cluster health score: ' + score + '%</title>' +
      '</circle>' +
    '</svg>' +
    '<div class="health-score-center">' +
      '<span class="health-score-num" style="color:' + color + '">' + score + '</span>' +
      '<span class="health-score-label">health</span>' +
    '</div>';
}

// ── Namespace filter ──────────────────────────────────────────────────────
var _activeNs  = 'all';
var _activeSev = 'all';

// Shared filter function — applies severity, namespace, and search filters conjunctively.
function applyFilters() {
  document.querySelectorAll('.finding-card').forEach(function(card) {
    var sevOk  = _activeSev === 'all' || card.dataset.severity === _activeSev;
    var nsOk   = _activeNs  === 'all' ||
                 (card.dataset.title  || '').indexOf(_activeNs + '/') !== -1 ||
                 (card.dataset.source || '').indexOf('/' + _activeNs) !== -1;
    var searchOk = !card.dataset.searchHidden;
    card.style.display = (sevOk && nsOk && searchOk) ? '' : 'none';
  });
  document.querySelectorAll('.finding-group').forEach(function(g) {
    var visible = g.querySelectorAll('.finding-card:not([style*="display: none"])').length > 0;
    g.style.display = visible ? '' : 'none';
  });
}

function buildNamespaceFilter(findings, container) {
  if (!container) return;
  var nsSet = {};
  findings.forEach(function(f) {
    // Extract k8s namespaces from "ns/name" patterns in the title.
    var title = f.title || '';
    var re = /\b([\w-]+)\/([\w.-]+)/g, m;
    while ((m = re.exec(title)) !== null) {
      var ns = m[1];
      if (ns && ns.length >= 3 && ns.indexOf('.') === -1 && ns !== 'cluster') {
        nsSet[ns] = true;
      }
    }
    // Also extract hostnames from the source field (e.g. "eventlog/win-dc-01" → "win-dc-01").
    var src = f.source || '';
    var slash = src.lastIndexOf('/');
    if (slash >= 0) {
      var host = src.slice(slash + 1);
      if (host && host.length >= 3) nsSet[host] = true;
    }
  });
  var namespaces = Object.keys(nsSet).sort();
  if (namespaces.length < 2) { container.innerHTML = ''; return; }

  container.innerHTML = '';
  var allPill = document.createElement('button');
  allPill.className = 'ns-pill all' + (_activeNs === 'all' ? ' active' : '');
  allPill.textContent = 'all ns';
  allPill.onclick = function() { filterByNamespace('all', allPill); };
  container.appendChild(allPill);

  namespaces.forEach(function(ns) {
    var pill = document.createElement('button');
    pill.className = 'ns-pill' + (_activeNs === ns ? ' active' : '');
    pill.textContent = ns;
    pill.onclick = (function(n, p) { return function() { filterByNamespace(n, p); }; })(ns, pill);
    container.appendChild(pill);
  });
}

function filterByNamespace(ns, clickedPill) {
  _activeNs = ns;
  document.querySelectorAll('.ns-pill').forEach(function(p) { p.classList.remove('active'); });
  if (clickedPill) clickedPill.classList.add('active');
  applyFilters();
}

// ── Donut chart ───────────────────────────────────────────────────────────
function buildDonutChart(container, counts) {
  const total = SEV_ORDER.reduce(function(s, k) { return s + (counts[k] || 0); }, 0);
  if (total === 0) { container.style.display = 'none'; return; }

  const R = 28, r = 18, cx = 34, cy = 34;
  const segments = SEV_ORDER.filter(function(k) { return counts[k] > 0; })
    .map(function(k) { return { sev: k, val: counts[k], pct: counts[k] / total }; });

  function polarToXY(angle, radius) {
    return { x: cx + radius * Math.cos(angle - Math.PI / 2), y: cy + radius * Math.sin(angle - Math.PI / 2) };
  }

  let svg = '<svg viewBox="0 0 68 68" xmlns="http://www.w3.org/2000/svg">';
  let startAngle = 0;
  segments.forEach(function(seg) {
    const endAngle = startAngle + seg.pct * 2 * Math.PI;
    const large = seg.pct > 0.5 ? 1 : 0;
    const s = polarToXY(startAngle, R), e = polarToXY(endAngle, R);
    const si = polarToXY(startAngle, r), ei = polarToXY(endAngle, r);
    svg += '<path d="M ' + s.x + ' ' + s.y +
           ' A ' + R + ' ' + R + ' 0 ' + large + ' 1 ' + e.x + ' ' + e.y +
           ' L ' + ei.x + ' ' + ei.y +
           ' A ' + r + ' ' + r + ' 0 ' + large + ' 0 ' + si.x + ' ' + si.y + ' Z"' +
           ' fill="' + SEV_COLORS[seg.sev] + '">' +
           '<title>' + seg.sev + ': ' + seg.val + '</title></path>';
    startAngle = endAngle;
  });
  svg += '</svg>';

  container.innerHTML = svg +
    '<div class="donut-center">' +
    '<span class="donut-center-num">' + total + '</span>' +
    '<span class="donut-center-label">findings</span>' +
    '</div>';
}

// ── Category bar chart ────────────────────────────────────────────────────
function buildCategoryChart(container, findings) {
  const cats = {};
  findings.forEach(function(f) {
    const c = f.category || 'Other';
    if (!cats[c]) cats[c] = { count: 0, maxSev: 4 };
    cats[c].count++;
    const sevIdx = SEV_ORDER.indexOf(f.severity);
    if (sevIdx < cats[c].maxSev) cats[c].maxSev = sevIdx;
  });

  const keys = Object.keys(cats);
  if (keys.length === 0) { container.style.display = 'none'; return; }

  const maxCount = Math.max.apply(null, keys.map(function(k) { return cats[k].count; }));
  const W = container.offsetWidth || 300;
  const H = 52;
  const barW = Math.min(36, Math.floor((W - keys.length * 4) / keys.length));
  const gap = Math.floor((W - keys.length * barW) / (keys.length + 1));

  let svg = '<svg width="100%" height="' + (H + 14) + '" xmlns="http://www.w3.org/2000/svg">';
  keys.forEach(function(k, i) {
    const x = gap + i * (barW + gap);
    const barH = Math.max(4, Math.round((cats[k].count / maxCount) * H));
    const y = H - barH;
    const color = SEV_COLORS[SEV_ORDER[cats[k].maxSev]] || '#484f58';
    svg += '<rect x="' + x + '" y="' + y + '" width="' + barW + '" height="' + barH + '" fill="' + color + '" rx="2">' +
           '<title>' + k + ': ' + cats[k].count + '</title></rect>';
    // Count label inside bar if tall enough.
    if (barH > 14) {
      svg += '<text x="' + (x + barW / 2) + '" y="' + (y + barH / 2 + 4) + '" text-anchor="middle" fill="#0d1117" font-size="9" font-weight="700" font-family="monospace">' + cats[k].count + '</text>';
    }
    // Category label below.
    const label = k.length > 7 ? k.slice(0, 6) + '…' : k;
    svg += '<text x="' + (x + barW / 2) + '" y="' + (H + 13) + '" text-anchor="middle" fill="#8b949e" font-size="8" font-family="monospace">' + label + '</text>';
  });
  svg += '</svg>';
  container.innerHTML = svg;
}

// ── Horizontal severity bar ───────────────────────────────────────────────
function buildSeverityBar(container, counts) {
  const total = SEV_ORDER.reduce(function(s, k) { return s + (counts[k] || 0); }, 0);
  if (total === 0) { container.style.display = 'none'; return; }

  const W = container.offsetWidth || 300;
  const H = 18;
  const segs = SEV_ORDER.filter(function(k) { return counts[k] > 0; })
    .map(function(k) { return { sev: k, count: counts[k], pct: counts[k] / total }; });

  let svg = '<svg width="100%" height="' + H + '" role="img" aria-label="Severity distribution">';
  let x = 0;
  segs.forEach(function(seg) {
    const w = Math.round(seg.pct * W);
    svg += '<rect x="' + x + '" y="0" width="' + w + '" height="' + H + '" fill="' + SEV_COLORS[seg.sev] + '">' +
           '<title>' + seg.sev + ': ' + seg.count + ' (' + Math.round(seg.pct * 100) + '%)</title></rect>';
    if (w > 40) {
      svg += '<text x="' + (x + w / 2) + '" y="' + (H / 2 + 4) + '" text-anchor="middle" fill="#0d1117" font-size="9" font-weight="700" font-family="monospace">' + seg.sev + ' ' + seg.count + '</text>';
    }
    x += w;
  });
  svg += '</svg>';
  container.innerHTML = svg;
}

// ── Markdown renderer ─────────────────────────────────────────────────────
function escHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function inlineFormat(s) {
  s = escHtml(s);
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
  return s;
}

function renderMarkdown(text) {
  if (!text || !text.trim()) return '<em>No narrative available.</em>';
  const lines = text.split('\n');
  let html = '', inFence = false, fenceContent = '', inList = false, inOL = false;
  function closeList() {
    if (inList) { html += '</ul>'; inList = false; }
    if (inOL)   { html += '</ol>'; inOL   = false; }
  }
  lines.forEach(function(raw) {
    const t = raw.trim();
    if (t.startsWith('```')) {
      if (!inFence) { closeList(); inFence = true; fenceContent = ''; }
      else { html += '<pre><code>' + escHtml(fenceContent.replace(/\n$/, '')) + '</code></pre>'; inFence = false; }
      return;
    }
    if (inFence) { fenceContent += raw + '\n'; return; }
    if (t.startsWith('## ')) { closeList(); html += '<h2>' + escHtml(t.slice(3)) + '</h2>'; return; }
    if (t.startsWith('- ') || t.startsWith('* ')) {
      if (inOL) { html += '</ol>'; inOL = false; }
      if (!inList) { html += '<ul>'; inList = true; }
      html += '<li>' + inlineFormat(t.slice(2)) + '</li>'; return;
    }
    const nm = t.match(/^(\d+)\.\s+(.*)/);
    if (nm) {
      if (inList) { html += '</ul>'; inList = false; }
      if (!inOL) { html += '<ol>'; inOL = true; }
      html += '<li>' + inlineFormat(nm[2]) + '</li>'; return;
    }
    if (!t) { closeList(); return; }
    closeList();
    html += '<p>' + inlineFormat(t) + '</p>';
  });
  closeList();
  if (inFence) html += '<pre><code>' + escHtml(fenceContent) + '</code></pre>';
  return html;
}

// ── Narrative tabs ────────────────────────────────────────────────────────
// Split raw markdown into named sections by ## headers.
// Tab keys: verdict, incidents, rbac, prevention, all.

function parseNarrativeSections(raw) {
  const sections = {};
  let currentKey = 'verdict';
  let currentLines = [];

  raw.split('\n').forEach(function(line) {
    if (line.startsWith('## ')) {
      if (currentLines.length > 0) sections[currentKey] = currentLines.join('\n');
      const heading = line.slice(3).trim().toLowerCase();
      if (heading.includes('verdict'))    currentKey = 'verdict';
      else if (heading.includes('incident') || heading.includes('top')) currentKey = 'incidents';
      else if (heading.includes('rbac'))  currentKey = 'rbac';
      else if (heading.includes('prevent')) currentKey = 'prevention';
      else currentKey = heading.replace(/\s+/g, '-');
      currentLines = ['## ' + line.slice(3)];
    } else {
      currentLines.push(line);
    }
  });
  if (currentLines.length > 0) sections[currentKey] = currentLines.join('\n');
  return sections;
}

let _narrativeSections = {};

function switchTab(btn) {
  const tab = btn.dataset.tab;
  document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');

  const el = document.getElementById('narrative-content');
  if (!el) return;

  if (tab === 'all') {
    el.innerHTML = renderMarkdown(el.dataset.raw || '');
    return;
  }
  const content = _narrativeSections[tab];
  el.innerHTML = content ? renderMarkdown(content) : '<em>No content for this section.</em>';
}

// ── Toggle helpers ────────────────────────────────────────────────────────
function toggleGroup(btn) {
  const expanded = btn.getAttribute('aria-expanded') === 'true';
  btn.setAttribute('aria-expanded', String(!expanded));
  const body = btn.nextElementSibling;
  if (body) body.classList.toggle('collapsed', expanded);
  const chevron = btn.querySelector('.group-chevron');
  if (chevron) chevron.textContent = expanded ? '▸' : '▾';
}

function toggleCard(card) {
  card.classList.toggle('expanded');
  const chevron = card.querySelector('.card-chevron');
  if (chevron) chevron.textContent = card.classList.contains('expanded') ? '▴' : '▾';
}

// ── Severity filter ───────────────────────────────────────────────────────
function filterBySeverity(btn) {
  document.querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  _activeSev = btn.dataset.sev;
  applyFilters();
}

// ── Copy to clipboard ─────────────────────────────────────────────────────
function copyText(btn, text) {
  navigator.clipboard.writeText(text).then(function() {
    btn.textContent = '✓';
    btn.classList.add('copied');
    setTimeout(function() { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1500);
  });
}

// ── Per-finding Apply Fix modal ───────────────────────────────────────────
let _pendingAction = null;
let _pendingFixWarning = '';

// Map shell type to a human-readable label used in the modal.
var _shellLabel = { powershell: '🪟 PowerShell', bash: '🐧 bash', '': '⬡ kubectl' };

function applyFix(card) {
  const raw = card.dataset.remediation;
  if (!raw) return;
  let action;
  try { action = JSON.parse(raw); } catch (e) { return; }
  _pendingAction = action;
  _pendingFixWarning = card._fixWarning || '';

  const desc    = document.getElementById('modal-description');
  const kubectl = document.getElementById('modal-kubectl');
  const result  = document.getElementById('modal-result');
  const applyBtn = document.getElementById('modal-apply-btn');
  const warnEl  = document.getElementById('modal-root-cause-warn');
  const warnTxt = document.getElementById('modal-root-cause-text');
  const title   = document.getElementById('modal-title');

  // Tailor modal title to the shell type.
  var shell = action.shell || '';
  var label = _shellLabel[shell] || '⬡ kubectl';
  if (title) title.textContent = 'Confirm Remediation — ' + label;

  if (desc) desc.textContent = action.description || '';
  if (kubectl) kubectl.textContent = action.kubectl_cmd || '';
  if (result)  { result.className = 'modal-result hidden'; result.textContent = ''; }
  if (applyBtn) {
    applyBtn.disabled = false;
    // Shell remediations run on the target host — label the button clearly.
    applyBtn.textContent = shell ? 'Copy & Confirm' : 'Apply';
  }

  // Show action.warning (static field from the report) or the root-cause warning.
  var warn = action.warning || _pendingFixWarning || '';
  if (warnEl && warnTxt) {
    if (warn) {
      warnTxt.textContent = warn;
      warnEl.classList.remove('hidden');
    } else {
      warnEl.classList.add('hidden');
    }
  }

  document.getElementById('fix-modal').classList.remove('hidden');
}

function closeFixModal() {
  document.getElementById('fix-modal').classList.add('hidden');
  _pendingAction = null;
  _pendingFixWarning = '';
}

function confirmFix() {
  if (!_pendingAction) return;
  const applyBtn = document.getElementById('modal-apply-btn');
  const result   = document.getElementById('modal-result');
  if (applyBtn) applyBtn.disabled = true;

  // Shell remediations (powershell/bash) run on the target host — copy the command
  // to the clipboard and record the action via /api/fix for audit purposes.
  var isShell = !!(_pendingAction.shell);
  if (isShell && _pendingAction.kubectl_cmd) {
    try { navigator.clipboard.writeText(_pendingAction.kubectl_cmd); } catch (_) {}
  }

  fetch('/api/fix', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Exalm-Request': 'true' },
    body: JSON.stringify(_pendingAction),
  })
    .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
    .then(function(res) {
      if (result) {
        result.className = 'modal-result ' + (res.ok ? 'success' : 'error');
        if (res.ok) {
          result.textContent = isShell
            ? '✓ Command copied to clipboard. Run it on the target host.'
            : '✓ Fix applied.';
        } else {
          result.textContent = '✗ Error: ' + (res.data.error || 'unknown');
        }
      }
      if (res.ok) {
        // The server re-collects after applying; reload so the resolved finding
        // drops out of the list (and stale remediations can't be re-fired).
        setTimeout(function() {
          closeFixModal();
          if (_autoRefreshEnabled && !document.hidden) window.location.reload();
        }, 1800);
      } else if (applyBtn) {
        applyBtn.disabled = false;
      }
    })
    .catch(function(err) {
      if (result) { result.className = 'modal-result error'; result.textContent = '✗ ' + err.message; }
      if (applyBtn) applyBtn.disabled = false;
    });
}

// ── Fix All modal ─────────────────────────────────────────────────────────
let _fixAllItems = [];

function openFixAll() {
  _fixAllItems = [];
  const list = document.getElementById('fix-all-list');
  const result = document.getElementById('fix-all-result');
  const applyBtn = document.getElementById('fix-all-apply-btn');
  if (!list) return;

  list.innerHTML = '';
  if (result) { result.className = 'modal-result hidden'; result.textContent = ''; }
  if (applyBtn) applyBtn.disabled = false;

  document.querySelectorAll('.finding-card[data-remediation]').forEach(function(card) {
    const raw = card.dataset.remediation;
    if (!raw || raw === '{}') return;
    let action;
    try { action = JSON.parse(raw); } catch (e) { return; }

    const sev     = card.dataset.severity || '';
    const title   = card.dataset.title   || action.description || '';
    const warning = card._fixWarning     || '';

    _fixAllItems.push({ title: title, action: action, warning: warning });

    const item = document.createElement('div');
    item.className = 'fix-all-item';
    item.innerHTML =
      '<div class="fix-all-item-header">' +
        '<span class="severity-badge ' + sev + '">' + sev + '</span>' +
        '<span class="fix-all-item-title">' + escHtml(title) + '</span>' +
        '<span class="fix-all-item-status" data-idx="' + (_fixAllItems.length - 1) + '"></span>' +
      '</div>' +
      '<div class="fix-all-item-cmd">' + escHtml(action.kubectl_cmd || '') + '</div>' +
      (warning ? '<div class="fix-all-item-warn">⚠ ' + escHtml(warning) + '</div>' : '');
    list.appendChild(item);
  });

  if (_fixAllItems.length === 0) {
    list.innerHTML = '<div style="padding:0.75rem;color:#8b949e">No fixable findings.</div>';
  }

  document.getElementById('fix-all-modal').classList.remove('hidden');
}

function closeFixAllModal() {
  document.getElementById('fix-all-modal').classList.add('hidden');
}

function confirmFixAll() {
  const applyBtn = document.getElementById('fix-all-apply-btn');
  const result   = document.getElementById('fix-all-result');
  if (applyBtn) applyBtn.disabled = true;

  const actions = _fixAllItems.map(function(item) { return item.action; });

  fetch('/api/fix-all', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Exalm-Request': 'true' },
    body: JSON.stringify(actions),
  })
    .then(function(r) { return r.json(); })
    .then(function(results) {
      results.forEach(function(res, i) {
        const statusEl = document.querySelector('.fix-all-item-status[data-idx="' + i + '"]');
        if (statusEl) {
          statusEl.textContent = res.ok ? '✓ applied' : '✗ ' + (res.error || 'failed');
          statusEl.className = 'fix-all-item-status ' + (res.ok ? 'ok' : 'error');
        }
      });
      const allOk = results.every(function(r) { return r.ok; });
      if (result) {
        result.className = 'modal-result ' + (allOk ? 'success' : 'error');
        result.textContent = allOk
          ? '✓ All fixes applied successfully.'
          : '⚠ Some fixes failed — check individual results above.';
      }
      // The server re-collects after the batch; reload so resolved findings
      // drop out and the remaining list reflects the new cluster state.
      if (_autoRefreshEnabled) {
        setTimeout(function() {
          if (!document.hidden) window.location.reload();
        }, 2200);
      }
    })
    .catch(function(err) {
      if (result) { result.className = 'modal-result error'; result.textContent = '✗ ' + err.message; }
      if (applyBtn) applyBtn.disabled = false;
    });
}

// ── Create PR ─────────────────────────────────────────────────────────────
function createPR(btn) {
  if (btn) btn.disabled = true;
  fetch('/api/create-pr', { method: 'POST', headers: { 'X-Exalm-Request': 'true' } })
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (d.url) window.open(d.url, '_blank', 'noopener');
      else alert('PR creation failed: ' + (d.error || 'unknown error'));
    })
    .catch(function(err) { alert('PR creation failed: ' + err.message); })
    .finally(function() { if (btn) btn.disabled = false; });
}

// ── Enrich cards with root cause and investigation steps ──────────────────
// ── Phase 6: Status bar (Komodor signature) ──────────────────────────────
// Reads the live report + changes feed and renders the four headline stats:
//   Health   — integer 0-100 (from buildHealthScore)
//   Incidents — count of critical+high findings (we don't have a real incident
//               store yet, so we proxy on severity until plugins/incident matures)
//   SLO     — chip showing the worst burn tier across all SLO findings, or
//               "all green" when none are triggered
//   Last deploy — humanized time-ago for the newest Deployment change
function buildStatusBar(findings, changes) {
  var sevCounts = {};
  SEV_ORDER.forEach(function(k) { sevCounts[k] = 0; });
  findings.forEach(function(f) {
    if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++;
  });

  var health = buildHealthScore(sevCounts);
  var healthEl = document.getElementById('status-health');
  if (healthEl) {
    healthEl.textContent = health;
    healthEl.style.color = health >= 75 ? 'var(--green)' :
                           health >= 50 ? 'var(--yellow)' :
                           health >= 25 ? 'var(--orange)' :
                                          'var(--red)';
  }

  // Incident count proxy: critical + high until we have a real incident store.
  var incidents = sevCounts.critical + sevCounts.high;
  var incEl = document.getElementById('status-incidents');
  if (incEl) {
    incEl.textContent = incidents;
    incEl.style.color = incidents > 0 ? 'var(--red)' : 'var(--green)';
  }

  // SLO chip — pick the worst tier across SLO findings.
  // Severity:critical means "page" tier in our burnRatesToFindings mapping.
  var sloChip = document.getElementById('status-slo');
  if (sloChip) {
    var page = 0, ticket = 0, warn = 0;
    findings.forEach(function(f) {
      if (f.category !== 'SLO') return;
      if (f.severity === 'critical') page++;
      else if (f.severity === 'high') ticket++;
      else if (f.severity === 'medium') warn++;
    });
    if (page > 0) {
      sloChip.textContent = '🔥 page (' + page + ')';
      sloChip.className = 'status-chip status-chip--red';
    } else if (ticket > 0) {
      sloChip.textContent = '⚠ ticket (' + ticket + ')';
      sloChip.className = 'status-chip status-chip--amber';
    } else if (warn > 0) {
      sloChip.textContent = 'ℹ warn (' + warn + ')';
      sloChip.className = 'status-chip status-chip--blue';
    } else {
      sloChip.textContent = 'all green';
      sloChip.className = 'status-chip status-chip--green';
    }
  }

  // Last deploy — newest Deployment-kind change.
  var deployEl = document.getElementById('status-last-deploy');
  if (deployEl) {
    var newest = null;
    (changes || []).forEach(function(c) {
      if (c.kind === 'Deployment' || c.kind === 'StatefulSet' || c.kind === 'DaemonSet') {
        if (!newest || new Date(c.timestamp) > new Date(newest.timestamp)) {
          newest = c;
        }
      }
    });
    if (newest) {
      var ago = Math.round((Date.now() - new Date(newest.timestamp).getTime()) / 1000);
      deployEl.textContent = humanizeAgo(ago) + ' (' + (newest.actor || 'unknown') + ')';
    } else {
      deployEl.textContent = 'none recorded';
      deployEl.style.color = 'var(--text-dim)';
    }
  }
}

// ── Backend correlation (Phase 4) ─────────────────────────────────────────
// Strength: komodor — "Change-correlation engine ... automatically ties failures
// to the recent change most likely to have caused them."
// Strength: openobserve — "AI SRE Agent shows complete evidence chain ...
// verifiable, not a black box." We render BOTH on every finding card.
function enrichWithBackendCorrelation(findings) {
  findings.forEach(function(f) {
    if (!f || !f.title) return;
    // Find the card by matching data-title attribute.
    var card = document.querySelector('.finding-card[data-title="' + cssEscapeAttr(f.title) + '"]');
    if (!card) return;

    // Likely cause badge near title.
    if (f.likely_cause && f.likely_cause.id) {
      renderLikelyCause(card, f.likely_cause);
    }

    // Evidence chain in body.
    if (f.evidence && f.evidence.length > 0) {
      renderEvidenceChain(card, f.evidence);
    }
  });
}

function cssEscapeAttr(s) {
  // Minimal escaper for use inside a CSS attribute selector.
  return String(s).replace(/"/g, '\\"');
}

function renderLikelyCause(card, cause) {
  if (card.querySelector('.likely-cause-badge')) return; // idempotent
  var actions = card.querySelector('.finding-header-actions');
  if (!actions) return;
  var badge = document.createElement('span');
  badge.className = 'likely-cause-badge';
  var ago = humanizeAgo(cause.ago_seconds || 0);
  var actor = cause.actor || 'unknown';
  badge.textContent = '↺ ' + cause.kind.toLowerCase() + ' ' + ago + ' by ' + actor;
  badge.title = 'Likely caused by ' + cause.kind + ' "' + (cause.namespace || '') + '/' + cause.name + '" — ' + ago + ' by ' + actor;
  actions.insertBefore(badge, actions.firstChild);
}

function renderEvidenceChain(card, items) {
  if (card.querySelector('.evidence-section')) return; // idempotent
  var body = card.querySelector('.finding-body');
  if (!body) return;
  var sec = document.createElement('div');
  sec.className = 'evidence-section';
  var label = document.createElement('div');
  label.className = 'section-label';
  label.textContent = 'Evidence (' + items.length + ')';
  sec.appendChild(label);

  var list = document.createElement('ul');
  list.className = 'evidence-list';
  items.forEach(function(it) {
    var li = document.createElement('li');
    li.className = 'evidence-item evidence-' + (it.kind || 'log');
    var icon = ({log: '📝', event: '⚡', metric: '📊', change: '↺'})[it.kind] || '•';
    var head = document.createElement('div');
    head.className = 'evidence-head';
    head.innerHTML = '<span class="evidence-icon">' + icon + '</span>' +
                     '<span class="evidence-kind">' + escHtml(it.kind || '') + '</span>' +
                     '<span class="evidence-source">' + escHtml(it.source || '') + '</span>';
    li.appendChild(head);
    if (it.excerpt) {
      var ex = document.createElement('div');
      ex.className = 'evidence-excerpt';
      ex.textContent = it.excerpt;
      li.appendChild(ex);
    }
    if (it.anchor) {
      var actions = document.createElement('div');
      actions.className = 'evidence-actions';
      var btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.type = 'button';
      btn.textContent = 'copy';
      btn.onclick = function(ev) { ev.stopPropagation(); copyText(btn, it.anchor); };
      actions.appendChild(btn);
      var cmd = document.createElement('code');
      cmd.className = 'evidence-anchor';
      cmd.textContent = it.anchor;
      actions.appendChild(cmd);
      li.appendChild(actions);
    }
    list.appendChild(li);
  });
  sec.appendChild(list);

  // Insert after the root-cause section if present, else as first child.
  var rcSec = body.querySelector('.root-cause-section');
  if (rcSec && rcSec.nextSibling) {
    body.insertBefore(sec, rcSec.nextSibling);
  } else {
    body.insertBefore(sec, body.firstChild);
  }
}

function humanizeAgo(seconds) {
  if (!seconds || seconds < 1) return 'just now';
  if (seconds < 60) return seconds + 's ago';
  if (seconds < 3600) return Math.round(seconds / 60) + 'm ago';
  if (seconds < 86400) return Math.round(seconds / 3600) + 'h ago';
  return Math.round(seconds / 86400) + 'd ago';
}

// ── Change timeline (Phase 4 + Phase 6) ───────────────────────────────────
// Komodor's signature UI element. Renders a horizontal strip of dots, one per
// recent change, colored by kind. Hovering shows actor + time; clicking would
// filter findings by LikelyCause.ID (Phase 6 polish).
function buildChangeTimeline(container, changes) {
  if (!container) return;
  container.innerHTML = '';
  if (!changes || changes.length === 0) {
    container.style.display = 'none';
    return;
  }
  container.style.display = '';

  var now = Date.now();
  var oldest = now - 24 * 3600 * 1000;

  // Map kind → color (deploy=teal, config=orange, RBAC=red, secret=purple, other=gray).
  var kindColor = {
    'Deployment':       '#00d9c5',
    'StatefulSet':      '#00d9c5',
    'DaemonSet':        '#00d9c5',
    'ConfigMap':        '#ffb454',
    'Secret':           '#bc8cff',
    'RoleBinding':      '#ff5b5b',
    'ClusterRoleBinding':'#ff5b5b',
    'NetworkPolicy':    '#6ad7ff'
  };

  var svg = '<svg viewBox="0 0 1000 50" preserveAspectRatio="none" class="change-timeline-svg">';
  // Axis line.
  svg += '<line x1="0" y1="25" x2="1000" y2="25" stroke="#2a3552" stroke-width="1"/>';
  // Hour ticks every 6h (= 4 ticks across 24h).
  for (var h = 0; h <= 24; h += 6) {
    var tx = (h / 24) * 1000;
    svg += '<line x1="' + tx + '" y1="20" x2="' + tx + '" y2="30" stroke="#2a3552" stroke-width="1"/>';
    svg += '<text x="' + tx + '" y="45" fill="#8b95b3" font-size="9" text-anchor="middle">' + (24 - h) + 'h</text>';
  }
  changes.forEach(function(c) {
    var ts = new Date(c.timestamp).getTime();
    if (ts < oldest) return;
    var x = ((ts - oldest) / (now - oldest)) * 1000;
    var color = kindColor[c.kind] || '#8b95b3';
    var tip = c.kind + ' ' + (c.namespace || '') + '/' + c.name + ' ' + (c.action || '') + ' by ' + (c.actor || 'unknown');
    svg += '<circle cx="' + x.toFixed(1) + '" cy="25" r="4" fill="' + color + '" data-change-id="' + escHtml(c.id) + '"><title>' + escHtml(tip) + '</title></circle>';
  });
  svg += '</svg>';
  container.innerHTML = svg;
}

function enrichCards(rootCauseMap) {
  document.querySelectorAll('.finding-card').forEach(function(card) {
    var title = card.dataset.title || '';
    var rc = rootCauseMap[title];

    // ── Cross-namespace / selector-mismatch badges ──
    var actions = card.querySelector('.finding-header-actions');
    if (actions && !card.querySelector('.cross-ns-badge') && !card.querySelector('.mismatch-badge')) {
      if (title.startsWith('Cross-namespace blocked')) {
        var badge = document.createElement('span');
        badge.className = 'cross-ns-badge';
        badge.textContent = 'cross-ns';
        badge.title = 'Cross-namespace connectivity issue';
        actions.insertBefore(badge, actions.firstChild);
      } else if (title.startsWith('Selector mismatch')) {
        var badge2 = document.createElement('span');
        badge2.className = 'mismatch-badge';
        badge2.textContent = 'svc mismatch';
        badge2.title = 'Service selector does not match any running pods';
        actions.insertBefore(badge2, actions.firstChild);
      }
    }

    // Root cause line in header.
    const rcLine = card.querySelector('.root-cause-line');
    if (rc && rcLine) {
      rcLine.textContent = '⬡ Root cause: ' + rc.rootCause;
      rcLine.style.display = '';
      rcLine.className = 'root-cause-line' + (rc.fixWarning ? '' : ' amber');
    }

    // Store fix warning on the card for the modal.
    card._fixWarning = rc ? rc.fixWarning : '';

    // Root cause section in body.
    const rcSection = card.querySelector('.root-cause-section');
    const rcText = card.querySelector('.root-cause-text');
    const warnEl = card.querySelector('.fix-warning');
    const warnTxt = card.querySelector('.fix-warning-text');
    if (rc && rcSection && rcText) {
      rcText.textContent = rc.rootCause;
      rcSection.style.display = '';
      if (rc.fixWarning && warnEl && warnTxt) {
        warnTxt.textContent = rc.fixWarning;
        warnEl.style.display = '';
      }
    }

    // Related findings.
    const relSection = card.querySelector('.related-section');
    const relList = card.querySelector('.related-list');
    if (rc && rc.related && rc.related.length > 0 && relSection && relList) {
      relList.innerHTML = rc.related.map(function(t) { return '<li>' + escHtml(t) + '</li>'; }).join('');
      relSection.style.display = '';
    }

    // Investigation steps.
    const invSection = card.querySelector('.investigation-section');
    const invList = card.querySelector('.investigation-steps');
    if (invSection && invList) {
      const steps = buildInvestigationSteps(card);
      if (steps.length > 0) {
        invList.innerHTML = steps.map(function(s) {
          return '<li>' +
            '<span class="step-desc">' + escHtml(s.desc) + '</span>' +
            '<div class="step-cmd-row">' +
              '<span class="step-cmd">' + escHtml(s.cmd) + '</span>' +
              '<button class="copy-btn" onclick="event.stopPropagation(); copyText(this, \'' + s.cmd.replace(/'/g, "\\'") + '\')"  >copy</button>' +
            '</div>' +
          '</li>';
        }).join('');
        invSection.style.display = '';
      }
    }
  });
}

// ── Theme toggle ─────────────────────────────────────────────────────────
// Reads/writes document.documentElement data-theme and persists to localStorage.
// Applied before render (see IIFE at bottom) to avoid flash.
var THEME_KEY = 'exalm-theme';

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  var btn = document.getElementById('theme-toggle');
  if (btn) btn.textContent = theme === 'light' ? '🌙' : '☀';
}

function toggleTheme() {
  var current = document.documentElement.getAttribute('data-theme') || 'dark';
  var next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* storage unavailable */ }
}

// ── Time filter ───────────────────────────────────────────────────────────
// Stores the selected time window; on change, re-fetches /api/changes?since=X
// and refreshes the timeline + status bar.
var TIME_KEY = 'exalm-time-since';
var _activeSince = '24h'; // mirrors the tab marked active in HTML

function setTimeFilter(btn) {
  _activeSince = btn.dataset.since || '24h';
  document.querySelectorAll('.time-btn').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  try { localStorage.setItem(TIME_KEY, _activeSince); } catch (e) { /* ignore */ }
  refreshChanges(_activeSince);
}

function refreshChanges(since) {
  var url = '/api/changes';
  if (since && since !== 'all') url += '?since=' + encodeURIComponent(since);
  fetch(url)
    .then(function(r) { return r.json(); })
    .then(function(changes) {
      var stripEl = document.getElementById('change-timeline');
      if (stripEl) buildChangeTimeline(stripEl, changes || []);
      fetch('/api/report')
        .then(function(r) { return r.json(); })
        .then(function(report) { buildStatusBar(report.findings || [], changes || []); })
        .catch(function() {});
    })
    .catch(function() {});
}

// ── Saved search ──────────────────────────────────────────────────────────
// Filters visible finding cards by matching query against title+detail+category.
// Persists to localStorage on every keystroke and restores on load.
var SEARCH_KEY = 'exalm-search';
var _searchQuery = '';

function applySearch(query) {
  _searchQuery = query;
  var q = query.trim().toLowerCase();
  document.querySelectorAll('.finding-card').forEach(function(card) {
    if (!q) {
      card.dataset.searchHidden = '';
    } else {
      var text = [
        card.dataset.title    || '',
        card.dataset.detail   || '',
        card.dataset.category || '',
      ].join(' ').toLowerCase();
      card.dataset.searchHidden = text.indexOf(q) === -1 ? '1' : '';
    }
  });
  // Re-run combined filter so severity/ns filters are respected.
  applyFilters();
}

function onSearchInput(value) {
  applySearch(value);
  try { localStorage.setItem(SEARCH_KEY, value); } catch (e) { /* ignore */ }
}

// ── Initial render ────────────────────────────────────────────────────────
(function init() {
  // ── Restore persisted theme (before render to avoid flash) ──
  try {
    var savedTheme = localStorage.getItem(THEME_KEY);
    if (savedTheme === 'light' || savedTheme === 'dark') {
      applyTheme(savedTheme);
    } else {
      applyTheme('dark'); // default
    }
  } catch (e) {
    applyTheme('dark');
  }

  // ── Restore persisted time filter ──
  try {
    var savedSince = localStorage.getItem(TIME_KEY);
    if (savedSince && ['1h', '24h', '7d', 'all'].indexOf(savedSince) !== -1) {
      _activeSince = savedSince;
      document.querySelectorAll('.time-btn').forEach(function(b) {
        b.classList.toggle('active', b.dataset.since === savedSince);
      });
    }
  } catch (e) { /* ignore */ }

  // ── Restore persisted search ──
  try {
    var savedSearch = localStorage.getItem(SEARCH_KEY);
    if (savedSearch) {
      var inp = document.getElementById('findings-search');
      if (inp) inp.value = savedSearch;
      applySearch(savedSearch);
    }
  } catch (e) { /* ignore */ }

  // Render narrative.
  const el = document.getElementById('narrative-content');
  if (el) {
    const raw = el.dataset.raw || '';
    _narrativeSections = parseNarrativeSections(raw);
    el.innerHTML = renderMarkdown(raw);
  }

  // Fetch full report to get structured findings for root cause + charts.
  fetch('/api/report')
    .then(function(r) { return r.json(); })
    .then(function(report) {
      const findings = report.findings || [];

      // Charts.
      const sevCounts = {};
      SEV_ORDER.forEach(function(k) { sevCounts[k] = 0; });
      findings.forEach(function(f) { if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++; });

      var donutEl = document.getElementById('donut-chart');
      if (donutEl) buildDonutChart(donutEl, sevCounts);

      var catEl = document.getElementById('category-chart');
      if (catEl) buildCategoryChart(catEl, findings);

      var barEl = document.getElementById('severity-chart');
      if (barEl) buildSeverityBar(barEl, sevCounts);

      // Health ring.
      var healthEl = document.getElementById('health-ring');
      if (healthEl) buildHealthRing(healthEl, buildHealthScore(sevCounts));

      // Namespace filter pills.
      var nsRow = document.getElementById('ns-filter-row');
      if (nsRow) buildNamespaceFilter(findings, nsRow);

      // Root cause correlation.
      var rcMap = buildRootCauseMap(findings);
      enrichCards(rcMap);

      // Phase 4: render backend-supplied LikelyCause + Evidence on each card.
      enrichWithBackendCorrelation(findings);
    })
    .then(function() {
      // Phase 4 + 6: change timeline strip + status bar. Best-effort.
      // Use the persisted time filter for the initial changes fetch.
      var changesUrl = '/api/changes';
      if (_activeSince && _activeSince !== 'all') changesUrl += '?since=' + encodeURIComponent(_activeSince);
      fetch(changesUrl)
        .then(function(r) { return r.json(); })
        .then(function(changes) {
          var stripEl = document.getElementById('change-timeline');
          if (stripEl) buildChangeTimeline(stripEl, changes || []);
          // Status bar reads both findings + changes; refetch findings.
          fetch('/api/report')
            .then(function(r) { return r.json(); })
            .then(function(report) { buildStatusBar(report.findings || [], changes || []); })
            .catch(function() {});
        })
        .catch(function() {
          // No /api/changes — still render status bar from findings alone.
          fetch('/api/report')
            .then(function(r) { return r.json(); })
            .then(function(report) { buildStatusBar(report.findings || [], []); })
            .catch(function() {});
        });
    })
    .catch(function() {
      // No report data yet — draw charts from DOM badge counts.
      var counts = {};
      SEV_ORDER.forEach(function(k) {
        var b = document.querySelector('.badge.' + k);
        if (b) { var m = b.textContent.match(/\d+/); counts[k] = m ? parseInt(m[0], 10) : 0; }
        else counts[k] = 0;
      });
      var donutEl2 = document.getElementById('donut-chart');
      if (donutEl2) buildDonutChart(donutEl2, counts);
      var barEl2 = document.getElementById('severity-chart');
      if (barEl2) buildSeverityBar(barEl2, counts);
      var healthEl2 = document.getElementById('health-ring');
      if (healthEl2) buildHealthRing(healthEl2, buildHealthScore(counts));
    });
})();

// ── Auto-refresh (30s) ────────────────────────────────────────────────────
let _lastRaw = (function() {
  const el = document.getElementById('narrative-content');
  return el ? (el.dataset.raw || '') : '';
}());

// Whether the server has a live refresh source wired (analyze/watch). When
// false (static snapshot — e.g. --from-file or serve --no-k8s) there is nothing
// new to fetch, so we never reload. Mirrors templateData.AutoRefresh.
const _autoRefreshEnabled = (document.body.dataset.autoRefresh === 'true');

// Signature of the current findings set (identity, not full content). When this
// changes between polls the server has re-collected and the server-rendered
// cards are stale, so we reload to let the Go template re-render them. Seeded
// to null and captured on the first poll so we never reload on the first tick.
let _lastFindingsSig = null;

function findingsSignature(findings) {
  return (findings || [])
    .map(function(f) { return (f.severity || '') + '|' + (f.category || '') + '|' + (f.title || ''); })
    .sort()
    .join('\n');
}

// A reload would interrupt the user mid-action, so suppress it while a modal is
// open or the tab is backgrounded.
function reloadSafe() {
  var modalOpen = document.querySelector('.modal:not(.hidden)') !== null;
  if (modalOpen || document.hidden) return false;
  window.location.reload();
  return true;
}

setInterval(function() {
  fetch('/api/report')
    .then(function(r) { return r.json(); })
    .then(function(report) {
      const ts = document.getElementById('ts');
      if (ts) ts.textContent = new Date().toUTCString();

      const el = document.getElementById('narrative-content');
      if (el && report.raw && report.raw !== _lastRaw) {
        _lastRaw = report.raw;
        _narrativeSections = parseNarrativeSections(report.raw);
        el.dataset.raw = report.raw;
        el.innerHTML = renderMarkdown(report.raw);
      }

      // Refresh charts and health.
      var findings = report.findings || [];
      var counts = {};
      SEV_ORDER.forEach(function(k) { counts[k] = 0; });
      findings.forEach(function(f) { if (counts[f.severity] !== undefined) counts[f.severity]++; });

      var donutEl = document.getElementById('donut-chart');
      if (donutEl) buildDonutChart(donutEl, counts);
      var catEl = document.getElementById('category-chart');
      if (catEl) buildCategoryChart(catEl, findings);
      var barEl = document.getElementById('severity-chart');
      if (barEl) buildSeverityBar(barEl, counts);
      var healthEl = document.getElementById('health-ring');
      if (healthEl) buildHealthRing(healthEl, buildHealthScore(counts));

      // The finding cards are server-rendered once; when the underlying set
      // changes (pods recreated, issues resolved) reload so the template
      // re-renders them. Filters/theme/search persist via localStorage.
      var sig = findingsSignature(findings);
      if (_autoRefreshEnabled) {
        if (_lastFindingsSig === null) {
          _lastFindingsSig = sig; // first tick: establish baseline, don't reload
        } else if (sig !== _lastFindingsSig) {
          _lastFindingsSig = sig;
          reloadSafe();
        }
      }
    })
    .catch(function() { /* server gone */ });
}, 30000);

// ── Resizable findings/analysis split ───────────────────────────────────────
// The two panels are a 3-track CSS grid (left | gutter | right); dragging the
// gutter rewrites the --split custom property and persists the width.
(function initSplitter() {
  var gutter = document.getElementById('split-gutter');
  var layout = document.querySelector('.main-layout');
  if (!gutter || !layout) return;

  var SPLIT_KEY = 'exalm.splitLeftPx';
  try {
    var saved = localStorage.getItem(SPLIT_KEY);
    if (saved) layout.style.setProperty('--split', parseInt(saved, 10) + 'px');
  } catch (e) { /* ignore */ }

  var dragging = false;

  function clampX(x, width) {
    var min = 300, max = width * 0.7;
    if (x < min) x = min;
    if (x > max) x = max;
    return Math.round(x);
  }

  function onMove(e) {
    if (!dragging) return;
    var rect = layout.getBoundingClientRect();
    var x = clampX(e.clientX - rect.left, rect.width);
    layout.style.setProperty('--split', x + 'px');
    e.preventDefault();
  }

  function onUp() {
    if (!dragging) return;
    dragging = false;
    gutter.classList.remove('dragging');
    document.body.style.userSelect = '';
    var v = layout.style.getPropertyValue('--split');
    if (v.indexOf('px') !== -1) {
      try { localStorage.setItem(SPLIT_KEY, parseInt(v, 10)); } catch (e) { /* ignore */ }
    }
    window.removeEventListener('pointermove', onMove);
    window.removeEventListener('pointerup', onUp);
  }

  gutter.addEventListener('pointerdown', function(e) {
    dragging = true;
    gutter.classList.add('dragging');
    document.body.style.userSelect = 'none';
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    e.preventDefault();
  });

  // Keyboard accessibility: arrow keys nudge the split by 24px.
  gutter.addEventListener('keydown', function(e) {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    var rect = layout.getBoundingClientRect();
    var cur = parseInt(layout.style.getPropertyValue('--split'), 10);
    if (isNaN(cur)) cur = rect.width * 0.58; // ~1.4fr default
    var next = clampX(cur + (e.key === 'ArrowRight' ? 24 : -24), rect.width);
    layout.style.setProperty('--split', next + 'px');
    try { localStorage.setItem(SPLIT_KEY, next); } catch (err) { /* ignore */ }
    e.preventDefault();
  });
})();
