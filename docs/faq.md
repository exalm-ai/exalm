# FAQ — how exalm connects to your infrastructure

The short version: **exalm runs where you run it** — your laptop, a CI runner, a pod. It reaches out to read; nothing reaches back in. There is no daemon on your hosts because it uses tools that are already there.

This page is deliberately specific. If you are being asked to give a tool SSH or cluster access, "trust us" is not an answer — so every command exalm can run is listed below, with the source file to check it against.

---

## Kubernetes

### How does it connect?

It is a `kubectl` client, not an agent. `plugins/k8s/client.go` uses `client-go`'s standard `clientcmd` loader — **the same kubeconfig, context and credentials `kubectl` already uses**.

```sh
exalm k8s analyze                              # current context
exalm k8s analyze --context prod --namespace payments
exalm k8s analyze --kubeconfig /path/to/config
```

If `kubectl get pods` works, exalm works. EKS/GKE/AKS exec-plugin auth, SSO, client certs and proxies are all inherited — exalm implements no auth of its own.

Running inside the cluster (Helm chart) uses the pod's ServiceAccount instead.

### What permissions does it need?

Read-only: `get`, `list`, `watch` on namespaces, pods, pods/log, events, endpoints, services, PVCs, nodes, resourcequotas, configmaps, deployments, statefulsets, replicasets, daemonsets, jobs, cronjobs, HPAs, ingresses, RBAC objects and storageclasses.

Secrets are a deliberate exception — `list` and `watch` only, never `get`:

```yaml
# Secrets are listed (NAMES ONLY — exalm never reads Secret payloads) so the
# plugin can detect referenced-but-missing secrets in workload specs.
# "get" is intentionally omitted: listing metadata is sufficient and prevents
# the agent from ever reading raw Secret values.
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["list", "watch"]
```

Exalm detects that a workload references a Secret that does not exist. It cannot read what is inside one.

### Can it change my cluster?

Not unless you ask it to, twice. Mutating verbs (`patch`, `update`, `delete`) are only granted when `rbac.allowApply=true`, and the CLI additionally refuses any mutating subcommand without `--apply` plus a confirmation prompt. A default install has no write path at all.

Authoritative list: [`deploy/helm/exalm-agent/templates/rbac.yaml`](../deploy/helm/exalm-agent/templates/rbac.yaml).

---

## Linux logs — syslog, nginx/Apache

### Local, no SSH

```sh
exalm syslog analyze --file /var/log/syslog
kubectl logs -l app=api --since=1h | exalm logs summarize
```

### Remote, over plain SSH

```sh
exalm syslog analyze  --host db-01  --ssh-key ~/.ssh/id_rsa
exalm httplog analyze --host web-01 --ssh-user deploy
```

Port 22, your existing key / ssh-agent / password. Nothing is installed on the target. The commands are bounded reads that exist on a vanilla install:

| What | Command run on the host |
|---|---|
| syslog (systemd) | `journalctl -n 5000 --no-pager` |
| syslog (fallback) | `tail -n 5000 /var/log/syslog` → `/var/log/messages` → `/var/log/system.log` |
| nginx / Apache access | `tail -n 10000 /var/log/nginx/access.log` → `/var/log/apache2/access.log` |
| nginx / Apache error | `tail -n 5000 /var/log/nginx/error.log` → `/var/log/apache2/error.log` |
| auth | `journalctl -u sshd -n 5000 --no-pager` → `/var/log/auth.log` → `/var/log/secure` |

POSIX `sh`, so Alpine and busybox work. Every command caps its own output.

### Host key verification

Trust-on-first-use: the first connection pins the host's fingerprint to `~/.exalm/known_hosts`. A later mismatch aborts **before any data is exchanged**.

Be aware of the trade-off TOFU makes: the *first* connection to a host is accepted without prior knowledge of its key, so it protects against later tampering, not against an attacker already in position on that first connect. If that matters for your environment, verify the pinned fingerprint in `~/.exalm/known_hosts` against the host out-of-band after the first run. A strict mode that refuses unknown hosts outright exists in the SSH layer but is not yet exposed as a CLI flag.

---

## Windows — Event Log and IIS

Same SSH transport, PowerShell on the far side.

```sh
exalm eventlog summarize --host dc-01  --log-name Security
exalm iis analyze        --host iis-01 --log-dir 'C:\inetpub\logs\LogFiles\W3SVC1'
```

| What | Command run on the host |
|---|---|
| Event Log | `Get-WinEvent -LogName 'Security' -MaxEvents 2000 \| ConvertTo-Json -Depth 3 -Compress` |
| IIS W3C | `Get-ChildItem '<dir>\*.log' \| Sort-Object LastWriteTime -Desc \| Select-Object -First 1 \| Get-Content -Tail 10000` |

Both inputs are validated rather than escaped. `--log-name` must be one of a fixed set of channel names (`Security`, `System`, `Application`, `Setup`, `ForwardedEvents`, the PowerShell channels); anything else falls back to `Security`. `--log-dir` is rejected outright if it contains shell metacharacters. Neither flag can be turned into command injection.

**Prerequisite:** the target needs **OpenSSH Server** enabled. That is a Microsoft-shipped optional Windows feature, not an exalm component — but it does have to be turned on.

---

## Remote diagnostics during an investigation

When you ask a follow-up like *"is memory the real problem?"*, exalm can run a few extra read-only commands rather than making you SSH in yourself.

These come from a fixed, compile-time allowlist in [`internal/ssh/diagnostics.go`](../internal/ssh/diagnostics.go) — 14 commands total. **The LLM never chooses or writes a command.** A parameter that does not match a strict character class is *refused*, never sanitised.

| Tier | What it unlocks |
|---|---|
| `off` | Nothing. The investigation reasons over collected logs only |
| `readonly` *(default)* | Disk/memory/uptime, service status, journal and event excerpts, IIS app pools |
| `full` | Also auth logs, login history, firewall state, certificate expiry, scheduled tasks |

Set per run with `--remote-diag off|readonly|full`, or globally with `EXALM_REMOTE_DIAG`. No tier can read credential material.

---

## "No agent, no account" — what that precisely means

**No agent.** exalm installs nothing on your hosts. No daemon, no sidecar, no collector to upgrade, no port beyond SSH/22, no kernel module. It reads what is already there using tools that ship with the OS. Stop using it and there is no residue to clean up.

It is *not* a claim that no access is needed — you still supply a kubeconfig or an SSH login. The difference is that exalm borrows credentials you already have rather than asking you to provision new infrastructure.

**No account.** There is no exalm signup, no licence server, no telemetry, and no phone-home. The binary works offline.

**The honest caveat about the LLM.** Unless you run a local model, **redacted** data is sent to whichever provider you configured, on your own API key. The precise claim is:

> Secrets never leave your machine.

not *"nothing leaves your machine."* Every byte passes the redaction engine first — there is no flag to disable it and no code path that skips it — but the redacted text does go to your chosen model.

If you need the stronger guarantee, use Ollama and nothing leaves your network at all:

```sh
export EXALM_LLM_PROVIDER=ollama
exalm k8s analyze
```

---

## Verify it yourself

The point of the list above is that you do not have to take it on trust:

- [`internal/ssh/commands.go`](../internal/ssh/commands.go) — every log-collection command, ~120 lines
- [`internal/ssh/diagnostics.go`](../internal/ssh/diagnostics.go) — the 14 allowlisted diagnostic commands and their tiers
- [`deploy/helm/exalm-agent/templates/rbac.yaml`](../deploy/helm/exalm-agent/templates/rbac.yaml) — every Kubernetes permission
- [`internal/redact/patterns.go`](../internal/redact/patterns.go) — every redaction pattern, each with a test in `redact_test.go`

Want to see what redaction removed on a given run? Add `--show-redactions` and exalm prints a summary to stderr before the LLM call.

Want to try it with no cluster, no credentials and no API key at all?

```sh
EXALM_LLM_PROVIDER=mock exalm syslog analyze \
  --file examples/syslog/wsl-live-session.jsonl --output web
```
