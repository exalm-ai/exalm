# Findings & remediation for the log analyzers

Exalm's log analyzers now emit **structured findings** the same way the
Kubernetes plugin does — and three of them can **apply fixes** over SSH.

## Which analyzers do what

| Analyzer | Structured findings | Proposes fixes | Applies fixes |
|---|---|---|---|
| syslog (Linux) | ✅ | ✅ `systemctl restart` | ✅ over SSH |
| eventlog (Windows) | ✅ | ✅ `Restart-Service` | ✅ over SSH (PowerShell) |
| iis (Windows) | ✅ | ✅ `Restart-WebAppPool` | ✅ over SSH (PowerShell) |
| httplog | ✅ | advice only | — |
| cloudtrail | ✅ | advice only | — |
| logs (generic) | ✅ (coarser) | advice only | — |

Findings surface everywhere a k8s finding does: `--output json` / `markdown`,
the MCP tools (`list_findings`, `get_finding`, `report_summary`,
`list_remediable`), the notify webhook, and the web dashboard's **Findings**
panel.

Findings are produced deterministically from each analyzer's existing symptom
catalog — **no extra LLM call**. The interactive AI copilot still provides deep,
evidence-backed investigation on demand.

## Proposing vs. applying

A finding may carry a **proposed** remediation — a shell command shown with a
copy button, its risk, rollback, and expected outcome. Proposing costs nothing
and changes nothing.

**Applying** executes the command, and is gated three ways depending on the
surface:

- **CLI** — `exalm <analyzer> fix --host <host> --apply` lists the applicable
  fixes and prompts `y/N` per fix before running each. Without `--apply` it only
  lists them; without `--host` it refuses (there's nothing to apply to).
  ```bash
  exalm syslog fix --host web-01 --ssh-user ops --apply
  ```
- **Web dashboard** — the "Apply this fix" button appears only for a remote
  analysis (one collected with `--host`); actions are protected by the bearer
  token and a CSRF/localhost-origin check.
- **MCP** — `apply_remediation` under `--write`, with `--host` supplied. See
  [mcp.md](mcp.md).

## The SSH safety model

Remediation over SSH mirrors the read-only diagnostics allowlist
(`internal/ssh/diagnostics.go`); the write side lives in
`internal/ssh/remediate.go`:

- **Fixed command templates.** Each remediation kind maps to one compile-time
  command: `svc-restart-linux` → `systemctl restart '%s'`, `svc-restart-windows`
  → `Restart-Service -Name '%s'`, `iis-pool-recycle` → `Restart-WebAppPool -Name
  '%s'`. The command string is always built here — the finding's displayed
  command is never executed verbatim.
- **Validated parameter.** The single `%s` (the unit / service / app-pool name)
  must match a strict character set (letters, digits, `._@:-`). A name with
  spaces, quotes, or shell metacharacters is **refused, not sanitized** — and is
  refused before any connection is made.
- **Conservative auto-derivation.** A fix is proposed only when the target name
  can be safely lifted from the corpus as a single token: a Windows display name
  with spaces (`The World Wide Web Publishing Service`) or a numeric IIS site id
  (`W3SVC1`) yields no proposal — the finding stays advice-only rather than
  guessing.
- **Explicit write gate.** The executor refuses unless the caller passes an
  allow flag wired to `--apply` / dashboard auth / `--mcp-write`; it fails closed.
- **TOFU host verification.** Connections use the same `~/.exalm/known_hosts`
  trust-on-first-use check as log collection.

## Deliberately not remediable

- **cloudtrail / AWS** — findings + prevention advice only; applying IAM or
  resource changes is out of scope (no AWS SDK, high blast radius).
- **httplog** — the origin host of an access log is ambiguous, so there's no
  safe single host to act on; advice only.
- **logs (generic)** — no host or service attribution; findings only.
