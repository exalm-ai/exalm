# exalm Architecture

This document describes the internal structure, component responsibilities, data flows,
and key design decisions in the exalm binary.

For day-to-day contributor conventions (coding style, commit format, PR checklist), see
[CONTRIBUTOR_WORKFLOW.md](CONTRIBUTOR_WORKFLOW.md).

---

## Core design principle

Every execution path follows the same invariant:

```
environment data  →  redact  →  LLM  →  report
```

No plugin can send data to an LLM without it passing through the redaction engine first.
This is enforced at the `RunArgs` injection point — every plugin receives a `Redactor`
and an `LLMClient`; it cannot construct either directly.

---

## Binary overview

exalm ships as a single static binary (~20 MB stripped). It has no persistent daemon,
no sidecar, and no cloud dependency beyond the chosen LLM API. It embeds:

- A **Cobra CLI** — one subcommand per plugin, all flags registered at startup
- A **plugin registry** — maps plugin names to CLI commands and subcommands
- An **HTTP dashboard** (`exalm serve`) served from embedded Go templates
- An **interactive TUI** (`exalm tui`) built on [Bubble Tea](https://github.com/charmbracelet/bubbletea)
- A **SQLite store** (`internal/store`) for DORA deployments and incident records

---

## Repository layout

```
exalm/
├── cmd/exalm/               CLI entry point, plugin registration, serve / tui / init commands
├── pkg/plugin/              Public plugin SDK (separate Go module — importable by external authors)
│   └── go.mod               Standalone module: github.com/exalm-ai/exalm/pkg/plugin
├── internal/
│   ├── config/              Environment variable + flag resolution
│   ├── llm/                 LLM provider adapters (Claude, OpenAI, Ollama, OpenRouter, Mock)
│   ├── redact/              Secret / PII redaction — THE TRUST FOUNDATION
│   ├── store/               SQLite store (deployments + incidents), legacy JSONL migration
│   ├── registry/            Plugin registry — maps plugin names to Cobra subcommands
│   ├── output/              Markdown and JSON renderers for plugin.Report
│   ├── ssh/                 SSH client + TOFU host-key verification
│   ├── ssh/sshtest/         In-process SSH test server (hermetic tests, no real sshd needed)
│   ├── network/             Hubble eBPF gRPC client (lazy-dial, hand-coded protowire)
│   ├── tui/                 Bubble Tea TUI — model, styles, key bindings, state machine
│   ├── web/                 HTTP dashboard: findings, DORA, timeline, Prometheus metrics
│   ├── webhook/             Terraform Cloud webhook receiver (HMAC-SHA512 verified)
│   ├── mcp/                 MCP / SSE server for Claude Desktop integration
│   ├── analyzer/            Map-reduce finding aggregator for multi-source analysis
│   ├── evidence/            Audit evidence chain builder
│   ├── changestore/         IaC change event store (ArgoCD, Helm, Terraform)
│   └── gitprovider/         GitHub PR creation helper (used by k8s --apply-pr)
├── plugins/                 One package per domain plugin
│   ├── logs/                Generic log summariser (stdin or file)
│   ├── k8s/                 Kubernetes pod / event / IaC analysis
│   ├── syslog/              Linux syslog (local or SSH)
│   ├── httplog/             nginx / Apache access log (local or SSH)
│   ├── eventlog/            Windows Event Log (SSH)
│   ├── iis/                 IIS W3C log (local or SSH)
│   ├── aws_cost/            AWS Cost Explorer anomaly analysis
│   ├── dora/                DORA four-key metrics
│   ├── incident/            Incident lifecycle + LLM postmortem
│   ├── chaos/               Resilience scoring + Litmus ChaosEngine YAML
│   ├── slo/                 SLO error budget tracking
│   ├── tf/                  Terraform plan JSON review
│   └── notify/              Slack / generic webhook notification output
├── deploy/helm/             Helm chart for in-cluster deployment
├── examples/                Sample inputs used in documentation and tests
└── docs/                    User-facing documentation
```

---

## Component diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                  exalm CLI binary (static ~20 MB)                    │
│                                                                       │
│  cmd/exalm/main.go                                                    │
│    │                                                                  │
│    ├── Cobra CLI ──────── internal/registry ──── plugin registry     │
│    │                            │                                     │
│    │         ┌──────────────────┤                                     │
│    │         │  plugins/                                              │
│    │         │  ├── k8s/         (k8s.io/client-go)                  │
│    │         │  ├── syslog/      (SSH → remote host)                 │
│    │         │  ├── httplog/     (SSH → remote host)                 │
│    │         │  ├── eventlog/    (SSH → remote host)                 │
│    │         │  ├── iis/         (SSH → remote host)                 │
│    │         │  ├── aws_cost/    (AWS SDK)                            │
│    │         │  ├── dora/        (SQLite store)                      │
│    │         │  ├── incident/    (SQLite store)                      │
│    │         │  ├── chaos/       (k8s snapshot → scorer)             │
│    │         │  ├── slo/         (Prometheus query)                  │
│    │         │  ├── tf/          (Terraform plan JSON → LLM)         │
│    │         │  └── notify/      (Slack / webhook POST)              │
│    │         │                                                        │
│    │         └── internal/                                            │
│    │              ├── redact/    (28+ patterns, always runs)          │
│    │              ├── llm/       (claude│openai│openrouter│ollama)    │
│    │              ├── store/     (SQLite, WAL mode, migrations)       │
│    │              ├── ssh/       (TOFU known_hosts)                   │
│    │              ├── network/   (Hubble gRPC, lazy dial)             │
│    │              ├── tui/       (Bubble Tea UI)                      │
│    │              ├── web/       (HTTP dashboard, auth middleware)    │
│    │              ├── webhook/   (Terraform Cloud inbound)            │
│    │              └── mcp/       (Claude Desktop SSE)                │
│    │                                                                   │
│    └── LLM provider (external)                                        │
│         ├── api.anthropic.com                                         │
│         ├── api.openai.com                                            │
│         ├── openrouter.ai                                             │
│         └── localhost:11434 (Ollama)                                  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## The plugin contract

Every plugin implements the `plugin.Plugin` interface from `pkg/plugin/plugin.go`:

```go
type Plugin interface {
    Name() string           // CLI subcommand name (e.g. "k8s")
    Description() string    // shown in --help
    Mutates() bool          // whether any subcommand can modify state
    Subcommands() []Subcommand
}

type Subcommand struct {
    Name        string
    Description string
    Run         func(ctx context.Context, args RunArgs) (Report, error)
}
```

`RunArgs` is injected at runtime and contains:

```go
type RunArgs struct {
    Flags    map[string]string  // parsed CLI flags
    LLM      LLMClient          // the chosen LLM adapter
    Redactor Redactor           // the redaction engine
    Store    Store              // SQLite store
}
```

**Key invariant:** plugins receive `LLMClient` and `Redactor` by injection. They cannot
construct either. This is the architectural guarantee that all LLM calls pass through redaction.

---

## The redaction layer

`internal/redact` is the trust foundation of the project. Rules that cannot be overridden:

1. Every byte of user-environment data passes through `Redactor.Redact()` before entering a
   `CompleteRequest`. There is no bypass.
2. The `Redact` method never returns an error. On failure it returns the input unchanged
   (no partial redaction presented as fully redacted).
3. Patterns are in `internal/redact/patterns.go`. Every pattern has a test in
   `internal/redact/redact_test.go` covering the match case **and** the boundary case
   (what should *not* be redacted).
4. Optional high-FP patterns (IP addresses, email addresses) live in `OptionalPatterns`
   and require explicit user opt-in.

---

## Investigation framework

`internal/investigate` is the generic AI investigation engine shared by every analyzer
(Kubernetes is the reference implementation; syslog, httplog, eventlog, iis, and logs plug in
the same way). Each conversation turn runs one deterministic pipeline:

```
focus resolution → intent classification (regex) → symptom-driven plan
→ collector execution (per-conversation cache, E1..En citation labels)
→ hypothesis ranking → evidence-quality confidence → prevention
→ ONE redacted LLM call → persisted transcript (convo store)
```

A domain supplies a `Profile`: its symptom catalog (what an experienced operator checks first
per failure mode, with candidate causes), resource-graph edges, question-intent patterns,
collectors, confidence rules, prevention catalog, cache TTLs, and prompt wording (built from
shared skeletons that keep the citation/redaction/RCA discipline identical everywhere). The
engine owns everything else. Adding a future analyzer (AWS, PostgreSQL, Docker, …) means
writing a Profile — no engine, web, or UI code.

**Trust model, enforced in the engine:** exactly one redacted `llm.Complete()` per turn; the
LLM never chooses collectors or commands (plans come solely from the symptom/intent tables);
every message passes the Redactor before the call; secrets are never collected (metadata only);
the no-LLM fallback renders the same sectioned, cited answer deterministically.

Log analyzers additionally build a bounded in-memory `LogSession` during analysis (parsed,
normalized events — never persisted) that feeds the corpus collectors ("what happened
before?"), the per-analyzer dashboard stats, and the chart-to-log drilldown.

**Remote diagnostics** (`internal/ssh/diagnostics.go`) are the only path from an investigation
to remote command execution: a fixed, reviewed, read-only allowlist keyed by collector name,
tier-gated (`off` / `readonly` default / `full` opt-in via `EXALM_REMOTE_DIAG` or
`--remote-diag`), with the single parameterized slot validated against a strict character
class — refused, never sanitized. The `full` tier unlocks security-sensitive *reads* (auth
logs, login history, firewall state, certificate expiry, scheduled tasks); no tier can read
credential material.

---

## Dashboard platform

The web UI is a plugin-registered dashboard platform, not a fixed page set.

**Registry** (`internal/web/dashboards.go`): every dashboard is a `DashboardDesc`
(id, name, icon, category, AI/timeline/remediation capability flags, widget list).
Platform built-ins (Kubernetes, DORA, Timeline, Incidents) plus one descriptor per
log-analyzer plugin, derived from the plugin registry at serve time — adding an analyzer
plugin adds its dashboard with zero web-layer changes. `GET /api/dashboards` serves the
list; the SPA builds its navigation from it (a payload without the registry falls back
to the legacy single-dashboard nav, so `--open` without a hub is unchanged).

**Settings** (`internal/settings`, `~/.exalm/settings.json`): per-dashboard
enable/disable (+ Enable All) and a global AI-features toggle, persisted atomically and
edited from the dashboard's Settings page (`GET/PUT /api/settings`). Disabled dashboards
disappear from navigation and their scoped routes 404; a settings file that disables
everything degrades to enable-all rather than bricking the UI.

**Scoped routes**: `/api/dashboards/{id}/{stats,logs,chat,logs/analyze}` dispatch per
dashboard; the pre-platform aliases (`/api/analyzer/*`, `/api/chat`) remain
byte-compatible.

**Hub** (`internal/web/{sessions,ingest}.go`, `cmd/exalm/serve_hub.go`): `exalm serve`
hosts every dashboard in one process. It writes a per-run discovery record
(`~/.exalm/hub.json`, 0600: port + random secret + pid, removed on shutdown); analyzer
`--open` runs probe `/healthz` for `"hub":true` and POST their parsed corpus as an
explicit `SessionSnapshot` to `/api/ingest/session`. The ingest endpoint is
loopback-only, requires the secret in the `X-Exalm-Ingest` header (constant-time
compare; the custom header doubles as CSRF protection), and caps the body. The hub
reconstructs a full investigation engine from the plugin registry's profile, so chat,
drilldown, and stats on ingested sessions run the same deterministic pipeline.
`RemoteParams.Password` is `json:"-"`, so credentials never cross the wire — ingested
sessions run **without** remote SSH diagnostics by construction. Any attach failure
falls back to the analyzer's own local server.

**Frontend** (`internal/web/static/`): `widgets.js` is the single chart library
(timelines, bar lists, counters, donut, tooltips); every drillable chart opens a menu —
*Show related logs* (corpus drilldown) or *✦ Investigate* (seeds the AI chat with the
clicked slice). Chat sessions are keyed per dashboard.

---

## SSH client

`internal/ssh` provides the SSH transport for all remote log plugins.

**TOFU (trust on first use):** the first connection to any host auto-accepts and stores the
key fingerprint at `~/.exalm/known_hosts`. Subsequent connections verify the stored fingerprint.
A mismatch returns an error before any data is exchanged. Use `--ssh-strict-host-key` to reject
unknown hosts without prompting.

**Test infrastructure:** `internal/ssh/sshtest` provides an in-process SSH server following the
`net/http/httptest` pattern. All SSH tests are hermetic — no real SSH daemon required.

---

## SQLite store

`internal/store` persists DORA deployments and incident records using
[`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) (pure Go, no CGO required).

- WAL mode enabled for concurrent reads
- Idempotent schema migrations on startup
- One-time import of legacy JSONL file data
- The store is passed to plugins via `RunArgs.Store` — plugins do not open their own database

---

## Web dashboard

`internal/web/server.go` implements the HTTP dashboard. Security properties:

- Binds to `localhost` by default (`--bind` flag to override)
- `requireToken` middleware: all endpoints require `Authorization: Bearer <token>` or
  `?token=<token>` when `EXALM_TOKEN` is set. Exempt: `/healthz`, `/metrics`.
- `requireCSRF` middleware: all mutating methods require `X-Exalm-Request: true` header
  (CSRF protection via custom header — browsers cannot add custom headers cross-origin
  without a CORS preflight)
- Rate-limited: `/api/fix` and `/api/fix-all` allow at most 3 concurrent in-flight LLM calls

---

## Hubble gRPC client

`internal/network` implements a lazy gRPC connection to Cilium Hubble Relay
(`/observer.Observer/GetFlows`). Wire encoding uses `google.golang.org/protobuf/encoding/protowire`
with hand-coded field numbers, avoiding a dependency on the full `github.com/cilium/cilium`
module. Falls back to a `disconnectedProvider` (clear error, no crash) when Relay is unreachable.

---

## MCP server

`internal/mcp` implements an SSE (Server-Sent Events) transport for the
[Model Context Protocol](https://modelcontextprotocol.io). This allows Claude Desktop
and other MCP-compatible clients to invoke exalm tools directly.

Authentication is provided by the same `RequireToken` middleware used by the web dashboard.

---

## Build and test

```sh
make build            # produces ./bin/exalm
make test             # go test -race ./...
make test-redact      # verbose redaction tests (run before any redact/ change)
make lint             # gofmt + go vet + golangci-lint
```

CI runs all of these on every PR. See `.github/workflows/ci.yml`.

---

## Dependency philosophy

The dependency tree is kept small deliberately. Before adding a new dependency:

1. Check if the standard library covers the need
2. Check if an existing dependency can be extended
3. Justify the addition in the PR description

Current key dependencies and their justification:

| Dependency | Justification |
|---|---|
| `k8s.io/client-go` | Kubernetes API — no viable stdlib replacement |
| `github.com/spf13/cobra` | CLI framework — industry standard, no practical stdlib alternative |
| `github.com/charmbracelet/bubbletea` | TUI framework — SSH-safe, well-tested |
| `google.golang.org/grpc` | Hubble's only API transport |
| `modernc.org/sqlite` | Pure-Go SQLite — avoids CGO dependency for the store |
| `github.com/aws/aws-sdk-go-v2` | AWS Cost Explorer — AWS's official Go SDK |
