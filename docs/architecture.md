# Exalm — Architecture

This document describes the internal structure, data flows, and key design
decisions of the Exalm binary. Read [DEVELOPMENT.md](../DEVELOPMENT.md) for the
contributor conventions that enforce these decisions day-to-day.

---

## System overview

Exalm is a **single static binary** (~20 MB stripped). It has no
persistent daemon, no sidecar, and no cloud dependency beyond the
chosen LLM API. Every execution path follows the same lifecycle:

```
environment data  →  redact  →  LLM  →  report
```

The binary bundles:
- A **Cobra CLI** with one subcommand per plugin
- A **plugin registry** that wires plugins to CLI commands
- An **HTTP dashboard** (`exalm serve`) served from embedded templates
- An **interactive TUI** (`exalm tui`) built on Bubble Tea
- A **SQLite store** for DORA deployments and incidents

---

## Repository layout

```
exalm/
├── cmd/exalm/            CLI entry point, plugin registration, serve/tui/init commands
├── pkg/plugin/           Public plugin SDK (separate Go module — importable by external authors)
├── internal/
│   ├── config/           Environment variable + flag resolution
│   ├── llm/              LLM provider adapters (Claude, OpenAI, Ollama, OpenRouter, Mock)
│   ├── redact/           Secret / PII redaction — THE TRUST FOUNDATION
│   ├── store/            SQLite store (deployments + incidents), legacy JSONL migration
│   ├── registry/         Plugin registry — maps plugin names to CLI subcommands
│   ├── output/           Markdown and JSON renderers for plugin.Report
│   ├── ssh/              SSH client + TOFU known-host verification
│   ├── ssh/sshtest/      In-process SSH test server (hermetic tests, no real sshd)
│   ├── network/          Hubble eBPF gRPC client (lazy-dial, protowire hand-coded)
│   ├── tui/              Bubble Tea TUI — model, styles, state machine
│   ├── web/              HTTP dashboard, timeline/DORA pages, API endpoints
│   ├── webhook/          Terraform Cloud webhook receiver
│   ├── mcp/              Claude Desktop MCP/SSE integration
│   ├── analyzer/         Map-reduce finding aggregator
│   ├── evidence/         Audit evidence chain builder
│   ├── changestore/      IaC change event store (ArgoCD, Helm, Terraform)
│   └── gitprovider/      GitHub PR creation helper
├── plugins/              One package per domain plugin
│   ├── logs/             Generic log summariser (stdin)
│   ├── k8s/              Kubernetes pod / event / IaC analysis
│   ├── syslog/           Linux syslog (local file or SSH)
│   ├── httplog/          nginx / Apache access log (local or SSH)
│   ├── eventlog/         Windows Event Log (SSH)
│   ├── iis/              IIS W3C log (SSH)
│   ├── aws_cost/         AWS Cost Explorer anomaly analysis
│   ├── dora/             DORA four-key metrics
│   ├── incident/         Incident lifecycle + LLM postmortem
│   ├── chaos/            Resilience scoring + Litmus ChaosEngine YAML
│   ├── slo/              SLO error budget tracking
│   ├── tf/               Terraform plan JSON review
│   └── notify/           Slack / generic webhook notification output
├── deploy/helm/          Helm chart for Kubernetes deployment
├── examples/             Sample inputs for docs and tests
└── docs/                 Docusaurus documentation site
```

---

## Component diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                      exalm CLI binary (static ~20 MB)               │
│                                                                      │
│  cmd/exalm/main.go                                                   │
│    │                                                                  │
│    ├── Cobra CLI ─────────────── plugin registry                    │
│    │                                  │                              │
│    │          ┌───────────────────────┤                              │
│    │          │  plugins/             │                              │
│    │          │  ├─ logs/             │ reads from: stdin            │
│    │          │  ├─ k8s/             ─┤ reads from: k8s API server   │
│    │          │  ├─ syslog/          ─┤ reads from: local or SSH     │
│    │          │  ├─ httplog/         ─┤ reads from: local or SSH     │
│    │          │  ├─ eventlog/        ─┤ reads from: SSH (Windows)    │
│    │          │  ├─ iis/             ─┤ reads from: SSH (Windows)    │
│    │          │  ├─ aws_cost/        ─┤ reads from: AWS Cost API     │
│    │          │  ├─ dora/            ─┤ reads from: SQLite / JSONL   │
│    │          │  ├─ incident/        ─┤ reads/writes: SQLite / JSON  │
│    │          │  ├─ chaos/           ─┤ reads from: k8s snapshot JSON│
│    │          │  ├─ slo/             ─┤ reads from: Prometheus       │
│    │          │  ├─ tf/              ─┤ reads from: terraform plan   │
│    │          │  └─ notify/          ─┤ writes to: Slack webhook     │
│    │          │                       │                              │
│    │          └── internal/           │                              │
│    │               ├─ redact/  ◄──────┘ (ALWAYS runs before LLM)   │
│    │               ├─ llm/     ──────────────────► LLM API          │
│    │               ├─ ssh/     ──────────────────► remote hosts     │
│    │               ├─ network/ ──────────────────► Hubble Relay     │
│    │               ├─ store/   ──────────────────► ~/.exalm/exalm.db│
│    │               ├─ tui/     (Bubble Tea terminal UI)             │
│    │               ├─ web/     (HTTP dashboard, see routes below)   │
│    │               ├─ webhook/ ──────────────────► Terraform Cloud  │
│    │               └─ mcp/     ──────────────────► Claude Desktop   │
│    │                                                                  │
│    └── LLM providers (external)                                      │
│         ├─ api.anthropic.com         (Claude)                       │
│         ├─ api.openai.com            (OpenAI)                       │
│         ├─ openrouter.ai             (OpenRouter)                   │
│         └─ localhost:11434           (Ollama — local, no key needed)│
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data flow: one analysis cycle

```
1. Plugin collects raw environment data
   (log lines, k8s JSON, AWS cost JSON, Terraform plan JSON, …)

2. internal/redact.Engine.Redact(rawData)
   ├─ Applies 28+ regex patterns (API keys, passwords, JWTs, IPs, …)
   ├─ Replaces matches with [REDACTED]
   └─ Returns sanitised string — NEVER returns partially redacted data

3. internal/llm.Client.Complete(ctx, CompleteRequest{System, Messages})
   ├─ Picks provider from config (Claude / OpenAI / Ollama / OpenRouter)
   ├─ Sends sanitised data to LLM API
   └─ Returns CompleteResponse{Content, InputTokens, OutputTokens}

4. Plugin assembles plugin.Report{Title, Summary, Findings, Raw}
   ├─ Findings carry Severity, Category, Detail, Suggestion
   └─ Report is returned to the CLI runner

5. internal/output.Render(report, format)
   ├─ format=markdown → coloured Markdown to stdout
   └─ format=json     → structured JSON to stdout (pipe-friendly)
```

The redaction step (2) **cannot be skipped**. The `plugin.RunArgs.Redactor`
interface is injected by the CLI runner; plugins never bypass it.

---

## Plugin system

### Public interface (`pkg/plugin/plugin.go`)

```go
type Plugin interface {
    Name()        string
    Description() string
    Mutates()     bool        // gates the --apply flag
    Subcommands() []Subcommand
}

type Subcommand struct {
    Name        string
    Description string
    Run         func(ctx context.Context, args RunArgs) (Report, error)
}

type RunArgs struct {
    LLM     LLMClient  // injected LLM adapter
    Redactor Redactor  // injected redactor (MUST be called before LLM)
    Config  Config     // flag values, env vars
    // … other context fields
}
```

`pkg/plugin` is a **standalone Go module** (`github.com/exalm-ai/exalm/pkg/plugin`)
with zero external dependencies. Community plugin authors import it without
taking the full Exalm binary as a dependency.

### Plugin registration

All plugins are registered in `cmd/exalm/main.go → registerPlugins()`. The
registry maps each plugin's `Name()` to a generated Cobra subcommand with
flags derived from the plugin's declared inputs.

### Mutating plugins and `--apply`

Plugins that change cluster or system state set `Mutates() = true`. The CLI
runner enforces that the `--apply` flag is present **and** prints a
confirmation prompt before any mutation executes. This cannot be bypassed via
the plugin interface.

---

## Redaction layer

`internal/redact` is the highest-security component. Key properties:

| Property | Implementation |
|---|---|
| 28+ patterns | `DefaultPatterns` in `patterns.go` — API keys, JWTs, passwords, IPs, credit card numbers, … |
| High-FP patterns | `OptionalPatterns` — e-mail, IPv4 — opt-in via `--redact email,ipv4` |
| Surrounding context preserved | Patterns capture prefix/suffix groups; only the secret group is replaced |
| Never fails silently | `Redact()` never returns a partially-redacted string marked as clean; on any internal failure it returns the input unchanged and logs to stderr |
| 100% test coverage | `internal/redact/redact_test.go` verifies every pattern: secret gone, context preserved |

---

## LLM provider adapters

`internal/llm` contains one file per provider:

| Provider | File | Key env var | Notes |
|---|---|---|---|
| Claude | `claude.go` | `ANTHROPIC_API_KEY` | Default model: `claude-sonnet-4-6` |
| OpenAI | `openai.go` | `OPENAI_API_KEY` | Supports `OPENAI_BASE_URL` override for Azure, LM Studio, LocalAI |
| OpenRouter | `openrouter.go` | `OPENROUTER_API_KEY` | Routes to 100+ models |
| Ollama | `ollama.go` | — | No key; default `http://localhost:11434` |
| Mock | `mock.go` | — | `EXALM_LLM_PROVIDER=mock`; routes by system-prompt keyword; CI/hermetic tests |

The factory `NewFromConfig()` in `llm.go` reads `EXALM_LLM_PROVIDER` and
returns the appropriate adapter. All adapters implement `plugin.LLMClient`.

---

## SSH remote log collection

`internal/ssh` provides an SSH client with TOFU (Trust On First Use)
host-key verification:

1. **First connection**: host key is accepted and persisted to
   `~/.exalm/known_hosts` (same format as OpenSSH).
2. **Subsequent connections**: stored fingerprint is verified. A mismatch
   causes a hard error with an actionable message.
3. **Strict mode**: `--ssh-strict-host-key` rejects unknown hosts without
   storing them.

`internal/ssh/sshtest` provides an in-process SSH server for hermetic
testing — no real `sshd` needed, following the `net/http/httptest` pattern.

Log plugins (`syslog`, `httplog`, `eventlog`, `iis`) call
`exassh.CollectIfNeeded()` which reads from the local filesystem when
`--host` is absent, or dials SSH when present.

---

## Web dashboard

`internal/web` serves an embedded HTTP dashboard on `localhost:7433` (default).

### Routes

| Method | Path | Auth required | Description |
|---|---|---|---|
| GET | `/` | Yes (if token set) | Main findings dashboard |
| GET | `/timeline` | Yes | Cross-signal SVG timeline |
| GET | `/dora` | Yes | DORA four-key metrics page |
| GET | `/api/report` | Yes | Current report as JSON |
| POST | `/api/fix` | Yes | Apply a single remediation action |
| POST | `/api/fix-all` | Yes | Apply all auto-fixable actions |
| POST | `/api/create-pr` | Yes | Create a GitHub PR for the fix |
| GET | `/api/changes` | Yes | IaC change events as JSON |
| GET | `/api/timeline` | Yes | Timeline data as JSON |
| GET | `/api/dora` | Yes | DORA metrics as JSON |
| GET | `/healthz` | **No** | Liveness probe (`{"status":"ok"}`) |
| GET | `/metrics` | **No** | Prometheus text metrics |
| GET | `/static/*` | Yes | Embedded CSS/JS assets |

Full API details: [docs/api.md](api.md)

### Authentication

Set `--token` (or `EXALM_TOKEN`) to require a Bearer token:

```sh
exalm serve --token $(openssl rand -hex 32)
```

Clients pass: `Authorization: Bearer <token>` or `?token=<token>` (query param,
convenient for browser links).

`/healthz` and `/metrics` bypass authentication intentionally to support
Kubernetes probes and Prometheus scraping without credentials.

### Bind address

`--bind` controls the network interface (default `localhost`). Binding to
`0.0.0.0` without a token prints a security warning.

---

## Persistent storage

### SQLite (`internal/store`)

Since Phase 6, Exalm uses a SQLite database at `~/.exalm/exalm.db` with
WAL mode for concurrent reads:

| Table | Contents |
|---|---|
| `schema_migrations` | Migration tracking (prevents double-apply) |
| `deployments` | DORA deployment records (timestamp, duration, outcome, …) |
| `incidents` | Incident lifecycle records (open/closed, severity, postmortem, …) |

On first run, `initStore()` applies migrations and optionally imports legacy
JSONL/JSON files from `~/.exalm/deployments.jsonl` and `~/.exalm/incidents/`.

**Fallback**: if the database cannot be opened (e.g. read-only filesystem
without a PVC), the tool falls back to the legacy file-based stores
transparently — no functionality is lost.

### Helm PVC

When deployed via Helm, a 1 Gi `PersistentVolumeClaim` is created and
mounted at `/home/nonroot/.exalm`. The PVC carries
`helm.sh/resource-policy: keep` so `helm uninstall` does not delete data.

---

## Hubble eBPF gRPC client (`internal/network`)

Exalm can correlate network flows from Cilium's Hubble eBPF observability
layer:

- **Lazy dial**: the gRPC connection to Hubble Relay is established on first
  use, not at startup. A Relay outage does not crash the binary.
- **Hand-coded protowire**: proto fields are encoded/decoded with
  `google.golang.org/protobuf/encoding/protowire` using hard-coded field
  numbers. This avoids a dependency on the full `github.com/cilium/cilium`
  package (only `google.golang.org/grpc` is added).
- **Fallback**: when Hubble Relay is unreachable, a `disconnectedProvider`
  returns a clear error — the k8s analysis continues without network flows.
- **No TLS / mTLS yet**: plain gRPC only. TLS support is on the 90-day
  roadmap.

---

## Cross-signal correlation timeline

`internal/web` + `internal/changestore` implement a swimlane timeline that
correlates three signal types across time:

| Swimlane | Data source |
|---|---|
| K8s Findings | `plugins/k8s` report findings |
| IaC Changes | `internal/changestore` (ArgoCD syncs + Helm releases + Terraform applies) |
| Incidents | `plugins/incident` store |

The `/timeline` page renders an SVG chart with 30-second auto-refresh.
`/api/timeline` returns the same data as JSON for external consumers.

---

## MCP integration

`internal/mcp` exposes Exalm analyses via the Model Context Protocol (MCP)
over Server-Sent Events (SSE). This allows Claude Desktop to call Exalm
analyses as tool calls. No authentication on the SSE endpoint yet (Phase 6
roadmap item).

---

## Security model

| Layer | Mechanism |
|---|---|
| Secret redaction | `internal/redact` — runs before every LLM call, always |
| SSH host verification | TOFU + `~/.exalm/known_hosts` — prevents MITM on first connection |
| Web dashboard auth | Bearer token via `requireToken()` middleware |
| Injection prevention | `internal/ssh` validates remote command strings before execution |
| Mutation gate | `Mutates() = true` + `--apply` flag + confirmation prompt |
| No telemetry by default | Zero opt-out-required telemetry; all network calls are explicit |

---

## Build pipeline

```
Developer machine
  └─ make build → go build -trimpath -ldflags="-s -w" -o ./bin/exalm ./cmd/exalm

CI (GitHub Actions .github/workflows/ci.yml)
  ├─ go test -race ./...               (race detector — catches real concurrency bugs)
  ├─ go test -coverprofile=...         (fails if total coverage < 60%)
  ├─ golangci-lint run                 (errcheck, staticcheck, govet, unused, …)
  ├─ govulncheck ./...                 (known CVE check)
  └─ gofmt -l . / goimports           (formatting gate)

Container image (.github/workflows/docker-image.yml)
  ├─ Build stage: golang:1.26-alpine
  ├─ Final stage: gcr.io/distroless/static-debian12:nonroot (no shell, no package manager)
  ├─ trivy image scan (fails on HIGH/CRITICAL CVEs)
  └─ Push to ghcr.io/exalm-ai/exalm
```

---

## Dependency philosophy

New third-party dependencies require explicit justification in the PR.
Current additions beyond the Go standard library:

| Dependency | Justification |
|---|---|
| `github.com/spf13/cobra` | CLI framework — industry standard, well-audited |
| `github.com/charmbracelet/bubbletea` | TUI framework — only option with full ANSI/Windows support |
| `github.com/charmbracelet/lipgloss` | TUI styling — bundled with Bubble Tea ecosystem |
| `github.com/charmbracelet/bubbles` | TUI components (viewport, spinner) |
| `modernc.org/sqlite` | Pure-Go SQLite — no CGO, no external library |
| `google.golang.org/grpc` | Hubble gRPC transport — Hubble's only API |
| `google.golang.org/protobuf` | Proto encoding for Hubble wire format |
| `k8s.io/client-go` | Kubernetes API client — no alternative |
| `github.com/aws/aws-sdk-go-v2` | AWS Cost Explorer API — no alternative |
| `golang.org/x/crypto` | SSH client (`x/crypto/ssh`) — needed for SSH transport |

Zero external dependencies in `pkg/plugin` (the community SDK).
