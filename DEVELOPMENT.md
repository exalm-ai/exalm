# Development Guide

Conventions, non-negotiables, and patterns for contributing to and extending
exalm without breaking the trust model.

**Read this before writing code.**

---

## Project at a glance

**Exalm** is an open-source, plugin-based AI assistant for ops engineers
(DevOps, SRE, sysadmins, MSPs). It runs as a single static binary, collects
context from the user's environment, **redacts secrets before anything leaves
the machine**, sends sanitized context to an LLM (Claude / OpenAI / OpenRouter /
Ollama), and returns diagnostic reports.

Domain: `exalm.com`. Repo: `github.com/exalm-ai/exalm`. License: Apache-2.0.

### What ships today

**Plugins** (one CLI subcommand each):
`logs`, `k8s`, `syslog`, `httplog`, `eventlog`, `iis`, `aws_cost`, `dora`,
`incident`, `chaos`, `slo`, `tf`, `notify`.

**Capabilities:**

- **Agentless SSH log collection** — every log plugin accepts `--host` to fetch
  logs over SSH with TOFU host-key verification (persisted to
  `~/.exalm/known_hosts`). No agent installed on the target.
- **Interactive TUI** — `exalm tui` (Bubble Tea) for browsing plugins, filling
  flag forms, and running analyses.
- **Web dashboard** — `exalm serve` exposes findings, a DORA dashboard
  (`/dora`), and a cross-signal correlation timeline (`/timeline`). Guarded by
  token auth + CSRF middleware (see "Web dashboard security posture" below).
- **DORA metrics** — `exalm dora report` computes Deployment Frequency, Lead
  Time for Changes, Change Failure Rate, and MTTR from a local store.
- **Incident lifecycle** — `open`, `list`, `close`, `postmortem`. LLM-powered
  blameless postmortems (timeline redacted before send).
- **k8s IaC change detection** — ArgoCD Application syncs and Helm release
  history appear in the `## IaC Changes` section of `k8s analyze`.
- **Chaos resilience scoring** — `exalm chaos suggest` scores services 0–100
  from a k8s snapshot and emits Litmus ChaosEngine YAML.
- **Hubble eBPF flow correlation** — lazy gRPC client to Cilium Hubble Relay;
  degrades to a clear error (no crash) when Relay is unreachable.
- **MCP server** — `exalm mcp serve` exposes Exalm tools over SSE for Claude
  Desktop and other MCP clients.
- **SQLite store** — DORA deployments + incident records via `modernc.org/sqlite`
  (pure Go, no CGO). WAL mode, idempotent migrations.
- **BYOM (bring your own model)** — Claude, OpenAI, OpenRouter, and local
  Ollama. No provider lock-in; local models keep data on-prem end to end.

---

## Architecture map

```
cmd/exalm/main.go         CLI entry, plugin registration, flag wiring
cmd/exalm/tui.go          `exalm tui` command — wires TUI to LLM + registry
cmd/exalm/serve.go        `exalm serve` command — k8s watch + web dashboard
pkg/plugin/plugin.go      Public plugin contract (THE interface; separate Go module)
internal/config/          Config loading from env + flags
internal/llm/             LLM provider adapters (claude, openai, openrouter, ollama, mock)
internal/redact/          Secret/PII redaction — TRUST FOUNDATION
internal/store/           SQLite store (DORA deployments + incidents; WAL; migrations)
internal/output/          Markdown + JSON renderers
internal/registry/        Plugin registry
internal/ssh/             SSH client + TOFU host-key verification
internal/ssh/sshtest/     In-process SSH test server (mirrors net/http/httptest)
internal/network/         Hubble eBPF gRPC client + flow correlation
internal/tui/             Bubble Tea TUI — model, styles, state machine
internal/web/             HTTP server: findings, DORA, timeline dashboards + auth
internal/webhook/         Terraform Cloud webhook receiver
internal/mcp/             MCP / SSE server for Claude Desktop
internal/version/         Build version metadata
plugins/<domain>/         One package per plugin (logs, k8s, aws_cost, ...)
docs/                     User-facing documentation
examples/                 Sample inputs used in docs and tests
```

`ARCHITECTURE.md` is the canonical, fuller component breakdown (including
`internal/evidence`, `internal/changestore`, `internal/analyzer`, and
`internal/gitprovider`) with data-flow diagrams and design rationale. The
`pkg/` (public, importable by external plugins) vs `internal/` (private to this
repo) boundary is intentional — keep it tight.

---

## Coding conventions

- **Language: Go 1.26+.** Idiomatic Go. No clever metaprogramming.
- **Module path:** `github.com/exalm-ai/exalm`.
- **Errors:** wrap with `fmt.Errorf("context: %w", err)`. No `panic` outside
  init-time misconfigurations.
- **Logging:** plugins should not log directly. Return findings via
  `plugin.Report`. The CLI handles all stdout/stderr.
- **Tests:** every new package gets a `*_test.go`. Tests must be hermetic
  (no live API calls in CI; record fixtures).
- **Imports:** stdlib, then third-party, then local — separated by blank lines.
- **Comments:** doc comments on every exported identifier. Be terse.
- **Formatting:** `gofmt -s` and `goimports`. Enforced by `make lint`.
- **Commit messages:** Conventional Commits. `feat(logs):`, `fix(redact):`,
  `docs:`, `chore:`, `refactor:`. One concern per commit.

For the full contributor walkthrough (setup, PR checklist, commit scopes), see
`CONTRIBUTOR_WORKFLOW.md`.

---

## The plugin contract — read before adding any plugin

Every plugin implements `plugin.Plugin`:

```go
type Plugin interface {
    Name() string                   // CLI subcommand name
    Description() string            // shown in --help
    Mutates() bool                  // gates --apply
    Subcommands() []Subcommand      // actions
}
```

A `Subcommand` is `{Name, Description, Run}` where `Run(ctx, RunArgs)`
returns a `Report`.

### Step-by-step: adding a new plugin

1. Create `plugins/<name>/<name>.go`. Define a struct that satisfies
   `plugin.Plugin`. Mirror the structure of `plugins/logs/logs.go`.
2. Create `plugins/<name>/prompts.go` for the system prompt(s). Keep
   prompts as Go string constants (easy to diff in PRs).
3. Add a unit test in `plugins/<name>/<name>_test.go` that uses a fake
   `plugin.LLMClient` and verifies the redactor is called.
4. In `cmd/exalm/main.go`:
   - Add the import: `<name>plugin "github.com/exalm-ai/exalm/plugins/<name>"`
   - In `registerPlugins()`: `registry.Register(<name>plugin.New())`
5. Add a sample input to `examples/<name>/`.
6. Add docs at `docs/plugins/<name>.md`.

### Plugin design rules

- **Read-only first.** A plugin should expose read-only diagnostics before
  any mutating action. `Mutates()` should stay `false` for as long as
  possible.
- **Redact before LLM.** Every byte of user-environment data must pass
  through `args.Redactor.Redact()` before it goes into a `CompleteRequest`.
  No exceptions.
- **Cap input size.** Define a `MaxInputBytes` constant per plugin (200 KB
  is a good default). Use `io.LimitReader`.
- **System prompts are the product.** Iterate on them, version them,
  test them with fixtures.
- **No hidden network calls.** Plugins must only make network calls to
  (a) the LLM via the injected `LLMClient` and (b) the explicit ops API
  the plugin is built for (e.g. AWS for `aws_cost`).

---

## The redaction layer — THE TRUST FOUNDATION

`internal/redact` is the most security-sensitive code in the project. Rules:

1. **Never** add a code path that sends user data to an LLM without
   redaction. There is no "just for debugging" exception.
2. **Never** lower the strictness of an existing redaction test. If a
   test fails, fix the code, not the test.
3. New patterns go in `internal/redact/patterns.go` with a corresponding
   test in `internal/redact/redact_test.go`. Test must verify both
   (a) the secret is gone and (b) surrounding context is preserved.
4. Optional patterns (high false-positive rate) go in `OptionalPatterns`,
   not `DefaultPatterns`. Users opt in via `--redact email,ipv4`.
5. The Engine's `Redact` method must never return an error. Failure
   modes are: redact what we can, or return the input unchanged. We
   never return *partially* redacted data flagged as fully redacted.

---

## Web dashboard security posture

`exalm serve` and `exalm mcp serve` are guarded by middleware in
`internal/web/server.go`. These are **implemented and wired** — keep this
section consistent with `ARCHITECTURE.md`; if you change the middleware,
update both files.

- **Token auth** — `requireToken` enforces `Authorization: Bearer <token>`
  (or `?token=`) when `--token` / `EXALM_TOKEN` is set. `/healthz` and
  `/metrics` bypass auth for monitoring. Unauthenticated mode warns on stderr.
- **CSRF** — `requireCSRF` rejects mutating requests (POST/PUT/DELETE) that
  lack the `X-Exalm-Request: true` header, plus an Origin allowlist check.
  The server is wired as `requireToken(requireCSRF(mux), token)`.
- **Concurrency gate** — `/api/fix` and `/api/fix-all` admit at most
  `maxConcurrentFixes = 3` in-flight LLM calls; excess requests get HTTP 429.

Defaults that matter: the dashboard binds to `localhost`; TLS is expected to be
terminated at a reverse proxy / ingress for remote exposure.

---

## LLM providers

`internal/llm` houses provider adapters (Claude, OpenAI, OpenRouter, Ollama,
plus a Mock for tests). To add one:

1. New file `internal/llm/<provider>.go` implementing `plugin.LLMClient`.
2. Add a case in `NewFromConfig()` in `internal/llm/llm.go`.
3. Add config fields in `internal/config/config.go` and env var loading.
4. Document required env vars in `docs/configuration.md`.

The default model for Claude is `claude-sonnet-4-6`. When new general
models ship, update `DefaultClaudeModel` in `internal/llm/claude.go` and
ship a release note.

**Never hardcode an API key.** Always read from env or config.

---

## Test commands

```sh
make test           # unit tests
make test-redact    # redaction tests, with verbose output (run before any redact change)
make lint           # gofmt + go vet + golangci-lint
make build          # local binary to ./bin/exalm
```

CI runs all of the above on every PR. Don't merge red builds.

---

## Things to NEVER do

These are non-negotiable. Pull requests doing any of them will be rejected.

- ❌ Add a network call from a plugin that bypasses the injected `LLMClient`.
- ❌ Log raw (un-redacted) user data anywhere — stdout, stderr, file, or
  telemetry.
- ❌ Add telemetry that is on by default. Telemetry is opt-in only.
- ❌ Commit API keys, even fake ones that look real (regex scanners pick
  them up). Use placeholders like `sk-ant-EXAMPLE-EXAMPLE`.
- ❌ Add a third-party dependency without justifying it in the PR. We're
  trying to keep the dependency tree small for security and supply-chain
  reasons. Stdlib first.
- ❌ Change the plugin interface in a breaking way without a deprecation
  note and a major version bump.
- ❌ Add a "convenience" function that bypasses the safety gate on
  mutating plugins.
- ❌ Use `panic` in non-init code.
- ❌ Add `--apply` semantics that don't print a clear, scary confirmation
  prompt before mutation.

---

## Style preferences for Claude Code

- When in doubt, prefer **adding tests** over adding features.
- When fixing a bug, **add a regression test first**, then fix.
- When a function grows past ~40 lines, ask whether it should split.
- When you need to make a design decision not covered here, **say so in
  the PR description** rather than guessing silently.
- Don't reformat unrelated code in a PR.
- Don't introduce new abstractions on the first use; wait for the third.

---

## SSH remote log collection

All log plugins (`syslog`, `httplog`, `eventlog`, `iis`) accept SSH flags:

```sh
# Linux syslog over SSH
exalm syslog analyze --host db-01 --ssh-key ~/.ssh/id_rsa

# nginx access log over SSH
exalm httplog analyze --host web-01 --ssh-user deploy

# Windows Event Log over SSH (requires OpenSSH for Windows on the target)
exalm eventlog summarize --host dc-01 --log-name Security

# IIS W3C logs over SSH
exalm iis analyze --host iis-01 --log-dir 'C:\inetpub\logs\LogFiles\W3SVC1'
```

SSH flags available on all log plugins:
- `--host` — remote hostname or IP
- `--ssh-user` — SSH username (default: current OS user)
- `--ssh-key` — path to PEM private key (default: `~/.ssh/id_rsa`)
- `--ssh-port` — SSH port (default: 22)
- `--ssh-password` — password auth (prefer `EXALM_SSH_PASSWORD` env var)
- `--log-lines` — number of log lines to fetch (default: plugin-specific)

**Security:** host-key verification uses TOFU — the first connection to any
host auto-accepts and persists the key fingerprint to `~/.exalm/known_hosts`.
Subsequent connections verify the stored fingerprint. A mismatch returns an
actionable error. Use `--ssh-strict-host-key` to reject unknown hosts without
prompting.

Test infrastructure: `internal/ssh/sshtest` provides an in-process SSH server
(no real SSH daemon needed) following the `net/http/httptest` pattern.

---

## Interactive TUI

```sh
exalm tui
```

The TUI (`internal/tui/`) uses Bubble Tea + Lipgloss + Bubbles:
- Arrow keys / Enter to select plugin and subcommand
- Tab / Shift+Tab to move between flag inputs
- q / Ctrl+C to quit
- r to re-run the same command from the result screen

Adding TUI-specific flag groups: edit `flagDefsFor()` in `internal/tui/model.go`.

---

## Quick reference: file you most likely want to touch

| Goal | File |
|---|---|
| Add a new plugin | `plugins/<name>/<name>.go` + register in `cmd/exalm/main.go` |
| Add SSH collection to a plugin | `exassh.CollectIfNeeded` — see `plugins/syslog/syslog.go` |
| Add SSH flag inputs to TUI | `flagDefsFor()` in `internal/tui/model.go` |
| Add a new redaction pattern | `internal/redact/patterns.go` + test in `redact_test.go` |
| Add a new LLM provider | `internal/llm/<provider>.go` + case in `llm.go` |
| Change CLI behavior | `cmd/exalm/main.go` |
| Change report rendering | `internal/output/markdown.go` or `json.go` |
| Update TOFU known_hosts logic | `internal/ssh/known_hosts.go` |
| Work with incident store | `internal/store/` (incident records) |
| Work with DORA metrics | `plugins/dora/metrics.go` (rating thresholds) |
| Work with k8s IaC detection | `plugins/k8s/iac.go` (ArgoCD + Helm collectors) |
| Work with chaos resilience scoring | `plugins/chaos/scorer.go` (risk weights) |
| Work with Litmus YAML generation | `plugins/chaos/litmus.go` |
| Work with Terraform webhook | `internal/webhook/webhook.go` |
| Work with timeline dashboard | `internal/web/server.go` + `templates/timeline.html` |
| Work with DORA dashboard | `internal/web/server.go` + `templates/dora.html` |
| Work with Hubble gRPC client | `internal/network/hubble_grpc.go` (proto field maps) |
| Configure web dashboard auth | `internal/web/server.go` (`requireToken` / `requireCSRF`) |
| Change init readiness checks | `cmd/exalm/init.go` |
| Change Helm persistence config | `deploy/helm/exalm-agent/values.yaml` + `templates/pvc.yaml` |
| Update CI / security gates | `.github/workflows/ci.yml`, `docker-image.yml`, `.golangci.yml` |
| Update docs | `docs/` and `README.md` |

---

*This file is the source of truth for how to work in this repo. Update it
whenever the architecture or rules change. For system design and rationale see
`ARCHITECTURE.md`; for the contributor process see `CONTRIBUTOR_WORKFLOW.md`.*
