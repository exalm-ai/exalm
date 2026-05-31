# Changelog

All notable changes to Exalm are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.7.0] — Phase 7: Publication Prep · v0.1.0-beta

### Added
- **MCP SSE authentication** — `RequireToken()` exported from `internal/web/server.go`;
  `exalm mcp serve --token` / `EXALM_TOKEN` env var; warning printed when unauthenticated
- **`/api/fix` concurrency gate** — semaphore (`maxConcurrentFixes = 3`) in `liveServer`;
  `/api/fix` and `/api/fix-all` return `429 Too Many Requests` when all slots are busy
- **Plugin SDK as standalone module** — `pkg/plugin/go.mod` (`go 1.21`, zero external deps);
  `go.work` for local multi-module workspace; `pkg/plugin/README.md` with full usage guide
- **GitHub issue templates** — `.github/ISSUE_TEMPLATE/{bug_report,feature_request}.md` and
  `config.yml` (disables blank issues, links Security Advisories + Discussions)
- **PR template** — `.github/pull_request_template.md` with code, security, plugin, and
  breaking-change checklists
- **Helm etcd encryption guide** — `deploy/helm/exalm-agent/README.md` now includes
  per-cloud etcd encryption-at-rest instructions, sealed-secrets full workflow, and
  External Secrets Operator (AWS Secrets Manager) example
- **Dashboard auth `--bind` flag** — `ServeOpts.BindAddr`; defaults to `"localhost"`;
  security warning when binding to a non-localhost address without a token
- **Helm auth token injection** — `auth.token` / `auth.existingSecret` values; new
  `templates/secret-token.yaml`; `EXALM_TOKEN` env var injected into the Deployment
- **SQLite store** — `internal/store/` replaces JSONL/JSON file stores; WAL mode;
  idempotent migrations; one-time import of legacy file data
- **`exalm usage`** — LLM token usage statistics (per-provider totals, daily breakdown)
- **TUI scrollable output** — Bubble Tea viewport in the result panel for long LLM responses
- **Fuzz tests** — `FuzzParseSyslogLine`, `FuzzParseHTTPLogLine`, `FuzzParseIISLogLine`
- **kind integration test** — `.github/workflows/integration.yml` spins up a kind cluster
  and runs `exalm k8s analyze` + `dora` + `incident` against it with the mock LLM
- **Mock LLM provider** — `internal/llm/mock.go`; `EXALM_LLM_PROVIDER=mock`; routes
  responses by system-prompt keyword; no API key required
- **Slack/webhook notify plugin** — `plugins/notify/` posts reports to Slack or any webhook
- **Documentation** — `docs/architecture.md`, `docs/deployment.md`, `docs/api.md`,
  `pkg/plugin/README.md`; README plugin tables updated to cover all 20 shipped features

### Changed
- `internal/web.requireToken` refactored into exported `RequireToken(h, token, publicPaths...)`
  — zero behaviour change for existing dashboard routes
- `exalm mcp serve` gained `--token` flag (SSE mode only; stdio is unaffected)
- Helm chart values table and README restructured for clarity

### Security
- MCP SSE endpoint was previously unauthenticated; now gated by `RequireToken`
- `/api/fix` and `/api/fix-all` now reject excess concurrent requests (429) to prevent
  LLM quota exhaustion
- Helm README explicitly warns about etcd base64-encoding and provides remediation path

### Fixed
- `internal/store`: atomic `sync/atomic.Pointer[sql.DB]` for global DB handle (race fix)
- `internal/store`: `errors.Is(err, sql.ErrNoRows)` replacing `==` comparison
- `internal/store`: `Update()` returns error when row ID not found (was silent no-op)
- `internal/store`: `min()` helper removed — shadowed Go 1.21 built-in
- `internal/store`: migration keys changed from path-encoded to stable fixed strings
- `internal/store`: `alreadyMigrated()` propagates errors (was silently swallowing them)
- `internal/store`: bounded reads in migration (`io.LimitReader`, 10 MB cap)

---

## [0.6.0] — Phase 6: Security Hardening, CI Gates, Production Readiness

### Added
- `exalm init` — prerequisite check wizard (LLM key, kube context, data dir, dashboard token)
- `internal/web`: `requireToken` auth middleware for `exalm serve` dashboard
- `--token` / `EXALM_TOKEN` env var for dashboard bearer-token authentication
- Warning printed to stderr when dashboard runs without authentication
- Helm chart: `persistence` section with PVC for `~/.exalm` data directory (prevents data loss on pod restart)
- `.golangci.yml`: errcheck, staticcheck, gosec, unused, gosimple linters
- CI: `golangci-lint` job, `govulncheck` job, coverage gate (60% minimum)
- CI: Trivy container image scan (CRITICAL/HIGH CVEs block build)
- `.github/dependabot.yml`: automated Go module and Actions dependency updates
- `SECURITY.md`: responsible disclosure policy, scope, known security posture
- `sync.Mutex` on incident `fileStore` for concurrent Create/Update safety

### Fixed
- Incident store: concurrent Create/Update operations are now serialised within a process

---

## [0.5.0] — Phase 5: Hubble eBPF gRPC Client

### Added
- `internal/network/hubble_grpc.go`: real lazy gRPC connection to Hubble Relay (`/observer.Observer/GetFlows`)
- Hand-coded protowire field encoding/decoding — avoids `github.com/cilium/cilium` dependency
- `Client.Close()` for connection lifecycle management (prevents goroutine leak)
- `disconnectedProvider` fallback with clear error when Relay is unreachable
- 10 new proto decode/encode unit tests + 2 Close tests

### Changed
- `internal/network/hubble.go`: `Dial()` now makes a real gRPC connection

### Fixed
- `plugins/chaos`: partial read bug in snapshot loading (`io.ReadAll(io.LimitReader(...))`)
- `internal/web`: Slowloris DoS — added `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`
- `internal/web`: `/api/fix` body limited to 64 KB with `http.MaxBytesReader`
- `plugins/chaos`: path traversal prevention via `filepath.Clean` before `os.Open`
- `internal/webhook`: `scanner.Buffer` sized to match 1 MB write limit

---

## [0.4.0] — Phase 4: Cross-Signal Timeline, DORA Lead Time, Chaos, Webhooks

### Added
- **Cross-signal correlation timeline**: `/timeline` (SVG swimlane) + `/api/timeline` (JSON)
- **DORA web dashboard**: `/dora` and `/api/dora` with `ComputePublicMetrics()`
- **DORA Lead Time**: `CommitSHA` + `CommitTime` fields on `DeploymentEvent`; `rateLeadTime()` using 2023 DORA bands
- **Incident → Deployment linking**: `--from-deploy <DEP-id>` flag on `exalm incident open`
- **Chaos engineering plugin** (`plugins/chaos/`): resilience scoring 0–100, Litmus ChaosEngine YAML for 4 scenarios
- **Terraform Cloud webhook receiver** (`internal/webhook/`): HMAC-SHA512 verification, JSONL append, DORA auto-feed
- `exalm webhook terraform` subcommand

---

## [0.3.0] — Phase 3: SSH TOFU, Incident Plugin, DORA Metrics, K8s IaC Detection

### Added
- **SSH TOFU** (`internal/ssh/known_hosts.go`): trust-on-first-use host-key verification persisted to `~/.exalm/known_hosts`
- **Incident plugin** (`plugins/incident/`): `open`, `list`, `close`, `postmortem` subcommands; file store at `~/.exalm/incidents/`; LLM-powered blameless postmortem
- **DORA metrics** (`plugins/dora/`): Deployment Frequency, CFR, MTTR, Lead Time; `exalm dora report` and `exalm dora log-deploy`
- **K8s IaC change detection**: ArgoCD Application syncs and Helm release history in `plugins/k8s/iac.go`
- `--ai` flag on `exalm dora report` for LLM narrative

### Changed
- All SSH connections now verify host keys via TOFU (replaces `InsecureIgnoreHostKey`)

---

## [0.2.0] — Phase 2: SSH Remote Collection, Bubble Tea TUI

### Added
- **SSH remote log collection**: all log plugins accept `--host`, `--ssh-user`, `--ssh-key`, `--ssh-port`, `--ssh-password`
- **Bubble Tea TUI** (`internal/tui/`): `exalm tui` interactive terminal UI
- `internal/ssh/sshtest/`: in-process SSH test server (mirrors `net/http/httptest`)
- SSH injection prevention: flag values sanitised before shell execution

---

## [0.1.0] — Phase 1: Core CLI

### Added
- `logs summarize`: LLM-powered log analysis
- `k8s analyze` / `k8s watch`: Kubernetes pod/event/node diagnostics; 30s auto-refresh dashboard
- `aws cost`: AWS Cost Explorer analysis
- `tf review`: Terraform plan JSON security and cost analysis
- `syslog analyze`, `httplog analyze`, `eventlog summarize`, `iis analyze`
- `slo check`: SLO burn-rate calculation with Prometheus backend
- `incident` (stubbed)
- `internal/redact/`: 28+ secret/PII redaction patterns; always runs before LLM calls
- `internal/llm/`: Claude, OpenAI, OpenRouter, Ollama adapters
- `pkg/plugin/`: plugin interface contract (`Name`, `Description`, `Mutates`, `Subcommands`)
- `internal/web/`: live HTTP dashboard with `exalm serve`
- Helm chart (`deploy/helm/exalm-agent/`): ClusterRole, RBAC, ConfigMap, Secret
- Distroless Docker image (`gcr.io/distroless/static-debian12:nonroot`)
- `Makefile` with `build`, `test`, `lint`, `image`, `chart-*` targets

[Unreleased]: https://github.com/exalm-ai/exalm/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/exalm-ai/exalm/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/exalm-ai/exalm/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/exalm-ai/exalm/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/exalm-ai/exalm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/exalm-ai/exalm/releases/tag/v0.1.0
