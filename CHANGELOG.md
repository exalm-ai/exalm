# Changelog

All notable changes to Exalm are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added — modular AI-ops platform work (feat/ops-workspace)

Built on top of the existing implementation after a full inventory (registry-driven navigation,
settings API, per-analyzer dashboards, the AI chat workspace, timeline backend, and all
source-aware collectors already existed — none were rebuilt). What was actually added:

- **`SupportsExplorer` registry capability** (`internal/web/dashboards.go`) — dashboards declare
  whether they carry a log/finding explorer surface (k8s + every analyzer: yes); the sidebar's
  Log Explorer entry is gated on the flag instead of assumed. Not zeroed by settings — it is a
  data view, not an AI feature.
- **Settings persisted in SQLite** (`internal/settings/sqlite.go`, `internal/store`) — the
  settings document moves from `~/.exalm/settings.json` into a single-row `settings` table in
  `~/.exalm/exalm.db`, selected via the same `SetSettingsDB` atomic-pointer switch the incident
  and conversation stores use, with automatic file fallback when the DB can't open. One-time
  `MigrateSettings` imports the legacy file verbatim (left in place). The GET/PUT `/api/settings`
  contract is unchanged byte-for-byte.
- **Surrounding-context log queries** (`internal/investigate/logsession.go`, `internal/web`) —
  `GET .../logs?around=<idx|RFC3339>&context=N` returns the events around one anchor;
  `LogSession.Around` anchors by corpus index (exact) or timestamp (fallback after re-ingest),
  and every log-query event now carries its corpus `idx`. The rest of the explorer wishlist
  (from/to, severity, unit/scope, contains, limit/offset) already existed server-side.
- **Shared logs explorer** (`internal/web/static/logexplorer.js`) — one view module replaces the
  two overlapping log viewers (k8s drawer + analyzer drilldown): search/regex, per-vocabulary
  severity, unit/scope + time-range filters, export, one-shot ✦ analysis (now routed through the
  dashboard-scoped analyze endpoint — the old hardcoded global URL 503'd in hub mode),
  show-surrounding-context with anchor highlight, conversational Investigate and jump-to-resource
  hand-offs. logviewer.js keeps only the k8s pod-selection shell and live-tail loop; analyzer.js'
  drilldown becomes a thin mount over the same module.
- **Investigation workspace everywhere** (`internal/web/static/{dashboard,chat,analyzer}.js`) —
  the AI page's tree+chat grid is a shared `workspaceHTML()` now also embedded in every analyzer
  dashboard's AI section, extended with a Timeline pane (mirrors the latest turn's investigation
  timeline, live-updating) and a Logs pane (embedded corpus explorer for analyzers, pod log
  drawer for k8s). Analyzer pages gain the cumulative evidence tree; the existing chat is
  untouched — its exports grew by two read-only functions.

Deliberately not built: IIS↔Windows-event cross-correlation (needs two corpora joined in one
session — architecturally new, flagged for later), and a network (Hubble) analyzer (the adapter
in `internal/network` remains dormant, wired to nothing).

### Added
- **Sortable Log Explorer columns** (`internal/web/static/dashboard.js`) — Severity, Namespace/Pod,
  Message, and Category headers are now clickable: click to sort by that column (with a sensible
  default direction per column — severity starts high-to-low, text columns start A-to-Z), click
  again to flip direction. An arrow on the active header shows the current direction. Severity
  compares by rank (critical > high > medium > low), other columns compare case-insensitively as
  text; ties keep the original order (stable sort). No "sort by latest" option yet — findings have
  no real detection timestamp today (the `Age` field is a hardcoded placeholder, `"—"`); sorting by
  it would silently fake recency rather than show it. Flagging as a possible follow-up if genuine
  chronological sort is wanted — it needs a real timestamp threaded from the k8s plugin through
  `dashFinding`, not just a front-end change.

### Changed
- **Deterministic answer-mode routing for the investigation chat** (`internal/investigate/questionmode.go`,
  `internal/investigate/engine.go`) — live testing against phi4-mini:3.8b on a real cluster showed that
  prompt-level mode instructions alone are not enough: the model kept restating the root-cause template
  when asked "what is the current memory limit?". Consistent with the engine's deterministic-first design,
  the question SHAPE is now classified in code (fact-shaped prefixes like "what is/how many/is there…" vs
  open-ended markers like "why/RCA/investigate"), and fact-shaped questions get a per-turn `ANSWER MODE:
  direct` directive injected into the enriched turn right next to the QUESTION — with the scope check as
  step 1 (unrelated questions get a fixed redirect reply; a trailing "if unrelated…" clause was measurably
  ignored, answered with fabricated citations). Polite phrasings ("Can you tell me…", "please show…")
  classify like their bare forms; action requests ("can you fix it?") stay on the default path. Also pins
  conversation-synthesis `Temperature` to 0.2 — previously unset, so Ollama's 0.8 default made the same
  question flip between direct answers and template restatements across runs — and raises `MaxTokens` to
  2048, because Ollama counts a reasoning model's thinking trace against the completion budget and
  qwen-class models were burning all 900 tokens thinking, returning empty content. Verified end-to-end on
  the live cluster: "what is the current memory limit ?" → "5000Mi [E11]", "what is the best pizza
  topping?" → scope redirect, open "why is X failing?" → full template, across phi4-mini:3.8b and
  qwen3.5:4b (qwen also reads yes/no evidence accurately where phi4-mini hallucinates negations —
  prefer qwen for the chat).
- **Atomic owner-chain evidence items** (`plugins/k8s/ownerchain.go`) — the workload config evidence was
  one dense compound line (status + limits + probes + pause flags); small local models misread it on
  yes/no questions (phi4-mini answered "does not have liveness probes" against evidence that listed them).
  It is now three atomic items — rollout status, resource limits, probes — which small models read and
  cite far more accurately. The `memLimits=%t` literal stays verbatim in the limits item for
  `symptoms.go`'s confidence/hypothesis regexes.
- **Investigation chat scope discipline, all 7 analyzer domains** (`internal/investigate/prompts.go`,
  `plugins/k8s/prompts.go`) — generalizes the memory-limit fix below: the chat should be able to
  answer any question related to the failure, not only the questions its fixed reply template
  anticipates, and should say so plainly when a question isn't related instead of forcing an
  answer out of unrelated evidence. `ConversationPromptFor` — the one function that builds the
  conversation prompt for httplog, syslog, eventlog, iis, logs, and cloudtrail (and any future
  cloud plugin built the same way) — gained a "Scope discipline" instruction: answer whatever the
  question actually asks (a value, a related resource, a timeline detail, a connection between
  two things) directly and concisely with citations, reserving the full root-cause template for
  genuinely open-ended questions; and when a question has no plausible connection to the focus
  resource or its evidence, say so and ask what the operator meant rather than stretching
  unrelated evidence to answer it. Out-of-scope questions get a fixed, copyable redirect reply —
  the same sentence the per-turn directive uses, because small models follow exact-match cues.
  k8s previously hand-rolled its conversation prompt (the only domain that did, against the
  Profile contract's documented guidance) and had silently missed shared-template improvements
  twice this session; `k8sProfile()` now builds it via `investigate.ConversationPromptFor` like
  every other domain, keeping only the genuinely k8s-specific rules (Secret values, DNS
  heuristics) as appended domain rules.

### Fixed
- **LLM-bound dashboard routes killed at 30s** (`internal/web/server.go`) — the server-wide
  `WriteTimeout: 30s` (Slowloris protection) also applied to chat, log-line analysis, and deep
  investigation, killing the connection mid-inference whenever a local model took longer ("empty
  reply from server"; `docs/deployment.md` used to advise rebuilding with a patched timeout). Those
  three handlers now extend their own write deadline to 10 minutes via `http.NewResponseController`;
  the 30s guard still protects every other route.
- **Fallback banner misdiagnosed a failed LLM call as missing configuration**
  (`internal/investigate/engine.go`) — when the one LLM call per turn errored or returned empty
  (reasoning models can burn the whole token budget "thinking"), the deterministic fallback opened
  with "No LLM is configured". The banner now states the actual reason.
- **k8s chat couldn't answer "what is the memory limit?"** (`plugins/k8s/ownerchain.go`,
  `plugins/k8s/prompts.go`) — every collector that touched a container's resource limits
  (`detailFromPodSpec` in owner-chain, plus the analyzers/quota checks) immediately collapsed
  the actual `resource.Quantity` to a `HasMemoryLimits`/`HasCPULimits` boolean before it ever
  reached an evidence item, so no evidence the LLM sees ever contains the configured value —
  only whether one exists. Asked a narrow factual question the model couldn't answer from
  evidence, it fell back to repeating the templated root-cause summary instead of saying so.
  `WorkloadDetail` now also carries `MemoryLimitDetail`/`CPULimitDetail` (actual per-container
  values, e.g. `app=512Mi; sidecar=none`), appended to the owner-chain evidence excerpt without
  touching the existing `memLimits=%t cpuLimits=%t` substring that `symptoms.go`'s confidence
  scoring regexes match on (the answer-side behavior — direct cited answers instead of the
  template — is the deterministic answer-mode routing described under Changed).
- **`exalm serve` k8s AI chat** (`cmd/exalm/serve.go`) — the serve path never wired the
  conversational investigation handlers (`Converse`, `GetConversation`, `AnalyzeLogLine`,
  `Investigate`, `LogFetch`, `PodInfo`), so the k8s dashboard's chat always answered
  503 "Chat is unavailable" even with a working LLM and cluster connection. Only the
  `k8s analyze/watch --open` path had them. `serve` now wires the same closures,
  including incident history for recurrence matching.

### Added
- **Clickable finding summaries** (`internal/web/static/{widgets,dashboard}.js`) — the k8s dashboard's
  top stat cards (Total findings / Errors / Critical / Warnings) and the severity-distribution donut
  legend now jump straight to the Log Explorer pre-filtered to that severity, reusing the Explorer's
  existing filter state instead of adding a parallel mechanism. "Namespaces" stays a plain display —
  it's a distinct-value count, not a findings bucket, and the namespace bars widget right below it
  already offers per-namespace drill-through. The Incidents dashboard's Open/Mitigated/Closed/Total
  tiles now filter the incident list the same way (click again, or click Total, to clear). Fixed a
  related correctness gap in the shared `counters()` widget along the way: a counter with no real
  `drill` query (e.g. httplog's "Slow requests", "Top URI count") no longer renders as clickable —
  previously it silently returned an *unfiltered* "related logs" result if clicked, since the drill
  menu never checked for an empty query.
- **AWS CloudTrail plugin** (`plugins/cloudtrail`) — a new investigable log analyzer following the
  `investigate.Profile` contract exactly (no engine or web-layer changes needed): `exalm cloudtrail
  analyze` reads newline-delimited CloudTrail records (`jq -c '.Records[]' trail.json` to convert a
  raw S3 export) and flags root-account usage, access-denied spikes, console-login brute forcing,
  resource deletions, and IAM privilege-escalation calls. Ships with its own dashboard (event
  timeline, top event names/principals/source IPs, a signals counter) and a worked example at
  `examples/cloudtrail/suspicious-activity.ndjson`. Demonstrates the framework's stated design goal
  for future cloud plugins (Azure, VMware, …): a `Profile` is all a new domain needs to supply.
- **Widget data-source extension** (`plugins/httplog`) — a new `topUserAgents` widget surfaces the
  user-agent strings the parser already captured but never exposed, re-derived from the raw log
  line at stats-build time (the same pattern `TopClients` already used). Distinguishes health-check
  and bot traffic from real users; drills straight to the matching log lines.
- **Incidents dashboard v2** (`internal/web/dashroutes.go`, `internal/web/static/dashboard.js`) —
  the Incidents dashboard grows from read-only to a working lifecycle workspace: open new
  incidents (title, severity, namespace, service) and close/reopen existing ones directly
  from the UI via `POST /api/dashboards/incidents/action`, backed by shared validation logic
  (`plugins/incident/actions.go`) now used by both the CLI and the web layer. Each incident
  also gets cross-links to every currently-attached analyzer dashboard so an operator can jump
  straight from an incident record to the log data behind it. Incident records gained
  `namespace`/`service` scope fields (`exalm incident open --namespace --service`).
- **Modular dashboard platform** — the web UI builds itself from a dashboard registry:
  platform dashboards (Kubernetes, DORA, Timeline, Incidents) plus one per analyzer
  plugin, grouped navigation, and per-dashboard widgets served by scoped routes
  (`/api/dashboards/{id}/…`). Legacy routes and the single-analyzer `--open` flow are
  unchanged.
- **Dashboard settings** — a read-write Settings page persisted at
  `~/.exalm/settings.json` (`GET/PUT /api/settings`): enable/disable each dashboard,
  Enable All, and a global AI-features toggle. Disabled dashboards vanish from
  navigation and their routes 404.
- **Multi-dashboard hub** — `exalm serve` hosts every dashboard in one process.
  Analyzer runs with `--open` attach their parsed session to the running hub
  (loopback-only ingest guarded by a per-run secret at `~/.exalm/hub.json`) instead of
  starting a second server; chat, drilldown, and stats on attached sessions run the
  full investigation pipeline. Ingested sessions never carry SSH credentials, so
  remote diagnostics are disabled for them by construction.
- **Unified widget library** — one shared chart library (`widgets.js`) powers every
  dashboard; each chart offers "Show related logs" and "✦ Investigate" (seeds the AI
  chat with the clicked slice).
- **Generic Investigation Framework** (`internal/investigate`) — the AI Operations Copilot
  extracted from the Kubernetes plugin into a reusable engine: deterministic per-turn
  investigation plans (symptom catalog + question intents), collectors with a
  per-conversation evidence cache, E1..En evidence citations, ranked root-cause hypotheses,
  numeric evidence-quality confidence, tiered remediation (mitigation / root-cause fix /
  prevention), timelines, follow-up suggestions, and persisted conversation memory — with
  exactly one redacted LLM call per turn. Kubernetes is now the reference Profile.
- **Conversational investigation for all log analyzers** — `syslog`, `httplog`, `eventlog`,
  `iis`, and `logs` gained investigation Profiles over an in-memory parsed corpus
  (`LogSession`), the same two-pane chat + investigation-tree UI as Kubernetes, and a
  `--open` flag that launches the dashboard after an analysis.
- **Per-analyzer dashboards** — severity/request timelines, top units/URLs/clients/event IDs,
  auth-failure/OOM/reboot/slow-request signals per analyzer; **every chart element drills
  down** to the matching log lines (`GET /api/analyzer/logs`), each with the ✦ Analyze-line
  action.
- **Tiered remote diagnostics** (`internal/ssh/diagnostics.go`) — a fixed read-only allowlist
  of SSH diagnostics (disk, memory, uptime, services, journal, kernel ring, IIS app pools;
  opt-in `full` tier adds auth logs, login history, firewall state, certificate expiry,
  scheduled tasks) gated by `EXALM_REMOTE_DIAG` / `--remote-diag`; parameters are
  strictly validated and commands are never user- or LLM-supplied.
- **Investigation report export** — `GET /api/chat/{id}/export` now also produces a
  standalone styled HTML report (`format=html`) with an executive summary; the Markdown
  export gained the same executive summary; PDF via the browser's print dialog.

---

## [0.7.0] — Publication Prep · v0.1.0-beta

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

## [0.6.0] — Security Hardening, CI Gates, Production Readiness

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

## [0.5.0] — Hubble eBPF gRPC Client

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

## [0.4.0] — Cross-Signal Timeline, DORA Lead Time, Chaos, Webhooks

### Added
- **Cross-signal correlation timeline**: `/timeline` (SVG swimlane) + `/api/timeline` (JSON)
- **DORA web dashboard**: `/dora` and `/api/dora` with `ComputePublicMetrics()`
- **DORA Lead Time**: `CommitSHA` + `CommitTime` fields on `DeploymentEvent`; `rateLeadTime()` using 2023 DORA bands
- **Incident → Deployment linking**: `--from-deploy <DEP-id>` flag on `exalm incident open`
- **Chaos engineering plugin** (`plugins/chaos/`): resilience scoring 0–100, Litmus ChaosEngine YAML for 4 scenarios
- **Terraform Cloud webhook receiver** (`internal/webhook/`): HMAC-SHA512 verification, JSONL append, DORA auto-feed
- `exalm webhook terraform` subcommand

---

## [0.3.0] — SSH TOFU, Incident Plugin, DORA Metrics, K8s IaC Detection

### Added
- **SSH TOFU** (`internal/ssh/known_hosts.go`): trust-on-first-use host-key verification persisted to `~/.exalm/known_hosts`
- **Incident plugin** (`plugins/incident/`): `open`, `list`, `close`, `postmortem` subcommands; file store at `~/.exalm/incidents/`; LLM-powered blameless postmortem
- **DORA metrics** (`plugins/dora/`): Deployment Frequency, CFR, MTTR, Lead Time; `exalm dora report` and `exalm dora log-deploy`
- **K8s IaC change detection**: ArgoCD Application syncs and Helm release history in `plugins/k8s/iac.go`
- `--ai` flag on `exalm dora report` for LLM narrative

### Changed
- All SSH connections now verify host keys via TOFU (replaces `InsecureIgnoreHostKey`)

---

## [0.2.0] — SSH Remote Collection, Bubble Tea TUI

### Added
- **SSH remote log collection**: all log plugins accept `--host`, `--ssh-user`, `--ssh-key`, `--ssh-port`, `--ssh-password`
- **Bubble Tea TUI** (`internal/tui/`): `exalm tui` interactive terminal UI
- `internal/ssh/sshtest/`: in-process SSH test server (mirrors `net/http/httptest`)
- SSH injection prevention: flag values sanitised before shell execution

---

## [0.1.0] — Core CLI

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
