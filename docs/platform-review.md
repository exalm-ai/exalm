# Exalm Platform Architecture Review

**Branch:** `feature/platform-api` (off `feature/ops-workspace`; experimental, must not modify stable behavior)
**Status:** REVIEW ONLY — no implementation until this document is approved.
**Goal:** Prepare Exalm to expose its capabilities through many interfaces (CLI, Web, REST, MCP, future gRPC) where every feature is implemented **once** in an internal service layer, and to make it MCP-ready. Establish the boundary for a future OSS / Pro / Enterprise split.

> Evidence base: three parallel code audits (MCP+auth, transport-logic, CLI/export) plus the full frontend/backend/engine inventory from prior sessions. All claims cite `file:line`.

---

## 0. Headline findings (the three that change the plan)

1. **An MCP server already exists.** `internal/mcp` is a hand-rolled JSON-RPC 2.0 server (protocol `2024-11-05`), stdio + SSE transports, 5 tools, a `--write` gate, and tests. But `exalm mcp serve` wires it to an **empty `plugin.Report`** (`cmd/exalm/main.go:767`) and never sets the apply handler. **MCP readiness is a wiring/service problem, not a greenfield build.**
2. **Plugins are already transport-agnostic.** Every `Subcommand.Run` returns a `plugin.Report` and renders nothing; only `cmd/*` calls renderers or `web.Serve`. The service layer is *latent* — it exists as the closure set injected into `web.ServeOpts`, just not named or deduplicated.
3. **There is no auth/identity model at all.** One shared Bearer token + per-run loopback ingest secret. No users, roles, scopes, API keys, licensing, or tenancy anywhere (`grep` across `internal/ pkg/ cmd/ plugins/` confirms). Everything in the Enterprise column is greenfield; the OSS/Pro gate has no enforcement point yet.

**Implication:** this is a *consolidation + naming* effort over a codebase that is 70% already shaped correctly — not a rewrite. The risk is over-engineering, not under-building.

---

## 1. Architecture Review

### Current layering (as-built)

```
CLI (cobra, cmd/exalm)                    Web (internal/web handlers)        MCP (internal/mcp)
        │  runSubcommand / serve                │  ServeOpts closures               │  tools → empty report
        └───────────────┬───────────────────────┴──────────────┬────────────────────┘
                        ▼                                        ▼
              plugin.Report (canonical hand-off)      ServeOpts closure set  ← the *latent* service layer
                        │                                        │
        ┌───────────────┴───────────────────────────────────────┴───────────────┐
        ▼                          ▼                          ▼                   ▼
  plugin registry          internal/investigate       internal/analyzer      plugins/* (k8s, syslog,
  (14 plugins)             (AI engine: focus→plan→     (map-reduce LLM         httplog, eventlog, iis,
                            collect→evidence→rank→      pipeline)              logs, cloudtrail, dora,
                            confidence→1 LLM call)                             incident, slo, tf, chaos,
                                                                              aws_cost, notify)
        │                          │                                                │
        └──────────────────────────┴── internal/{store(SQLite), convo, changestore, redact, ssh, metrics, config}
```

### What's healthy
- **Plugin contract** (`pkg/plugin/plugin.go:29-58`): clean 4-method interface; central `--apply` mutation gate (`main.go:491-493`); LLM + Redactor injected via `RunArgs`. Adding a capability = one `registry.Register`.
- **The investigation engine** (`internal/investigate`): already a domain service — Profile-driven, transport-free, one redacted LLM call per turn. k8s is the reference impl; 6 log analyzers reuse it.
- **`internal/analyzer`** and **`plugins/incident/actions.go`**: textbook thin-transport-over-reusable-logic. These are the pattern to replicate.
- **`plugin.Report`** is the canonical plugin→core hand-off and feeds all three output renderers + the dashboard mapper.

### What's unhealthy (the actual debt)
- **The service layer is anonymous and duplicated.** It lives as closures rebuilt in three near-identical wirings: `main.go` `runSubcommand` (~559-714), `serve.go` `runServe` (~252-352), `serve_investigate.go` `buildAnalyzerHandlers`. The k8s Converse + incident-history wiring is **copy-pasted verbatim** across `main.go:627-647` and `serve.go:305-325`, with a third structural copy in `serve_investigate.go:129-155`. `GetConversation` is written out 4×; CreatePR wiring is duplicated (`serve.go:468-501` factored, `main.go:682-712` inline copy).
- **Domain logic stranded in HTTP handlers**: timeline 4-source aggregation (`server.go:1155-1253`, even opens its own stores), fix-all ordering policy (`server.go:1465-1526`), `buildDashboard` (~290 lines, `dashboard.go:176-463`), chat export renderers (`chat_export*.go`), `buildTemplateData`, `handleMetricsJSON` magnitude heuristic.
- **Two parallel currencies + a lossy path**: `plugin.Report` for findings, `plugin.Conversation` for chat/exports (never flows through `internal/output`); the terminal renderer drops Evidence/Fixes/Confidence/Investigation (`markdown.go:227`).
- **MCP reaches nothing**: 5 tools over a single in-memory Report; no registry/engine access; empty in the CLI.
- **No auth/identity substrate** for anything past a shared token.

### Verdict
| Layer | State |
|---|---|
| Plugins / capabilities | **Existing, healthy** — transport-agnostic |
| Investigation + analyzer engines | **Existing, healthy** — already services |
| Service layer (named, deduplicated) | **Needs extraction** — latent in ServeOpts closures, triplicated |
| Transport handlers (web) | **Needs refactoring** — several carry domain logic |
| MCP | **Existing skeleton** — needs wiring to real services |
| REST API | **Partial** — the `/api/*` routes ARE a REST-ish API, but ad hoc, unversioned, dashboard-shaped |
| Auth / identity / entitlements | **Missing** — greenfield |
| gRPC | **Missing** — out of scope for now, design must not preclude it |

---

## 2. Existing Capability Inventory

Every capability, its home today, and the single service it should map to (§4). "Currency" = the object it produces.

| Capability | Lives in | Transport(s) today | Currency | Service (target) |
|---|---|---|---|---|
| Analyze log corpus (syslog/httplog/eventlog/iis/logs/cloudtrail) | plugins/* `Run` + `internal/analyzer` | CLI, web attach | Report + LogSession | AnalysisService |
| Investigate k8s / converse (multi-turn) | `internal/investigate` + plugins/k8s | CLI `--open`, web `/chat`, (MCP: no) | Conversation | InvestigationService / ConversationService |
| Search logs (corpus query) | `LogSession.Query`, `serveLogQuery` | web `/logs` | LogQueryResponse | SearchService |
| Surrounding context | `LogSession.Around` (added this session) | web `/logs?around` | LogQueryResponse | SearchService |
| Findings (list/get/summary) | `plugin.Report`, `buildDashboard`, MCP tools | CLI, web, **MCP** | Report/Finding | FindingsService |
| Timeline (cross-signal) | `handleTimelineJSON` (in transport!) | web `/timeline` | TimelineData | TimelineService |
| Evidence chain | `investigate` evidence + `Finding.Evidence` | web (in findings) | EvidenceItem | EvidenceService |
| Confidence / hypotheses ranking | `internal/investigate/{confidence,hypotheses}` | web (in chat) | scores | (part of InvestigationService) |
| Remediation preview | `Finding.Remediation`, `list_remediable` (MCP) | CLI, web, MCP | RemediationAction | RemediationService |
| Execute fix / fix-all | `applyFix`, `handleFixAll`, k8s `ApplyRemediation` | web, MCP (`apply_remediation`, gated) | result | RemediationService (approval-gated) |
| Rollback | `RemediationAction.Rollback` field exists; **no executor** | — | — | RemediationService (missing exec) |
| Generate RCA / postmortem | `plugins/incident/postmortem.go`, chat RCA mode | CLI, web chat | Postmortem/Conversation | ReportService |
| Generate report / export (md/json/html) | `chat_export*.go`, `output.*` | web `/chat/export`, CLI | string | ReportService |
| Health summary | `handleHealthz`, k8s report verdict | web `/healthz` | status | HealthService |
| Describe resource / owner-chain | plugins/k8s collectors | web chat (as evidence) | evidence | (InvestigationService collectors) |
| Correlate resources | k8s graph edges, timeline | web | — | TimelineService / InvestigationService |
| Dashboard summary | `buildDashboard`, registry | web | dashboardPayload | DashboardService |
| DORA metrics | `plugins/dora ComputePublicMetrics` | CLI, web `/dora` | PublicMetrics | MetricsService |
| SLO burn-rate | `plugins/slo` | CLI | Report | (AnalysisService) |
| Incident lifecycle (open/close/list/postmortem) | `plugins/incident` | CLI, web action | Incident | IncidentService |
| Deployment logging | `plugins/dora log-deploy`, TF webhook | CLI, webhook | DeploymentEvent | MetricsService |
| TF plan review / AWS cost / chaos suggest | plugins tf/aws_cost/chaos | CLI | Report | AnalysisService |
| Notify (Slack/webhook) | `plugins/notify Send` | CLI, `--notify-url` | — | NotificationService |
| Token usage accounting | `internal/store/usage`, `usage report` | CLI | — | (MetricsService/admin) |
| Change ledger | `internal/changestore` | web `/changes`, timeline | ChangeEvent | TimelineService |

---

## 3. Refactoring Plan (extraction targets, ranked by value)

Ordered by (duplication removed × domain logic freed), highest first. **Each is behavior-preserving; each ships behind its own commit + tests; the web/CLI keep working identically.**

**R1 — Consolidate the k8s Converse + history-sources wiring.** Highest duplication in the codebase (history-sources ×3, GetConversation ×4, AnalyzeLogLine ×2). Extract one builder that both `runSubcommand` and `runServe` call. *Pure dedup, no behavior change.* (`main.go:622-680`, `serve.go:303-346`, `serve_investigate.go:129-216`.)

**R2 — Extract `buildDashboard` + timeline aggregation + fix-all ordering into services.** Move the ~290-line dashboard mapper (`dashboard.go`), the 4-source timeline merge (`server.go:1155-1253`), and the fix-ordering policy (`server.go:1465-1526`) into a `dashboard`/`timeline`/`remediation` service package. Handlers become decode→call→encode. The timeline extraction also fixes the store-instantiation-in-handler smell (it currently opens `incidentpkg` + `changestore` itself).

**R3 — Extract export renderers.** `conversationMarkdown`/`conversationHTML` + `generatePostmortem` are already pure functions of `Conversation`/`Incident`; move to a `report`/`export` package, collapse the fix-tier partition duplicated ×3 (`chat_export.go:130`, `chat_export_html.go:167`, `k8s/investigate.go:59`).

**R4 — Name the service layer.** Introduce `internal/service` with the interfaces in §4. Initially these **wrap the existing closures/plugins** — thin facades, not reimplementations. CLI, web, and MCP switch to calling services instead of building closures inline.

**R5 — Wire MCP to the services.** Replace the empty-report MCP wiring with the real FindingsService/InvestigationService/SearchService (read-only first). Keep `apply_remediation` behind `--write` + the future approval workflow.

**Not doing (anti-scope):** rewriting the engine, changing `plugin.Report`, adding gRPC, or building auth in this pass. R1–R3 are safe dedup that pay off regardless of what's decided about editions.

---

## 4. Service Layer Design

Principle: **transport carries no business logic**; every interface calls the same service. Services take domain inputs, return domain objects (Report/Conversation/TimelineData/…), never `http` or `cobra` types. They wrap today's engines/plugins — this is a naming + consolidation layer, not new logic.

```
CLI ── Web ── REST ── MCP ── (future gRPC)
                  │
        internal/service  (interfaces below)
                  │
  investigate · analyzer · plugins/* · store · convo · changestore · redact · metrics
```

Proposed interfaces (names match the mandate; each maps to existing code):

- **AnalysisService** — `Analyze(ctx, source, opts) (Report, *Session)`. Wraps plugin `Run` + `internal/analyzer`.
- **InvestigationService** — `Converse(ctx, req) (Conversation)`, `Investigate(ctx, findingID) (Investigation)`, `GetConversation(ctx, id)`. Wraps `internal/investigate` + the R1 builder.
- **ConversationService** — persistence/history over `internal/convo` (may fold into InvestigationService; kept distinct for the Pro "saved investigations" line).
- **SearchService** — `Query(ctx, LogQuery)`, `Around(...)`. Wraps `LogSession`.
- **FindingsService** — `List/Get/Summary/Remediable`. Wraps `plugin.Report`. **This is what MCP read tools should call.**
- **EvidenceService** — evidence retrieval/labeling (from investigate).
- **TimelineService** — `Aggregate(ctx, window)`. Absorbs `handleTimelineJSON` + changestore.
- **RemediationService** — `Preview`, `Apply` (approval-gated), `ApplyAll` (absorbs fix ordering), future `Rollback`.
- **ReportService** — `Markdown/HTML/JSON(conversation|report)`, postmortem, RCA. Absorbs `chat_export*` + `output`.
- **DashboardService** — `Summary(ctx)` → payload. Absorbs `buildDashboard`.
- **MetricsService** — DORA + `internal/metrics` + usage.
- **IncidentService** — lifecycle over `plugins/incident`.
- **HealthService** — readiness/verdict.
- **NotificationService** — `plugins/notify`.

Each service is an interface + a default impl; transports depend on the interface. This is also where entitlement checks (§6) will slot in — one gate per service method, not per handler.

---

## 5. MCP Readiness Design

**Current:** working JSON-RPC server, both transports, 5 tools, `--write` gate, tests — wired to nothing. **Target:** read-only MCP over the real services; execution designed but held behind approval.

### Tool catalogue (read-only first — maps 1:1 to services)
| Tool | Service | Notes |
|---|---|---|
| `list_findings`, `get_finding`, `report_summary`, `list_remediable` | FindingsService | already exist; point at real report |
| `search_logs` | SearchService | new; corpus query |
| `summarize_logs` | AnalysisService | new |
| `investigate` / `continue_investigation` | InvestigationService | multi-turn; needs session state (below) |
| `get_timeline` | TimelineService | new |
| `describe_resource`, `correlate_resources` | InvestigationService | new |
| `generate_rca`, `generate_report`, `export_report` | ReportService | new |
| `health_summary` | HealthService | new |
| `remediation_preview` | RemediationService | read-only preview |
| `execute_fix`, `rollback` | RemediationService | **write — approval-gated, NOT in v1** |

### Design docs the MCP layer needs (to produce, not yet build)
- **Tool definitions**: JSON Schema per tool (the 5 existing ones are the template, `tools.go:18-67`).
- **Permissions**: reuse the `Write:true` flag + `--write`/`ErrCodePermissionDenied` pattern already in `server.go:200-204`. Read tools always on; write tools hidden unless enabled.
- **Authentication**: SSE mode already wraps `web.RequireToken`; stdio inherits process trust. This is where the future entitlement check attaches.
- **Streaming**: current SSE is request/response only (`transport_sse.go:8-11` admits no server→client stream). Long investigations need real streaming — design an SSE notification channel or adopt an MCP SDK. **Documented gap.**
- **Conversation state / investigation sessions**: `internal/convo` (SQLite) already persists multi-turn state keyed by conversation id + fingerprint; MCP `investigate`/`continue_investigation` map onto it directly.
- **Long-running jobs / progress / cancellation**: not present anywhere today. Investigations are synchronous single-LLM-call turns, so v1 MCP can be synchronous. Async job model = a later design (needed before "execute fix" over MCP).
- **Dangerous functionality**: `execute_fix`/`rollback` excluded from v1; when added, gate behind an explicit approval workflow (preview → human approve → execute), never a bare tool call.

---

## 6. OSS vs Pro Matrix (evidence-based)

Reasoning rule: **OSS = individual practitioner value + adoption driver; Pro = team/persistence/scale value; Enterprise = org governance/integration.** Not everything is OSS — the differentiated engine's *outputs* are OSS (adoption), but *persistence, collaboration, and execution at scale* are where willingness-to-pay lives.

| Capability | Edition | Why |
|---|---|---|
| CLI (all `analyze`/`review`/`report` read commands) | **OSS** | Adoption driver; commodity parsing; must be free to win mindshare |
| Core investigation engine (single-shot, ephemeral) | **OSS** | The "wow" that drives adoption; ephemeral = no ops burden for us |
| Basic dashboard (single session, `--open`) | **OSS** | Table stakes vs competitors |
| Basic AI (bring-your-own LLM key, incl. local Ollama) | **OSS** | Cost borne by user; differentiator is the engine, not the model |
| Basic timeline / findings / evidence / recommendations | **OSS** | Read-only insight; commodity |
| Remediation **suggestions** (preview only) | **OSS** | Insight, not action — safe and valuable free |
| MCP **read-only** (findings/search/investigate/report) | **OSS** | Ecosystem adoption; strategic to be the free MCP in every AI IDE |
| Basic reports (md/json/html export) | **OSS** | Individual value |
| **Persistent investigation history / saved investigations** | **Pro** | Requires our storage + is a team memory asset — clear WTP |
| **Multi-dashboard hub (`serve` as a standing service)** | **Pro** | Shifts from tool to platform; team-shared, always-on |
| **Shared dashboards / shared investigations** | **Pro** | Collaboration = team seat value |
| **Execution engine (apply fix / fix-all / rollback)** | **Pro** | Action > insight; the highest-value, highest-risk capability |
| **Approvals / workflow automation** | **Pro** | Team process value |
| **Advanced correlation / advanced timeline / dashboard builder** | **Pro** | Depth features for power teams |
| **Advanced AI (hosted models, higher limits, tuned prompts)** | **Pro** | We bear cost → we charge |
| **Incident lifecycle + DORA at team scale** | **Pro** | Ops-management, not individual debugging |
| MCP **write tools (execute over MCP)** | **Pro** | Same as execution engine; gated |

Rationale note: keeping **read-only MCP + single-shot investigation OSS** is deliberate — it maximizes adoption and makes Exalm the default free AI-ops assistant, while **persistence, collaboration, and execution** (the things a *team* needs and an individual doesn't) carry the paid tier. This is the standard successful open-core line (insight free, action/scale/memory paid).

---

## 7. Enterprise Matrix

All greenfield (no substrate exists today — §0 finding 3).

| Capability | Why Enterprise | Build note |
|---|---|---|
| RBAC (roles/permissions) | Org governance; multi-user | Needs the identity model that doesn't exist yet |
| SSO / OIDC | Enterprise IdP requirement | New auth layer |
| Audit logs | Compliance | `internal/store` can back it; no capture points today |
| Multi-tenancy / workspaces | Org isolation | Deep — touches every service + storage keying |
| Policy engine | Governed automation | Gates RemediationService |
| Auto-remediation (unattended) | Highest-trust action | Only after approvals + policy + audit exist |
| ServiceNow / Jira / Slack / Teams / GitHub Enterprise | Enterprise workflow integration | `plugins/notify` is the seed; rest is new |
| Advanced security (secret scanning depth, compliance packs) | Regulated orgs | Extends `internal/redact` |
| Cluster fleet management | Multi-cluster scale | k8s plugin is single-context today |

Enterprise is a **later phase** — it presupposes the §4 service layer (gate points) and an identity model. Nothing here should be attempted before Pro gating exists.

---

## 8. Migration Plan (incremental, non-breaking)

Each phase = mergeable on its own, `main`/stable untouched, full test sweep green.

- **Phase 0 (this doc):** review + branch. ✅
- **Phase 1 — dedup (R1):** consolidate k8s Converse/history/GetConversation wiring. Pure refactor, behavior-identical, golden tests already pin the chat pipeline.
- **Phase 2 — extract renderers/aggregators (R2, R3):** dashboard, timeline, fix-all, exports → reusable packages. Handlers thin out. Characterization tests assert byte-identical output before/after.
- **Phase 3 — name the service layer (R4):** `internal/service` facades wrapping the above; CLI + web call services. No new behavior.
- **Phase 4 — wire MCP read-only (R5):** MCP tools call FindingsService/SearchService/InvestigationService; `exalm mcp serve` exposes a real report. Add SSE-streaming design doc.
- **Phase 5 — entitlement gate (only after edition decision):** one check per service method; time-boxed trial key first (per the earlier licensing discussion — held pending your go-ahead).
- **Phase 6+ — Enterprise substrate:** identity → RBAC → audit → integrations. Separate track.

Test discipline every phase: `go build ./... && go vet ./... && gofmt -l . && go test ./...` + browser verification for any web-observable change. Golden/characterization tests are the safety net for the pure refactors.

---

## 9. Branch Summary

- **Branch:** `feature/platform-api`, forked from `feature/ops-workspace` (which holds this session's unpushed platform work). Local only — nothing pushed, consistent with the standing "keep everything local" decision.
- **This commit:** adds only `docs/platform-review.md` (this file). **Zero code change.**
- **Intent:** the design home for the service-layer consolidation + MCP-readiness work. Stable behavior is not touched until phases are approved individually.

---

## 10. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Over-engineering — building a service framework heavier than the code needs | **High** | Medium | Services start as thin facades over existing code; extract only the 4 proven-duplicated targets first (R1–R3). Stop if a service has one caller and one impl. |
| Refactor regressions in the chat/investigation pipeline | Medium | High | Golden tests (`converse_golden_test.go`) + characterization tests pin behavior; each phase behavior-identical and separately revertable. |
| MCP streaming gap blocks real MCP use | Medium | Medium | v1 MCP is synchronous read-only (matches today's single-LLM-call model); streaming is a documented, deferred design item. |
| Edition boundary litigated after code is public | Medium | High | Gate points designed into the service layer NOW (one check per method); no push to public until boundary + trial mechanism decided (§6 + prior discussion). |
| Auth greenfield underestimated (Enterprise) | Medium | High | Explicitly deferred to Phase 6; nothing depends on it until then. |
| Two currencies (Report vs Conversation) complicate a uniform service return | Low | Medium | Keep both; ReportService handles the conversion surface. Don't force unification. |
| Scope creep from the capability list into premature Pro/Enterprise builds | **High** | Medium | This doc's phase gates: nothing past Phase 4 starts without an explicit edition decision. |
| Divergence from stable `main` while this branch is long-lived | Medium | Medium | Keep phases small and mergeable; rebase on stable frequently; the pure-dedup phases can land first to shrink the diff. |

---

## Recommendation

Approve **Phases 1–4 only** (dedup + extraction + service naming + read-only MCP wiring) as the initial scope. These are behavior-preserving, independently valuable regardless of the edition decision, and turn the *latent* service layer into a real one — which is the actual prerequisite for both MCP and any future OSS/Pro gate. Hold Phase 5 (entitlements) and Phase 6 (Enterprise) until the edition boundary and trial model from the earlier discussion are decided.

No code will be written until this review is approved.
