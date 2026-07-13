# Handoff — AI Investigation Framework & Dashboard Platform

This file exists so a fresh Claude Code session (on any machine) can pick up this
work with full context, without needing the original chat transcript. If you are
that fresh session: read this file, then `ARCHITECTURE.md` for the technical
design, then jump straight into whatever's in "Next steps" below.

Branch: `feat/ai-investigation-chat` (not yet pushed to `origin` as of this
writing — confirm with `git log origin/main..HEAD` before assuming it's remote).

---

## What this branch built

Two back-to-back efforts, in order:

### 1. Generic AI Investigation Framework (commits `ea342e5` .. `ee57fd6`)

Exalm's Kubernetes plugin had a conversational "AI Operations Copilot" (chat,
evidence-gathering, root cause hypotheses, confidence scoring, remediation
tiers, timelines, follow-ups, memory). This phase extracted that into a
**generic framework** (`internal/investigate`) and rolled it out to every log
analyzer — `syslog`, `httplog`, `eventlog`, `iis`, `logs` — so all six analyzers
(including k8s) now share one investigation engine. k8s is the reference
implementation; each analyzer supplies only a `Profile` (symptom catalog,
collectors, confidence rules, prevention advice, prompts).

Key pieces:
- `internal/investigate/engine.go` — the per-turn pipeline (deterministic plan
  → collectors → hypothesis ranking → confidence scoring → **one** redacted
  LLM call → persisted transcript). The LLM never picks collectors.
- `internal/investigate/logsession.go` — bounded in-memory parsed corpus per
  analysis run, feeds both collectors and the dashboard.
- `internal/ssh/diagnostics.go` — the **only** path to remote command
  execution: a fixed, reviewed, read-only allowlist, tier-gated
  (`off`/`readonly`/`full` via `--remote-diag` / `EXALM_REMOTE_DIAG`).
- `plugins/{syslog,httplog,eventlog,iis,logs}/profile.go` — one per analyzer,
  each with `profile_test.go` (Validate, symptom matching, plan ordering, a
  full deterministic Converse turn, redaction guard, diag-unavailable guard).
- `cmd/exalm/serve_investigate.go` — wires an analyzer's session+profile into
  the web dashboard (`--open` flag).

Full details + the original design rationale: see the "Investigation
framework" section in `ARCHITECTURE.md`.

### 2. Modular Dashboard Platform (commits `9ee7bd4` .. `b7de92b`)

Redesigned the web UI from "a k8s dashboard that can borrow one analyzer" into
a plugin-registered platform, Grafana-style:

- **`internal/settings`** — persisted dashboard preferences
  (`~/.exalm/settings.json`): enable/disable per dashboard + Enable All + a
  global AI-features toggle. `GET/PUT /api/settings`.
- **`internal/web/dashboards.go`** — the dashboard registry (`DashboardDesc` /
  `WidgetDesc`). Platform built-ins (k8s, DORA, Timeline, Incidents) plus one
  descriptor per analyzer plugin, each with a data-backed widget table.
  `GET /api/dashboards`. The SPA sidebar builds itself from this — no more
  hardcoded nav.
- **`internal/web/static/widgets.js`** — one shared chart library (merged what
  used to be two parallel vocabularies). Every drillable chart offers "Show
  related logs" and "✦ Investigate" (seeds the AI chat with the clicked
  slice).
- **`internal/web/{sessions,ingest}.go`, `cmd/exalm/serve_hub.go`** — the
  **multi-dashboard hub**. `exalm serve` now hosts every dashboard in one
  process. Analyzer `--open` runs discover a running hub via
  `~/.exalm/hub.json` (random per-run secret, 0600, removed on shutdown),
  probe `/healthz` for `"hub":true`, then POST their parsed corpus as an
  explicit `SessionSnapshot` to `/api/ingest/session` (loopback-only,
  secret-gated, size-capped). The hub reconstructs a full investigation
  engine from the plugin registry, so chat/drilldown/stats on attached
  sessions run the real pipeline. **Any attach failure falls back to the
  analyzer's own local server** — this is not a hard dependency.
- Scoped routes `/api/dashboards/{id}/{stats,logs,chat,logs/analyze}`, with
  the old `/api/analyzer/*` and `/api/chat` routes kept as byte-identical
  legacy aliases.

Full details: see "Dashboard platform" section in `ARCHITECTURE.md`.

---

## Standing rules (do not violate these)

These were established early and held throughout — keep holding them:

1. **Redaction before LLM is non-negotiable.** Every byte sent to an LLM
   passes through `Redactor.Redact()` first. `Redact()` must never return an
   error (best-effort redaction, never a hard failure).
2. **No agentic LLM tool-use loop.** Exactly one redacted LLM call per
   conversation turn. The LLM narrates gathered evidence; it never chooses
   collectors, commands, or files to read.
3. **Remote commands only from the fixed SSH allowlist**
   (`internal/ssh/diagnostics.go`), tier-gated, with the single parameterized
   slot validated by a strict regex — refused, never sanitized, on any
   deviation. Ingested (hub-attached) sessions never carry SSH credentials
   (`RemoteParams.Password` is `json:"-"`), so they run without remote
   diagnostics by design — this is intentional, not a bug.
4. **No secrets/credentials ever collected** beyond existence/type/age
   metadata.
5. **No new Go module dependencies** without justification; stdlib-first.
   Frontend stays vanilla JS, no build step, no framework.
6. **Don't push to `origin` without being asked.** All work so far is local
   commits only.
7. **Windows test-server cleanup**: `pkill -f` doesn't reliably kill
   background Go server processes spawned via Git Bash on Windows. Use
   `netstat -ano | grep 7433` to find the real PID, then
   `taskkill //F //PID <pid>`.

---

## Known gap (tracked, not yet fixed)

`analyze --output web` / `--open` does **not** wire `--token`/`EXALM_TOKEN`
into the dashboard's auth middleware — it serves unauthenticated even when a
token is set, printing a "running WITHOUT authentication" warning. Confirmed
via `git log -S` that this predates all of this work (introduced at the
initial public release commit `f9fabfc`) and equally affects
`k8s analyze --output web`. The proper `exalm serve --token` path IS wired
correctly. Fix: read `--token`/`EXALM_TOKEN` in the `analyze --output web`
code path in `cmd/exalm/main.go` (mirror what `cmd/exalm/serve.go` already
does) and set `serveOpts.Token`. Low priority for solo local use; matters
before exposing the dashboard beyond localhost.

---

## How to verify everything still works

```sh
go build ./... && go vet ./... && go test ./... && gofmt -l .   # must be empty
node --check internal/web/static/*.js                            # all pass
```

Live smoke test (mock LLM, no API key needed):
```sh
export EXALM_LLM_PROVIDER=mock
go build -o bin/exalm ./cmd/exalm

# Terminal 1: the hub
./bin/exalm serve --no-k8s --open-browser=false

# Terminal 2: attach analyzers
./bin/exalm syslog analyze --file examples/syslog/messages.log --open
./bin/exalm httplog analyze --file examples/httplog/nginx-access.log --open
./bin/exalm eventlog summarize --file examples/eventlog/security-4625.json --open
./bin/exalm iis analyze --file examples/iis/u_ex.log --open
./bin/exalm logs summarize --file examples/oom-loop.log --open

curl -s http://localhost:7433/api/dashboards   # all 5 analyzers should show "live":true
```
Then open `http://localhost:7433` in a browser and click through the sidebar.

---

## Next steps (pick up here)

Nothing is currently in-progress — the plan (`D1`–`D5` in the dashboard
platform redesign) finished cleanly. Reasonable next directions, roughly in
priority order:

1. **Fix the token gap above** — it's the most concrete known issue.
2. **Extend widget data sources** — the current widget tables are
   "data-backed only" by deliberate scope decision (no geo/user-agent/
   live-gauge placeholders). If real demand shows up, extend the relevant
   analyzer's parser + stats struct first, then add the widget.
3. **Incidents dashboard is read-only v1** (`GET /api/dashboards/incidents/stats`
   just lists records). Could grow open/close actions, links to related
   analyzer dashboards, etc.
4. **Cloud plugins** (AWS/Azure/VMware/Fortigate/PostgreSQL/SQL
   Server/Docker) were mentioned as future targets for the same framework —
   the plugin contract in `CLAUDE.md`-equivalent docs (`ARCHITECTURE.md`,
   "The plugin contract" section) plus `investigate.Profile` is the pattern
   to follow; no engine changes should be needed.
5. **Push the branch** once you're ready to open a PR — ask the user first.

If picking any of these up, follow the existing repo conventions: Go 1.26+,
`gofmt -s`/`goimports`, Conventional Commits, hermetic tests, one concern per
commit, full verification sweep before calling anything done.
