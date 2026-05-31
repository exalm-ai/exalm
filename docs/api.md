# HTTP API reference

The Exalm web dashboard (`exalm serve`) exposes a REST API on
`http://localhost:7433` (default). All endpoints return JSON or HTML.

---

## Authentication

When `--token` (or `EXALM_TOKEN`) is set, every request except `/healthz`
and `/metrics` must include a valid Bearer token:

```
Authorization: Bearer <token>
```

Alternatively, pass the token as a query parameter (convenient for browser
links):

```
http://localhost:7433/api/report?token=<token>
```

Requests without a valid token receive `401 Unauthorized`.

`/healthz` and `/metrics` are intentionally public to support Kubernetes
liveness probes and Prometheus scraping without credentials.

---

## Base URL

```
http://localhost:7433
```

Override the port with `--port` or the bind address with `--bind`.

---

## Endpoints

### `GET /`

Returns the main findings dashboard as an HTML page.

**Auth**: required (if token set)

**Response**: `text/html` — rendered Bubble-Tea–style dashboard with findings
table, severity breakdown, and (when `--apply` is configured) remediation
buttons.

---

### `GET /timeline`

Returns the cross-signal correlation timeline as an HTML page with an SVG
swimlane chart. Three swimlanes: **K8s Findings**, **IaC Changes**,
**Incidents**. Auto-refreshes every 30 seconds.

**Auth**: required (if token set)

**Response**: `text/html`

---

### `GET /dora`

Returns the DORA four-key metrics dashboard as an HTML page.

**Auth**: required (if token set)

**Response**: `text/html` — four metric cards (Deployment Frequency, Lead
Time for Changes, Change Failure Rate, MTTR) plus a deployments table.

---

### `GET /api/report`

Returns the current analysis report as JSON.

**Auth**: required (if token set)

**Response**: `200 OK`, `application/json`

```json
{
  "title": "Kubernetes cluster analysis",
  "summary": "3 critical findings in namespace production.",
  "findings": [
    {
      "severity": "critical",
      "category": "pod",
      "detail": "payments-api has been CrashLoopBackOff for 14 minutes.",
      "suggestion": "Check resource limits and recent image changes.",
      "source_host": "k8s://production/payments-api",
      "source_platform": "kubernetes"
    }
  ],
  "raw": "# Kubernetes cluster analysis\n\n..."
}
```

**Polling**: Poll this endpoint to detect when watch mode delivers a new
report. The response body changes when the report updates.

---

### `POST /api/fix`

Applies a single remediation action.

**Auth**: required (if token set)

**Requires**: `--apply` semantics must be configured on server start
(the `ApplyFix` callback must be set). Returns `501 Not Implemented` if not.

**Request body**: `application/json`

```json
{
  "id": "restart-payments-api",
  "kind": "restart_deployment",
  "namespace": "production",
  "resource": "payments-api"
}
```

The `id`, `kind`, `namespace`, and `resource` fields match the
`plugin.RemediationAction` returned in the report's finding.

**Response**: `200 OK`

```json
{"ok": true}
```

**Error response**: `500 Internal Server Error`

```json
{"error": "failed to restart deployment: ..."}
```

---

### `POST /api/fix-all`

Applies all auto-fixable remediation actions in the current report.

**Auth**: required (if token set)

**Requires**: `ApplyFix` callback configured.

**Request body**: empty

**Response**: `200 OK`

```json
{"applied": 3, "failed": 0}
```

**Error response**: `500 Internal Server Error`

```json
{"error": "...", "applied": 1, "failed": 2}
```

---

### `POST /api/create-pr`

Creates a GitHub Pull Request containing the suggested fix for the current
report.

**Auth**: required (if token set)

**Requires**: `GITHUB_TOKEN` and `GITHUB_REPO` configured; `CreatePR`
callback set on server start.

**Request body**: empty

**Response**: `200 OK`

```json
{"url": "https://github.com/myorg/myrepo/pull/42"}
```

**Error response**: `500 Internal Server Error`

```json
{"error": "failed to create PR: ..."}
```

---

### `GET /api/changes`

Returns IaC change events as JSON. Change events are collected from ArgoCD
Application syncs, Helm release history, and Terraform Cloud webhooks.

**Auth**: required (if token set)

**Response**: `200 OK`, `application/json`

```json
[
  {
    "at": "2026-05-27T10:14:00Z",
    "kind": "argocd_sync",
    "app": "payments",
    "revision": "abc1234",
    "status": "Succeeded"
  },
  {
    "at": "2026-05-27T09:55:00Z",
    "kind": "helm_upgrade",
    "release": "nginx-ingress",
    "namespace": "ingress",
    "chart_version": "4.10.0"
  },
  {
    "at": "2026-05-27T09:30:00Z",
    "kind": "terraform_apply",
    "workspace": "production",
    "run_id": "run-XYZ",
    "status": "applied"
  }
]
```

Returns `[]` when no change events have been recorded.

---

### `GET /api/timeline`

Returns the full cross-signal timeline as JSON. Suitable for building
custom visualisations.

**Auth**: required (if token set)

**Response**: `200 OK`, `application/json`

```json
{
  "generated_at": "2026-05-27T10:20:00Z",
  "snapshots": [
    {
      "collected_at": "2026-05-27T10:14:00Z",
      "report": { /* plugin.Report — same shape as /api/report */ }
    }
  ],
  "changes": [ /* same shape as /api/changes */ ],
  "incidents": [
    {
      "id": "INC-2026-0042",
      "severity": "sev2",
      "title": "payments-api latency spike",
      "opened_at": "2026-05-27T09:50:00Z",
      "closed_at": "2026-05-27T10:10:00Z",
      "status": "closed"
    }
  ]
}
```

---

### `GET /api/dora`

Returns DORA four-key metrics as JSON.

**Auth**: required (if token set)

**Query parameters**:

| Parameter | Default | Description |
|---|---|---|
| `days` | `30` | Window size in days |

**Response**: `200 OK`, `application/json`

```json
{
  "window_days": 30,
  "deployment_frequency": {
    "value": 4.2,
    "unit": "per_day",
    "rating": "elite",
    "label": "Elite"
  },
  "lead_time_for_changes": {
    "value": 18.5,
    "unit": "hours",
    "rating": "high",
    "label": "High"
  },
  "change_failure_rate": {
    "value": 0.05,
    "unit": "fraction",
    "rating": "elite",
    "label": "Elite"
  },
  "mean_time_to_restore": {
    "value": 22.0,
    "unit": "minutes",
    "rating": "elite",
    "label": "Elite"
  },
  "deployments": [
    {
      "id": "DEP-2026-0123",
      "deployed_at": "2026-05-27T09:30:00Z",
      "duration_seconds": 145,
      "outcome": "success",
      "commit_sha": "abc1234",
      "lead_time_hours": 12.5
    }
  ]
}
```

**Rating values**: `elite` / `high` / `medium` / `low` — aligned with the
2023 DORA State of DevOps report band thresholds.

---

### `GET /healthz`

Kubernetes liveness probe endpoint. Always public (no auth required).

**Response**: `200 OK`, `application/json`

```json
{"status": "ok", "uptime_seconds": 3600}
```

---

### `GET /metrics`

Prometheus text-format metrics endpoint. Always public (no auth required)
to support Prometheus scraping without credentials.

**Response**: `200 OK`, `text/plain; version=0.0.4`

```
# HELP exalm_report_count Total number of reports generated since startup.
# TYPE exalm_report_count counter
exalm_report_count 14

# HELP exalm_uptime_seconds Seconds since the dashboard started.
# TYPE exalm_uptime_seconds gauge
exalm_uptime_seconds 3600
```

---

### `GET /static/*`

Serves embedded CSS and JavaScript assets for the dashboard UI. Auth
required (if token set).

---

## Error format

All API endpoints (`/api/*`) return errors as JSON:

```json
{"error": "human-readable description of what went wrong"}
```

HTTP status codes follow standard semantics:

| Code | Meaning |
|---|---|
| `200` | Success |
| `401` | Missing or invalid Bearer token |
| `404` | Route not found |
| `405` | Wrong HTTP method |
| `500` | Internal server error (LLM call failed, k8s API error, etc.) |
| `501` | Feature not configured (e.g. `ApplyFix` callback not set) |

---

## Example: full curl workflow

```sh
# Set your token
TOKEN=$(openssl rand -hex 32)

# Start the dashboard (in another terminal)
exalm serve --token $TOKEN

# Fetch the current report
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:7433/api/report | jq .

# Check DORA metrics for the last 14 days
curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:7433/api/dora?days=14" | jq .

# List IaC changes
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:7433/api/changes | jq .

# Health check (no auth needed)
curl -s http://localhost:7433/healthz

# Prometheus metrics (no auth needed)
curl -s http://localhost:7433/metrics
```

---

## Terraform Cloud webhook

`exalm webhook terraform` starts a separate HTTP listener (default port 9000)
that receives Terraform Cloud workspace events, verifies the HMAC-SHA512
signature, and records successful applies as DORA deployment events.

```sh
exalm webhook terraform --port 9000 --secret $TF_WEBHOOK_SECRET
```

Configure in Terraform Cloud: **Settings → Notifications → Webhook** with
URL `https://your-host:9000/webhook/terraform` and the same HMAC secret.

This webhook listener is **separate** from the dashboard server. It does not
expose dashboard routes and has no authentication beyond the HMAC verification.

**Supported event types**: `run:applied` (recorded as a deployment),
`run:errored` (recorded as a failed deployment).

**Replay protection**: webhook events are deduplicated by Terraform run ID.
A missing `X-TFE-Notification-Signature` header causes an immediate `403`.
