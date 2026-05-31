# Exalm Testing Guide

This guide covers three areas added in `feat/phase-2-observability`:

1. [Kubernetes cluster test scenarios](#kubernetes-cluster-test-scenarios)
2. [MCP server testing](#mcp-server-testing)
3. [SLO engine testing](#slo-engine-testing)

---

## Kubernetes cluster test scenarios

### Prerequisites

```bash
# Start minikube with enough resources for the advanced scenarios
minikube start --cpus=4 --memory=8192 --driver=docker

# (Optional) Enable metrics-server for HPA scenarios
minikube addons enable metrics-server

# Build the binary
go build -o bin/exalm.exe ./cmd/exalm
```

### Scenario set A — basic multi-namespace (already exists)

Covers: CrashLoopBackOff, ImagePullBackOff, PVC Pending, selector mismatch,
unschedulable pods, suspended CronJobs, ghost services.

```bash
kubectl apply -f examples/k8s/multi-namespace-workloads.yaml

# Wait ~60s for failures to materialise
./bin/exalm.exe k8s analyze \
  --namespaces exalm-prod,exalm-staging,exalm-data \
  --output web

# Open http://localhost:7433
```

**Expected findings:** 8–12 findings across critical/high/medium.

### Scenario set B — advanced failures (new)

Covers: OOMKilled, init-container deadlock, sidecar crash (multi-container),
CPU throttle, termination stuck, ResourceQuota exhausted, RBAC denial,
node-selector mismatch, toleration mismatch, StatefulSet rolling update stuck,
HPA metrics unknown, PodDisruptionBudget violation, wrong liveness probe port,
ephemeral-storage eviction.

```bash
kubectl apply -f examples/k8s/advanced-test-scenarios.yaml

# Wait 90s — OOMKill and init-deadlock take ~30s each to enter their loops
./bin/exalm.exe k8s analyze \
  --namespaces exalm-adv-a,exalm-adv-b,exalm-adv-c \
  --output web
```

**Expected findings per namespace:**

| Namespace | Scenario | Expected finding |
|-----------|----------|-----------------|
| exalm-adv-a | memory-hog | OOMKilled — critical |
| exalm-adv-a | init-deadlock | Init:CrashLoopBackOff — high |
| exalm-adv-a | sidecar-crashloop | Container log-shipper crash — high |
| exalm-adv-a | cpu-throttle-canary | CPU throttle / low request — medium |
| exalm-adv-a | termination-stuck | Pod stuck Terminating — medium |
| exalm-adv-b | quota-buster | ResourceQuota exceeded — high |
| exalm-adv-b | secret-lister | RBAC forbidden (403) — high |
| exalm-adv-b | gpu-workload | Unschedulable nodeSelector — high |
| exalm-adv-b | taint-required | Unschedulable affinity — high |
| exalm-adv-c | message-queue | StatefulSet update stuck — high |
| exalm-adv-c | autoscaled-api-hpa | HPA metrics unknown — medium |
| exalm-adv-c | zero-disruption-pdb | PDB blocks disruption — medium |
| exalm-adv-c | wrong-probe-port | Liveness restart loop — medium |
| exalm-adv-c | log-flood | Ephemeral storage eviction — high |

### Run all scenarios together

```bash
kubectl apply -f examples/k8s/multi-namespace-workloads.yaml
kubectl apply -f examples/k8s/advanced-test-scenarios.yaml

./bin/exalm.exe k8s analyze \
  --namespaces exalm-prod,exalm-staging,exalm-data,exalm-adv-a,exalm-adv-b,exalm-adv-c \
  --output web
```

### Seed the change store to test correlation

The change-correlation engine reads `~/.exalm/changes.jsonl`. Seed it to see
"Likely caused by deploy X minutes ago" badges on findings in the dashboard.

```bash
mkdir -p ~/.exalm

# Simulate a deployment 20 minutes ago to exalm-adv-a
cat >> ~/.exalm/changes.jsonl << 'EOF'
{"id":"abc12345abcd1234","kind":"Deployment","namespace":"exalm-adv-a","name":"memory-hog","action":"updated","actor":"alice","old_rev":"100","new_rev":"101","diff_url":"","timestamp":"2026-05-20T09:00:00Z"}
{"id":"def56789def56789","kind":"Deployment","namespace":"exalm-adv-c","name":"message-queue","action":"updated","actor":"ci-bot","old_rev":"55","new_rev":"56","diff_url":"https://github.com/org/repo/commit/abc","timestamp":"2026-05-20T09:10:00Z"}
EOF

# Re-run analysis — change timeline and LikelyCause badges should appear
./bin/exalm.exe k8s analyze --namespaces exalm-adv-a,exalm-adv-c --output web
```

### Clean up

```bash
kubectl delete namespace exalm-prod exalm-staging exalm-data 2>/dev/null
kubectl delete namespace exalm-adv-a exalm-adv-b exalm-adv-c 2>/dev/null
```

---

## MCP server testing

The MCP server (`exalm mcp serve`) implements JSON-RPC 2.0 over two transports.
Both transports use the same `Server.Handle(reqBytes)` dispatch path.

### Step 1 — generate a report first

The MCP server exposes whatever `plugin.Report` was loaded into it. Run a k8s
analysis and save the JSON output, then pass it to the MCP server.

```bash
# Option A: analyze against a live cluster (preferred)
./bin/exalm.exe k8s analyze \
  --namespaces exalm-adv-a,exalm-adv-b,exalm-adv-c \
  --output json > /tmp/exalm-report.json

# Option B: use a fixture snapshot (no cluster needed)
./bin/exalm.exe k8s analyze \
  --snap examples/k8s/advanced-test-scenarios.snap \   # if snapshot file exists
  --output json > /tmp/exalm-report.json
```

### Step 2a — stdio transport (default)

The stdio transport reads newline-delimited JSON-RPC requests from stdin and
writes responses to stdout. Each request is one line.

```bash
# Pipe a single initialize request
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n' \
  | ./bin/exalm.exe mcp serve

# Expected response (one line):
# {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"exalm","version":"..."}}}
```

```bash
# List all available tools
printf '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' \
  | ./bin/exalm.exe mcp serve
```

```bash
# Call list_findings filtered to critical severity
printf '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_findings","arguments":{"severity":"critical"}}}\n' \
  | ./bin/exalm.exe mcp serve
```

```bash
# Multi-request session using a here-doc (requests processed sequentially)
./bin/exalm.exe mcp serve << 'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"report_summary","arguments":{}}}
EOF
```

```bash
# Test with --write enabled (apply_remediation tool becomes visible)
printf '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' \
  | ./bin/exalm.exe mcp serve --write
# apply_remediation should appear in the tools list
```

### Step 2b — SSE transport

The SSE transport accepts HTTP POST requests and returns `text/event-stream`
responses. Start it in one terminal, query from another.

```bash
# Terminal 1 — start SSE server
./bin/exalm.exe mcp serve --sse :7434

# Terminal 2 — initialize
curl -s -X POST http://localhost:7434/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

# Terminal 2 — list findings with severity filter
curl -s -X POST http://localhost:7434/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":2,"method":"tools/call",
    "params":{
      "name":"list_findings",
      "arguments":{"severity":"high","namespace":"exalm-adv-a"}
    }
  }'

# Terminal 2 — get a specific finding by ID (replace ID from list_findings output)
curl -s -X POST http://localhost:7434/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_finding","arguments":{"id":"<FINDING_ID>"}}}'

# Terminal 2 — report summary
curl -s -X POST http://localhost:7434/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"report_summary","arguments":{}}}'
```

### Step 2c — write tools (apply_remediation)

```bash
# Start with --write to unlock the apply_remediation tool
./bin/exalm.exe mcp serve --sse :7434 --write

# List remediable findings first
curl -s -X POST http://localhost:7434/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_remediable","arguments":{}}}'

# Apply a specific remediation (get the action_id from list_remediable output)
curl -s -X POST http://localhost:7434/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"apply_remediation","arguments":{"action_id":"<ACTION_ID>"}}}'
```

### Step 3 — Claude Desktop integration

Add to `~/.config/claude/claude_desktop_config.json` (macOS/Linux) or
`%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "exalm": {
      "command": "C:/path/to/bin/exalm.exe",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

Restart Claude Desktop. In a new conversation ask:
- "List all critical findings in the exalm-adv-a namespace"
- "Show me the evidence chain for the OOMKilled finding"
- "What is the current report summary?"

### Step 4 — automated round-trip test

The `internal/mcp/server_test.go` already covers round-trip for all read tools.
Run it in isolation:

```bash
go test ./internal/mcp/... -v -run TestServer
```

---

## SLO engine testing

### Quickstart — no cluster needed

```bash
# Healthy SLOs (synthesized samples — no errors, all green)
./bin/exalm.exe slo check --file examples/slo/specs.json

# Slow burn (~0.15% error rate, warn tier)
./bin/exalm.exe slo check \
  --file examples/slo/specs.json \
  --samples examples/slo/samples-slowburn.json

# Original burning scenario (checkout-api ~2% error rate in 6 samples)
./bin/exalm.exe slo check \
  --file examples/slo/specs.json \
  --samples examples/slo/samples-burning.json

# Fast burn (~2% error rate sustained — all three windows triggered)
./bin/exalm.exe slo check \
  --file examples/slo/specs.json \
  --samples examples/slo/samples-fastburn.json

# AI narrative report (requires --provider)
./bin/exalm.exe slo report \
  --file examples/slo/specs.json \
  --samples examples/slo/samples-fastburn.json \
  --provider claude
```

### Understanding the burn rate output

Each SLO spec is checked against three windows using the Google SRE Workbook §5 pattern:

| Window | Threshold multiplier | Alert tier | Meaning |
|--------|---------------------|------------|---------|
| 1h     | 14.4×               | page       | Budget exhausted in ~2 days at this rate |
| 6h     | 6×                  | ticket     | Budget exhausted in ~5 days |
| 72h    | 1×                  | warn       | Budget exhausted within the SLO window |

For a 99.9% SLO (allowed error rate = 0.1%):

| Observed error rate | 1h mult | 6h mult | Tiers triggered |
|--------------------|---------|---------|-----------------|
| 0.05% (healthy)    | 0.5×    | 0.5×    | none |
| 0.15% (slow burn)  | 1.5×    | 1.5×    | warn (72h) |
| 0.6% (medium burn) | 6×      | 6×      | ticket + warn |
| 2% (fast burn)     | 20×     | 20×     | page + ticket + warn |

### Write a custom SLO spec

```json
[
  {
    "name": "my-api-availability",
    "service": "my-api",
    "namespace": "production",
    "window": "30d",
    "objective": 0.999,
    "sli": {
      "good_query": "sum(rate(http_requests_total{job=\"my-api\",status!~\"5..\"}[5m]))",
      "total_query": "sum(rate(http_requests_total{job=\"my-api\"}[5m]))"
    }
  }
]
```

Then provide sample data:

```json
{
  "my-api-availability": [
    {"at": "2026-05-20T09:00:00Z", "good": 99, "total": 100},
    {"at": "2026-05-20T09:10:00Z", "good": 98, "total": 100}
  ]
}
```

The `at` timestamps, `good` (successful requests), and `total` (all requests)
fields are the only three values the engine needs. The `SLI` query fields are
recorded for documentation; they are not executed by `slo check` (they are used
when wiring a real Prometheus scraper in `collect.go`).

### Run the unit tests

```bash
# Run all SLO tests with verbose output
go test ./plugins/slo/... -v

# Run just the burn-rate engine tests
go test ./plugins/slo/... -v -run TestComputeMultiWindow
go test ./plugins/slo/... -v -run TestWorstTier

# Run with race detector
go test -race ./plugins/slo/...
```

### Wire real Prometheus data (optional)

When you have a Prometheus endpoint, modify `plugins/slo/collect.go` to run the
`good_query` and `total_query` and populate `[]Sample` from the result. The
engine in `burnrate.go` is backend-agnostic and accepts any `[]Sample` slice.

Example Prometheus instant query (in `collect.go`):

```go
// GET /api/v1/query?query=<good_query>&time=<unix>
// Response: {"data":{"result":[{"value":[<ts>,"<float>"]}]}}
// Parse float → Sample.Good ; run same for total_query → Sample.Total
```

---

## Full validation checklist

Run all of the following before opening a PR from `feat/phase-2-observability`:

```bash
# 1. Unit tests
go test ./... -count=1

# 2. Race detector
go test -race ./... -count=1

# 3. Build
go build -o bin/exalm.exe ./cmd/exalm

# 4. Vet
go vet ./...

# 5. SLO smoke test (no cluster)
./bin/exalm.exe slo check --file examples/slo/specs.json --samples examples/slo/samples-fastburn.json

# 6. MCP smoke test (no cluster)
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n' | ./bin/exalm.exe mcp serve

# 7. K8s analysis (requires minikube with scenarios deployed)
kubectl apply -f examples/k8s/advanced-test-scenarios.yaml
sleep 90
./bin/exalm.exe k8s analyze \
  --namespaces exalm-adv-a,exalm-adv-b,exalm-adv-c \
  --output web \
  --provider claude

# 8. Open http://localhost:7433 and verify:
#    - Status bar shows health percentage
#    - Change timeline appears if ~/.exalm/changes.jsonl is seeded
#    - Filter buttons work
#    - Evidence section expands per finding
#    - Fix modal opens and shows correct kubectl command
```
