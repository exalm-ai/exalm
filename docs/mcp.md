# MCP usage guide

Exalm ships a built-in [Model Context Protocol](https://modelcontextprotocol.io)
server that exposes its diagnostic findings and remediation actions as
structured tools any MCP-compatible LLM agent (Claude Desktop, etc.) can call.

The server is hand-rolled JSON-RPC 2.0 (protocol `2024-11-05`), supports both
**stdio** (default) and **SSE/HTTP** transports, and reuses the exact same
service layer the web dashboard and CLI use — so a finding you see in the
dashboard is the finding the MCP tools return.

## Tools

| Tool | Kind | Description |
|---|---|---|
| `list_findings` | read | All findings, optionally filtered by `severity`, `category`, or `namespace` |
| `get_finding` | read | One finding by exact `title`, with its evidence chain |
| `report_summary` | read | Report title, summary, and severity counts |
| `list_remediable` | read | Only findings that have an attached remediation action |
| `apply_remediation` | **write** | Apply the remediation attached to a finding — requires `--write` |

Read tools are always available. `apply_remediation` is hidden entirely
unless the server was started with `--write`.

---

## Step 1 — Build

```bash
go build -o bin/exalm.exe ./cmd/exalm
```

## Step 2 — Produce a report to serve

The MCP read tools operate over a `plugin.Report`. Generate one from a live
cluster:

```bash
exalm k8s analyze --output json > report.json
```

> **Note:** Only the **k8s** plugin currently emits structured `findings`
> (with attached `remediation`). The log analyzers (syslog, httplog, etc.)
> emit a narrative report — `report_summary` will return their title/summary,
> but `list_findings` will be empty until those plugins populate structured
> findings.

You can start without a report; the read tools then return an empty surface
and `report_summary` says plainly that no report is loaded.

## Step 3 — Serve over stdio (read-only)

stdio mode reads one JSON-RPC request per line on stdin and writes one
response per line on stdout. Quick smoke test:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | ./bin/exalm.exe mcp serve --file report.json
```

Call a tool:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_findings","arguments":{"severity":"critical"}}}' \
  | ./bin/exalm.exe mcp serve --file report.json
```

## Step 4 — Connect Claude Desktop

Add to `claude_desktop_config.json` (read-only):

```json
{
  "mcpServers": {
    "exalm": {
      "command": "/absolute/path/to/bin/exalm.exe",
      "args": ["mcp", "serve", "--file", "/absolute/path/to/report.json"]
    }
  }
}
```

Restart Claude Desktop; the `exalm` tools appear in the tool picker.

## Step 5 — Enable remediation (write mode)

`--write` unhides `apply_remediation` **and** connects the k8s remediation
executor — the same `ApplyRemediation` the web dashboard's "Apply fix" button
uses. It's wired via standard kubeconfig discovery:

```bash
exalm mcp serve --write --file report.json
# or point at a specific cluster:
exalm mcp serve --write --file report.json --kubeconfig ~/.kube/config --context prod-eks
```

On startup you'll see one of:

- `⬡ MCP write mode: k8s remediation executor connected — apply_remediation is live.`
- `⚠️  MCP write mode: <error> — apply_remediation will report "not configured" until a kubeconfig is available.`

The second is a **graceful degradation**: read tools still work with no
cluster at all; only `apply_remediation` is inert until a kubeconfig exists.
Building the client does **not** dial the cluster — the connection is made
only when a fix is actually applied.

For Claude Desktop, add the flags to `args`:

```json
"args": ["mcp", "serve", "--write", "--file", "/path/report.json", "--kubeconfig", "/path/.kube/config"]
```

### Safety model

- `apply_remediation` is **denied** (`-32001 permission denied`) unless
  `--write` was passed at startup — mirroring the CLI's `--apply` gate.
- Only findings that carry a remediation action can be applied; everything
  else returns "finding has no remediation".
- The executor supports the k8s remediation kinds (`rollout-restart`,
  `resume-cronjob`, `delete-pod`, `patch-resource`, `scale-deployment`,
  `add-limits`, `label-resource`, `cordon-node`).

## Step 6 — SSE / HTTP transport

For running Exalm as a long-lived sidecar instead of a child process:

```bash
exalm mcp serve --sse :7434 --file report.json --token "$EXALM_TOKEN"
```

Every request must carry the bearer token:

```bash
curl -X POST http://localhost:7434/mcp \
  -H "Authorization: Bearer $EXALM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"report_summary"}}'
```

> **Warning:** Starting `--sse` without `--token` (or `$EXALM_TOKEN`) prints a
> warning and runs **without authentication**. Never expose an unauthenticated
> SSE endpoint beyond localhost.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `list_findings` returns `[]` | The loaded report has no structured findings (log analyzers), or no `--file` was passed |
| `apply_remediation` → "requires --mcp-write" | Server started without `--write` |
| `apply_remediation` → "apply handler not configured" | `--write` set but no usable kubeconfig was found at startup |
| SSE returns `401` | Missing or wrong bearer token |
