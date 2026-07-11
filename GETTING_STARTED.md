# Getting Started with exalm

## Step 1: Install

Choose the method that fits your environment.

### macOS (Homebrew — recommended)

```sh
brew install exalm-ai/tap/exalm
```

### macOS / Linux (go install)

```sh
go install github.com/exalm-ai/exalm/cmd/exalm@latest
```

Requires Go 1.26+. The binary is placed in `$(go env GOPATH)/bin` — make sure
that directory is in your `$PATH`.

### Linux (pre-built binary)

```sh
curl -sSL https://github.com/exalm-ai/exalm/releases/latest/download/exalm_linux_amd64.tar.gz \
  | tar xz
sudo mv exalm /usr/local/bin/
exalm --version
```

Also available: `linux_arm64`, `darwin_amd64`, `darwin_arm64`, `windows_amd64.zip`.
See [all releases →](https://github.com/exalm-ai/exalm/releases)

### Docker

```sh
docker pull ghcr.io/exalm-ai/exalm:latest
docker run --rm -it \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v ~/.kube:/home/nonroot/.kube:ro \
  ghcr.io/exalm-ai/exalm:latest k8s analyze
```

### Verify the installation

```sh
exalm --version
exalm --help
```

---

## Step 2: Run the setup wizard

Always run `exalm init` before anything else on a new machine.

```sh
exalm init
```

The wizard checks:

| Check | What it validates |
|---|---|
| **LLM provider** | Your API key is set and the provider is reachable |
| **Kubernetes context** | `KUBECONFIG` or `~/.kube/config` is present and pointing at a cluster |
| **Data directory** | `~/.exalm/` exists and is writable (used for DORA and incident data) |
| **Dashboard token** | `EXALM_TOKEN` is set if you plan to use `exalm serve` |

`exalm init` is non-destructive — it reads your environment and prints a checklist.
It does not write any configuration files.

---

## Step 3: Configure your LLM provider

exalm supports four providers. Set the environment variables for the one you want.

### Claude (Anthropic) — recommended for diagnostic quality

```sh
export EXALM_LLM_PROVIDER=claude
export ANTHROPIC_API_KEY=sk-ant-...
```

### OpenAI

```sh
export EXALM_LLM_PROVIDER=openai
export OPENAI_API_KEY=sk-...
```

### OpenRouter (100+ models, good for cost optimisation)

```sh
export EXALM_LLM_PROVIDER=openrouter
export OPENROUTER_API_KEY=sk-or-...
export EXALM_LLM_MODEL=meta-llama/llama-3.3-70b-instruct  # optional
```

### Ollama (local, air-gapped)

```sh
# Start Ollama locally first
ollama serve
ollama pull llama3.2

export EXALM_LLM_PROVIDER=ollama
# EXALM_OLLAMA_URL defaults to http://localhost:11434
```

**Persist your configuration** by adding the export lines to `~/.bashrc`, `~/.zshrc`,
or your shell's equivalent.

---

## Step 4: Your first Kubernetes analysis

If you have a kubeconfig pointing at a cluster:

```sh
exalm k8s analyze
```

Output is Markdown by default. To get structured JSON:

```sh
exalm k8s analyze --output json
```

To analyse a specific namespace:

```sh
exalm k8s analyze --namespace production
```

**What exalm collects:**
- Pod status and restart counts for all namespaces
- Kubernetes Events (warnings and errors)
- Node conditions
- ArgoCD Application sync status (if ArgoCD is installed)
- Helm release history

All of this is passed through the redaction engine before being sent to the LLM.

**Example output:**

```
# Kubernetes Cluster Analysis

**Verdict:** Two pods in the payments namespace are in CrashLoopBackOff due to
a missing environment variable introduced in the last Helm upgrade (12 minutes ago).

## Findings

### [CRITICAL] CrashLoopBackOff: payments/api-7d9f8b-xkv2p
- 22 restarts in the last 30 minutes
- Exit code 1: panic: environment variable STRIPE_WEBHOOK_SECRET not set
- IaC change: helm upgrade payments payments/api at 14:23 UTC

### [HIGH] Pending pod: payments/worker-5c8d9f-m3n4p
- Insufficient memory: 512Mi requested, 420Mi available on node worker-2

## Suggested actions
1. Add STRIPE_WEBHOOK_SECRET to the Helm values or Kubernetes Secret
2. Add node or increase memory limit on worker pods
```

---

## Step 5: Analyse logs

### Local log file

```sh
exalm syslog analyze --file /var/log/syslog
exalm httplog analyze --file /var/log/nginx/access.log
```

### Any log via stdin

```sh
# Kubernetes pod logs
kubectl logs -l app=api --since=2h | exalm logs summarize

# journald
journalctl -u postgresql --since "2 hours ago" | exalm logs summarize

# Tail a live log
tail -f /var/log/app.log | exalm logs summarize
```

### Remote logs over SSH (no agent required)

```sh
# Linux syslog from a remote host
exalm syslog analyze --host db-prod-01 --ssh-key ~/.ssh/id_rsa

# nginx from a remote web server
exalm httplog analyze --host web-01 --ssh-user ubuntu

# Windows Event Log (requires OpenSSH for Windows on the target)
exalm eventlog summarize --host win-dc-01 --log-name Security

# IIS W3C logs
exalm iis analyze --host iis-prod --log-dir 'C:\inetpub\logs\LogFiles\W3SVC1'
```

The first connection to any SSH host triggers a trust-on-first-use (TOFU) prompt.
The fingerprint is saved to `~/.exalm/known_hosts` and verified on all subsequent connections.

---

## Step 6: Ask the AI investigator

Every analyzer you just used — `syslog`, `httplog`, `eventlog`, `iis`, `logs`, and
Kubernetes — shares the same conversational investigation experience. Add `--open` to
launch it right after the analysis:

```sh
exalm syslog analyze --file /var/log/syslog --open
exalm httplog analyze --host web-01 --ssh-user ubuntu --open
```

This opens the web dashboard (same as Step 9) straight to the AI investigation view. Ask
questions like:

- "Why is this failing?"
- "What happened before this?"
- "Is memory the real problem?"
- "Generate an RCA"

Every answer cites the exact evidence it used, includes a confidence score with its
rationale, and proposes remediation in tiers — immediate mitigation, root-cause fix, and
prevention. Click any chart on the dashboard to drill down into the matching raw log
lines. Export the conversation as Markdown, JSON, or a standalone HTML report.

During an investigation, exalm can also run a small set of **read-only** diagnostics on
a remote host (disk/memory/uptime, service status, journal excerpts, …) to answer
follow-up questions without you running another SSH command by hand. This is gated by a
fixed, reviewed command allowlist — the LLM never chooses or writes a command:

```sh
# Default: read-only diagnostics allowed
exalm syslog analyze --host db-prod-01 --open

# Disable remote diagnostics entirely
exalm syslog analyze --host db-prod-01 --open --remote-diag off

# Opt in to security-sensitive reads (auth logs, login history, firewall state, …)
exalm syslog analyze --host db-prod-01 --open --remote-diag full
```

Set `EXALM_REMOTE_DIAG` to change the default tier for every run.

---

## Step 7: DORA metrics

DORA measures engineering health through four key metrics: Deployment Frequency,
Lead Time for Changes, Change Failure Rate, and Mean Time to Restore.

### Record deployments

```sh
# Record a deployment manually
exalm dora log-deploy \
  --service payments-api \
  --version v2.4.1 \
  --commit abc1234 \
  --commit-time 2025-06-01T14:00:00Z

# Or: set up the Terraform Cloud webhook receiver to record deploys automatically
exalm webhook terraform --listen :8765
```

### View your DORA report

```sh
exalm dora report          # last 30 days
exalm dora report --days 7 # last 7 days
```

```
# DORA Report — last 30 days

| Metric                    | Value    | Band    |
|---------------------------|----------|---------|
| Deployment Frequency      | 4.2/day  | Elite   |
| Lead Time for Changes     | 2h 14m   | High    |
| Change Failure Rate       | 4.2%     | Elite   |
| Mean Time to Restore      | 38 min   | High    |
```

---

## Step 8: Incident management

```sh
# Open an incident
exalm incident open --title "Payments API CrashLoopBackOff" --severity critical

# List open incidents
exalm incident list

# Link to a deployment
exalm incident open --title "Memory spike after deploy" --from-deploy DEP-2024-06-01-001

# Close an incident
exalm incident close INC-2024-06-01-001 --resolution "Rolled back Helm release"

# Generate a blameless postmortem
exalm incident postmortem INC-2024-06-01-001
```

The postmortem is generated by your chosen LLM using the incident timeline and linked
deployment records. All data is redacted before it is sent.

---

## Step 9: Web dashboard

`exalm serve` is a multi-dashboard hub: one browser tab for Kubernetes findings, AI
investigations, DORA metrics, the cross-signal timeline, incidents, and a dashboard
per log analyzer — navigation builds itself from your enabled plugins.

```sh
# Always set a token when running the dashboard
export EXALM_TOKEN=$(openssl rand -hex 32)

# Start the hub
exalm serve --token $EXALM_TOKEN
```

Open `http://localhost:7433`. While the hub runs, any analysis started with `--open`
(Step 6) **attaches** its session to it — the analyzer's dashboard lights up in the
hub navigation instead of opening a second server. Use the **Settings** page to
enable/disable dashboards and AI features; choices persist at `~/.exalm/settings.json`.

**Dashboard routes:**

| Route | What's there |
|---|---|
| `/` | Findings with severity filter and remediation steps |
| `/dora` | DORA four-key metrics and deployment history |
| `/timeline` | Cross-signal timeline: k8s findings, IaC changes, incidents |
| `/api/report` | JSON API: current analysis report |
| `/api/dora` | JSON API: DORA metrics |
| `/metrics` | Prometheus metrics endpoint |
| `/healthz` | Health check |

---

## Step 10: MCP integration (Claude Desktop)

If you use Claude Desktop, exalm can expose its tools via the Model Context Protocol
so you can ask Claude to run analyses from a conversation.

```sh
exalm mcp serve --token $EXALM_TOKEN
```

In your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "exalm": {
      "command": "exalm",
      "args": ["mcp", "serve"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-...",
        "EXALM_TOKEN": "your-token"
      }
    }
  }
}
```

Restart Claude Desktop. You can now say: _"Check my cluster for problems and show me the DORA metrics."_

---

## Troubleshooting

### `exalm init` reports a missing LLM key

Set the appropriate environment variable and rerun `exalm init`:
```sh
export ANTHROPIC_API_KEY=sk-ant-...
exalm init
```

### `exalm k8s analyze` says no kubeconfig found

Make sure `KUBECONFIG` is set or `~/.kube/config` exists and points at a reachable cluster:
```sh
kubectl cluster-info   # should return your cluster details
exalm k8s analyze
```

### SSH connection refused

Verify the host is reachable on port 22 and your key has access:
```sh
ssh -i ~/.ssh/id_rsa user@host "echo OK"
exalm syslog analyze --host host --ssh-key ~/.ssh/id_rsa
```

### Dashboard returns 401 Unauthorized

You have `EXALM_TOKEN` set. Pass the token as a header or query parameter:
```sh
curl -H "Authorization: Bearer $EXALM_TOKEN" http://localhost:7433/api/report
# or
open "http://localhost:7433?token=$EXALM_TOKEN"
```

---

## Next steps

- **Helm deployment**: run exalm inside your cluster — see [README.md](README.md#kubernetes-deployment-via-helm)
- **Full configuration reference**: [docs/configuration.md](docs/configuration.md)
- **Architecture overview**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Add a plugin**: [CONTRIBUTOR_WORKFLOW.md](CONTRIBUTOR_WORKFLOW.md)
- **API reference**: [docs/api.md](docs/api.md)
