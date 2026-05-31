# Install

## Quick start

```sh
# 1. Install the binary (pick a method below)
brew install exalm/tap/exalm

# 2. Set your LLM provider
export ANTHROPIC_API_KEY=sk-ant-...
export EXALM_LLM_PROVIDER=claude

# 3. Run
cat /var/log/syslog | exalm logs summarize
```

---

## Install methods

### Homebrew (macOS / Linux)

> The tap is a placeholder — it will be live at the first public release.

```sh
brew install exalm/tap/exalm
exalm --version
```

### go install

Requires Go 1.26+.

```sh
go install github.com/exalm-ai/exalm/cmd/exalm@latest
```

The binary is placed in `$(go env GOPATH)/bin/exalm`. Make sure that
directory is on your `PATH`.

### Build from source

```sh
git clone https://github.com/exalm-ai/exalm.git
cd exalm
make build
# binary is ./bin/exalm
```

### Pre-built binaries (GitHub Releases)

Download the latest release tarball from
[github.com/exalm-ai/exalm/releases](https://github.com/exalm-ai/exalm/releases),
extract, and place the binary on your `PATH`:

```sh
tar xzf exalm_linux_amd64.tar.gz
sudo mv exalm /usr/local/bin/
```

---

## Install in Kubernetes via Helm

Run the live dashboard inside your cluster with one command:

```sh
helm install exalm ./deploy/helm/exalm-agent \
    --create-namespace --namespace exalm \
    --set llm.provider=claude \
    --set llm.apiKey=$ANTHROPIC_API_KEY
```

Port-forward to access the dashboard locally:

```sh
kubectl -n exalm port-forward svc/exalm-exalm-agent 7433:7433
# open http://localhost:7433
```

The chart is read-only by default. To enable one-click remediation from
the dashboard:

```sh
helm upgrade exalm ./deploy/helm/exalm-agent \
    --set rbac.allowApply=true
```

### Helm values reference

| Value | Default | Description |
|---|---|---|
| `llm.provider` | `ollama` | LLM provider: `claude`, `openai`, `ollama`, `openrouter` |
| `llm.apiKey` | — | API key (stored as a Secret) |
| `llm.model` | — | Model override |
| `rbac.allowApply` | `false` | Grant the pod permission to patch/delete K8s resources |
| `serve.interval` | `60s` | Cluster refresh interval |
| `serve.namespace` | all | Namespace scope |
| `service.port` | `7433` | Service port |

See [deploy/helm/exalm-agent/README.md](../deploy/helm/exalm-agent/README.md)
for the full list including Ingress, SLO integration, and Prometheus options.

---

## Configuration

Set your LLM provider before running. See
[docs/configuration.md](configuration.md) for the full reference.

Minimal setup for each provider:

```sh
# Claude
export ANTHROPIC_API_KEY=sk-ant-...
export EXALM_LLM_PROVIDER=claude

# OpenAI
export OPENAI_API_KEY=sk-...
export EXALM_LLM_PROVIDER=openai

# Ollama (local, no key needed)
export EXALM_LLM_PROVIDER=ollama   # already the default
```

---

## Verify it works

```sh
cat /var/log/syslog | exalm logs summarize
```

Expected output (Markdown):

```
# Log analysis

Analyzed 18432 bytes of log content using claude.

**Verdict:** Likely OOM kill of the `payments-api` pod under burst load.

**Evidence:**
    Memory cgroup out of memory: Killed process 8123 (payments-api)

**Likely causes:**
- Memory limit too low for current request volume
...

**Suggested next steps:**
1. Raise the memory limit on the payments-api Deployment
...
```

For JSON output:

```sh
cat /var/log/syslog | exalm logs summarize --output json
```

---

## Upgrading

### Homebrew

```sh
brew upgrade exalm
```

### go install

```sh
go install github.com/exalm-ai/exalm/cmd/exalm@latest
```

### Helm

```sh
helm upgrade exalm ./deploy/helm/exalm-agent \
    --set llm.provider=claude \
    --set llm.apiKey=$ANTHROPIC_API_KEY
```

### Build from source

```sh
git pull
make build
```
