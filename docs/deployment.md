# Deployment guide

This guide covers every supported deployment target for Exalm, from a
developer laptop to a production Kubernetes cluster.

---

## Prerequisites

| Prerequisite | Required for |
|---|---|
| Go 1.26+ | Building from source |
| Docker 24+ | Container deployment |
| `kubectl` + kubeconfig | Kubernetes deployment |
| Helm 3.12+ | Helm-managed Kubernetes deployment |
| `kind` or `k3d` | Local Kubernetes testing |
| LLM API key | All deployments (unless using Ollama) |

---

## Option 1 — Local binary (recommended for getting started)

### Install

```sh
# go install (requires Go 1.26+)
go install github.com/exalm-ai/exalm/cmd/exalm@latest

# Build from source
git clone https://github.com/exalm-ai/exalm.git
cd exalm
make build          # binary → ./bin/exalm
```

### Minimal configuration

```sh
# Claude (recommended for best results)
export ANTHROPIC_API_KEY=sk-ant-...
export EXALM_LLM_PROVIDER=claude

# OpenAI
export OPENAI_API_KEY=sk-...
export EXALM_LLM_PROVIDER=openai

# Ollama — local, no key needed
# ollama pull llama3.1:8b
export EXALM_LLM_PROVIDER=ollama   # default

# Mock provider — for testing without any LLM API key
export EXALM_LLM_PROVIDER=mock
```

### Run the onboarding wizard

```sh
exalm init
```

`exalm init` validates your LLM API key, Kubernetes context, data directory,
and (optionally) dashboard token. Run it once after install.

### First analysis

```sh
# Kubernetes analysis
exalm k8s analyze

# Pipe a log file
cat /var/log/syslog | exalm logs summarize

# DORA metrics
exalm dora report

# Launch the web dashboard
exalm serve --token $(openssl rand -hex 32)
```

---

## Option 2 — Docker

### Pull and run

```sh
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e EXALM_LLM_PROVIDER=claude \
  -v ~/.kube:/home/nonroot/.kube:ro \
  -v ~/.exalm:/home/nonroot/.exalm \
  ghcr.io/exalm-ai/exalm:latest \
  k8s analyze
```

### Web dashboard in Docker

```sh
docker run -d \
  --name exalm-dashboard \
  -p 127.0.0.1:7433:7433 \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e EXALM_LLM_PROVIDER=claude \
  -e EXALM_TOKEN=$(openssl rand -hex 32) \
  -v ~/.kube:/home/nonroot/.kube:ro \
  -v exalm-data:/home/nonroot/.exalm \
  ghcr.io/exalm-ai/exalm:latest \
  serve --bind 0.0.0.0
```

The dashboard is available at `http://localhost:7433`.

> **Security**: always bind to `127.0.0.1` (host side `-p 127.0.0.1:7433:7433`)
> and set `EXALM_TOKEN`. Never publish port 7433 without a reverse proxy
> providing TLS and authentication.

### Build the image locally

```sh
make docker-build           # builds ghcr.io/exalm-ai/exalm:dev
# or
docker build -t exalm:local .
```

---

## Option 3 — Kubernetes via Helm

### Quick install

```sh
helm install exalm ./deploy/helm/exalm-agent \
    --create-namespace --namespace exalm \
    --set llm.provider=claude \
    --set llm.apiKey=$ANTHROPIC_API_KEY \
    --set auth.token=$(openssl rand -hex 32)
```

### Access the dashboard

```sh
kubectl -n exalm port-forward svc/exalm-exalm-agent 7433:7433
# open http://localhost:7433
```

Supply the token in your browser: `http://localhost:7433?token=<your-token>`

### Helm values reference

#### LLM provider

| Value | Default | Description |
|---|---|---|
| `llm.provider` | `ollama` | `claude` / `openai` / `ollama` / `openrouter` |
| `llm.model` | — | Override the provider's default model |
| `llm.apiKey` | — | Inline API key — creates a Kubernetes Secret |
| `llm.existingSecret` | — | Name of a pre-existing Secret (preferred for sealed-secrets / ESO) |
| `llm.ollamaURL` | `http://localhost:11434` | Ollama base URL (for in-cluster Ollama) |
| `llm.openaiBaseURL` | — | Override for Azure OpenAI / LM Studio / LocalAI |

#### Dashboard authentication

| Value | Default | Description |
|---|---|---|
| `auth.token` | — | Bearer token (creates a Secret named `<release>-token`) |
| `auth.existingSecret` | — | Use a pre-existing Secret's `dashboard-token` key |

#### K8s watch loop

| Value | Default | Description |
|---|---|---|
| `watch.namespace` | all | Scope to one namespace, e.g. `production` |
| `watch.interval` | `60s` | Cluster refresh interval (minimum 10s) |

#### Service and ingress

| Value | Default | Description |
|---|---|---|
| `service.type` | `ClusterIP` | Kubernetes service type |
| `service.port` | `7433` | Service port |
| `ingress.enabled` | `false` | Enable Ingress resource |
| `ingress.className` | — | Ingress class (nginx, traefik, …) |
| `ingress.hosts` | `[{host: exalm.local}]` | Ingress host rules |
| `ingress.tls` | `[]` | TLS secret references |

#### Persistent storage

| Value | Default | Description |
|---|---|---|
| `persistence.enabled` | `true` | Mount a PVC for `~/.exalm` data directory |
| `persistence.storageClass` | — | Storage class (empty = cluster default) |
| `persistence.accessMode` | `ReadWriteOnce` | PVC access mode |
| `persistence.size` | `1Gi` | PVC size |
| `persistence.existingClaim` | — | Reuse an existing PVC |

> **Important**: Without `persistence.enabled=true`, all DORA and incident
> data is lost on every pod restart because the container filesystem is
> read-only. Always enable persistence in production.

#### RBAC

| Value | Default | Description |
|---|---|---|
| `rbac.create` | `true` | Create ClusterRole and ClusterRoleBinding |
| `rbac.allowApply` | `false` | Grant patch verbs for "Apply Fix" dashboard button |

#### SLO integration

| Value | Default | Description |
|---|---|---|
| `slo.enabled` | `false` | Enable SLO error-budget tracking |
| `slo.specFile` | `/etc/exalm/slo/specs.json` | Path to SLO spec JSON in container |
| `slo.specConfigMap` | — | Mount SLO specs from this ConfigMap |
| `slo.prometheusURL` | — | Prometheus base URL for live error budgets |

#### Resources and scheduling

| Value | Default | Description |
|---|---|---|
| `resources.limits.cpu` | `500m` | CPU limit |
| `resources.limits.memory` | `512Mi` | Memory limit |
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |
| `nodeSelector` | `{}` | Node selector labels |
| `tolerations` | `[]` | Pod tolerations |
| `affinity` | `{}` | Pod affinity rules |

### Using an existing API key Secret

Create the Secret yourself (with sealed-secrets, External Secrets Operator,
Vault Agent, etc.) then reference it:

```sh
# Create sealed secret (example)
kubectl -n exalm create secret generic my-llm-secret \
    --from-literal=anthropic-api-key=$ANTHROPIC_API_KEY \
    --dry-run=client -o yaml | kubeseal -o yaml > sealedsecret.yaml
kubectl apply -f sealedsecret.yaml

# Install without inline apiKey
helm install exalm ./deploy/helm/exalm-agent \
    --namespace exalm \
    --set llm.provider=claude \
    --set llm.existingSecret=my-llm-secret \
    --set auth.token=$(openssl rand -hex 32)
```

The same pattern works for the dashboard token via `auth.existingSecret`.

### Enabling the "Apply Fix" button

The dashboard can apply Kubernetes remediations in one click. This requires
additional RBAC verbs:

```sh
helm upgrade exalm ./deploy/helm/exalm-agent \
    --namespace exalm \
    --set rbac.allowApply=true
```

> **Warning**: `allowApply=true` grants the pod permission to patch and delete
> Kubernetes resources in the watched namespace. Review the generated
> ClusterRole before enabling this in production.

### Exposing via Ingress with TLS

```sh
helm upgrade exalm ./deploy/helm/exalm-agent \
    --namespace exalm \
    --set ingress.enabled=true \
    --set ingress.className=nginx \
    --set "ingress.hosts[0].host=exalm.example.com" \
    --set "ingress.hosts[0].paths[0].path=/" \
    --set "ingress.hosts[0].paths[0].pathType=Prefix" \
    --set "ingress.tls[0].secretName=exalm-tls" \
    --set "ingress.tls[0].hosts[0]=exalm.example.com" \
    --set auth.token=$(openssl rand -hex 32)
```

Always terminate TLS **before** the Exalm service. Exalm itself does not
serve HTTPS.

---

## Option 4 — Local Kubernetes with kind (for development / CI)

```sh
# Create a kind cluster
kind create cluster --name exalm-test

# Load a locally built image
make docker-build
kind load docker-image ghcr.io/exalm-ai/exalm:dev --name exalm-test

# Install the chart
helm install exalm ./deploy/helm/exalm-agent \
    --create-namespace --namespace exalm \
    --set image.repository=ghcr.io/exalm-ai/exalm \
    --set image.tag=dev \
    --set image.pullPolicy=Never \
    --set llm.provider=mock \
    --set auth.token=test-token-local

# Watch pod logs
kubectl -n exalm logs -f deploy/exalm-exalm-agent

# Tear down
kind delete cluster --name exalm-test
```

---

## Environment variables reference

All environment variables can also be set as Kubernetes ConfigMap/Secret
values via the Helm chart.

### LLM provider

| Variable | Required | Default | Description |
|---|---|---|---|
| `EXALM_LLM_PROVIDER` | no | `ollama` | `claude` / `openai` / `ollama` / `openrouter` / `mock` |
| `EXALM_LLM_MODEL` | no | _(provider default)_ | Model name override |
| `ANTHROPIC_API_KEY` | for Claude | — | Anthropic API key |
| `OPENAI_API_KEY` | for OpenAI | — | OpenAI API key |
| `OPENAI_BASE_URL` | no | _(OpenAI default)_ | Override endpoint (Azure, LM Studio, LocalAI) |
| `OPENROUTER_API_KEY` | for OpenRouter | — | OpenRouter API key |
| `EXALM_OLLAMA_URL` | no | `http://localhost:11434` | Ollama base URL |

### Dashboard

| Variable | Required | Default | Description |
|---|---|---|---|
| `EXALM_TOKEN` | no | — | Bearer token for dashboard auth (strongly recommended) |

### Plugins

| Variable | Required | Default | Description |
|---|---|---|---|
| `EXALM_OUTPUT` | no | `markdown` | Default output format: `markdown` or `json` |
| `EXALM_PROMETHEUS_URL` | no | — | Prometheus base URL for SLO error-budget data |
| `GITHUB_TOKEN` | for PR creation | — | GitHub token for fix-PR creation |
| `GITHUB_REPO` | for PR creation | — | Target repo: `owner/repo` |

### SSH collection

| Variable | Required | Default | Description |
|---|---|---|---|
| `EXALM_SSH_PASSWORD` | no | — | SSH password (prefer key-based auth) |

---

## Data directory layout

Exalm stores all persistent data under `~/.exalm/` (or
`/home/nonroot/.exalm/` in the container):

```
~/.exalm/
├── exalm.db           SQLite database (deployments + incidents)
├── known_hosts        SSH TOFU host key store
├── config.yaml        Optional config file (generated by exalm init)
│
# Legacy files (migrated to SQLite on first run with Phase 6+)
├── deployments.jsonl  Legacy DORA deployment log
└── incidents/         Legacy incident JSON files
    └── INC-*.json
```

The SQLite database uses WAL mode. It is safe to copy `exalm.db` for backups
while Exalm is running.

---

## Upgrading

### Local binary

```sh
go install github.com/exalm-ai/exalm/cmd/exalm@latest
# or build from source
git pull && make build
```

### Docker

```sh
docker pull ghcr.io/exalm-ai/exalm:latest
```

### Helm

```sh
helm upgrade exalm ./deploy/helm/exalm-agent \
    --namespace exalm \
    --reuse-values
```

The PVC carries `helm.sh/resource-policy: keep` — your data is preserved
across upgrades and across `helm uninstall`.

---

## Uninstalling

### Helm

```sh
helm uninstall exalm --namespace exalm
# Data PVC is NOT deleted (resource-policy: keep). To also delete data:
kubectl -n exalm delete pvc -l app.kubernetes.io/instance=exalm
```

### Docker

```sh
docker stop exalm-dashboard && docker rm exalm-dashboard
docker volume rm exalm-data      # removes persistent data
```

---

## Troubleshooting

### Dashboard shows `unauthorized`

You set `--token` or `EXALM_TOKEN` but are not sending the header. Supply
the token:

```sh
curl -H "Authorization: Bearer $EXALM_TOKEN" http://localhost:7433/api/report
# or in a browser
http://localhost:7433?token=$EXALM_TOKEN
```

### Pod crashes with `OOMKilled`

Increase the memory limit:

```sh
helm upgrade exalm ./deploy/helm/exalm-agent \
    --namespace exalm \
    --set resources.limits.memory=1Gi \
    --reuse-values
```

### DORA data not persisted after pod restart

Enable persistence:

```sh
helm upgrade exalm ./deploy/helm/exalm-agent \
    --namespace exalm \
    --set persistence.enabled=true \
    --reuse-values
```

### LLM call times out

The default `WriteTimeout` on the web server is 30 seconds. LLM calls on
Ollama with large models can exceed this. Use the CLI (`exalm k8s analyze`)
instead of the dashboard for long-running analyses, or increase the timeout
by rebuilding with a patched `WriteTimeout`.

### SSH: `known_hosts mismatch`

A stored SSH host key no longer matches. Investigate the target host for
unexpected changes, then remove the stale entry:

```sh
ssh-keygen -R <hostname> -f ~/.exalm/known_hosts
```

Re-run the plugin — TOFU will accept and store the new key.

### `exalm init` reports missing kubeconfig

Set `KUBECONFIG` or ensure `~/.kube/config` exists:

```sh
export KUBECONFIG=~/.kube/my-cluster.yaml
exalm init
```
