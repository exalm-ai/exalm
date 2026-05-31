# exalm-agent — Helm chart

Open-source AI ops agent for Kubernetes. Installs a single read-only
diagnostic agent that watches your cluster and serves an AI-powered
findings dashboard on **port 7433**.

- 🔒 **Read-only by default.** Mutations are gated behind `rbac.allowApply=true`.
- 🤖 **Bring your own LLM.** Claude, OpenAI, Ollama, or OpenRouter.
- 🧱 **Single static binary.** Distroless image, non-root, ~25 MB.
- 🛡 **Secret redaction at the source.** Cluster data is redacted before it
   ever leaves the pod for the LLM.

---

## TL;DR

```sh
helm install exalm ./deploy/helm/exalm-agent \
    --create-namespace --namespace exalm \
    --set llm.provider=claude \
    --set llm.apiKey=$ANTHROPIC_API_KEY

kubectl -n exalm port-forward svc/exalm-exalm-agent 7433:7433
# → http://localhost:7433
```

---

## Provider examples

The repository ships ready-to-go values files under
[`deploy/helm/values-examples/`](../values-examples/):

| File | Provider | Use case |
|---|---|---|
| [`claude.yaml`](../values-examples/claude.yaml) | Claude | Best-in-class reasoning, cloud API |
| [`openrouter.yaml`](../values-examples/openrouter.yaml) | OpenRouter + Qwen 2.5 0.5B | 100+ models behind one key, cheap testing |
| [`ollama-local.yaml`](../values-examples/ollama-local.yaml) | Ollama | Fully offline, no API key |

```sh
helm install exalm ./deploy/helm/exalm-agent \
    --values ./deploy/helm/values-examples/openrouter.yaml \
    --set llm.apiKey=$OPENROUTER_API_KEY
```

---

## Values reference

| Key | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/exalm-ai/exalm` | Container image repo |
| `image.tag` | `""` (= `.Chart.AppVersion`) | Container image tag |
| `image.pullPolicy` | `IfNotPresent` | Pull policy |
| `replicaCount` | `1` | Phase 1 only supports 1 replica |
| `llm.provider` | `ollama` | `claude` / `openai` / `ollama` / `openrouter` |
| `llm.model` | `""` | Override provider's default model |
| `llm.apiKey` | `""` | Inline API key → chart creates a Secret |
| `llm.existingSecret` | `""` | Reference a pre-existing Secret instead |
| `llm.ollamaURL` | `http://localhost:11434` | Used only when `provider=ollama` |
| `llm.openaiBaseURL` | `""` | Override for Azure OpenAI / LM Studio / etc. |
| `watch.namespace` | `""` (= all) | Restrict the watch loop to one namespace |
| `watch.interval` | `60s` | Cluster-state refresh interval |
| `slo.enabled` | `false` | Enable SLO burn-rate findings |
| `slo.specFile` | `/etc/exalm/slo/specs.json` | Path inside container |
| `slo.specConfigMap` | `""` | Mount specs from a pre-existing ConfigMap |
| `slo.prometheusURL` | `""` | Prometheus base URL for live error budgets |
| `service.type` | `ClusterIP` | Service type |
| `service.port` | `7433` | Dashboard port |
| `ingress.enabled` | `false` | Optional Ingress |
| `rbac.create` | `true` | Create ClusterRole + ClusterRoleBinding |
| `rbac.allowApply` | `false` | Grant patch verbs for the "Apply Fix" button |
| `serviceAccount.create` | `true` | Create a dedicated ServiceAccount |
| `resources.*` | sane defaults | CPU/memory requests + limits |
| `storage.enabled` | `false` | Stub for LGTM-lite subcharts (Phase 2) |

See [`values.yaml`](values.yaml) for the full annotated default set.

---

## Secret management and etcd encryption

### Why this matters

Kubernetes Secrets are **base64-encoded, not encrypted** by default. Any
principal that can `kubectl get secret` in the namespace — or that has direct
read access to etcd — can recover the raw API key. This affects every managed
Kubernetes provider (EKS, GKE, AKS, DOKS) unless you explicitly enable
encryption at rest.

### Step 1 — Enable etcd encryption at rest (recommended for production)

| Provider | How to enable |
|---|---|
| **EKS** | [AWS KMS envelope encryption](https://docs.aws.amazon.com/eks/latest/userguide/enable-kms.html) (`--encryption-config` flag on the API server) |
| **GKE** | [Application-layer secrets encryption](https://cloud.google.com/kubernetes-engine/docs/how-to/encrypting-secrets) |
| **AKS** | [Azure Key Vault with AKS Key Management Service](https://learn.microsoft.com/azure/aks/use-kms-etcd-encryption) |
| **Self-managed** | Add an `EncryptionConfiguration` resource to your API server manifest with a `secretbox` or `aescbc` provider |

### Step 2 — Use sealed-secrets or External Secrets Operator

Even with etcd encryption, the API key must travel from your CI/CD pipeline
into the cluster. Use one of these tools so plaintext secrets never appear in
your GitOps repo:

**sealed-secrets (offline encryption):**

```sh
# Install the controller once per cluster
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm install sealed-secrets sealed-secrets/sealed-secrets -n kube-system

# Seal your API key
kubectl -n exalm create secret generic exalm-llm \
    --from-literal=anthropic-api-key=$ANTHROPIC_API_KEY \
    --dry-run=client -o yaml \
  | kubeseal --format yaml > sealedsecret-exalm-llm.yaml

# Commit sealedsecret-exalm-llm.yaml to git (safe — encrypted with cluster public key)
git add sealedsecret-exalm-llm.yaml && git commit -m "feat: add sealed LLM secret"

# Reference in Helm
helm install exalm ./deploy/helm/exalm-agent \
    --set llm.provider=claude \
    --set llm.existingSecret=exalm-llm
```

**External Secrets Operator (pull from Vault / AWS Secrets Manager / GCP Secret Manager):**

```sh
# Install ESO once per cluster
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace

# Create an ExternalSecret that pulls from AWS Secrets Manager
cat <<EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: exalm-llm
  namespace: exalm
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager   # your ClusterSecretStore
    kind: ClusterSecretStore
  target:
    name: exalm-llm
  data:
    - secretKey: anthropic-api-key
      remoteRef:
        key: prod/exalm/anthropic-api-key
EOF

# Reference in Helm
helm install exalm ./deploy/helm/exalm-agent \
    --set llm.provider=claude \
    --set llm.existingSecret=exalm-llm
```

### Dashboard token

The same recommendations apply to `auth.token`. Use `auth.existingSecret`
with a sealed or externally-managed Secret instead of passing the token
via `--set auth.token=...`:

```sh
kubectl -n exalm create secret generic exalm-dashboard-token \
    --from-literal=dashboard-token=$(openssl rand -hex 32) \
    --dry-run=client -o yaml \
  | kubeseal --format yaml > sealedsecret-exalm-dashboard-token.yaml

helm install exalm ./deploy/helm/exalm-agent \
    --set auth.existingSecret=exalm-dashboard-token
```

### Pre-existing Secret key reference

When using `llm.existingSecret`, the Secret must contain the provider-specific key:

| Provider | Required key |
|---|---|
| `claude` | `anthropic-api-key` |
| `openai` | `openai-api-key` |
| `openrouter` | `openrouter-api-key` |
| `ollama` | _(no key — Ollama doesn't require authentication)_ |

When using `auth.existingSecret`, the Secret must contain the key `dashboard-token`.

---

## RBAC scope

The agent is granted **read-only verbs** (`get`, `list`, `watch`) on every
Kubernetes resource it reads — see [`templates/rbac.yaml`](templates/rbac.yaml).

When `rbac.allowApply=true` it additionally gets:

- `patch`, `update` on Deployments, StatefulSets, Services, PVCs, Nodes
- `delete` on Pods

These are the minimum verbs needed for the "Apply Fix" dashboard flow
(see [`plugins/k8s/remediate.go`](../../../plugins/k8s/remediate.go)). With
`allowApply=false` (the default), the Apply Fix button still appears in
the UI but the corresponding kubectl-equivalent call fails with a
Forbidden error — which is the desired safety behaviour.

---

## SLO integration

To merge SLO burn-rate findings into the dashboard:

```sh
# 1. Create a ConfigMap with your SLO spec
kubectl -n exalm create configmap exalm-slos \
    --from-file=specs.json=./examples/slo/specs.json

# 2. Enable SLO mode pointing at the ConfigMap + Prometheus
helm upgrade exalm ./deploy/helm/exalm-agent --reuse-values \
    --set slo.enabled=true \
    --set slo.specConfigMap=exalm-slos \
    --set slo.prometheusURL=http://prometheus-server.monitoring:9090
```

---

## Uninstall

```sh
helm uninstall exalm -n exalm
kubectl delete namespace exalm
```

---

## License

Apache-2.0. See the [LICENSE](../../../LICENSE) at the repo root.
