# `exalm k8s`

Diagnose Kubernetes cluster health using live cluster state: pod status,
container logs, warning events, resource quotas, and recent changes.
Returns a ranked findings report with LLM-generated root-cause analysis
and one-click remediation options.

---

## Prerequisites

- A valid kubeconfig (or `KUBECONFIG` env var). Standard discovery applies:
  `~/.kube/config` → `KUBECONFIG` → in-cluster service account.
- RBAC: read access to `pods`, `events`, `nodes`, `namespaces`,
  `replicasets`, `deployments`, `configmaps`. The Helm chart creates a
  purpose-built ClusterRole — see
  [deploy/helm/exalm-agent/README.md](../../deploy/helm/exalm-agent/README.md).

Exalm never writes to the cluster unless you run `exalm k8s fix --apply`.

---

## Subcommands

### `exalm k8s analyze`

One-shot snapshot analysis. Connects to the cluster, collects state, sends
it through the LLM, and prints a findings report.

```sh
exalm k8s analyze
exalm k8s analyze --namespace prod
exalm k8s analyze --output json
```

| Flag | Default | Description |
|---|---|---|
| `--namespace`, `-n` | all | Kubernetes namespace to inspect |
| `--kubeconfig` | _(standard discovery)_ | Path to kubeconfig file |
| `--context` | _(current-context)_ | kubeconfig context to use |
| `--max-pods` | `25` | Maximum unhealthy pods to include |
| `--since` | `1h` | Time window for warning events (e.g. `30m`, `2h`) |
| `--log-lines` | `100` | Lines of log tail per failing container |
| `--include-nodes` | `false` | Also collect unhealthy node conditions |
| `--github-token` | — | Git provider token for fix PR creation |
| `--github-repo` | — | Repo for fix PRs: `owner/repo` |
| `--github-base-branch` | `main` | Base branch for fix PRs |
| `--git-provider` | `github` | `github`, `gitlab`, `bitbucket`, `azuredevops` |

`analyze` automatically opens the web dashboard (`--output web` is the
default for this subcommand). Pass `--output json` to suppress it.

---

### `exalm k8s fix`

Lists auto-fixable findings and optionally applies them. Requires `--apply`
to write anything to the cluster.

```sh
# Dry-run: show what would be fixed
exalm k8s fix --dry-run

# Interactive: prompt y/N per finding
exalm k8s fix --apply
```

| Flag | Default | Description |
|---|---|---|
| `--dry-run` | `false` | Print fixable actions without applying |
| `--apply` | `false` | Execute remediations (prompts y/N per finding) |
| _(k8s flags)_ | — | Same kubeconfig/namespace/context flags as `analyze` |

Exalm only applies changes you explicitly confirm. Every remediation prints
the `kubectl` command it will run before asking for confirmation.

---

### `exalm k8s watch`

Continuously monitors cluster health and serves a live web dashboard.
Cluster state is re-collected every `--interval`; the LLM analysis runs
once at startup and the dashboard updates findings on each refresh.

```sh
exalm k8s watch
exalm k8s watch --namespace prod --interval 30s
```

| Flag | Default | Description |
|---|---|---|
| `--interval` | `60s` | How often to refresh cluster state |
| _(k8s flags)_ | — | Same kubeconfig/namespace/context flags as `analyze` |

The dashboard opens at `http://localhost:7433` (port configurable via
`exalm serve --port`).

---

## Dashboard mode (`exalm serve`)

`exalm serve` is the recommended way to run continuous monitoring. It
combines K8s watch with optional SLO checking and starts the dashboard
directly without picking a plugin subcommand:

```sh
# K8s only
exalm serve

# K8s + SLO with Prometheus
exalm serve --slo-file specs.json --prometheus-url http://prometheus:9090

# Namespace-scoped, custom port, headless
exalm serve --namespace prod --interval 30s --port 8080 --open-browser=false
```

See [docs/configuration.md](../configuration.md) for the full `serve` flag
reference.

---

## Example output

```
# Kubernetes analysis

Analysed 14 pods (3 unhealthy) in prod using claude.

## CRITICAL — payments-api CrashLoopBackOff

Container exited with code 137 (OOM kill). Memory limit: 256Mi.
Last 5 lines of log:
  fatal error: runtime: out of memory

**Suggestion:** Increase memory limit to at least 512Mi. Consider adding
a VPA or HPA policy.

kubectl patch deployment payments-api -n prod \
  --patch '{"spec":{"template":{"spec":{"containers":[{"name":"payments-api","resources":{"limits":{"memory":"512Mi"}}}]}}}}'

## HIGH — worker-queue ImagePullBackOff

Image gcr.io/myproject/worker:v1.9.3 not found.

**Suggestion:** Verify the image tag exists in the registry and that
imagePullSecrets are configured.
```
