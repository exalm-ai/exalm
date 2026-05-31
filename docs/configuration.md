# Configuration reference

Exalm resolves configuration in the following order (highest precedence first):

1. CLI flags
2. Environment variables
3. Defaults

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `EXALM_LLM_PROVIDER` | no | `ollama` | LLM backend: `claude`, `openai`, `ollama`, `openrouter` |
| `EXALM_LLM_MODEL` | no | _(provider default)_ | Override the model name |
| `ANTHROPIC_API_KEY` | for Claude | — | Anthropic API key |
| `OPENAI_API_KEY` | for OpenAI | — | OpenAI API key |
| `OPENAI_BASE_URL` | no | _(OpenAI default)_ | Override the OpenAI endpoint (Azure, LM Studio, LocalAI, etc.) |
| `OPENROUTER_API_KEY` | for OpenRouter | — | OpenRouter API key |
| `EXALM_OLLAMA_URL` | no | `http://localhost:11434` | Ollama base URL |
| `EXALM_OUTPUT` | no | `markdown` | Default output format: `markdown` or `json` |
| `EXALM_PROMETHEUS_URL` | no | — | Prometheus base URL for SLO error-budget data |
| `GITHUB_TOKEN` | for PR creation | — | Git provider token (also `--github-token`) |
| `GITHUB_REPO` | for PR creation | — | Repo for fix PRs: `owner/repo` (also `--github-repo`) |

---

## Global CLI flags

These flags are available on every subcommand.

| Flag | Default | Description |
|---|---|---|
| `--output` | `markdown` | Output format: `markdown`, `json`, or `web` |
| `--apply` | `false` | Allow mutating actions (required by plugins with side effects) |
| `--show-redactions` | `false` | Print a redaction summary to stderr before sending data to the LLM |
| `--provider` | — | LLM provider: `claude`, `openai`, `ollama`, `openrouter` (overrides env) |
| `--model` | — | Model name (overrides provider default) |

---

## `exalm serve` flags

`exalm serve` starts the live K8s watch dashboard. All flags are optional.

| Flag | Default | Description |
|---|---|---|
| `--port` | `7433` | TCP port for the web dashboard |
| `--interval` | `60s` | K8s cluster-state refresh interval (e.g. `30s`, `2m`) |
| `--namespace`, `-n` | all | Kubernetes namespace to watch |
| `--kubeconfig` | _(standard discovery)_ | Path to kubeconfig file |
| `--context` | _(current-context)_ | kubeconfig context to use |
| `--slo-file` | — | SLO spec JSON file; enables SLO findings in the dashboard |
| `--prometheus-url` | — | Prometheus base URL for live error budgets (overrides `EXALM_PROMETHEUS_URL`) |
| `--open-browser` | `true` | Open the dashboard in the default browser on start |
| `--github-token` | — | Git provider token for PR creation (or `GITHUB_TOKEN`) |
| `--github-repo` | — | Repo for fix PRs: `owner/repo` (or `GITHUB_REPO`) |
| `--github-base-branch` | `main` | Base branch for fix PRs |
| `--git-provider` | `github` | Git hosting provider: `github`, `gitlab`, `bitbucket`, `azuredevops` |

---

## `exalm mcp serve` flags

| Flag | Default | Description |
|---|---|---|
| `--sse` | — | If set, serve over HTTP/SSE on this address (e.g. `:7434`); otherwise stdio |
| `--write` | `false` | Enable mutating MCP tools (`apply_remediation`, `open_incident`) |

---

## LLM provider examples

### Claude (recommended)

```sh
export ANTHROPIC_API_KEY=sk-ant-...
export EXALM_LLM_PROVIDER=claude
```

Default model: `claude-sonnet-4-6`. Override:

```sh
export EXALM_LLM_MODEL=claude-opus-4-5
```

### OpenAI

```sh
export OPENAI_API_KEY=sk-...
export EXALM_LLM_PROVIDER=openai
```

### OpenAI-compatible endpoint (Azure, LM Studio, LocalAI)

```sh
export OPENAI_API_KEY=<your-key>
export OPENAI_BASE_URL=https://my-azure-instance.openai.azure.com/
export EXALM_LLM_PROVIDER=openai
```

### OpenRouter

```sh
export OPENROUTER_API_KEY=sk-or-...
export EXALM_LLM_PROVIDER=openrouter
```

### Ollama (local, no API key)

```sh
# Ollama is the default provider. Start it first:
ollama serve
ollama pull llama3

export EXALM_LLM_PROVIDER=ollama          # already the default
export EXALM_OLLAMA_URL=http://localhost:11434
export EXALM_LLM_MODEL=llama3
```

---

## EXALM_HOME directory

Exalm persists state under `~/.config/exalm/` (the _EXALM_HOME_):

```
~/.config/exalm/
├── config.yaml          # (future) file-based config; env vars take precedence today
└── changestore/         # change-correlation event log (k8s watch mode)
```

The directory is created automatically on first use. No sensitive data is
written to disk; the changestore contains only Kubernetes event metadata
(resource type, namespace, name, timestamp, actor).
