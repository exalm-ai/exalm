# Exalm Plugin SDK

This package is the public contract every Exalm plugin implements.
It is published as a **standalone Go module** so community plugin authors
can write plugins without depending on the full Exalm binary.

## Installation

```sh
go get github.com/exalm-ai/exalm/pkg/plugin
```

**Zero external dependencies** — only the Go standard library is required.

## Writing a plugin

```go
package myplugin

import (
    "context"
    "fmt"
    "github.com/exalm-ai/exalm/pkg/plugin"
)

// MyPlugin satisfies plugin.Plugin.
type MyPlugin struct{}

func (p *MyPlugin) Name() string        { return "myplugin" }
func (p *MyPlugin) Description() string { return "My custom Exalm plugin" }
func (p *MyPlugin) Mutates() bool       { return false }

func (p *MyPlugin) Subcommands() []plugin.Subcommand {
    return []plugin.Subcommand{
        {
            Name:        "analyze",
            Description: "Run my custom analysis",
            Run:         p.analyze,
        },
    }
}

func (p *MyPlugin) analyze(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
    // 1. Collect data from the environment.
    rawData := "collected data..."

    // 2. ALWAYS redact before sending to the LLM.
    safe := args.Redactor.Redact(rawData)

    // 3. Send to LLM.
    resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
        System: "You are an expert analyst. Summarise the following data.",
        Messages: []plugin.Message{
            {Role: "user", Content: safe},
        },
        MaxTokens: 2048,
    })
    if err != nil {
        return plugin.Report{}, fmt.Errorf("myplugin: LLM: %w", err)
    }

    return plugin.Report{
        Title:   "My Plugin Analysis",
        Summary: "Custom analysis complete.",
        Raw:     resp.Content,
    }, nil
}
```

## Registering your plugin

Add your plugin to `cmd/exalm/main.go`:

```go
import myplugin "github.com/your-org/myplugin"

func registerPlugins() {
    // ... existing plugins ...
    registry.Register(myplugin.New())
}
```

## Safety rules

All plugins **must** follow these rules (enforced via code review):

| Rule | Why |
|---|---|
| Call `args.Redactor.Redact()` on all environment data before the LLM | Privacy — never leak secrets |
| Only make network calls via the injected `args.LLM` | Auditability |
| Return `Mutates() = true` if any subcommand changes state | Safety gate |
| Require `--apply` before any mutating action | Prevents accidents |
| No `panic` outside init-time configuration | Stability |

## Types reference

See [plugin.go](./plugin.go) for the full type definitions:

- `Plugin` — the interface every plugin implements
- `Subcommand` — a single action (e.g., `analyze`, `summarize`)
- `RunArgs` — runtime context injected into every `Run` call
- `Report` — structured output returned by every subcommand
- `Finding` — one diagnostic item with severity, category, and suggestion
- `LLMClient` — abstraction over Claude, OpenAI, Ollama, etc.
- `Redactor` — secret/PII scrubbing interface
- `CompleteRequest` / `CompleteResponse` — LLM request/response types

## Versioning

The plugin SDK follows [Semantic Versioning](https://semver.org/).
Breaking changes to `plugin.Plugin` or `LLMClient` trigger a **major** version bump
and are announced in [CHANGELOG.md](../../CHANGELOG.md).
