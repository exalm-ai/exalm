# Plugin development

This is the user-facing version of the contract. The internal source of
truth lives in [`DEVELOPMENT.md`](../DEVELOPMENT.md) at the repo root.

## Anatomy of a plugin

A plugin is a Go package under `plugins/<name>/` that exports a type
implementing `plugin.Plugin`:

```go
type Plugin interface {
    Name() string
    Description() string
    Mutates() bool
    Subcommands() []Subcommand
}
```

A `Subcommand` is `{Name, Description, Run}` where `Run` does the work
and returns a `Report`.

## Hello-world plugin

```go
// plugins/hello/hello.go
package hello

import (
    "context"
    "github.com/exalm-ai/exalm/pkg/plugin"
)

type Plugin struct{}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string        { return "hello" }
func (p *Plugin) Description() string { return "Demo plugin" }
func (p *Plugin) Mutates() bool       { return false }

func (p *Plugin) Subcommands() []plugin.Subcommand {
    return []plugin.Subcommand{
        {
            Name:        "say",
            Description: "Say hello via the LLM",
            Run: func(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
                resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
                    Messages: []plugin.Message{
                        {Role: "user", Content: "Say hi to an ops engineer in one short sentence."},
                    },
                    MaxTokens: 64,
                })
                if err != nil {
                    return plugin.Report{}, err
                }
                return plugin.Report{Title: "Hello", Raw: resp.Content}, nil
            },
        },
    }
}
```

Then in `cmd/exalm/main.go`:

```go
import helloplugin "github.com/exalm-ai/exalm/plugins/hello"

func registerPlugins() {
    registry.Register(logsplugin.New())
    registry.Register(helloplugin.New()) // <-- new
}
```

Build and run:

```sh
make build
./bin/exalm hello say
```

## Mandatory rules

1. **Always redact** before sending to the LLM:
   ```go
   redacted := args.Redactor.Redact(rawData)
   ```
2. **Cap input size** with `io.LimitReader`. Suggested cap: 200 KB.
3. **Read-only first.** Set `Mutates() bool` to `true` only when you
   genuinely need to write — and add an explicit confirmation prompt
   in your `Run` function before the mutation.
4. **One file per concern.** Big plugins split into:
   - `<name>.go` — `Plugin` impl + subcommand wiring
   - `prompts.go` — system prompts as constants
   - `collect.go` — environment data collection
   - `<name>_test.go` — tests with a fake LLM client

## Testing your plugin

Use a fake LLM client:

```go
type fakeLLM struct{ resp string }

func (f *fakeLLM) Name() string { return "fake" }
func (f *fakeLLM) Complete(ctx context.Context, req plugin.CompleteRequest) (plugin.CompleteResponse, error) {
    return plugin.CompleteResponse{Content: f.resp}, nil
}
```

…and a fake redactor that records calls so you can assert it was used.
