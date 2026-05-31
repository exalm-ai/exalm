# Contributor Workflow

This document covers development setup, coding conventions, the plugin contract,
and the PR process for contributing to exalm.

For the system architecture, component responsibilities, and design rationale, see
[ARCHITECTURE.md](ARCHITECTURE.md).

---

## Before you start

1. Read [ARCHITECTURE.md](ARCHITECTURE.md) to understand the plugin contract and the
   redaction invariant. PRs that skip the redaction layer will be rejected.
2. Read [SECURITY.md](SECURITY.md) before touching `internal/redact` or `internal/web`.
3. For non-trivial changes, open an issue first to align on the approach.

---

## Development setup

```sh
git clone https://github.com/exalm-ai/exalm.git
cd exalm
go mod tidy
make test    # all tests should pass
make build   # produces ./bin/exalm
```

**Requirements:** Go 1.26+. No C toolchain — the SQLite driver is pure Go.

**Optional:** set an LLM API key to test end-to-end paths:

```sh
export ANTHROPIC_API_KEY=sk-ant-...
export EXALM_LLM_PROVIDER=claude
echo "kernel: out of memory: killed pid 8123 (nginx)" | ./bin/exalm logs summarize
```

---

## Adding a new plugin

The plugin interface is 3 methods. All 13 existing plugins follow the same structure.
A new plugin that reads a data source and returns an LLM-powered report is a half-day
of work.

### Step 1: Create the plugin package

```sh
mkdir plugins/<name>
```

Create `plugins/<name>/<name>.go`. Copy the structure from `plugins/logs/logs.go` —
it is the simplest complete plugin.

```go
package myplugin

import (
    "context"
    "fmt"

    "github.com/exalm-ai/exalm/pkg/plugin"
)

type myPlugin struct{}

func New() plugin.Plugin { return &myPlugin{} }

func (p *myPlugin) Name() string        { return "myplugin" }
func (p *myPlugin) Description() string { return "one-line description" }
func (p *myPlugin) Mutates() bool       { return false }

func (p *myPlugin) Subcommands() []plugin.Subcommand {
    return []plugin.Subcommand{
        {
            Name:        "analyze",
            Description: "analyze something",
            Run:         p.runAnalyze,
        },
    }
}

func (p *myPlugin) runAnalyze(ctx context.Context, args plugin.RunArgs) (plugin.Report, error) {
    // 1. Collect raw data from the environment
    raw := collectData(ctx, args.Flags)

    // 2. ALWAYS redact before sending to the LLM
    redacted := args.Redactor.Redact(raw)

    // 3. Send to the LLM
    resp, err := args.LLM.Complete(ctx, plugin.CompleteRequest{
        System: systemPrompt,
        User:   redacted,
    })
    if err != nil {
        return plugin.Report{}, fmt.Errorf("myplugin analyze: %w", err)
    }

    // 4. Return a structured Report
    return plugin.Report{
        Title:   "My Plugin Analysis",
        Summary: resp.Content,
        Raw:     resp.Content,
    }, nil
}
```

### Step 2: Write the system prompt

Create `plugins/<name>/prompts.go`:

```go
package myplugin

const systemPrompt = `You are an expert at diagnosing <domain> problems.
// ...
`
```

Prompts are Go string constants so they are easy to diff in PRs and test with fixtures.

### Step 3: Add tests

Create `plugins/<name>/<name>_test.go`. At minimum, test that:

- The redactor is called (pass a `FakeRedactor` that panics if not called)
- The LLM client is called with the redacted content (not the raw content)
- The returned `Report` has the expected shape

Use `internal/llm.NewMock()` or implement a fake `plugin.LLMClient` in your test file.

```go
func TestAnalyze_CallsRedactor(t *testing.T) {
    called := false
    fakeRedactor := plugin.RedactorFunc(func(s string) string {
        called = true
        return "[REDACTED]"
    })
    args := plugin.RunArgs{
        LLM:      llm.NewMock(),
        Redactor: fakeRedactor,
    }
    _, err := New().Subcommands()[0].Run(context.Background(), args)
    if err != nil {
        t.Fatal(err)
    }
    if !called {
        t.Error("redactor was never called")
    }
}
```

### Step 4: Register the plugin

In `cmd/exalm/main.go`, add:

```go
import myplugin "github.com/exalm-ai/exalm/plugins/myplugin"

// in registerPlugins():
registry.Register(myplugin.New())
```

### Step 5: Add examples and documentation

- Add a sample input to `examples/<name>/`
- Add a documentation page at `docs/plugins/<name>.md`

---

## Coding conventions

### Go style

- **Language:** Go 1.26+. Idiomatic Go. No clever metaprogramming.
- **Module path:** `github.com/exalm-ai/exalm`
- **Formatting:** `gofmt -s` and `goimports`. Enforced by `make lint`.
- **Comments:** doc comments on every exported identifier. Be terse.
- **Imports:** stdlib, then third-party, then local — separated by blank lines.
- **Errors:** wrap with `fmt.Errorf("context: %w", err)`. No `panic` except in
  `init()` or one-time startup validation.
- **File size:** aim for 200–400 lines per file. Split when a file grows beyond 800 lines.

### Logging

Plugins must not write to stdout or stderr directly. All output goes through `plugin.Report`.
The CLI handles all user-facing output.

### Input size limits

Every plugin that accepts user-controlled input must cap it. The standard is 200 KB:

```go
const MaxInputBytes = 200 * 1024

reader := io.LimitReader(src, MaxInputBytes)
```

### Mutations

The `--apply` flag is the only way to trigger a mutation. Any plugin subcommand that
modifies state must:

1. Return `true` from `Mutates()`
2. Check `args.Flags["apply"] == "true"` before executing the mutation
3. Print a clear, scary confirmation prompt before any write

There is no way to bypass this check from a plugin.

---

## The non-negotiables

These rules are enforced in code review. PRs violating them will be sent back.

| Rule | Rationale |
|---|---|
| Every LLM call must pass through `args.Redactor.Redact()` | Trust foundation — no exceptions |
| No raw user data in logs (stdout, stderr, files, or traces) | Privacy — log only metadata |
| No telemetry that is on by default | User trust |
| No new third-party dependencies without PR justification | Supply chain |
| No `panic` outside init-time misconfiguration | Stability |
| No breaking change to `plugin.Plugin` without a major version bump | Plugin compatibility |
| No mutating action without `--apply` and a confirmation prompt | Safety |
| No hardcoded API keys, even fake-looking ones | Security scanners flag them |

---

## PR checklist

Before opening a PR:

- [ ] `gofmt -s` and `goimports` clean
- [ ] `go vet ./...` passes
- [ ] `make test` passes (all tests, including race detector on Linux/macOS)
- [ ] New packages have `*_test.go` with at least one test
- [ ] New plugins have a test that verifies `Redactor.Redact()` is called
- [ ] If you touched `internal/redact`: run `make test-redact -v` and add a test for
      every new pattern (match case **and** boundary case)
- [ ] No new dependencies without justification in the PR description
- [ ] Conventional Commit title: `feat(k8s): ...`, `fix(redact): ...`, `docs: ...`
- [ ] [ARCHITECTURE.md](ARCHITECTURE.md) updated if you changed the component structure

---

## Commit message format

```
<type>(<scope>): <short description>

<optional body>
```

**Types:** `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

**Scopes** (use the package name): `k8s`, `redact`, `llm`, `web`, `ssh`, `dora`,
`incident`, `chaos`, `store`, `mcp`, `helm`, `ci`

**Examples:**
```
feat(k8s): add multi-cluster analysis via --kubeconfig flag
fix(redact): handle JWT tokens with non-standard padding
docs(mcp): add Claude Desktop config example for Windows
test(incident): add concurrent Create/Update race regression test
```

---

## Test commands

```sh
make test           # go test -race ./...
make test-redact    # redaction tests with verbose output (run before any redact/ change)
make lint           # gofmt + go vet + golangci-lint
make build          # local binary to ./bin/exalm
```

CI runs all of these on every PR. Do not merge a PR with a red build.

---

## Reporting security issues

**Do not file a public GitHub issue for security reports.**

See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Reports of
redaction bypass — any way to make secrets reach an LLM — are treated as the highest
priority class in the project.
