## Summary

<!-- What does this PR do and why? 1-3 bullet points. -->

-
-
-

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behaviour)
- [ ] Refactor / tech debt
- [ ] Documentation update
- [ ] CI / infrastructure change

## Related issues

Closes #

## Checklist

### Code
- [ ] `make lint` passes (`gofmt -s`, `go vet`, `golangci-lint`)
- [ ] `make test` passes (all unit tests green)
- [ ] New functionality has unit tests
- [ ] Functions are ≤ 40 lines; files are ≤ 800 lines
- [ ] Errors are wrapped with `fmt.Errorf("context: %w", err)`

### Security
- [ ] No API keys or secrets committed (not even fake-looking ones)
- [ ] New user input passes through `args.Redactor.Redact()` before reaching the LLM
- [ ] No new direct LLM calls that bypass the injected `LLMClient`
- [ ] No `panic` outside init-time configuration checks

### Plugin changes (if applicable)
- [ ] `plugin.Plugin` interface is satisfied
- [ ] `Mutates()` is correct (true only if the plugin changes cluster/system state)
- [ ] `--apply` is required before any mutating action
- [ ] Plugin registered in `cmd/exalm/main.go` → `registerPlugins()`
- [ ] Sample input added to `examples/<plugin>/`
- [ ] Plugin docs updated in `docs/plugins/<plugin>.md`

### Breaking changes
- [ ] DEVELOPMENT.md updated if architecture or conventions changed
- [ ] CHANGELOG.md entry added under `[Unreleased]`

## Testing

<!-- How did you test this? Paste relevant command output or test results. -->

```sh
$ exalm <plugin> <subcommand>
# paste output
```

## Screenshots (if UI changes)

<!-- Before / after screenshots for web dashboard or TUI changes. -->
