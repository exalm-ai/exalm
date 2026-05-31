# Examples

Real-world-shaped log samples used in docs and integration tests.

## Quick try

```sh
export ANTHROPIC_API_KEY=sk-ant-...

# OOM loop
exalm logs summarize --file examples/oom-loop.log
```

## Adding new examples

When adding a plugin, drop at least one example input in this directory:
`examples/<plugin-name>/<scenario>.log` (or `.json`, `.tf`, etc.).

Use realistic-shaped data, but **never include real secrets** even fake-looking
ones. Use placeholders like `[REDACTED]` or obviously fake values.
