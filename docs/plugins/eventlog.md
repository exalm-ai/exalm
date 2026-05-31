# `exalm eventlog`

Analyze Windows Event Log exports.

## Why a separate plugin

The generic `exalm logs summarize` plugin works on any text. The `eventlog`
plugin understands the structure of `Get-WinEvent` JSON: it filters out
informational events, normalizes EventID/Provider/Level/Channel into a compact
form, and the prompt is tuned for incident response (attack indicators, audit
log clears, lateral movement signals).

## Input formats

**Recommended: PowerShell JSON.** Binary `.evtx` files are NOT parsed
directly — exalm asks you to pipe through PowerShell first. We deliberately
don't carry a binary-XML parser in the static binary.

```powershell
# Live, from a channel
Get-WinEvent -LogName Security -MaxEvents 1000 |
    ConvertTo-Json -Depth 3 |
    exalm eventlog summarize

# From an exported .evtx
Get-WinEvent -Path C:\path\to\Security.evtx |
    Where-Object { $_.Level -le 3 } |
    ConvertTo-Json -Depth 3 |
    exalm eventlog summarize

# Multiple exported files
exalm eventlog summarize --file 'C:\evtx-exports\*.json' --concurrency=8
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--file` | — | Path or glob, repeatable. If omitted, reads stdin. |
| `--concurrency` | 4 | Parallel LLM calls. |
| `--chunk-size` | 256KB | Soft cap per chunk (`200KB`, `1MB`, etc.). |

## Output

Five-section Markdown report:

- **VERDICT** — one-sentence summary
- **CRITICAL EVENTS** — 1-3 most important events
- **ATTACK INDICATORS** — failed logon clusters, privilege use, audit-log clear
- **CAUSES** — ranked likely causes
- **NEXT STEPS** — concrete operator actions

## Redaction

The default redaction set is augmented for Windows:

- `windows-sid` — SIDs (`S-1-5-21-...`) are redacted by default
- `ntlm-hash` — LM:NT hash pairs are redacted by default
- Opt-in: `--redact windows-account` redacts `DOMAIN\username` strings
- Opt-in: `--redact internal-ipv4` redacts RFC1918 IPs

Add to `EXALM_OPTIONAL_REDACTIONS` to enable opt-ins by default.

## Try it

```sh
./bin/exalm eventlog summarize --file examples/eventlog/security-4625.json
```

The example surfaces a brute-force pattern against `jdoe` followed by an audit
log clear — exactly the kind of correlation that's easy to miss in a sea of
informational events.
