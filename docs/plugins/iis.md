# `exalm iis`

Analyze IIS W3C Extended access logs.

## What it does

Parses the `#Fields:` header to learn the column order, then surfaces:

- Top status codes (with counts)
- 5xx bursts grouped by minute
- Slow requests (≥ 5s by default)
- Suspicious URIs (`/.env`, `/wp-login.php`, `/admin`, traversal attempts)
- Top URIs / methods / client IPs

The system prompt is tuned for web operations, not general SRE.

## Usage

```sh
# Single file
exalm iis analyze --file C:\inetpub\logs\LogFiles\W3SVC1\u_ex260513.log

# All today's logs across multiple sites, concurrently
exalm iis analyze \
  --file 'C:\inetpub\logs\LogFiles\W3SVC*\u_ex*.log' \
  --concurrency=8 \
  --chunk-size=512KB

# Stdin from a forwarder
Get-Content u_ex.log -Tail 10000 | exalm iis analyze
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--file` | — | Path or glob, repeatable. |
| `--concurrency` | 4 | Parallel LLM calls. |
| `--chunk-size` | 512KB | Soft cap per chunk. |

## Concurrent map-reduce

For large or many files, exalm chunks at line boundaries, analyzes each chunk
in parallel, then runs a single reduce step that synthesizes the per-chunk
findings into one report. Set `--concurrency=8` for a 4-core system; respect
the LLM provider's rate limits.

## Redaction

In addition to the global redaction set, opt in with `--redact internal-ipv4`
if the IIS server is behind a reverse proxy and the `c-ip` column shows
RFC1918 addresses you don't want to send to the LLM.

## Try it

```sh
./bin/exalm iis analyze --file examples/iis/u_ex.log
```

The fixture shows a 5xx burst on `/v1/checkout` and a scanner hitting
`/.env`, `/wp-login.php`, and `/admin` — a realistic morning's noise.
