# `exalm syslog`

Analyze Linux syslog and `journalctl` output.

## Input formats

Auto-detected per line:

- **RFC 5424** — `<PRI>VERSION TIMESTAMP HOST APP PROCID MSGID MSG`
- **RFC 3164** with PRI — `<PRI>MMM dd hh:mm:ss host tag: msg`
- **Bare BSD** syslog (no PRI) — common in `/var/log/messages`
- **journalctl JSON** — `journalctl -o json` one-object-per-line

Events with PRIORITY > 4 (notice/info/debug) are filtered out by default —
the model focuses on warnings, errors, and worse.

## Usage

```sh
# Live system journal (warnings and worse)
journalctl -p warning -n 5000 -o json | exalm syslog analyze

# Across /var/log/*.log files
exalm syslog analyze --file '/var/log/messages*' --concurrency=8

# Multi-host investigation
exalm syslog analyze --file 'web*/messages' --file 'db*/messages'
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--file` | — | Path or glob, repeatable. |
| `--concurrency` | 4 | Parallel LLM calls. |
| `--chunk-size` | 256KB | Soft cap per chunk. |

## Redaction

In addition to the default set:

- Opt-in: `--redact linux-username` redacts usernames in sshd/sudo lines
  (matches `password for X`, `session opened for user X`, `Invalid user X`,
  `USER=X`). Off by default because usernames are often legitimate signal.
- Opt-in: `--redact internal-ipv4` redacts RFC1918 IPs in source addresses.

## Try it

```sh
./bin/exalm syslog analyze --file examples/syslog/messages.log
./bin/exalm syslog analyze --file examples/syslog/journal.jsonl
```

The fixture pairs an sshd brute-force pattern from `198.51.100.40` with an
OOM kill on `payments-api`, plus an `upstream timed out` storm in the
journal — three independent stories you'd otherwise have to piece together
by eye.
