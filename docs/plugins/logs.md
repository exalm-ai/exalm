# `exalm logs`

Root-cause analysis for any plaintext log content. Accepts input from stdin
or `--file`. Redacts secrets before sending to the LLM. Returns a structured
Markdown or JSON report with verdict, evidence, likely causes, and next steps.

---

## Usage

```sh
# Pipe from stdin
cat /var/log/syslog | exalm logs summarize

# From a file
exalm logs summarize --file ./app.log

# JSON output
exalm logs summarize --file ./app.log --output json

# Use a specific provider for this call
cat app.log | exalm logs summarize --provider claude
```

---

## Subcommands

### `exalm logs summarize`

Reads up to 200 KB of log content, redacts secrets and PII, sends it to
the configured LLM, and returns a root-cause-oriented summary.

| Flag | Default | Description |
|---|---|---|
| `--file` | — | Read input from this file instead of stdin |

If neither `--file` nor stdin is provided, the command exits with an error.

---

## Input limits

Input is capped at **200 KB** (approximately 50 000 tokens). If your log
file is larger, pipe a relevant slice:

```sh
# Last 5000 lines
tail -n 5000 /var/log/app.log | exalm logs summarize

# Last hour (systemd journal)
journalctl --since "1 hour ago" | exalm logs summarize

# Specific service
journalctl -u nginx --since "2 hours ago" | exalm logs summarize
```

---

## Output formats

### Markdown (default)

```
# Log analysis

Analyzed 18432 bytes of log content using claude.

**Verdict:** Likely OOM kill of the `payments-api` pod under burst load.

**Evidence:**
    Memory cgroup out of memory: Killed process 8123 (payments-api)
    ...

**Likely causes:**
- Memory limit too low for current request volume
- Recent dependency upgrade (libgo-7.2) increased baseline RSS by ~30%

**Suggested next steps:**
1. Raise the memory limit on the payments-api Deployment to 1.5x current
2. Capture a heap profile during peak traffic
```

### JSON

```sh
cat app.log | exalm logs summarize --output json
```

```json
{
  "title": "Log analysis",
  "summary": "Analyzed 18432 bytes of log content using claude.",
  "raw": "...",
  "findings": []
}
```

---

## Redaction

All data is redacted before leaving your machine. The default patterns cover:

- AWS access keys and secret keys
- Anthropic and OpenAI API keys
- Bearer tokens and Authorization headers
- Private key blocks (RSA, EC, Ed25519)
- JWTs
- Connection strings (database URLs with embedded credentials)
- Password assignments in config files

Pass `--show-redactions` to print a summary of what was redacted:

```sh
cat app.log | exalm logs summarize --show-redactions
```

Optional patterns (higher false-positive rate) can be enabled via
`EXALM_OPTIONAL_REDACTIONS`:

```sh
export EXALM_OPTIONAL_REDACTIONS=email,ipv4
cat app.log | exalm logs summarize
```

---

## Try it

```sh
./bin/exalm logs summarize --file examples/logs/oom-kill.log
```
