# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest (`main`) | ✅ |
| older releases | ❌ — please upgrade |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Send a report by email to **security@exalm.com** with:

1. A description of the vulnerability and the potential impact
2. Steps to reproduce (proof-of-concept code or a detailed walkthrough)
3. The version of Exalm you are using (`exalm --version`)
4. Your name / handle for the acknowledgement section (optional)

We aim to acknowledge receipt within **48 hours** and to publish a fix within
**14 days** for critical issues.

## Scope

The following are **in scope** for security reports:

- The Exalm CLI binary and all plugins under `plugins/`
- The web dashboard served by `exalm serve`
- The redaction engine (`internal/redact/`) — any bypass that causes secrets
  to be sent to the LLM without redaction is a **critical** finding
- The Terraform webhook receiver (`internal/webhook/`)
- The SSH client and TOFU host-key verification (`internal/ssh/`)
- The Hubble gRPC client (`internal/network/`)

The following are **out of scope**:

- Vulnerabilities in third-party LLM providers (Claude, OpenAI, etc.)
- Issues that require physical access to the machine running Exalm
- Social engineering attacks
- Vulnerabilities only exploitable by a user with full filesystem access

## Responsible Disclosure

We follow the [CVD (Coordinated Vulnerability Disclosure)](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)
model. We will credit researchers in the release notes unless they prefer
to remain anonymous.

## Known Security Posture

### What Exalm does to protect your data

- **Redaction before every LLM call**: All environment data passes through
  `internal/redact/` before it is sent to any LLM provider. The redaction
  engine contains 28+ patterns covering API keys, passwords, tokens, IP
  addresses, email addresses, and more.
- **No telemetry by default**: Exalm does not phone home. There is no
  analytics, crash reporting, or usage tracking unless you explicitly
  opt in.
- **Secret-free binary**: The binary contains no embedded API keys or
  credentials. All secrets are read from environment variables at runtime.

### Known limitations

- **The web dashboard (`exalm serve`) is unauthenticated by default.**
  Use `--token` or the `EXALM_TOKEN` environment variable to require a
  Bearer token. Never expose the dashboard port outside localhost without
  a token set.
- **TOFU host-key verification** is used for SSH connections. The first
  connection to a new host is auto-accepted and stored in
  `~/.exalm/known_hosts`. Use `--ssh-strict-host-key` to reject unknown
  hosts instead of auto-accepting them.
- **File-based persistence** (`~/.exalm/`) has no encryption at rest.
  DORA deployment records and incident JSON files are stored in plaintext.
  Ensure your home directory has appropriate permissions (`chmod 700 ~/.exalm`).

### CSRF protection

The web dashboard's mutating API endpoints (`/api/fix`, `/api/fix-all`,
`/api/create-pr`) require a custom HTTP header on every request:

```
X-Exalm-Request: true
```

**Attack scenario without this header**: Any webpage loaded in a browser that
can reach `http://localhost:7433` could send a `fetch('/api/fix', { method:
'POST', ... })` request. The browser would include any active session state,
meaning a malicious tab could trigger pod deletions or workload restarts
without user consent — a classic cross-site request forgery (CSRF) attack.

**Why the custom header works**: Browsers apply CORS restrictions to
cross-origin requests. Adding a custom header (`X-Exalm-Request`) to a
cross-origin `fetch()` triggers a CORS preflight. Because the Exalm server
does not respond with permissive `Access-Control-Allow-Origin` or
`Access-Control-Allow-Headers` headers, the browser blocks the preflight
and the malicious request never reaches the server. The Exalm dashboard
itself (a same-origin page) always includes the header via `fetch()` in
`static/app.js`.

As a defence-in-depth measure, the server also validates the `Origin` header
when it is present: any origin that is not `localhost` or `127.0.0.1` is
rejected with HTTP 403.
