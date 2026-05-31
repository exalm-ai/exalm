# `exalm httplog`

Analyze Apache and nginx access and error logs.

> Why "httplog" and not "web"? The CLI already uses `web` as an output mode
> (`--output web`) and the package name `web` is taken in `internal/web`.
> `httplog` reads cleanly: `exalm httplog analyze`.

## What it does

Detects per line:

- **Combined Log Format** access records — extracts IP, method, URI, status,
  optionally response time (last field if numeric)
- **nginx error log** — `YYYY/MM/DD HH:MM:SS [level] pid#tid: msg`
- **Apache error log** — `[date] [level] [pid] [client IP] msg`

Surfaces top status codes, 5xx bursts, slow requests (≥5s), and a sample of
error-log lines for context. The prompt is tuned for web operators and flags
scanner traffic (`/.env`, `/wp-login`, traversal) under "SUSPICIOUS REQUESTS".

## Usage

```sh
# nginx access log
exalm httplog analyze --file /var/log/nginx/access.log

# Both access and error logs together
exalm httplog analyze \
  --file /var/log/nginx/access.log \
  --file /var/log/nginx/error.log

# Many sites, concurrently
exalm httplog analyze --file '/var/log/nginx/*-access.log' --concurrency=8

# Apache
exalm httplog analyze --file /var/log/apache2/error.log
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--file` | — | Path or glob, repeatable. |
| `--concurrency` | 4 | Parallel LLM calls. |
| `--chunk-size` | 512KB | Soft cap per chunk. |

## Try it

```sh
./bin/exalm httplog analyze \
  --file examples/httplog/nginx-access.log \
  --file examples/httplog/apache-error.log
```

The fixtures combine a checkout-endpoint 5xx burst, a scanner from
`198.51.100.99`, and a ModSecurity traversal block — exactly the kind of
correlated signal the reduce step is designed to merge.
