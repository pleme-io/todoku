# Todoku (届く) — HTTP Client Framework

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before non-trivial changes.


## Build & Test

```bash
cargo build
cargo test --lib
```

## Architecture

Shared authenticated HTTP client with retry and JSON deserialization. Wraps reqwest
so every pleme-io app with API calls uses the same patterns.

### Modules

| Module | Purpose |
|--------|---------|
| `client.rs` | `HttpClient`, `HttpClientBuilder` — builder, get/post/put/delete/get_raw; `Transport` enum (Reqwest \| Stealth) + async `guard_url` SSRF hook |
| `auth.rs` | `Auth` trait, `BearerToken`, `BasicAuth`, `HeaderAuth`, `NoAuth` |
| `retry.rs` | `RetryPolicy`, `retry_with_backoff`, `RetryError` — exponential backoff, generic loop for any flaky async op |
| `tls.rs` | `TlsProfile` — `Rustls` (default) + `Chrome`/`Firefox`/`Safari` JA3/JA4 browser-fingerprint emulation (via `wreq`, behind the `stealth` feature). `is_emulated`/`requires_stealth`/`available`. (Obscura absorption.) |
| `ssrf.rs` | `SsrfReason` (10 variants) + `classify_ip` + `check_url` / `check_url_resolved` — SSRF guard that rejects loopback/private/link-local/metadata targets, at parse-time AND DNS-resolution-time (`tokio::net::lookup_host`). Opt-in via the builder's `ssrf_guard`. (Obscura absorption.) |
| `blocking.rs` | `BlockingHttpClient` + `HttpResponse` — a **sync facade** over the async `HttpClient` (owns a current-thread `Runtime`, `rt.block_on`). Solve-once for sync callers (e.g. nami-core's `FetchClient`) so there is ONE fleet HTTP implementation, not a parallel blocking client. |
| `github.rs` | `GitHubApi`/`GitHubClient`/`GitHubRepo` — typed GitHub REST surface over `HttpClient` |
| `error.rs` | `TodokuError` — request, HTTP status, max retries, JSON parse, `Ssrf(SsrfReason)`, `UnsupportedTlsProfile`, `Runtime` |

### Features

| Feature | Enables | Optional deps |
|---------|---------|---------------|
| (default) | rustls transport, SSRF guard, blocking facade, retry, GitHub | none |
| `stealth` | `TlsProfile::{Chrome,Firefox,Safari}` JA3/JA4 emulation via the `wreq` transport | `wreq`, `wreq-util` |

### Consumers

Used by: kagi (1Password API), kekkai (NordVPN API), nami / nami-core (web
fetching, via `BlockingHttpClient`), fumi (Slack REST), hibiki (metadata APIs)

## Design Decisions

- **Builder pattern**: `HttpClient::builder().base_url(...).auth(...).retry(...).build()`
- **Auth trait**: pluggable authentication (Bearer, Basic, custom header)
- **Retry with backoff**: exponential backoff on timeout and configurable status codes
- **Generic retry loop**: `retry_with_backoff(&policy, op, should_retry)` — promotes
  `RetryPolicy` to the canonical fleet retry primitive. Any pleme-io binary with a
  flaky async op (NATS publish, DB write, subprocess call, file I/O) consumes this
  instead of hand-rolling its own `RetryConfig` + retry loop. See `retry.rs` for the
  contract; returns `RetryError<E>` (`Exhausted` / `NonRetryable`).
- **get_raw()**: for non-JSON responses (HTML, binary)
- **Sync over async (solve-once)**: `BlockingHttpClient` is the ONE blocking
  entry point — it wraps the async `HttpClient` behind a current-thread runtime
  rather than maintaining a second client. Sync consumers (nami-core) never grow
  their own HTTP stack.
- **SSRF is opt-in but DNS-aware**: `check_url_resolved` resolves the host and
  re-classifies every resolved IP, so a domain that resolves to `169.254.169.254`
  or `127.0.0.1` is rejected even though the URL string looked public.
- **TLS fingerprint emulation is a feature, not a default**: `stealth` pulls in
  `wreq` only when a caller needs Chrome/Firefox/Safari JA3/JA4 emulation; the
  default build stays rustls-only with zero extra deps.
- **Does NOT do** WebSocket, gRPC, or non-HTTP protocols
