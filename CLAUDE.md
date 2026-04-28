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
| `client.rs` | `HttpClient`, `HttpClientBuilder` — builder, get/post/put/delete/get_raw |
| `auth.rs` | `Auth` trait, `BearerToken`, `BasicAuth`, `HeaderAuth`, `NoAuth` |
| `retry.rs` | `RetryPolicy`, `retry_with_backoff`, `RetryError` — exponential backoff, generic loop for any flaky async op |
| `error.rs` | `TodokuError` — request, HTTP status, max retries, JSON parse |

### Consumers

Used by: kagi (1Password API), kekkai (NordVPN API), nami (web fetching),
fumi (Slack REST), hibiki (metadata APIs)

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
- **Does NOT do** WebSocket, gRPC, or non-HTTP protocols
