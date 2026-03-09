# Todoku (届く) — HTTP Client Framework

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
| `retry.rs` | `RetryPolicy` — exponential backoff, configurable retryable status codes |
| `error.rs` | `TodokuError` — request, HTTP status, max retries, JSON parse |

### Consumers

Used by: kagi (1Password API), kekkai (NordVPN API), nami (web fetching),
fumi (Slack REST), hibiki (metadata APIs)

## Design Decisions

- **Builder pattern**: `HttpClient::builder().base_url(...).auth(...).retry(...).build()`
- **Auth trait**: pluggable authentication (Bearer, Basic, custom header)
- **Retry with backoff**: exponential backoff on timeout and configurable status codes
- **get_raw()**: for non-JSON responses (HTML, binary)
- **Does NOT do** WebSocket, gRPC, or non-HTTP protocols
