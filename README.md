# todoku (届く)

Shared authenticated HTTP client with retry and JSON deserialization.

Wraps [`reqwest`] so every pleme-io app that talks to an API uses one builder
pattern, one pluggable auth model, and one exponential-backoff retry policy —
rather than each service re-deriving its own.

## Modules

| Module | What it gives you |
|---|---|
| `client` | `HttpClient` + `HttpClientBuilder` — the async entry point |
| `blocking` | `BlockingHttpClient` + `HttpResponse` for non-async callers |
| `auth` | `Auth` trait with `BearerToken`, `BasicAuth`, `HeaderAuth`, `NoAuth` |
| `retry` | `RetryPolicy`, `retry_with_backoff`, `Idempotency`, `parse_retry_after` |
| `github` | `GitHubClient` / `GitHubApi` — a typed GitHub surface built on the above |
| `ssrf` | `check_url` / `classify_ip` — SSRF classification before a request leaves |
| `tls` | `TlsProfile` |
| `error` | `TodokuError` |

## Usage

```toml
[dependencies]
todoku = "0.1"
```

```rust
use todoku::{HttpClientBuilder, BearerToken};

let client = HttpClientBuilder::new()
    .auth(BearerToken::new(token))
    .build()?;
```

`retry_with_backoff` honours a server's `Retry-After` (see `parse_retry_after`)
and takes an `Idempotency` marker, so a non-idempotent request is never
silently replayed.

## License

MIT — see [LICENSE](./LICENSE).
