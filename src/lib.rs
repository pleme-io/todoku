//! Todoku (届く) — Shared authenticated HTTP client with retry and JSON deserialization.
//!
//! Wraps [`reqwest`] so every pleme-io app with API calls uses the same
//! builder pattern, pluggable auth, and exponential-backoff retry.

pub mod auth;
pub mod blocking;
pub mod client;
pub mod credentials;
pub mod error;
pub mod github;
pub mod retry;
pub mod ssrf;
pub mod tls;

pub use auth::{Auth, BasicAuth, BearerToken, HeaderAuth, NoAuth};
pub use blocking::{BlockingHttpClient, HttpResponse};
pub use client::{HttpClient, HttpClientBuilder};
pub use credentials::{
    CredentialError, CredentialTable, OwnerEntry, Resolution, Token, owner_from_remote_url,
    owner_from_repo_arg,
};
pub use error::TodokuError;
pub use github::{FileInfo, GitHubApi, GitHubClient, GitHubRepo, OwnerType};
pub use retry::{Idempotency, RetryError, RetryPolicy, parse_retry_after, retry_with_backoff};
pub use ssrf::{SsrfReason, check_url, classify_ip};
pub use tls::TlsProfile;
