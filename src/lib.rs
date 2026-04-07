//! Todoku (届く) — Shared authenticated HTTP client with retry and JSON deserialization.
//!
//! Wraps [`reqwest`] so every pleme-io app with API calls uses the same
//! builder pattern, pluggable auth, and exponential-backoff retry.

pub mod auth;
pub mod client;
pub mod error;
pub mod github;
pub mod retry;

pub use auth::{Auth, BasicAuth, BearerToken, HeaderAuth, NoAuth};
pub use client::{HttpClient, HttpClientBuilder};
pub use error::TodokuError;
pub use github::{FileInfo, GitHubApi, GitHubClient, GitHubRepo, OwnerType};
pub use retry::RetryPolicy;
