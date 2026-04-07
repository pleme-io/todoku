//! Core HTTP client with authentication, retry, and JSON deserialization.

use crate::auth::{Auth, NoAuth};
use crate::error::{Result, TodokuError};
use crate::retry::RetryPolicy;
use reqwest::header::HeaderMap;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;

/// Shared HTTP client with authentication and retry.
#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
    base_url: Option<String>,
    auth: Arc<dyn Auth>,
    retry: RetryPolicy,
    default_headers: HeaderMap,
}

/// Builder for `HttpClient`.
pub struct HttpClientBuilder {
    base_url: Option<String>,
    auth: Arc<dyn Auth>,
    retry: RetryPolicy,
    timeout: Duration,
    user_agent: String,
    default_headers: HeaderMap,
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self {
            base_url: None,
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::default(),
            timeout: Duration::from_secs(30),
            user_agent: format!("pleme-io/todoku {}", env!("CARGO_PKG_VERSION")),
            default_headers: HeaderMap::new(),
        }
    }
}

impl HttpClientBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    #[must_use]
    pub fn auth(mut self, auth: impl Auth + 'static) -> Self {
        self.auth = Arc::new(auth);
        self
    }

    #[must_use]
    pub fn retry(mut self, policy: RetryPolicy) -> Self {
        self.retry = policy;
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    #[must_use]
    pub fn header(mut self, name: reqwest::header::HeaderName, value: &str) -> Self {
        if let Ok(v) = reqwest::header::HeaderValue::from_str(value) {
            self.default_headers.insert(name, v);
        }
        self
    }

    /// Build the `HttpClient`.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError::Request` if the underlying reqwest client fails to build.
    pub fn build(self) -> Result<HttpClient> {
        let inner = reqwest::Client::builder()
            .timeout(self.timeout)
            .user_agent(&self.user_agent)
            .default_headers(self.default_headers.clone())
            .build()
            .map_err(TodokuError::Request)?;

        Ok(HttpClient {
            inner,
            base_url: self.base_url,
            auth: self.auth,
            retry: self.retry,
            default_headers: self.default_headers,
        })
    }
}

impl HttpClient {
    /// Create a new builder.
    #[must_use]
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::new()
    }

    /// Resolve a path against the base URL.
    fn url(&self, path: &str) -> String {
        match &self.base_url {
            Some(base) => {
                let base = base.trim_end_matches('/');
                let path = path.trim_start_matches('/');
                format!("{base}/{path}")
            }
            None => path.to_string(),
        }
    }

    /// Execute a GET request and deserialize JSON response.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError` on network failure, non-success status, or deserialization failure.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(reqwest::Method::GET, path, None::<&()>).await
    }

    /// Execute a POST request with JSON body and deserialize response.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError` on network failure, non-success status, or deserialization failure.
    pub async fn post<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }

    /// Execute a PUT request with JSON body and deserialize response.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError` on network failure, non-success status, or deserialization failure.
    pub async fn put<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.request(reqwest::Method::PUT, path, Some(body)).await
    }

    /// Execute a DELETE request and deserialize response.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError` on network failure, non-success status, or deserialization failure.
    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(reqwest::Method::DELETE, path, None::<&()>)
            .await
    }

    /// Execute a request with optional body, applying auth and retry.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError` on network failure, non-success status, max retries exceeded,
    /// or deserialization failure.
    pub async fn request<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let url = self.url(path);

        for attempt in 0..=self.retry.max_retries {
            let mut headers = self.default_headers.clone();
            self.auth.apply(&mut headers);

            let mut req = self.inner.request(method.clone(), &url).headers(headers);
            if let Some(b) = body {
                req = req.json(b);
            }

            let response = match req.send().await {
                Ok(r) => r,
                Err(e) if e.is_timeout() => {
                    if attempt < self.retry.max_retries {
                        let backoff = self.retry.backoff_for(attempt);
                        tracing::warn!(
                            attempt,
                            max = self.retry.max_retries,
                            "request timeout, retrying in {backoff:?}"
                        );
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    return Err(TodokuError::Request(e));
                }
                Err(e) => return Err(TodokuError::Request(e)),
            };

            let status = response.status().as_u16();

            if response.status().is_success() {
                let body_text = response.text().await.map_err(TodokuError::Request)?;
                let parsed: T = serde_json::from_str(&body_text)?;
                return Ok(parsed);
            }

            if self.retry.should_retry_status(status) && attempt < self.retry.max_retries {
                let backoff = self.retry.backoff_for(attempt);
                tracing::warn!(
                    status,
                    attempt,
                    max = self.retry.max_retries,
                    "retryable status, retrying in {backoff:?}"
                );
                tokio::time::sleep(backoff).await;
                continue;
            }

            let body_text = response.text().await.unwrap_or_default();
            return Err(TodokuError::Http {
                status,
                body: body_text,
            });
        }

        Err(TodokuError::MaxRetries {
            url,
            max: self.retry.max_retries,
        })
    }

    /// Execute a raw GET request (no JSON deserialization) -- useful for HTML, binary, etc.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError::Request` on network failure.
    pub async fn get_raw(&self, path: &str) -> Result<reqwest::Response> {
        let url = self.url(path);
        let mut headers = self.default_headers.clone();
        self.auth.apply(&mut headers);

        self.inner
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(TodokuError::Request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{BasicAuth, BearerToken, HeaderAuth};
    use reqwest::header::HeaderName;

    // --- URL resolution ---

    #[test]
    fn url_resolution_with_leading_slash() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some("https://api.example.com/v1".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        assert_eq!(client.url("/items"), "https://api.example.com/v1/items");
    }

    #[test]
    fn url_resolution_without_leading_slash() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some("https://api.example.com/v1".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        assert_eq!(client.url("items"), "https://api.example.com/v1/items");
    }

    #[test]
    fn url_no_base() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: None,
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        assert_eq!(
            client.url("https://example.com/api"),
            "https://example.com/api"
        );
    }

    #[test]
    fn url_base_with_trailing_slash() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some("https://api.example.com/v1/".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        // Trailing slash on base and leading slash on path should not double-slash
        assert_eq!(client.url("/items"), "https://api.example.com/v1/items");
    }

    #[test]
    fn url_base_with_trailing_slash_path_no_leading() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some("https://api.example.com/v1/".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        assert_eq!(client.url("items"), "https://api.example.com/v1/items");
    }

    #[test]
    fn url_empty_path() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some("https://api.example.com".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        assert_eq!(client.url(""), "https://api.example.com/");
    }

    #[test]
    fn url_nested_path() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some("https://api.example.com".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        assert_eq!(
            client.url("/a/b/c/d"),
            "https://api.example.com/a/b/c/d"
        );
    }

    #[test]
    fn url_with_query_params() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some("https://api.example.com/v1".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        assert_eq!(
            client.url("/search?q=hello&page=1"),
            "https://api.example.com/v1/search?q=hello&page=1"
        );
    }

    #[test]
    fn url_no_base_returns_path_as_is() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: None,
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        assert_eq!(client.url("/relative/path"), "/relative/path");
    }

    #[test]
    fn url_empty_base() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some(String::new()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        assert_eq!(client.url("/items"), "/items");
    }

    #[test]
    fn url_base_multiple_trailing_slashes() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some("https://api.example.com///".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        // trim_end_matches('/') removes all trailing slashes
        assert_eq!(
            client.url("/items"),
            "https://api.example.com/items"
        );
    }

    #[test]
    fn url_path_multiple_leading_slashes() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some("https://api.example.com".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        // trim_start_matches('/') removes all leading slashes from path
        assert_eq!(
            client.url("///items"),
            "https://api.example.com/items"
        );
    }

    // --- Builder defaults ---

    #[test]
    fn builder_default_no_base_url() {
        let client = HttpClient::builder().build().unwrap();
        assert!(client.base_url.is_none());
    }

    #[test]
    fn builder_default_no_auth() {
        let client = HttpClient::builder().build().unwrap();
        // NoAuth should leave headers empty
        let mut headers = HeaderMap::new();
        client.auth.apply(&mut headers);
        assert!(headers.is_empty());
    }

    #[test]
    fn builder_default_retry_policy() {
        let client = HttpClient::builder().build().unwrap();
        assert_eq!(client.retry.max_retries, 3);
    }

    #[test]
    fn builder_default_headers_empty() {
        let client = HttpClient::builder().build().unwrap();
        assert!(client.default_headers.is_empty());
    }

    // --- Builder with base_url ---

    #[test]
    fn builder_sets_base_url_from_str() {
        let client = HttpClient::builder()
            .base_url("https://api.example.com")
            .build()
            .unwrap();
        assert_eq!(
            client.base_url.as_deref(),
            Some("https://api.example.com")
        );
    }

    #[test]
    fn builder_sets_base_url_from_string() {
        let url = String::from("https://api.example.com");
        let client = HttpClient::builder().base_url(url).build().unwrap();
        assert_eq!(
            client.base_url.as_deref(),
            Some("https://api.example.com")
        );
    }

    #[test]
    fn builder_base_url_last_wins() {
        let client = HttpClient::builder()
            .base_url("https://first.com")
            .base_url("https://second.com")
            .build()
            .unwrap();
        assert_eq!(client.base_url.as_deref(), Some("https://second.com"));
    }

    // --- Builder with auth ---

    #[test]
    fn builder_sets_bearer_auth() {
        let client = HttpClient::builder()
            .auth(BearerToken::new("my-token"))
            .build()
            .unwrap();
        let mut headers = HeaderMap::new();
        client.auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer my-token"
        );
    }

    #[test]
    fn builder_sets_basic_auth() {
        let client = HttpClient::builder()
            .auth(BasicAuth::new("user", "pass"))
            .build()
            .unwrap();
        let mut headers = HeaderMap::new();
        client.auth.apply(&mut headers);
        let val = headers
            .get(reqwest::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(val.starts_with("Basic "));
    }

    #[test]
    fn builder_sets_header_auth() {
        let client = HttpClient::builder()
            .auth(HeaderAuth::new(
                HeaderName::from_static("x-api-key"),
                "secret",
            ))
            .build()
            .unwrap();
        let mut headers = HeaderMap::new();
        client.auth.apply(&mut headers);
        assert_eq!(headers.get("x-api-key").unwrap(), "secret");
    }

    #[test]
    fn builder_auth_last_wins() {
        let client = HttpClient::builder()
            .auth(BearerToken::new("first"))
            .auth(BearerToken::new("second"))
            .build()
            .unwrap();
        let mut headers = HeaderMap::new();
        client.auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer second"
        );
    }

    // --- Builder with retry ---

    #[test]
    fn builder_sets_retry_none() {
        let client = HttpClient::builder()
            .retry(RetryPolicy::none())
            .build()
            .unwrap();
        assert_eq!(client.retry.max_retries, 0);
    }

    #[test]
    fn builder_sets_retry_aggressive() {
        let client = HttpClient::builder()
            .retry(RetryPolicy::aggressive())
            .build()
            .unwrap();
        assert_eq!(client.retry.max_retries, 5);
    }

    #[test]
    fn builder_sets_custom_retry() {
        let policy = RetryPolicy {
            max_retries: 10,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            multiplier: 1.5,
            retry_statuses: vec![503],
        };
        let client = HttpClient::builder().retry(policy).build().unwrap();
        assert_eq!(client.retry.max_retries, 10);
        assert_eq!(client.retry.initial_backoff, Duration::from_millis(100));
        assert_eq!(client.retry.multiplier, 1.5);
        assert!(client.retry.should_retry_status(503));
        assert!(!client.retry.should_retry_status(429));
    }

    // --- Builder with timeout ---

    #[test]
    fn builder_sets_timeout() {
        // We can't directly inspect the reqwest Client's timeout,
        // but we verify the builder chain compiles and builds successfully.
        let client = HttpClient::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap();
        // Client was built successfully with custom timeout
        assert!(client.base_url.is_none());
    }

    // --- Builder with user_agent ---

    #[test]
    fn builder_sets_user_agent() {
        // Similar to timeout, we verify the builder chain works.
        let client = HttpClient::builder()
            .user_agent("my-app/1.0")
            .build()
            .unwrap();
        assert!(client.base_url.is_none());
    }

    // --- Builder with default headers ---

    #[test]
    fn builder_sets_custom_header() {
        let client = HttpClient::builder()
            .header(
                reqwest::header::ACCEPT,
                "application/json",
            )
            .build()
            .unwrap();
        assert_eq!(
            client
                .default_headers
                .get(reqwest::header::ACCEPT)
                .unwrap(),
            "application/json"
        );
    }

    #[test]
    fn builder_sets_multiple_headers() {
        let client = HttpClient::builder()
            .header(reqwest::header::ACCEPT, "application/json")
            .header(
                HeaderName::from_static("x-request-id"),
                "abc-123",
            )
            .build()
            .unwrap();
        assert_eq!(client.default_headers.len(), 2);
        assert_eq!(
            client
                .default_headers
                .get(reqwest::header::ACCEPT)
                .unwrap(),
            "application/json"
        );
        assert_eq!(
            client.default_headers.get("x-request-id").unwrap(),
            "abc-123"
        );
    }

    // --- Builder full chain ---

    #[test]
    fn builder_full_chain() {
        let client = HttpClient::builder()
            .base_url("https://api.example.com/v2")
            .auth(BearerToken::new("token123"))
            .retry(RetryPolicy::aggressive())
            .timeout(Duration::from_secs(10))
            .user_agent("test-agent/0.1")
            .header(reqwest::header::ACCEPT, "application/json")
            .build()
            .unwrap();

        assert_eq!(
            client.base_url.as_deref(),
            Some("https://api.example.com/v2")
        );
        assert_eq!(client.retry.max_retries, 5);

        let mut headers = HeaderMap::new();
        client.auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer token123"
        );
    }

    // --- HttpClient::builder() static method ---

    #[test]
    fn static_builder_method() {
        // Ensure HttpClient::builder() returns a working builder
        let builder = HttpClient::builder();
        let client = builder.build().unwrap();
        assert!(client.base_url.is_none());
    }

    // --- Clone ---

    #[test]
    fn client_is_cloneable() {
        let client = HttpClient::builder()
            .base_url("https://api.example.com")
            .retry(RetryPolicy::aggressive())
            .build()
            .unwrap();
        let cloned = client.clone();
        assert_eq!(cloned.base_url, client.base_url);
        assert_eq!(cloned.retry.max_retries, client.retry.max_retries);
    }

    // --- URL resolution with built client ---

    #[test]
    fn built_client_url_resolution() {
        let client = HttpClient::builder()
            .base_url("https://api.example.com/v1")
            .build()
            .unwrap();
        assert_eq!(client.url("/users"), "https://api.example.com/v1/users");
        assert_eq!(client.url("users"), "https://api.example.com/v1/users");
    }

    #[test]
    fn built_client_no_base_url_resolution() {
        let client = HttpClient::builder().build().unwrap();
        assert_eq!(
            client.url("https://other.com/api"),
            "https://other.com/api"
        );
    }
}
