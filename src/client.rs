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

    #[test]
    fn url_resolution() {
        let client = HttpClient {
            inner: reqwest::Client::new(),
            base_url: Some("https://api.example.com/v1".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
        };
        assert_eq!(client.url("/items"), "https://api.example.com/v1/items");
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
}
