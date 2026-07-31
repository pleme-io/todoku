//! Core HTTP client with authentication, retry, and JSON deserialization.

use crate::auth::{Auth, NoAuth};
use crate::error::{Result, TodokuError};
use crate::retry::{Idempotency, RetryPolicy};
use crate::tls::TlsProfile;
use reqwest::header::HeaderMap;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;

/// Shared HTTP client with authentication and retry.
#[derive(Clone)]
pub struct HttpClient {
    inner: Transport,
    base_url: Option<String>,
    auth: Arc<dyn Auth>,
    retry: RetryPolicy,
    default_headers: HeaderMap,
    /// When `true`, every resolved request URL is run through
    /// [`crate::ssrf::check_url`] before sending; a forbidden target returns
    /// [`TodokuError::Ssrf`] instead of a network call. Off by default.
    ssrf_guard: bool,
}

/// The concrete HTTP/TLS stack behind an [`HttpClient`].
///
/// `Reqwest` (rustls) is always available; `Stealth` (wreq / browser
/// JA3-JA4 emulation) is only compiled with the `stealth` feature. The
/// [`TlsProfile`] on the builder selects which one `build()` constructs.
#[derive(Clone)]
enum Transport {
    Reqwest(reqwest::Client),
    #[cfg(feature = "stealth")]
    Stealth(wreq::Client),
}

/// A completed HTTP exchange, normalized across transports.
struct RawResponse {
    status: u16,
    body: String,
    /// The server's own `Retry-After`, parsed at the transport because the
    /// header set is dropped when the body is consumed. `None` means the
    /// server did not ask for a specific delay (or asked in the HTTP-date
    /// form todoku does not parse — see [`crate::retry::parse_retry_after`]),
    /// and the caller falls back to its exponential backoff.
    retry_after: Option<std::time::Duration>,
}

/// A transport-level send failure, carrying whether it was a timeout so the
/// retry loop can decide to retry without depending on a concrete error type.
struct TransportError {
    is_timeout: bool,
    err: TodokuError,
}

impl Transport {
    /// Send one request and read the full body, regardless of status code.
    /// The caller's retry loop interprets the status; transport errors carry
    /// `is_timeout` so the loop stays transport-agnostic.
    async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: HeaderMap,
        body: Option<&serde_json::Value>,
    ) -> std::result::Result<RawResponse, TransportError> {
        match self {
            Transport::Reqwest(c) => {
                let mut req = c.request(method, url).headers(headers);
                if let Some(b) = body {
                    req = req.json(b);
                }
                let resp = req.send().await.map_err(|e| TransportError {
                    is_timeout: e.is_timeout(),
                    err: TodokuError::Request(e),
                })?;
                let status = resp.status().as_u16();
                let retry_after = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(crate::retry::parse_retry_after);
                let body = resp.text().await.map_err(|e| TransportError {
                    is_timeout: false,
                    err: TodokuError::Request(e),
                })?;
                Ok(RawResponse {
                    status,
                    body,
                    retry_after,
                })
            }
            #[cfg(feature = "stealth")]
            Transport::Stealth(c) => {
                let wmethod =
                    wreq::Method::from_bytes(method.as_str().as_bytes()).map_err(|_| {
                        TransportError {
                            is_timeout: false,
                            err: TodokuError::StealthRequest(
                                "invalid HTTP method for stealth transport".to_string(),
                            ),
                        }
                    })?;
                let mut wheaders = wreq::header::HeaderMap::new();
                for (k, v) in headers.iter() {
                    if let (Ok(name), Ok(val)) = (
                        wreq::header::HeaderName::from_bytes(k.as_str().as_bytes()),
                        wreq::header::HeaderValue::from_bytes(v.as_bytes()),
                    ) {
                        wheaders.insert(name, val);
                    }
                }
                let mut req = c.request(wmethod, url).headers(wheaders);
                if let Some(b) = body {
                    req = req.json(b);
                }
                let resp = req.send().await.map_err(|e| TransportError {
                    is_timeout: e.is_timeout(),
                    err: TodokuError::stealth(e),
                })?;
                let status = resp.status().as_u16();
                let retry_after = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(crate::retry::parse_retry_after);
                let body = resp.text().await.map_err(|e| TransportError {
                    is_timeout: false,
                    err: TodokuError::stealth(e),
                })?;
                Ok(RawResponse {
                    status,
                    body,
                    retry_after,
                })
            }
        }
    }
}

/// Build a browser-emulating (wreq/BoringSSL) client for an emulated profile.
///
/// NOTE: the [`wreq_util::Emulation`] variant names track browser releases —
/// verify them against the pinned `wreq-util` version when bumping.
#[cfg(feature = "stealth")]
fn build_stealth_client(
    profile: TlsProfile,
    timeout: Duration,
    user_agent: &str,
    headers: &HeaderMap,
) -> Result<wreq::Client> {
    use wreq_util::Emulation;
    let emulation = match profile {
        TlsProfile::Chrome => Emulation::Chrome136,
        TlsProfile::Firefox => Emulation::Firefox136,
        TlsProfile::Safari => Emulation::Safari18,
        TlsProfile::Rustls => {
            return Err(TodokuError::UnsupportedTlsProfile {
                profile: TlsProfile::Rustls.as_str(),
                reason: "rustls is served by the default transport, not the stealth transport",
            });
        }
    };
    let mut wheaders = wreq::header::HeaderMap::new();
    for (k, v) in headers.iter() {
        if let (Ok(name), Ok(val)) = (
            wreq::header::HeaderName::from_bytes(k.as_str().as_bytes()),
            wreq::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            wheaders.insert(name, val);
        }
    }
    wreq::Client::builder()
        .emulation(emulation)
        .timeout(timeout)
        .user_agent(user_agent)
        .default_headers(wheaders)
        .build()
        .map_err(TodokuError::stealth)
}

/// Builder for `HttpClient`.
pub struct HttpClientBuilder {
    base_url: Option<String>,
    auth: Arc<dyn Auth>,
    retry: RetryPolicy,
    timeout: Duration,
    user_agent: String,
    default_headers: HeaderMap,
    tls_profile: TlsProfile,
    ssrf_guard: bool,
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
            tls_profile: TlsProfile::default(),
            // Off by default to preserve existing behavior — consumers opt in.
            ssrf_guard: false,
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

    /// Select the TLS fingerprint the client presents on the wire.
    ///
    /// The default ([`TlsProfile::Rustls`]) is the honest reqwest+rustls
    /// fingerprint. Browser-emulating profiles ([`TlsProfile::Chrome`] etc.)
    /// require the `stealth` feature; requesting one without it makes
    /// [`Self::build`] return [`TodokuError::UnsupportedTlsProfile`] rather
    /// than silently using the rustls fingerprint.
    #[must_use]
    pub fn tls_profile(mut self, profile: TlsProfile) -> Self {
        self.tls_profile = profile;
        self
    }

    /// Enable (or disable) the SSRF guard.
    ///
    /// When enabled, every resolved request URL is checked by
    /// [`crate::ssrf::check_url`] before any network call: non-http(s) schemes,
    /// missing hosts, and IP-literal hosts in private / loopback / link-local /
    /// CGNAT / ULA / multicast / cloud-metadata ranges are rejected with a
    /// typed [`TodokuError::Ssrf`]. Off by default to preserve existing
    /// behavior; hostname DNS-time resolution is a documented follow-up.
    #[must_use]
    pub fn ssrf_guard(mut self, enabled: bool) -> Self {
        self.ssrf_guard = enabled;
        self
    }

    /// Build the `HttpClient`.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError::Request` if the underlying client fails to build,
    /// or `TodokuError::UnsupportedTlsProfile` if an emulated [`TlsProfile`]
    /// was requested without the `stealth` feature.
    pub fn build(self) -> Result<HttpClient> {
        let inner = self.build_transport()?;
        Ok(HttpClient {
            inner,
            base_url: self.base_url,
            auth: self.auth,
            retry: self.retry,
            default_headers: self.default_headers,
            ssrf_guard: self.ssrf_guard,
        })
    }

    /// Construct the concrete transport for the selected [`TlsProfile`].
    fn build_transport(&self) -> Result<Transport> {
        if self.tls_profile.is_emulated() {
            #[cfg(feature = "stealth")]
            {
                let c = build_stealth_client(
                    self.tls_profile,
                    self.timeout,
                    &self.user_agent,
                    &self.default_headers,
                )?;
                return Ok(Transport::Stealth(c));
            }
            #[cfg(not(feature = "stealth"))]
            {
                return Err(TodokuError::UnsupportedTlsProfile {
                    profile: self.tls_profile.as_str(),
                    reason: "rebuild todoku with the `stealth` feature to enable browser TLS emulation",
                });
            }
        }

        let c = reqwest::Client::builder()
            .timeout(self.timeout)
            .user_agent(&self.user_agent)
            .default_headers(self.default_headers.clone())
            .build()
            .map_err(TodokuError::Request)?;
        Ok(Transport::Reqwest(c))
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

    /// Run the SSRF guard on a resolved URL when enabled — including DNS-time
    /// resolution of hostname hosts ([`crate::ssrf::check_url_resolved`]).
    ///
    /// A no-op when `ssrf_guard` is off (preserving existing behavior). When on,
    /// parses `url`, rejects forbidden IP-literal targets, and resolves hostname
    /// hosts to re-check every address — blocking `metadata.google.internal`-style
    /// names and DNS-rebinding hosts with [`TodokuError::Ssrf`]. A URL that fails
    /// to parse passes through here — the underlying transport surfaces its own
    /// typed error so the guard never masks a genuine malformed-URL signal.
    async fn guard_url(&self, url: &str) -> Result<()> {
        if !self.ssrf_guard {
            return Ok(());
        }
        match url::Url::parse(url) {
            Ok(parsed) => crate::ssrf::check_url_resolved(&parsed)
                .await
                .map_err(TodokuError::Ssrf),
            Err(_) => Ok(()),
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
    /// Execute a request, deriving retry-safety from the method's own HTTP
    /// semantics ([`Idempotency::Inherent`]).
    ///
    /// GET/PUT/DELETE/HEAD/OPTIONS retry; **POST and PATCH do not**, because
    /// re-sending them can duplicate an effect the server already applied.
    /// To opt a POST into retrying, use [`Self::request_with_idempotency`]
    /// with a key the target API actually honors.
    pub async fn request<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        self.request_with_idempotency(method, path, body, &Idempotency::Inherent)
            .await
    }

    /// Execute a request with an explicit idempotency declaration.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError` on network failure, non-success status, max
    /// retries exceeded, or deserialization failure — and
    /// [`TodokuError::Indeterminate`] when a non-idempotent request fails in a
    /// way that cannot distinguish "never applied" from "applied, response
    /// lost". A caller receiving `Indeterminate` must **re-observe** the
    /// remote; it must never re-send.
    pub async fn request_with_idempotency<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
        idempotency: &Idempotency,
    ) -> Result<T> {
        let url = self.url(path);
        self.guard_url(&url).await?;
        let body_value = match body {
            Some(b) => Some(serde_json::to_value(b)?),
            None => None,
        };

        // DERIVED, not authored — see RetryPolicy::is_retry_safe. When this is
        // false the loop below runs exactly once, so a non-idempotent write is
        // never re-sent no matter what the status or the policy says.
        let retry_safe = RetryPolicy::is_retry_safe(&method, idempotency);

        for attempt in 0..=self.retry.max_retries {
            let mut headers = self.default_headers.clone();
            self.auth.apply(&mut headers);
            if let Idempotency::Key(key) = idempotency
                && let Ok(v) = reqwest::header::HeaderValue::from_str(key)
            {
                headers.insert("idempotency-key", v);
            }

            match self
                .inner
                .send(method.clone(), &url, headers, body_value.as_ref())
                .await
            {
                Ok(raw) => {
                    if (200..300).contains(&raw.status) {
                        let parsed: T = serde_json::from_str(&raw.body)?;
                        return Ok(parsed);
                    }

                    // A retryable status on an unsafe request is still a
                    // refusal to re-send: 503 means "not now", but we cannot
                    // know the first attempt did not land.
                    if retry_safe
                        && self.retry.should_retry_status(raw.status)
                        && attempt < self.retry.max_retries
                    {
                        // The server's own ask wins over our guess.
                        let backoff = raw
                            .retry_after
                            .unwrap_or_else(|| self.retry.backoff_for(attempt));
                        tracing::warn!(
                            status = raw.status,
                            attempt,
                            max = self.retry.max_retries,
                            server_asked = raw.retry_after.is_some(),
                            "retryable status, retrying in {backoff:?}"
                        );
                        tokio::time::sleep(backoff).await;
                        continue;
                    }

                    return Err(TodokuError::Http {
                        status: raw.status,
                        body: raw.body,
                    });
                }
                Err(te) => {
                    if te.is_timeout {
                        if retry_safe && attempt < self.retry.max_retries {
                            let backoff = self.retry.backoff_for(attempt);
                            tracing::warn!(
                                attempt,
                                max = self.retry.max_retries,
                                "request timeout, retrying in {backoff:?}"
                            );
                            tokio::time::sleep(backoff).await;
                            continue;
                        }
                        if !retry_safe {
                            // The whole point: neither Ok nor a plain Err is
                            // true here. Say so instead of guessing.
                            tracing::warn!(
                                method = %method,
                                url = %url,
                                "timeout on a non-idempotent request — outcome unknown, not retrying"
                            );
                            return Err(TodokuError::Indeterminate {
                                method: method.to_string(),
                                url,
                            });
                        }
                    }
                    return Err(te.err);
                }
            }
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
        self.guard_url(&url).await?;
        let mut headers = self.default_headers.clone();
        self.auth.apply(&mut headers);

        match &self.inner {
            Transport::Reqwest(c) => c
                .get(&url)
                .headers(headers)
                .send()
                .await
                .map_err(TodokuError::Request),
            #[cfg(feature = "stealth")]
            Transport::Stealth(_) => Err(TodokuError::StealthRawUnsupported),
        }
    }
}

#[cfg(test)]
mod retry_safety_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A socket that accepts and NEVER answers, counting accepts. The count is
    /// the evidence: it measures how many times the request actually hit the
    /// wire, which is the only thing that distinguishes "did not retry" from
    /// "retried and we could not tell".
    async fn hanging_server() -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepts);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(stream); // hold open, never write a response
            }
        });
        (format!("http://{addr}"), accepts)
    }

    fn fast_retry() -> RetryPolicy {
        RetryPolicy {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
            ..Default::default()
        }
    }

    /// THE REGRESSION THIS FIX EXISTS FOR. Before it, a POST whose response was
    /// lost to a timeout was silently re-sent up to `max_retries` times — so a
    /// Jira comment the server had already accepted appeared 2-4 times while
    /// the caller saw one `Ok`. Delete the `retry_safe` gate in `request_with_
    /// idempotency` and this goes red on the accept count (4, not 1).
    #[tokio::test]
    async fn post_timeout_sends_exactly_once_and_reports_indeterminate() {
        let (base, accepts) = hanging_server().await;
        let client = HttpClient::builder()
            .base_url(base)
            .timeout(Duration::from_millis(200))
            .retry(fast_retry())
            .build()
            .unwrap();

        let out: Result<serde_json::Value> = client
            .post("/comment", &serde_json::json!({ "body": "hi" }))
            .await;

        assert!(
            matches!(out, Err(TodokuError::Indeterminate { .. })),
            "a lost POST response is neither Ok nor a plain Err; got {out:?}"
        );
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "a non-idempotent POST must reach the wire exactly once"
        );
    }

    /// The control that keeps the gate from being vacuous: if this passed while
    /// the test above also passed for the wrong reason (retries disabled
    /// wholesale), the fix would be a regression dressed as a safety property.
    #[tokio::test]
    async fn get_timeout_still_retries() {
        let (base, accepts) = hanging_server().await;
        let client = HttpClient::builder()
            .base_url(base)
            .timeout(Duration::from_millis(200))
            .retry(fast_retry())
            .build()
            .unwrap();

        let out: Result<serde_json::Value> = client.get("/items").await;
        assert!(out.is_err());
        assert!(
            accepts.load(Ordering::SeqCst) > 1,
            "GET is idempotent and must still retry; saw {} attempt(s)",
            accepts.load(Ordering::SeqCst)
        );
    }

    /// An explicit key is the ONE way to opt a POST back into retrying.
    #[tokio::test]
    async fn post_with_idempotency_key_may_retry() {
        let (base, accepts) = hanging_server().await;
        let client = HttpClient::builder()
            .base_url(base)
            .timeout(Duration::from_millis(200))
            .retry(fast_retry())
            .build()
            .unwrap();

        let out: Result<serde_json::Value> = client
            .request_with_idempotency(
                reqwest::Method::POST,
                "/comment",
                Some(&serde_json::json!({ "body": "hi" })),
                &Idempotency::Key("stable-key-1".into()),
            )
            .await;

        assert!(out.is_err());
        assert!(
            accepts.load(Ordering::SeqCst) > 1,
            "a keyed POST is safe to re-send; saw {} attempt(s)",
            accepts.load(Ordering::SeqCst)
        );
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
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: Some("https://api.example.com/v1".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
        };
        assert_eq!(client.url("/items"), "https://api.example.com/v1/items");
    }

    #[test]
    fn url_resolution_without_leading_slash() {
        let client = HttpClient {
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: Some("https://api.example.com/v1".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
        };
        assert_eq!(client.url("items"), "https://api.example.com/v1/items");
    }

    #[test]
    fn url_no_base() {
        let client = HttpClient {
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: None,
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
        };
        assert_eq!(
            client.url("https://example.com/api"),
            "https://example.com/api"
        );
    }

    #[test]
    fn url_base_with_trailing_slash() {
        let client = HttpClient {
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: Some("https://api.example.com/v1/".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
        };
        // Trailing slash on base and leading slash on path should not double-slash
        assert_eq!(client.url("/items"), "https://api.example.com/v1/items");
    }

    #[test]
    fn url_base_with_trailing_slash_path_no_leading() {
        let client = HttpClient {
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: Some("https://api.example.com/v1/".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
        };
        assert_eq!(client.url("items"), "https://api.example.com/v1/items");
    }

    #[test]
    fn url_empty_path() {
        let client = HttpClient {
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: Some("https://api.example.com".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
        };
        assert_eq!(client.url(""), "https://api.example.com/");
    }

    #[test]
    fn url_nested_path() {
        let client = HttpClient {
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: Some("https://api.example.com".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
        };
        assert_eq!(
            client.url("/a/b/c/d"),
            "https://api.example.com/a/b/c/d"
        );
    }

    #[test]
    fn url_with_query_params() {
        let client = HttpClient {
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: Some("https://api.example.com/v1".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
        };
        assert_eq!(
            client.url("/search?q=hello&page=1"),
            "https://api.example.com/v1/search?q=hello&page=1"
        );
    }

    #[test]
    fn url_no_base_returns_path_as_is() {
        let client = HttpClient {
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: None,
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
        };
        assert_eq!(client.url("/relative/path"), "/relative/path");
    }

    #[test]
    fn url_empty_base() {
        let client = HttpClient {
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: Some(String::new()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
        };
        assert_eq!(client.url("/items"), "/items");
    }

    #[test]
    fn url_base_multiple_trailing_slashes() {
        let client = HttpClient {
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: Some("https://api.example.com///".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
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
            inner: Transport::Reqwest(reqwest::Client::new()),
            base_url: Some("https://api.example.com".into()),
            auth: Arc::new(NoAuth),
            retry: RetryPolicy::none(),
            default_headers: HeaderMap::new(),
            ssrf_guard: false,
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
        assert!((client.retry.multiplier - 1.5).abs() < f64::EPSILON);
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

    // --- URL resolution edge cases with builder ---

    #[test]
    fn built_client_url_with_fragment() {
        let client = HttpClient::builder()
            .base_url("https://api.example.com")
            .build()
            .unwrap();
        assert_eq!(
            client.url("/docs#section"),
            "https://api.example.com/docs#section"
        );
    }

    // --- Clone preserves default headers ---

    #[test]
    fn cloned_client_preserves_headers() {
        let client = HttpClient::builder()
            .header(reqwest::header::ACCEPT, "application/json")
            .header(HeaderName::from_static("x-custom"), "val")
            .build()
            .unwrap();
        let cloned = client.clone();
        assert_eq!(cloned.default_headers.len(), 2);
        assert_eq!(
            cloned.default_headers.get(reqwest::header::ACCEPT).unwrap(),
            "application/json"
        );
        assert_eq!(
            cloned.default_headers.get("x-custom").unwrap(),
            "val"
        );
    }

    // --- Clone preserves retry policy fully ---

    #[test]
    fn cloned_client_preserves_retry_policy_details() {
        let policy = RetryPolicy {
            max_retries: 7,
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(10),
            multiplier: 1.5,
            retry_statuses: vec![418, 503],
        };
        let client = HttpClient::builder()
            .retry(policy)
            .build()
            .unwrap();
        let cloned = client.clone();
        assert_eq!(cloned.retry.max_retries, 7);
        assert_eq!(cloned.retry.initial_backoff, Duration::from_millis(250));
        assert_eq!(cloned.retry.max_backoff, Duration::from_secs(10));
        assert_eq!(cloned.retry.retry_statuses, vec![418, 503]);
    }

    #[test]
    fn built_client_url_with_port() {
        let client = HttpClient::builder()
            .base_url("https://localhost:8080/api")
            .build()
            .unwrap();
        assert_eq!(
            client.url("/health"),
            "https://localhost:8080/api/health"
        );
    }

    // --- HttpClient is Send + Sync ---

    #[test]
    fn http_client_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HttpClient>();
    }

    // --- HttpClient default via builder().build() ---

    #[test]
    fn builder_new_equals_default() {
        let from_new = HttpClientBuilder::new();
        let from_default = HttpClientBuilder::default();
        // Both should produce clients with the same configuration
        let c1 = from_new.build().unwrap();
        let c2 = from_default.build().unwrap();
        assert_eq!(c1.base_url, c2.base_url);
        assert_eq!(c1.retry.max_retries, c2.retry.max_retries);
        assert!(c1.default_headers.is_empty());
        assert!(c2.default_headers.is_empty());
    }

    // --- Builder method chaining returns correct type ---

    #[test]
    fn builder_methods_are_chainable() {
        let _client = HttpClient::builder()
            .base_url("https://example.com")
            .auth(BearerToken::new("tok"))
            .retry(RetryPolicy::none())
            .timeout(Duration::from_secs(5))
            .user_agent("test/1.0")
            .header(reqwest::header::ACCEPT, "text/plain")
            .header(HeaderName::from_static("x-custom"), "val")
            .build()
            .unwrap();
    }

    // --- Builder default user agent ---

    #[test]
    fn builder_default_user_agent_contains_version() {
        let _client = HttpClient::builder().build().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let expected_ua = format!("pleme-io/todoku {version}");
        assert!(!expected_ua.is_empty());
    }

    // --- Header validation ---

    #[test]
    fn builder_header_ignores_invalid_value() {
        let client = HttpClient::builder()
            .header(reqwest::header::ACCEPT, "valid")
            .header(reqwest::header::ACCEPT, "\r\ninvalid")
            .build()
            .unwrap();
        let accept = client.default_headers.get(reqwest::header::ACCEPT);
        assert_eq!(accept.unwrap(), "valid");
    }

    // --- Auth + headers together ---

    #[test]
    fn auth_headers_applied_on_top_of_defaults() {
        let client = HttpClient::builder()
            .auth(BearerToken::new("tok"))
            .header(reqwest::header::ACCEPT, "application/json")
            .build()
            .unwrap();

        let mut headers = client.default_headers.clone();
        client.auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer tok"
        );
        assert_eq!(
            headers.get(reqwest::header::ACCEPT).unwrap(),
            "application/json"
        );
    }

    // --- Retry policy preserved through builder ---

    #[test]
    fn builder_retry_fields_preserved() {
        let policy = RetryPolicy {
            max_retries: 7,
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(10),
            multiplier: 1.5,
            retry_statuses: vec![429, 503],
        };
        let client = HttpClient::builder().retry(policy).build().unwrap();
        assert_eq!(client.retry.max_retries, 7);
        assert_eq!(client.retry.initial_backoff, Duration::from_millis(250));
        assert_eq!(client.retry.max_backoff, Duration::from_secs(10));
        assert!((client.retry.multiplier - 1.5).abs() < f64::EPSILON);
        assert!(client.retry.should_retry_status(429));
        assert!(client.retry.should_retry_status(503));
        assert!(!client.retry.should_retry_status(500));
    }

    // --- Clone preserves auth behavior ---

    #[test]
    fn cloned_client_preserves_auth() {
        let client = HttpClient::builder()
            .auth(BearerToken::new("secret"))
            .build()
            .unwrap();
        let cloned = client.clone();
        let mut headers = HeaderMap::new();
        cloned.auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer secret"
        );
    }

    // --- Multiple base URL overrides ---

    #[test]
    fn builder_base_url_overrides_correctly() {
        let client = HttpClient::builder()
            .base_url("https://first.example.com")
            .base_url("https://second.example.com")
            .base_url("https://third.example.com")
            .build()
            .unwrap();
        assert_eq!(
            client.base_url.as_deref(),
            Some("https://third.example.com")
        );
    }

    // --- URL with unicode path ---

    #[test]
    fn url_resolution_with_encoded_chars() {
        let client = HttpClient::builder()
            .base_url("https://api.example.com")
            .build()
            .unwrap();
        assert_eq!(
            client.url("/search?q=hello%20world"),
            "https://api.example.com/search?q=hello%20world"
        );
    }

    // --- TLS profile ---

    #[test]
    fn builder_default_tls_profile_is_rustls() {
        let b = HttpClientBuilder::new();
        assert_eq!(b.tls_profile, TlsProfile::Rustls);
    }

    #[test]
    fn builder_sets_tls_profile() {
        let b = HttpClientBuilder::new().tls_profile(TlsProfile::Chrome);
        assert_eq!(b.tls_profile, TlsProfile::Chrome);
    }

    #[test]
    fn rustls_profile_builds_a_reqwest_transport() {
        let client = HttpClient::builder()
            .tls_profile(TlsProfile::Rustls)
            .build()
            .unwrap();
        assert!(matches!(client.inner, Transport::Reqwest(_)));
    }

    #[test]
    fn default_profile_builds() {
        // No explicit profile -> rustls -> builds.
        let client = HttpClient::builder().build();
        assert!(client.is_ok());
    }

    #[cfg(not(feature = "stealth"))]
    #[test]
    fn emulated_profile_without_stealth_is_typed_error() {
        for profile in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Safari] {
            match HttpClient::builder().tls_profile(profile).build() {
                Ok(_) => panic!("emulated profile must not build without the stealth feature"),
                Err(err) => {
                    assert_matches::assert_matches!(
                        err,
                        TodokuError::UnsupportedTlsProfile { .. }
                    );
                    assert!(err.to_string().contains(profile.as_str()));
                }
            }
        }
    }

    // --- SSRF guard wiring ---

    use crate::ssrf::SsrfReason;

    #[test]
    fn builder_default_ssrf_guard_off() {
        let b = HttpClientBuilder::new();
        assert!(!b.ssrf_guard);
    }

    #[test]
    fn builder_sets_ssrf_guard() {
        let b = HttpClientBuilder::new().ssrf_guard(true);
        assert!(b.ssrf_guard);
    }

    #[test]
    fn built_client_preserves_ssrf_guard() {
        let client = HttpClient::builder().ssrf_guard(true).build().unwrap();
        assert!(client.ssrf_guard);
    }

    #[test]
    fn cloned_client_preserves_ssrf_guard() {
        let client = HttpClient::builder().ssrf_guard(true).build().unwrap();
        assert!(client.clone().ssrf_guard);
    }

    // `guard_url` is async (it does DNS-time resolution for hostname hosts), so
    // these are `#[tokio::test]`. The cases below use IP literals (no DNS) or an
    // unresolvable `.invalid` host (RFC 6761 — deterministic, offline) to stay
    // hermetic; the hostname→IP resolution path itself is covered in `ssrf`'s
    // `resolved_*` tests against `localhost`.

    #[tokio::test]
    async fn guard_url_off_is_noop_for_forbidden_target() {
        let client = HttpClient::builder().build().unwrap();
        // Guard off (default) -> even a metadata URL passes the pre-flight check.
        assert!(client.guard_url("http://169.254.169.254/").await.is_ok());
    }

    #[tokio::test]
    async fn guard_url_on_blocks_metadata() {
        let client = HttpClient::builder().ssrf_guard(true).build().unwrap();
        let err = client
            .guard_url("http://169.254.169.254/")
            .await
            .unwrap_err();
        assert_matches::assert_matches!(err, TodokuError::Ssrf(SsrfReason::CloudMetadata));
    }

    #[tokio::test]
    async fn guard_url_on_blocks_loopback() {
        let client = HttpClient::builder().ssrf_guard(true).build().unwrap();
        let err = client
            .guard_url("http://127.0.0.1:8080/admin")
            .await
            .unwrap_err();
        assert_matches::assert_matches!(err, TodokuError::Ssrf(SsrfReason::Loopback));
    }

    #[tokio::test]
    async fn guard_url_on_blocks_private() {
        let client = HttpClient::builder().ssrf_guard(true).build().unwrap();
        let err = client
            .guard_url("https://10.1.2.3/internal")
            .await
            .unwrap_err();
        assert_matches::assert_matches!(err, TodokuError::Ssrf(SsrfReason::Private));
    }

    #[tokio::test]
    async fn guard_url_on_allows_public_ip() {
        let client = HttpClient::builder().ssrf_guard(true).build().unwrap();
        assert!(client.guard_url("https://8.8.8.8/").await.is_ok());
    }

    #[tokio::test]
    async fn guard_url_on_allows_unresolvable_host() {
        // A hostname host exercises the DNS path; `.invalid` never resolves
        // (RFC 6761), so it passes — the transport surfaces the real error.
        // Offline-deterministic, unlike a real public hostname.
        let client = HttpClient::builder().ssrf_guard(true).build().unwrap();
        assert!(
            client
                .guard_url("https://nonexistent.invalid/v1")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn guard_url_on_blocks_non_http_scheme() {
        let client = HttpClient::builder().ssrf_guard(true).build().unwrap();
        let err = client.guard_url("ftp://example.com/x").await.unwrap_err();
        assert_matches::assert_matches!(err, TodokuError::Ssrf(SsrfReason::NonHttpScheme));
    }

    #[tokio::test]
    async fn request_with_guard_blocks_before_send() {
        // base_url is a metadata endpoint; the guard must fire before any
        // network call, returning a typed Ssrf error (never a Request error).
        let client = HttpClient::builder()
            .base_url("http://169.254.169.254")
            .ssrf_guard(true)
            .build()
            .unwrap();
        let res: Result<serde_json::Value> = client.get("/latest/meta-data/").await;
        assert_matches::assert_matches!(
            res,
            Err(TodokuError::Ssrf(SsrfReason::CloudMetadata))
        );
    }

    #[tokio::test]
    async fn get_raw_with_guard_blocks_before_send() {
        let client = HttpClient::builder()
            .base_url("http://127.0.0.1:9")
            .ssrf_guard(true)
            .build()
            .unwrap();
        let res = client.get_raw("/").await;
        assert_matches::assert_matches!(res, Err(TodokuError::Ssrf(SsrfReason::Loopback)));
    }

    #[tokio::test]
    async fn get_raw_without_guard_attempts_send() {
        // Guard off: the loopback URL is NOT pre-empted by the SSRF guard. The
        // connection to a dead port fails with a transport (Request) error, not
        // an Ssrf error — proving the guard did not intervene.
        let client = HttpClient::builder()
            .base_url("http://127.0.0.1:9")
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let res = client.get_raw("/").await;
        match res {
            Err(TodokuError::Ssrf(_)) => panic!("guard fired while disabled"),
            Err(_) | Ok(_) => {}
        }
    }
}
