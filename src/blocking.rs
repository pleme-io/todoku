//! Blocking (synchronous) HTTP facade over the async [`HttpClient`].
//!
//! Sync consumers — nami-core's `FetchClient`, aranami, one-shot CLIs — drive
//! the **same** async [`HttpClient`] through a dedicated current-thread tokio
//! runtime, so the fleet has ONE HTTP implementation (solve-once), not a
//! parallel blocking client. Every request still flows through the async
//! client's auth, retry/backoff, [`crate::TlsProfile`], and SSRF guard.
//!
//! Do NOT call these from inside an async context — `block_on` panics when a
//! runtime is already running on the thread. In async code use [`HttpClient`]
//! directly; this facade is for genuinely synchronous call sites.

use serde::de::DeserializeOwned;
use tokio::runtime::Runtime;

use crate::client::{HttpClient, HttpClientBuilder};
use crate::error::{Result, TodokuError};

/// A synchronous wrapper around an async [`HttpClient`] + its own current-thread
/// runtime. Construct once and reuse; the runtime is shared across calls.
pub struct BlockingHttpClient {
    inner: HttpClient,
    rt: Runtime,
}

impl std::fmt::Debug for BlockingHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingHttpClient").finish_non_exhaustive()
    }
}

impl BlockingHttpClient {
    /// Wrap an already-built async [`HttpClient`] with a dedicated
    /// current-thread runtime.
    ///
    /// # Errors
    /// Returns [`TodokuError::Runtime`] if the tokio runtime can't be built.
    pub fn new(inner: HttpClient) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| TodokuError::Runtime(e.to_string()))?;
        Ok(Self { inner, rt })
    }

    /// Build the async client from a builder and wrap it (convenience).
    ///
    /// # Errors
    /// Returns the builder's [`TodokuError`] (e.g. an emulated TLS profile
    /// without the `stealth` feature) or [`TodokuError::Runtime`].
    pub fn from_builder(builder: HttpClientBuilder) -> Result<Self> {
        Self::new(builder.build()?)
    }

    /// The wrapped async client (for code that needs the async surface).
    #[must_use]
    pub fn inner(&self) -> &HttpClient {
        &self.inner
    }

    /// Blocking GET + JSON deserialize.
    ///
    /// # Errors
    /// Propagates the async client's [`TodokuError`].
    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.rt.block_on(self.inner.get(path))
    }

    /// Blocking POST (JSON body) + JSON deserialize.
    ///
    /// # Errors
    /// Propagates the async client's [`TodokuError`].
    pub fn post<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.rt.block_on(self.inner.post(path, body))
    }

    /// Blocking arbitrary request + JSON deserialize.
    ///
    /// # Errors
    /// Propagates the async client's [`TodokuError`].
    pub fn request<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        self.rt.block_on(self.inner.request(method, path, body))
    }

    /// Blocking GET returning the raw body as text (HTML, etc.). Reads the full
    /// body; returns [`TodokuError::Http`] on a non-2xx status.
    ///
    /// # Errors
    /// Propagates network / status / read errors as [`TodokuError`].
    pub fn get_text(&self, path: &str) -> Result<String> {
        self.rt.block_on(async {
            let resp = self.inner.get_raw(path).await?;
            let status = resp.status().as_u16();
            let body = resp.text().await.map_err(TodokuError::Request)?;
            if (200..300).contains(&status) {
                Ok(body)
            } else {
                Err(TodokuError::Http { status, body })
            }
        })
    }

    /// Blocking GET returning the raw body bytes (binary, images). Does not
    /// status-gate — returns whatever bytes the response carried.
    ///
    /// # Errors
    /// Propagates network / read errors as [`TodokuError`].
    pub fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        self.rt.block_on(async {
            let resp = self.inner.get_raw(path).await?;
            let bytes = resp.bytes().await.map_err(TodokuError::Request)?;
            Ok(bytes.to_vec())
        })
    }

    /// Blocking GET returning the full response — status, headers, final URL
    /// (after redirects), and raw body bytes. For consumers that need response
    /// metadata (e.g. content-type sniffing), like nami-core's `FetchClient`.
    ///
    /// # Errors
    /// Propagates network / read errors as [`TodokuError`].
    pub fn get_response(&self, path: &str) -> Result<HttpResponse> {
        self.rt.block_on(async {
            let resp = self.inner.get_raw(path).await?;
            let status = resp.status().as_u16();
            let final_url = resp.url().to_string();
            let headers = resp
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|s| (k.as_str().to_owned(), s.to_owned()))
                })
                .collect();
            let body = resp.bytes().await.map_err(TodokuError::Request)?.to_vec();
            Ok(HttpResponse {
                status,
                headers,
                body,
                final_url,
            })
        })
    }
}

/// A fully-read HTTP response: status, headers, final URL, and body bytes.
/// Returned by [`BlockingHttpClient::get_response`] for consumers that need
/// response metadata rather than just the body.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub final_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_over_a_plain_client() {
        let client = HttpClient::builder().build().unwrap();
        let blocking = BlockingHttpClient::new(client);
        assert!(blocking.is_ok());
    }

    #[test]
    fn from_builder_builds() {
        let blocking =
            BlockingHttpClient::from_builder(HttpClient::builder().base_url("https://api.x.io"));
        assert!(blocking.is_ok());
    }

    #[test]
    fn ssrf_guard_blocks_before_send_synchronously() {
        // The blocking facade reuses the async SSRF guard: a metadata target is
        // rejected before any network I/O, so this is deterministic + offline.
        let blocking =
            BlockingHttpClient::from_builder(HttpClient::builder().ssrf_guard(true)).unwrap();
        let err = blocking
            .get::<serde_json::Value>("http://169.254.169.254/latest/meta-data/")
            .unwrap_err();
        assert_matches::assert_matches!(
            err,
            TodokuError::Ssrf(crate::ssrf::SsrfReason::CloudMetadata)
        );
    }

    #[test]
    fn is_debug() {
        let blocking = BlockingHttpClient::new(HttpClient::builder().build().unwrap()).unwrap();
        assert!(format!("{blocking:?}").contains("BlockingHttpClient"));
    }
}
