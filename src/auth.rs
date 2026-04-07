//! Pluggable authentication strategies for HTTP requests.

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tracing::warn;

/// Authentication strategy for HTTP requests.
pub trait Auth: Send + Sync {
    /// Apply authentication to the request headers.
    fn apply(&self, headers: &mut HeaderMap);
}

/// No authentication.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAuth;

impl Auth for NoAuth {
    fn apply(&self, _headers: &mut HeaderMap) {}
}

/// Bearer token authentication (`OAuth2`, API keys).
pub struct BearerToken {
    token: String,
}

impl BearerToken {
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl Auth for BearerToken {
    fn apply(&self, headers: &mut HeaderMap) {
        match HeaderValue::from_str(&format!("Bearer {}", self.token)) {
            Ok(val) => {
                headers.insert(reqwest::header::AUTHORIZATION, val);
            }
            Err(e) => warn!("BearerToken: invalid header value: {e}"),
        }
    }
}

/// Basic authentication (username:password).
pub struct BasicAuth {
    encoded: String,
}

impl BasicAuth {
    #[must_use]
    pub fn new(username: &str, password: &str) -> Self {
        let credentials = format!("{username}:{password}");
        Self {
            encoded: Self::base64_encode(credentials.as_bytes()),
        }
    }

    fn base64_encode(input: &[u8]) -> String {
        const CHARS: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = u32::from(chunk[0]);
            let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
            let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(CHARS[(triple & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
        }
        result
    }
}

impl Auth for BasicAuth {
    fn apply(&self, headers: &mut HeaderMap) {
        match HeaderValue::from_str(&format!("Basic {}", self.encoded)) {
            Ok(val) => {
                headers.insert(reqwest::header::AUTHORIZATION, val);
            }
            Err(e) => warn!("BasicAuth: invalid header value: {e}"),
        }
    }
}

/// Custom header authentication (e.g., X-API-Key).
pub struct HeaderAuth {
    name: HeaderName,
    value: String,
}

impl HeaderAuth {
    /// Create a new custom header authentication.
    #[must_use]
    pub fn new(name: impl Into<HeaderName>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl Auth for HeaderAuth {
    fn apply(&self, headers: &mut HeaderMap) {
        match HeaderValue::from_str(&self.value) {
            Ok(val) => {
                headers.insert(self.name.clone(), val);
            }
            Err(e) => warn!("HeaderAuth({}): invalid header value: {e}", self.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- NoAuth ---

    #[test]
    fn no_auth_noop() {
        let auth = NoAuth;
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert!(headers.is_empty());
    }

    #[test]
    fn no_auth_preserves_existing_headers() {
        let auth = NoAuth;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-existing"),
            HeaderValue::from_static("keep-me"),
        );
        auth.apply(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get("x-existing").unwrap(), "keep-me");
    }

    // --- BearerToken ---

    #[test]
    fn bearer_token_applies() {
        let auth = BearerToken::new("test-token-123");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer test-token-123"
        );
    }

    #[test]
    fn bearer_token_from_string_owned() {
        let token = String::from("owned-token");
        let auth = BearerToken::new(token);
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer owned-token"
        );
    }

    #[test]
    fn bearer_token_empty_string() {
        let auth = BearerToken::new("");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer "
        );
    }

    #[test]
    fn bearer_token_overwrites_existing_authorization() {
        let auth = BearerToken::new("new-token");
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer old-token"),
        );
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer new-token"
        );
    }

    // --- BasicAuth ---

    #[test]
    fn basic_auth_encodes_correctly() {
        // "user:pass" base64 = "dXNlcjpwYXNz"
        let auth = BasicAuth::new("user", "pass");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Basic dXNlcjpwYXNz"
        );
    }

    #[test]
    fn basic_auth_empty_password() {
        // "user:" base64 = "dXNlcjo="
        let auth = BasicAuth::new("user", "");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Basic dXNlcjo="
        );
    }

    #[test]
    fn basic_auth_empty_username() {
        // ":pass" base64 = "OnBhc3M="
        let auth = BasicAuth::new("", "pass");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Basic OnBhc3M="
        );
    }

    #[test]
    fn basic_auth_both_empty() {
        // ":" base64 = "Og=="
        let auth = BasicAuth::new("", "");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Basic Og=="
        );
    }

    #[test]
    fn basic_auth_special_characters() {
        // Verify we can encode credentials with special chars
        let auth = BasicAuth::new("admin@example.com", "p@ss:w0rd!");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        let value = headers
            .get(reqwest::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(value.starts_with("Basic "));
        // Manually verify: "admin@example.com:p@ss:w0rd!" in base64
        assert_eq!(value, "Basic YWRtaW5AZXhhbXBsZS5jb206cEBzczp3MHJkIQ==");
    }

    #[test]
    fn base64_encode_empty_input() {
        let result = BasicAuth::base64_encode(b"");
        assert_eq!(result, "");
    }

    #[test]
    fn base64_encode_single_byte() {
        // 'A' = 0x41 -> base64 = "QQ=="
        let result = BasicAuth::base64_encode(b"A");
        assert_eq!(result, "QQ==");
    }

    #[test]
    fn base64_encode_two_bytes() {
        // 'AB' -> base64 = "QUI="
        let result = BasicAuth::base64_encode(b"AB");
        assert_eq!(result, "QUI=");
    }

    #[test]
    fn base64_encode_three_bytes() {
        // 'ABC' -> base64 = "QUJD" (no padding)
        let result = BasicAuth::base64_encode(b"ABC");
        assert_eq!(result, "QUJD");
    }

    #[test]
    fn base64_encode_longer_input() {
        // "Hello, World!" -> "SGVsbG8sIFdvcmxkIQ=="
        let result = BasicAuth::base64_encode(b"Hello, World!");
        assert_eq!(result, "SGVsbG8sIFdvcmxkIQ==");
    }

    // --- HeaderAuth ---

    #[test]
    fn header_auth_custom() {
        let auth = HeaderAuth::new(HeaderName::from_static("x-api-key"), "my-secret-key");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(headers.get("x-api-key").unwrap(), "my-secret-key");
    }

    #[test]
    fn header_auth_authorization_header() {
        // HeaderAuth can also be used for custom Authorization schemes
        let auth = HeaderAuth::new(reqwest::header::AUTHORIZATION, "Token abc123");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Token abc123"
        );
    }

    #[test]
    fn header_auth_empty_value() {
        let auth = HeaderAuth::new(HeaderName::from_static("x-api-key"), "");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(headers.get("x-api-key").unwrap(), "");
    }

    #[test]
    fn header_auth_overwrites_same_header() {
        let auth = HeaderAuth::new(HeaderName::from_static("x-api-key"), "new-key");
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("old-key"),
        );
        auth.apply(&mut headers);
        assert_eq!(headers.get("x-api-key").unwrap(), "new-key");
    }

    #[test]
    fn header_auth_does_not_affect_other_headers() {
        let auth = HeaderAuth::new(HeaderName::from_static("x-api-key"), "secret");
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-other"),
            HeaderValue::from_static("untouched"),
        );
        auth.apply(&mut headers);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get("x-other").unwrap(), "untouched");
        assert_eq!(headers.get("x-api-key").unwrap(), "secret");
    }

    // --- Auth trait object usage ---

    #[test]
    fn auth_trait_object_bearer() {
        let auth: Box<dyn Auth> = Box::new(BearerToken::new("dynamic"));
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer dynamic"
        );
    }

    #[test]
    fn auth_trait_object_basic() {
        let auth: Box<dyn Auth> = Box::new(BasicAuth::new("user", "pass"));
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        let value = headers
            .get(reqwest::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(value.starts_with("Basic "));
    }

    #[test]
    fn auth_trait_object_no_auth() {
        let auth: Box<dyn Auth> = Box::new(NoAuth);
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert!(headers.is_empty());
    }

    // --- Auth is Send + Sync ---

    #[test]
    fn bearer_token_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BearerToken>();
    }

    #[test]
    fn basic_auth_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BasicAuth>();
    }

    #[test]
    fn header_auth_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HeaderAuth>();
    }

    #[test]
    fn no_auth_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoAuth>();
    }

    // --- Auth trait object in Arc ---

    #[test]
    fn auth_arc_trait_object() {
        let auth: std::sync::Arc<dyn Auth> = std::sync::Arc::new(BearerToken::new("arc-tok"));
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer arc-tok"
        );
    }

    // --- Bearer token with long value ---

    #[test]
    fn bearer_token_long_value() {
        let long = "a".repeat(1000);
        let auth = BearerToken::new(&long);
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        let val = headers
            .get(reqwest::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(val, format!("Bearer {long}"));
    }

    // --- BasicAuth base64 encode known values ---

    #[test]
    fn base64_encode_all_bytes() {
        let input: Vec<u8> = (0..=255).collect();
        let result = BasicAuth::base64_encode(&input);
        assert!(!result.is_empty());
        assert!(result.chars().all(|c| c.is_ascii_alphanumeric()
            || c == '+' || c == '/' || c == '='));
    }

    #[test]
    fn base64_encode_padding_one() {
        let result = BasicAuth::base64_encode(b"ab");
        assert_eq!(result, "YWI=");
    }

    #[test]
    fn base64_encode_padding_two() {
        let result = BasicAuth::base64_encode(b"a");
        assert_eq!(result, "YQ==");
    }

    #[test]
    fn base64_encode_no_padding() {
        let result = BasicAuth::base64_encode(b"abc");
        assert_eq!(result, "YWJj");
    }

    // --- HeaderAuth with various header names ---

    #[test]
    fn header_auth_with_content_type() {
        let auth = HeaderAuth::new(reqwest::header::CONTENT_TYPE, "application/json");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(headers.get(reqwest::header::CONTENT_TYPE).unwrap(), "application/json");
    }

    // --- Multiple auth applications ---

    #[test]
    fn no_auth_default() {
        let auth = NoAuth::default();
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert!(headers.is_empty());
    }

    #[test]
    fn no_auth_is_copy() {
        let a = NoAuth;
        let b = a;
        let _ = a;
        let mut headers = HeaderMap::new();
        b.apply(&mut headers);
        assert!(headers.is_empty());
    }

    #[test]
    fn auth_apply_is_idempotent() {
        let auth = BearerToken::new("tok");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        auth.apply(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer tok"
        );
    }
}
