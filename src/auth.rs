use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

/// Authentication strategy for HTTP requests.
pub trait Auth: Send + Sync {
    /// Apply authentication to the request headers.
    fn apply(&self, headers: &mut HeaderMap);
}

/// No authentication.
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
        if let Ok(val) = HeaderValue::from_str(&format!("Bearer {}", self.token)) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
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
        use std::io::Write;
        let mut buf = Vec::new();
        write!(buf, "{username}:{password}").unwrap();
        Self {
            encoded: Self::base64_encode(&buf),
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
        if let Ok(val) = HeaderValue::from_str(&format!("Basic {}", self.encoded)) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
    }
}

/// Custom header authentication (e.g., X-API-Key).
pub struct HeaderAuth {
    name: HeaderName,
    value: String,
}

impl HeaderAuth {
    pub fn new(name: impl Into<HeaderName>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl Auth for HeaderAuth {
    fn apply(&self, headers: &mut HeaderMap) {
        if let Ok(val) = HeaderValue::from_str(&self.value) {
            headers.insert(self.name.clone(), val);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn no_auth_noop() {
        let auth = NoAuth;
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert!(headers.is_empty());
    }

    #[test]
    fn header_auth_custom() {
        let auth = HeaderAuth::new(HeaderName::from_static("x-api-key"), "my-secret-key");
        let mut headers = HeaderMap::new();
        auth.apply(&mut headers);
        assert_eq!(headers.get("x-api-key").unwrap(), "my-secret-key");
    }
}
