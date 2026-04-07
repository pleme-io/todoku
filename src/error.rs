//! Error types for the todoku HTTP client.

/// Errors that can occur during HTTP operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum TodokuError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("HTTP {status}: {body}")]
    Http { status: u16, body: String },

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("invalid header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("max retries ({max}) exceeded for {url}")]
    MaxRetries { url: String, max: u32 },

    #[error("deserialization failed: {0}")]
    Deserialize(#[from] serde_json::Error),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),
}

impl TodokuError {
    /// Returns `true` if this is an HTTP status error.
    #[must_use]
    pub fn is_http(&self) -> bool {
        matches!(self, Self::Http { .. })
    }

    /// Returns the HTTP status code if this is an `Http` variant.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Http { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Returns `true` if this is a timeout error.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }

    /// Returns `true` if this is a max-retries-exceeded error.
    #[must_use]
    pub fn is_max_retries(&self) -> bool {
        matches!(self, Self::MaxRetries { .. })
    }

    /// Construct an HTTP error from a status code and body.
    #[must_use]
    pub fn http(status: u16, body: impl Into<String>) -> Self {
        Self::Http {
            status,
            body: body.into(),
        }
    }
}

/// Convenience alias for `Result<T, TodokuError>`.
pub type Result<T> = std::result::Result<T, TodokuError>;

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use std::time::Duration;

    #[test]
    fn http_error_display() {
        let err = TodokuError::Http {
            status: 404,
            body: "Not Found".into(),
        };
        let msg = format!("{err}");
        assert_eq!(msg, "HTTP 404: Not Found");
    }

    #[test]
    fn http_error_display_empty_body() {
        let err = TodokuError::Http {
            status: 500,
            body: String::new(),
        };
        let msg = format!("{err}");
        assert_eq!(msg, "HTTP 500: ");
    }

    #[test]
    fn auth_error_display() {
        let err = TodokuError::Auth("token expired".into());
        let msg = format!("{err}");
        assert_eq!(msg, "authentication failed: token expired");
    }

    #[test]
    fn max_retries_error_display() {
        let err = TodokuError::MaxRetries {
            url: "https://api.example.com/v1/data".into(),
            max: 3,
        };
        let msg = format!("{err}");
        assert_eq!(
            msg,
            "max retries (3) exceeded for https://api.example.com/v1/data"
        );
    }

    #[test]
    fn timeout_error_display() {
        let err = TodokuError::Timeout(Duration::from_secs(30));
        let msg = format!("{err}");
        assert_eq!(msg, "timeout after 30s");
    }

    #[test]
    fn timeout_error_display_millis() {
        let err = TodokuError::Timeout(Duration::from_millis(500));
        let msg = format!("{err}");
        assert_eq!(msg, "timeout after 500ms");
    }

    #[test]
    fn deserialize_error_from_serde_json() {
        let bad_json = "not valid json";
        let serde_err = serde_json::from_str::<serde_json::Value>(bad_json).unwrap_err();
        let err: TodokuError = serde_err.into();
        let msg = format!("{err}");
        assert!(msg.starts_with("deserialization failed:"));
    }

    #[test]
    fn error_is_debug() {
        let err = TodokuError::Http {
            status: 403,
            body: "Forbidden".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("Http"));
        assert!(debug.contains("403"));
    }

    #[test]
    fn result_type_alias_ok() {
        let result: Result<i32> = Ok(42);
        assert_matches!(result, Ok(val) if val == 42);
    }

    #[test]
    fn result_type_alias_err() {
        let result: Result<i32> = Err(TodokuError::Auth("fail".into()));
        assert!(result.is_err());
    }

    #[test]
    fn max_retries_error_zero_retries() {
        let err = TodokuError::MaxRetries {
            url: "https://example.com".into(),
            max: 0,
        };
        let msg = format!("{err}");
        assert_eq!(msg, "max retries (0) exceeded for https://example.com");
    }

    #[test]
    fn http_error_with_json_body() {
        let err = TodokuError::Http {
            status: 422,
            body: r#"{"error":"validation_failed","fields":["name"]}"#.into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("422"));
        assert!(msg.contains("validation_failed"));
    }

    // --- assert_matches tests ---

    #[test]
    fn assert_matches_http_variant() {
        let err = TodokuError::Http {
            status: 429,
            body: "rate limited".into(),
        };
        assert_matches!(err, TodokuError::Http { status: 429, .. });
    }

    #[test]
    fn assert_matches_auth_variant() {
        let err = TodokuError::Auth("invalid token".into());
        assert_matches!(err, TodokuError::Auth(msg) if msg == "invalid token");
    }

    #[test]
    fn assert_matches_max_retries_variant() {
        let err = TodokuError::MaxRetries {
            url: "https://api.test.com".into(),
            max: 5,
        };
        assert_matches!(err, TodokuError::MaxRetries { max: 5, .. });
    }

    #[test]
    fn assert_matches_timeout_variant() {
        let err = TodokuError::Timeout(Duration::from_secs(10));
        assert_matches!(err, TodokuError::Timeout(d) if d == Duration::from_secs(10));
    }

    #[test]
    fn assert_matches_deserialize_variant() {
        let serde_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err: TodokuError = serde_err.into();
        assert_matches!(err, TodokuError::Deserialize(_));
    }

    #[test]
    fn error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TodokuError>();
    }

    #[test]
    fn error_implements_std_error() {
        let err = TodokuError::Auth("test".into());
        let std_err: &dyn std::error::Error = &err;
        assert!(!std_err.to_string().is_empty());
    }

    #[test]
    fn http_error_all_status_codes() {
        for status in [400, 401, 403, 404, 405, 409, 422, 429, 500, 502, 503, 504] {
            let err = TodokuError::Http {
                status,
                body: String::new(),
            };
            let msg = format!("{err}");
            assert!(msg.contains(&status.to_string()));
        }
    }

    #[test]
    fn max_retries_error_large_retry_count() {
        let err = TodokuError::MaxRetries {
            url: "https://example.com/api".into(),
            max: 100,
        };
        let msg = format!("{err}");
        assert!(msg.contains("100"));
    }

    #[test]
    fn timeout_error_zero_duration() {
        let err = TodokuError::Timeout(Duration::ZERO);
        let msg = format!("{err}");
        assert!(msg.contains('0'));
    }

    #[test]
    fn auth_error_empty_message() {
        let err = TodokuError::Auth(String::new());
        let msg = format!("{err}");
        assert_eq!(msg, "authentication failed: ");
    }

    #[test]
    fn is_http_returns_true_for_http_variant() {
        let err = TodokuError::Http {
            status: 404,
            body: String::new(),
        };
        assert!(err.is_http());
    }

    #[test]
    fn is_http_returns_false_for_other_variants() {
        let err = TodokuError::Auth("fail".into());
        assert!(!err.is_http());
    }

    #[test]
    fn status_returns_code_for_http() {
        let err = TodokuError::Http {
            status: 503,
            body: String::new(),
        };
        assert_eq!(err.status(), Some(503));
    }

    #[test]
    fn status_returns_none_for_non_http() {
        let err = TodokuError::Auth("no status".into());
        assert_eq!(err.status(), None);
    }

    #[test]
    fn is_timeout_check() {
        let err = TodokuError::Timeout(Duration::from_secs(10));
        assert!(err.is_timeout());
        assert!(!err.is_http());
    }

    #[test]
    fn is_max_retries_check() {
        let err = TodokuError::MaxRetries {
            url: "https://example.com".into(),
            max: 3,
        };
        assert!(err.is_max_retries());
        assert!(!err.is_timeout());
    }

    #[test]
    fn invalid_header_value_from_conversion() {
        use reqwest::header::HeaderValue;
        let bad = HeaderValue::from_str("invalid \x00 value");
        assert!(bad.is_err());
        let err: TodokuError = bad.unwrap_err().into();
        let msg = format!("{err}");
        assert!(msg.contains("invalid header value"));
    }

    #[test]
    fn invalid_header_value_display() {
        use reqwest::header::HeaderValue;
        let bad = HeaderValue::from_str("\x00").unwrap_err();
        let err = TodokuError::InvalidHeaderValue(bad);
        let msg = format!("{err}");
        assert!(msg.starts_with("invalid header value:"));
    }

    #[test]
    fn http_constructor() {
        let err = TodokuError::http(502, "Bad Gateway");
        assert_eq!(err.status(), Some(502));
        assert!(err.is_http());
        let msg = format!("{err}");
        assert_eq!(msg, "HTTP 502: Bad Gateway");
    }

    #[test]
    fn http_constructor_from_string() {
        let body = String::from("Service Unavailable");
        let err = TodokuError::http(503, body);
        assert_eq!(err.status(), Some(503));
    }
}
