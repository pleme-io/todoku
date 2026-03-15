#[derive(thiserror::Error, Debug)]
pub enum TodokuError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("HTTP {status}: {body}")]
    Http { status: u16, body: String },

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("max retries ({max}) exceeded for {url}")]
    MaxRetries { url: String, max: u32 },

    #[error("deserialization failed: {0}")]
    Deserialize(#[from] serde_json::Error),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),
}

pub type Result<T> = std::result::Result<T, TodokuError>;

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(result.unwrap(), 42);
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
}
