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
