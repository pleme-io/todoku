use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Retry policy for failed requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryPolicy {
    /// Maximum number of retries (0 = no retries).
    pub max_retries: u32,
    /// Initial backoff duration.
    pub initial_backoff: Duration,
    /// Maximum backoff duration.
    pub max_backoff: Duration,
    /// Backoff multiplier (exponential).
    pub multiplier: f64,
    /// HTTP status codes that trigger retry.
    pub retry_statuses: Vec<u16>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            multiplier: 2.0,
            retry_statuses: vec![429, 500, 502, 503, 504],
        }
    }
}

impl RetryPolicy {
    /// No retries at all.
    #[must_use]
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Aggressive retry for critical operations.
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(60),
            multiplier: 2.0,
            retry_statuses: vec![429, 500, 502, 503, 504],
        }
    }

    /// Calculate backoff duration for given attempt number.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_wrap,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        let base = self.initial_backoff.as_millis() as f64;
        let backoff_ms = base * self.multiplier.powi(attempt.cast_signed());
        let clamped = backoff_ms.min(self.max_backoff.as_millis() as f64);
        Duration::from_millis(clamped as u64)
    }

    /// Check if a status code should be retried.
    #[must_use]
    pub fn should_retry_status(&self, status: u16) -> bool {
        self.retry_statuses.contains(&status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_retries, 3);
        assert!(p.should_retry_status(429));
        assert!(p.should_retry_status(503));
        assert!(!p.should_retry_status(404));
    }

    #[test]
    fn exponential_backoff() {
        let p = RetryPolicy::default();
        assert_eq!(p.backoff_for(0), Duration::from_millis(500));
        assert_eq!(p.backoff_for(1), Duration::from_millis(1000));
        assert_eq!(p.backoff_for(2), Duration::from_millis(2000));
    }

    #[test]
    fn backoff_clamped_to_max() {
        let p = RetryPolicy {
            max_backoff: Duration::from_secs(1),
            ..Default::default()
        };
        assert_eq!(p.backoff_for(10), Duration::from_secs(1));
    }

    #[test]
    fn none_policy() {
        let p = RetryPolicy::none();
        assert_eq!(p.max_retries, 0);
    }
}
