//! Configurable retry policies with exponential backoff.

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
    use pretty_assertions::assert_eq;

    // --- Default policy ---

    #[test]
    fn default_policy() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_retries, 3);
        assert_eq!(p.initial_backoff, Duration::from_millis(500));
        assert_eq!(p.max_backoff, Duration::from_secs(30));
        assert_eq!(p.multiplier, 2.0);
        assert!(p.should_retry_status(429));
        assert!(p.should_retry_status(503));
        assert!(!p.should_retry_status(404));
    }

    #[test]
    fn default_retry_statuses() {
        let p = RetryPolicy::default();
        let expected = [429, 500, 502, 503, 504];
        for status in expected {
            assert!(
                p.should_retry_status(status),
                "expected {status} to be retryable"
            );
        }
    }

    #[test]
    fn non_retryable_statuses() {
        let p = RetryPolicy::default();
        let non_retryable = [200, 201, 301, 400, 401, 403, 404, 405, 409, 422];
        for status in non_retryable {
            assert!(
                !p.should_retry_status(status),
                "expected {status} to NOT be retryable"
            );
        }
    }

    // --- None policy ---

    #[test]
    fn none_policy() {
        let p = RetryPolicy::none();
        assert_eq!(p.max_retries, 0);
        // Other fields still come from default
        assert_eq!(p.initial_backoff, Duration::from_millis(500));
        assert_eq!(p.multiplier, 2.0);
    }

    // --- Aggressive policy ---

    #[test]
    fn aggressive_policy() {
        let p = RetryPolicy::aggressive();
        assert_eq!(p.max_retries, 5);
        assert_eq!(p.initial_backoff, Duration::from_millis(200));
        assert_eq!(p.max_backoff, Duration::from_secs(60));
        assert_eq!(p.multiplier, 2.0);
        assert!(p.should_retry_status(429));
        assert!(p.should_retry_status(504));
    }

    // --- Exponential backoff ---

    #[test]
    fn exponential_backoff() {
        let p = RetryPolicy::default();
        assert_eq!(p.backoff_for(0), Duration::from_millis(500));
        assert_eq!(p.backoff_for(1), Duration::from_millis(1000));
        assert_eq!(p.backoff_for(2), Duration::from_millis(2000));
        assert_eq!(p.backoff_for(3), Duration::from_millis(4000));
    }

    #[test]
    fn backoff_clamped_to_max() {
        let p = RetryPolicy {
            max_backoff: Duration::from_secs(1),
            ..Default::default()
        };
        // Attempt 10: 500ms * 2^10 = 512000ms, clamped to 1000ms
        assert_eq!(p.backoff_for(10), Duration::from_secs(1));
    }

    #[test]
    fn backoff_at_boundary_of_max() {
        let p = RetryPolicy {
            initial_backoff: Duration::from_millis(1000),
            max_backoff: Duration::from_millis(4000),
            multiplier: 2.0,
            ..Default::default()
        };
        // attempt 0: 1000ms
        assert_eq!(p.backoff_for(0), Duration::from_millis(1000));
        // attempt 1: 2000ms
        assert_eq!(p.backoff_for(1), Duration::from_millis(2000));
        // attempt 2: 4000ms (exactly at max)
        assert_eq!(p.backoff_for(2), Duration::from_millis(4000));
        // attempt 3: 8000ms clamped to 4000ms
        assert_eq!(p.backoff_for(3), Duration::from_millis(4000));
    }

    #[test]
    fn backoff_aggressive_policy_values() {
        let p = RetryPolicy::aggressive();
        // 200ms * 2^0 = 200ms
        assert_eq!(p.backoff_for(0), Duration::from_millis(200));
        // 200ms * 2^1 = 400ms
        assert_eq!(p.backoff_for(1), Duration::from_millis(400));
        // 200ms * 2^2 = 800ms
        assert_eq!(p.backoff_for(2), Duration::from_millis(800));
    }

    #[test]
    fn backoff_with_multiplier_of_one() {
        let p = RetryPolicy {
            initial_backoff: Duration::from_millis(100),
            multiplier: 1.0,
            ..Default::default()
        };
        // With multiplier 1.0, backoff is always initial_backoff
        assert_eq!(p.backoff_for(0), Duration::from_millis(100));
        assert_eq!(p.backoff_for(1), Duration::from_millis(100));
        assert_eq!(p.backoff_for(5), Duration::from_millis(100));
    }

    #[test]
    fn backoff_with_fractional_multiplier() {
        let p = RetryPolicy {
            initial_backoff: Duration::from_millis(1000),
            max_backoff: Duration::from_secs(60),
            multiplier: 1.5,
            ..Default::default()
        };
        // attempt 0: 1000ms * 1.5^0 = 1000ms
        assert_eq!(p.backoff_for(0), Duration::from_millis(1000));
        // attempt 1: 1000ms * 1.5^1 = 1500ms
        assert_eq!(p.backoff_for(1), Duration::from_millis(1500));
        // attempt 2: 1000ms * 1.5^2 = 2250ms
        assert_eq!(p.backoff_for(2), Duration::from_millis(2250));
    }

    // --- Custom retry statuses ---

    #[test]
    fn custom_retry_statuses() {
        let p = RetryPolicy {
            retry_statuses: vec![418, 503],
            ..Default::default()
        };
        assert!(p.should_retry_status(418));
        assert!(p.should_retry_status(503));
        assert!(!p.should_retry_status(429));
        assert!(!p.should_retry_status(500));
    }

    #[test]
    fn empty_retry_statuses() {
        let p = RetryPolicy {
            retry_statuses: vec![],
            ..Default::default()
        };
        assert!(!p.should_retry_status(429));
        assert!(!p.should_retry_status(500));
        assert!(!p.should_retry_status(503));
    }

    // --- Serde round-trip ---

    #[test]
    fn serde_round_trip_default() {
        let original = RetryPolicy::default();
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: RetryPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.max_retries, original.max_retries);
        assert_eq!(restored.initial_backoff, original.initial_backoff);
        assert_eq!(restored.max_backoff, original.max_backoff);
        assert_eq!(restored.multiplier, original.multiplier);
        assert_eq!(restored.retry_statuses, original.retry_statuses);
    }

    #[test]
    fn serde_round_trip_aggressive() {
        let original = RetryPolicy::aggressive();
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: RetryPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.max_retries, original.max_retries);
        assert_eq!(restored.initial_backoff, original.initial_backoff);
    }

    #[test]
    fn serde_round_trip_none() {
        let original = RetryPolicy::none();
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: RetryPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.max_retries, 0);
    }

    #[test]
    fn serde_deserialize_partial_json_uses_defaults() {
        // Only specifying max_retries; everything else should use defaults
        let json = r#"{"max_retries": 10}"#;
        let p: RetryPolicy = serde_json::from_str(json).expect("deserialize");
        assert_eq!(p.max_retries, 10);
        // Check defaults are applied for missing fields
        assert_eq!(p.initial_backoff, Duration::from_millis(500));
        assert_eq!(p.max_backoff, Duration::from_secs(30));
        assert_eq!(p.multiplier, 2.0);
        assert_eq!(p.retry_statuses, vec![429, 500, 502, 503, 504]);
    }

    #[test]
    fn serde_deserialize_empty_json_uses_all_defaults() {
        let json = "{}";
        let p: RetryPolicy = serde_json::from_str(json).expect("deserialize");
        let d = RetryPolicy::default();
        assert_eq!(p.max_retries, d.max_retries);
        assert_eq!(p.initial_backoff, d.initial_backoff);
        assert_eq!(p.max_backoff, d.max_backoff);
        assert_eq!(p.multiplier, d.multiplier);
        assert_eq!(p.retry_statuses, d.retry_statuses);
    }

    // --- Clone ---

    #[test]
    fn clone_preserves_all_fields() {
        let original = RetryPolicy {
            max_retries: 7,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            multiplier: 3.0,
            retry_statuses: vec![418, 503],
        };
        let cloned = original.clone();
        assert_eq!(cloned.max_retries, 7);
        assert_eq!(cloned.initial_backoff, Duration::from_millis(100));
        assert_eq!(cloned.max_backoff, Duration::from_secs(5));
        assert_eq!(cloned.multiplier, 3.0);
        assert_eq!(cloned.retry_statuses, vec![418, 503]);
    }

    // --- Debug ---

    #[test]
    fn debug_format_is_non_empty() {
        let p = RetryPolicy::default();
        let debug = format!("{p:?}");
        assert!(debug.contains("RetryPolicy"));
        assert!(debug.contains("max_retries"));
    }

    // --- Backoff edge cases ---

    #[test]
    fn backoff_zero_initial() {
        let p = RetryPolicy {
            initial_backoff: Duration::ZERO,
            ..Default::default()
        };
        assert_eq!(p.backoff_for(0), Duration::ZERO);
        assert_eq!(p.backoff_for(5), Duration::ZERO);
    }

    #[test]
    fn backoff_very_large_attempt() {
        let p = RetryPolicy::default();
        let backoff = p.backoff_for(100);
        assert_eq!(backoff, p.max_backoff);
    }

    #[test]
    fn backoff_multiplier_less_than_one() {
        let p = RetryPolicy {
            initial_backoff: Duration::from_millis(1000),
            multiplier: 0.5,
            max_backoff: Duration::from_secs(60),
            ..Default::default()
        };
        assert_eq!(p.backoff_for(0), Duration::from_millis(1000));
        assert_eq!(p.backoff_for(1), Duration::from_millis(500));
        assert_eq!(p.backoff_for(2), Duration::from_millis(250));
    }

    // --- should_retry_status edge cases ---

    #[test]
    fn should_retry_status_boundary_values() {
        let p = RetryPolicy::default();
        assert!(!p.should_retry_status(0));
        assert!(!p.should_retry_status(u16::MAX));
        assert!(!p.should_retry_status(428));
        assert!(p.should_retry_status(429));
        assert!(!p.should_retry_status(430));
    }

    #[test]
    fn should_retry_duplicate_statuses() {
        let p = RetryPolicy {
            retry_statuses: vec![503, 503, 503],
            ..Default::default()
        };
        assert!(p.should_retry_status(503));
    }

    // --- Serde edge cases ---

    #[test]
    fn serde_round_trip_custom_policy() {
        let original = RetryPolicy {
            max_retries: 42,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(120),
            multiplier: 3.5,
            retry_statuses: vec![418, 503, 504],
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: RetryPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.max_retries, 42);
        assert_eq!(restored.initial_backoff, Duration::from_millis(100));
        assert_eq!(restored.max_backoff, Duration::from_secs(120));
        assert_eq!(restored.multiplier, 3.5);
        assert_eq!(restored.retry_statuses, vec![418, 503, 504]);
    }

    #[test]
    fn serde_json_includes_all_fields() {
        let p = RetryPolicy::default();
        let json = serde_json::to_string(&p).expect("serialize");
        assert!(json.contains("max_retries"));
        assert!(json.contains("initial_backoff"));
        assert!(json.contains("max_backoff"));
        assert!(json.contains("multiplier"));
        assert!(json.contains("retry_statuses"));
    }

    // --- Policy constructor consistency ---

    #[test]
    fn none_policy_still_has_default_statuses() {
        let p = RetryPolicy::none();
        assert_eq!(p.retry_statuses, vec![429, 500, 502, 503, 504]);
    }

    #[test]
    fn aggressive_has_same_statuses_as_default() {
        let aggressive = RetryPolicy::aggressive();
        let default = RetryPolicy::default();
        assert_eq!(aggressive.retry_statuses, default.retry_statuses);
    }

    #[test]
    fn none_backoff_still_computable() {
        let p = RetryPolicy::none();
        let backoff = p.backoff_for(0);
        assert_eq!(backoff, Duration::from_millis(500));
    }
}
