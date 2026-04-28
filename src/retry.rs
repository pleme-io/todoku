//! Configurable retry policies with exponential backoff.
//!
//! The [`RetryPolicy`] type is the canonical retry/backoff config across
//! pleme-io fleet binaries. Use it for HTTP retries (consumed by
//! [`crate::HttpClient`]) and for any other flaky async operation via
//! [`retry_with_backoff`] — a generic retry loop that takes a closure
//! returning any `Result<T, E>`.

use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::Duration;

/// Retry policy for failed requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Error returned by [`retry_with_backoff`] when the operation cannot be
/// produced as a successful value.
///
/// Carries the underlying error verbatim — callers can inspect, log, or
/// convert into a domain error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryError<E> {
    /// The operation failed every attempt up to `max_retries + 1`.
    ///
    /// `attempts` is the total number of times the operation ran (≥ 1).
    /// `last` is the error from the final attempt.
    Exhausted { attempts: u32, last: E },
    /// The caller's `should_retry` predicate classified the error as
    /// non-retryable; the loop bailed early.
    NonRetryable(E),
}

impl<E: std::fmt::Display> std::fmt::Display for RetryError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exhausted { attempts, last } => {
                write!(f, "retry exhausted after {attempts} attempts: {last}")
            }
            Self::NonRetryable(e) => write!(f, "non-retryable error: {e}"),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for RetryError<E> {}

impl<E> RetryError<E> {
    /// Extract the underlying error, regardless of variant.
    pub fn into_inner(self) -> E {
        match self {
            Self::Exhausted { last, .. } | Self::NonRetryable(last) => last,
        }
    }
}

/// Execute an async operation with exponential backoff retry.
///
/// The operation runs up to `policy.max_retries + 1` times. Between
/// failed attempts the loop sleeps for [`RetryPolicy::backoff_for`] and
/// the predicate `should_retry` is consulted — if it returns `false`
/// for a given error, the loop bails immediately with
/// [`RetryError::NonRetryable`]. If every attempt fails and the predicate
/// keeps allowing retries, the loop returns [`RetryError::Exhausted`]
/// carrying the last error.
///
/// # Errors
///
/// Returns [`RetryError::NonRetryable`] if `should_retry` returns `false`
/// at any attempt, or [`RetryError::Exhausted`] when retries are exhausted.
///
/// # Example
///
/// ```rust,ignore
/// use todoku::{retry_with_backoff, RetryPolicy};
///
/// let policy = RetryPolicy::default();
/// // Retry every error.
/// let result: Result<String, _> = retry_with_backoff(
///     &policy,
///     || async { connect_db().await },
///     |_err| true,
/// ).await;
/// ```
pub async fn retry_with_backoff<F, Fut, T, E, P>(
    policy: &RetryPolicy,
    mut operation: F,
    mut should_retry: P,
) -> Result<T, RetryError<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    P: FnMut(&E) -> bool,
{
    let mut attempt: u32 = 0;
    loop {
        attempt = attempt.saturating_add(1);
        match operation().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if !should_retry(&err) {
                    return Err(RetryError::NonRetryable(err));
                }
                if attempt > policy.max_retries {
                    return Err(RetryError::Exhausted {
                        attempts: attempt,
                        last: err,
                    });
                }
                let backoff = policy.backoff_for(attempt - 1);
                tracing::warn!(
                    attempt,
                    max = policy.max_retries,
                    backoff_ms = backoff.as_millis() as u64,
                    "operation failed, retrying"
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
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
    fn partial_eq_same_policies() {
        assert_eq!(RetryPolicy::default(), RetryPolicy::default());
        assert_eq!(RetryPolicy::none(), RetryPolicy::none());
        assert_eq!(RetryPolicy::aggressive(), RetryPolicy::aggressive());
    }

    #[test]
    fn partial_eq_different_policies() {
        assert_ne!(RetryPolicy::default(), RetryPolicy::none());
        assert_ne!(RetryPolicy::default(), RetryPolicy::aggressive());
        assert_ne!(RetryPolicy::none(), RetryPolicy::aggressive());
    }

    #[test]
    fn none_backoff_still_computable() {
        let p = RetryPolicy::none();
        let backoff = p.backoff_for(0);
        assert_eq!(backoff, Duration::from_millis(500));
    }

    // --- Zero max_backoff ---

    #[test]
    fn backoff_zero_max_backoff() {
        let p = RetryPolicy {
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::ZERO,
            multiplier: 2.0,
            ..Default::default()
        };
        // All attempts clamped to zero
        assert_eq!(p.backoff_for(0), Duration::ZERO);
        assert_eq!(p.backoff_for(3), Duration::ZERO);
    }

    // --- Backoff sequence for aggressive ---

    #[test]
    fn backoff_full_sequence_aggressive() {
        let p = RetryPolicy::aggressive();
        let sequence: Vec<Duration> = (0..=4).map(|i| p.backoff_for(i)).collect();
        assert_eq!(
            sequence,
            vec![
                Duration::from_millis(200),
                Duration::from_millis(400),
                Duration::from_millis(800),
                Duration::from_millis(1600),
                Duration::from_millis(3200),
            ]
        );
    }

    // --- Large multiplier ---

    #[test]
    fn backoff_large_multiplier_clamped() {
        let p = RetryPolicy {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(1),
            multiplier: 10.0,
            ..Default::default()
        };
        // attempt 0: 100ms
        assert_eq!(p.backoff_for(0), Duration::from_millis(100));
        // attempt 1: 1000ms (exactly at max)
        assert_eq!(p.backoff_for(1), Duration::from_secs(1));
        // attempt 2: 10000ms clamped to 1000ms
        assert_eq!(p.backoff_for(2), Duration::from_secs(1));
    }

    // --- Serde with very small durations ---

    #[test]
    fn serde_round_trip_microsecond_backoff() {
        let original = RetryPolicy {
            initial_backoff: Duration::from_micros(100),
            max_backoff: Duration::from_micros(1000),
            ..Default::default()
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: RetryPolicy = serde_json::from_str(&json).expect("deserialize");
        // Microsecond precision may be lost in serde (Duration serializes as {secs, nanos})
        // but the value should round-trip correctly
        assert_eq!(restored.initial_backoff, original.initial_backoff);
        assert_eq!(restored.max_backoff, original.max_backoff);
    }

    // --- PartialEq with modified single field ---

    #[test]
    fn partial_eq_differs_on_single_field() {
        let base = RetryPolicy::default();
        let modified = RetryPolicy {
            max_retries: base.max_retries + 1,
            ..base.clone()
        };
        assert_ne!(base, modified);
    }

    // --- Constructors do not share state ---

    #[test]
    fn constructors_produce_independent_values() {
        let mut a = RetryPolicy::default();
        let b = RetryPolicy::default();
        a.max_retries = 99;
        assert_ne!(a.max_retries, b.max_retries);
    }
}

#[cfg(test)]
mod retry_with_backoff_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn fast_policy(max_retries: u32) -> RetryPolicy {
        RetryPolicy {
            max_retries,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
            multiplier: 1.0,
            retry_statuses: vec![],
        }
    }

    #[tokio::test]
    async fn succeeds_first_attempt() {
        let policy = fast_policy(3);
        let result: Result<i32, RetryError<&str>> =
            retry_with_backoff(&policy, || async { Ok::<_, &str>(42) }, |_| true).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn succeeds_after_failures() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();
        let policy = fast_policy(5);
        let result: Result<i32, RetryError<&str>> = retry_with_backoff(
            &policy,
            || {
                let counter = counter_clone.clone();
                async move {
                    let count = counter.fetch_add(1, Ordering::SeqCst);
                    if count < 2 { Err("transient") } else { Ok(7) }
                }
            },
            |_| true,
        )
        .await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn exhausted_returns_last_error() {
        let policy = fast_policy(2);
        let result: Result<i32, RetryError<&str>> =
            retry_with_backoff(&policy, || async { Err::<i32, _>("always fails") }, |_| true)
                .await;
        match result {
            Err(RetryError::Exhausted { attempts, last }) => {
                assert_eq!(attempts, 3);
                assert_eq!(last, "always fails");
            }
            other => panic!("expected Exhausted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_retryable_short_circuits() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();
        let policy = fast_policy(5);
        let result: Result<i32, RetryError<&str>> = retry_with_backoff(
            &policy,
            || {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err::<i32, _>("fatal")
                }
            },
            |_e| false,
        )
        .await;
        match result {
            Err(RetryError::NonRetryable(e)) => assert_eq!(e, "fatal"),
            other => panic!("expected NonRetryable, got {other:?}"),
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn zero_retries_runs_once() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();
        let policy = fast_policy(0);
        let _ = retry_with_backoff(
            &policy,
            || {
                let counter = counter_clone.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err::<i32, _>("nope")
                }
            },
            |_| true,
        )
        .await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn predicate_inspects_error() {
        let policy = fast_policy(5);
        // Retry only "transient", bail on "fatal".
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();
        let result: Result<(), RetryError<&str>> = retry_with_backoff(
            &policy,
            || {
                let attempts = attempts_clone.clone();
                async move {
                    let n = attempts.fetch_add(1, Ordering::SeqCst);
                    if n == 0 { Err("transient") } else { Err("fatal") }
                }
            },
            |e| *e == "transient",
        )
        .await;
        match result {
            Err(RetryError::NonRetryable(e)) => assert_eq!(e, "fatal"),
            other => panic!("expected NonRetryable on second attempt, got {other:?}"),
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn retry_error_into_inner_extracts() {
        let exhausted = RetryError::Exhausted {
            attempts: 3,
            last: "boom",
        };
        assert_eq!(exhausted.into_inner(), "boom");
        let nonr = RetryError::NonRetryable("nope");
        assert_eq!(nonr.into_inner(), "nope");
    }

    #[test]
    fn retry_error_display() {
        let e = RetryError::Exhausted {
            attempts: 5,
            last: "boom",
        };
        let msg = format!("{e}");
        assert!(msg.contains("5"));
        assert!(msg.contains("boom"));
        let n = RetryError::NonRetryable("fatal");
        assert!(format!("{n}").contains("fatal"));
    }
}
