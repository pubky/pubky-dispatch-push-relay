//! Sliding-window rate limiting abstraction and in-memory implementation
//! (Wire Format §8.3 rule 6 and registration throttling).

use std::collections::{HashMap, VecDeque};

use parking_lot::Mutex;
use thiserror::Error;

use crate::store::BoxFuture;

/// Rate-limit window duration: 60 seconds in milliseconds.
pub const RATE_WINDOW_MS: u64 = 60_000;

/// Default maximum pushes per handle per minute.
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 60;

/// Default cap on simultaneously tracked keys to bound memory usage.
pub const DEFAULT_MAX_TRACKED_HANDLES: usize = 100_000;

/// Errors returned by [`RateLimitStore`] implementations.
#[derive(Debug, Error)]
pub enum RateLimitError {
    /// Underlying storage backend error.
    #[error("rate limit store backend error: {0}")]
    Backend(String),
}

/// Async abstraction for sliding-window rate limiting.
///
/// Single-instance SQLite deployments use the in-memory [`RateLimiter`], while
/// multi-replica PostgreSQL deployments share a durable table via
/// [`crate::store::postgres::PostgresRateLimitStore`].
pub trait RateLimitStore: Send + Sync {
    /// Atomically attempts to consume one slot for `key` at `now_ms`.
    ///
    /// Returns `Ok(Ok(()))` if permitted, `Ok(Err(retry_after_secs))` (`>= 1`) when
    /// the key has reached its limit, or `Err(RateLimitError)` on backend failure.
    fn check_and_record<'a>(
        &'a self,
        key: &'a str,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<Result<(), u64>, RateLimitError>>;

    /// Removes rate-limit state for `key` (for example after dead-token handle pruning).
    fn remove_key<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), RateLimitError>>;

    /// Prunes expired rate-limit buckets at `now_ms`, returning how many were removed.
    fn prune_expired<'a>(&'a self, now_ms: u64) -> BoxFuture<'a, Result<usize, RateLimitError>>;
}

struct LimiterState {
    buckets: HashMap<String, VecDeque<u64>>,
}

/// Thread-safe, bounded-memory per-key sliding-window rate limiter.
///
/// Never evicts an active live bucket under saturation; if `max_handles` active keys are
/// already tracked after pruning expired entries, new keys are throttled fail-closed.
pub struct RateLimiter {
    window_ms: u64,
    max_per_window: usize,
    max_handles: usize,
    state: Mutex<LimiterState>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("window_ms", &self.window_ms)
            .field("max_per_window", &self.max_per_window)
            .field("max_handles", &self.max_handles)
            .field("tracked_handles", &self.tracked_handles())
            .finish()
    }
}

impl RateLimiter {
    /// Creates a new sliding-window rate limiter.
    #[must_use]
    pub fn new(max_per_minute: u32, max_handles: usize) -> Self {
        Self::with_window(RATE_WINDOW_MS, max_per_minute, max_handles)
    }

    /// Creates a rate limiter with a custom window length in milliseconds.
    #[must_use]
    pub fn with_window(window_ms: u64, max_per_window: u32, max_handles: usize) -> Self {
        Self {
            window_ms: window_ms.max(1),
            max_per_window: usize::try_from(max_per_window).unwrap_or(usize::MAX),
            max_handles: max_handles.max(1),
            state: Mutex::new(LimiterState {
                buckets: HashMap::new(),
            }),
        }
    }

    /// Attempts to consume one slot for `handle` at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns `Err(retry_after_secs)` (always `>= 1`) when `handle` has reached its
    /// per-minute limit or when `max_handles` live buckets are already active.
    pub fn check_and_record(&self, handle: &str, now_ms: u64) -> Result<(), u64> {
        if self.max_per_window == 0 {
            return Err(self.window_ms.div_ceil(1_000).max(1));
        }

        let mut state = self.state.lock();
        let window_ms = self.window_ms;

        if !state.buckets.contains_key(handle) && state.buckets.len() >= self.max_handles {
            Self::prune_expired_locked(&mut state, now_ms, window_ms);
            if state.buckets.len() >= self.max_handles {
                return Err(window_ms.div_ceil(1_000).max(1));
            }
        }

        let bucket = state.buckets.entry(handle.to_owned()).or_default();
        while let Some(&ts) = bucket.front() {
            if now_ms.saturating_sub(ts) >= window_ms {
                bucket.pop_front();
            } else {
                break;
            }
        }

        if bucket.len() >= self.max_per_window {
            let oldest = bucket.front().copied().unwrap_or(now_ms);
            let wait_ms = oldest.saturating_add(window_ms).saturating_sub(now_ms);
            let retry_after_secs = wait_ms.div_ceil(1_000).max(1);
            return Err(retry_after_secs);
        }

        bucket.push_back(now_ms);
        Ok(())
    }

    /// Drops rate-limit state for a handle (e.g. after dead-token handle pruning).
    pub fn remove_handle(&self, handle: &str) {
        self.state.lock().buckets.remove(handle);
    }

    /// Removes all inactive handles whose timestamps have aged out of the window.
    pub fn prune_expired(&self, now_ms: u64) -> usize {
        let mut state = self.state.lock();
        Self::prune_expired_locked(&mut state, now_ms, self.window_ms)
    }

    /// Returns the number of handles currently tracked in memory.
    #[must_use]
    pub fn tracked_handles(&self) -> usize {
        self.state.lock().buckets.len()
    }

    fn prune_expired_locked(state: &mut LimiterState, now_ms: u64, window_ms: u64) -> usize {
        let before = state.buckets.len();
        state.buckets.retain(|_, timestamps| {
            while let Some(&ts) = timestamps.front() {
                if now_ms.saturating_sub(ts) >= window_ms {
                    timestamps.pop_front();
                } else {
                    break;
                }
            }
            !timestamps.is_empty()
        });
        before.saturating_sub(state.buckets.len())
    }
}

impl RateLimitStore for RateLimiter {
    fn check_and_record<'a>(
        &'a self,
        key: &'a str,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<Result<(), u64>, RateLimitError>> {
        Box::pin(async move { Ok(Self::check_and_record(self, key, now_ms)) })
    }

    fn remove_key<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), RateLimitError>> {
        Box::pin(async move {
            Self::remove_handle(self, key);
            Ok(())
        })
    }

    fn prune_expired<'a>(&'a self, now_ms: u64) -> BoxFuture<'a, Result<usize, RateLimitError>> {
        Box::pin(async move { Ok(Self::prune_expired(self, now_ms)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_per_handle_sliding_window_and_isolation() {
        let limiter = RateLimiter::new(2, 100);

        assert_eq!(limiter.check_and_record("h1", 0), Ok(()));
        assert_eq!(limiter.check_and_record("h1", 1_000), Ok(()));
        assert_eq!(limiter.check_and_record("h1", 1_500), Err(59));

        assert_eq!(limiter.check_and_record("h2", 1_500), Ok(()));

        assert_eq!(limiter.check_and_record("h1", 60_000), Ok(()));
        assert_eq!(limiter.check_and_record("h1", 60_500), Err(1));
    }

    #[test]
    fn fails_closed_when_bucket_table_full_of_live_keys_and_prunes_when_stale() {
        let limiter = RateLimiter::new(5, 2);
        assert!(limiter.check_and_record("h1", 100).is_ok());
        assert!(limiter.check_and_record("h2", 200).is_ok());
        assert_eq!(limiter.tracked_handles(), 2);

        // Live buckets are never evicted to make room for h3.
        assert!(limiter.check_and_record("h3", 300).is_err());
        assert_eq!(limiter.tracked_handles(), 2);

        // Once h1 and h2 age out of the 60s window, they are pruned and h3 is accepted.
        assert!(limiter.check_and_record("h3", 70_000).is_ok());
        assert_eq!(limiter.tracked_handles(), 1);
    }
}
