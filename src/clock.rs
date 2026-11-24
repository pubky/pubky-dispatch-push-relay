//! Clock abstraction for deterministic timestamp, replay-window, and rate-limit testing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Source of current wall-clock time in Unix milliseconds (UTC).
pub trait Clock: Send + Sync {
    /// Returns the current Unix timestamp in milliseconds.
    fn now_ms(&self) -> u64;
}

/// Production clock backed by [`SystemTime::now`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// Manually controlled clock for deterministic tests.
#[derive(Debug)]
pub struct FixedClock {
    now_ms: AtomicU64,
}

impl FixedClock {
    /// Creates a fixed clock initialized to `now_ms` Unix milliseconds.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        Self {
            now_ms: AtomicU64::new(now_ms),
        }
    }

    /// Sets the clock to an exact Unix millisecond timestamp.
    pub fn set(&self, now_ms: u64) {
        self.now_ms.store(now_ms, Ordering::SeqCst);
    }

    /// Advances the clock forward by `delta_ms` milliseconds.
    pub fn advance_ms(&self, delta_ms: u64) {
        self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}
