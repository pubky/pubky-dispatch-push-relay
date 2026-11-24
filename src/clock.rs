//! Clock abstraction providing both wall-clock time (for RFC 3339 ±5 minute checks and
//! registration expiry) and monotonic time (so forward-and-back wall-clock jumps cannot
//! prematurely expire live nonces).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static PROCESS_EPOCH: OnceLock<Instant> = OnceLock::new();

fn process_monotonic_ms() -> u64 {
    let epoch = PROCESS_EPOCH.get_or_init(Instant::now);
    u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Source of wall-clock and monotonic timestamps in milliseconds.
pub trait Clock: Send + Sync {
    /// Returns the current Unix wall-clock timestamp in milliseconds (UTC).
    fn now_ms(&self) -> u64;

    /// Returns a monotonically non-decreasing process-local timestamp in milliseconds.
    fn monotonic_ms(&self) -> u64;
}

/// Production clock backed by [`SystemTime::now`] and [`Instant::now`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn monotonic_ms(&self) -> u64 {
        process_monotonic_ms()
    }
}

/// Manually controlled clock for deterministic tests.
#[derive(Debug)]
pub struct FixedClock {
    now_ms: AtomicU64,
    monotonic_ms: AtomicU64,
}

impl FixedClock {
    /// Creates a fixed clock initialized to `now_ms` Unix milliseconds and `0` monotonic ms.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        Self {
            now_ms: AtomicU64::new(now_ms),
            monotonic_ms: AtomicU64::new(0),
        }
    }

    /// Sets the wall clock to `now_ms` and advances the monotonic clock by any forward delta.
    pub fn set(&self, now_ms: u64) {
        let prev = self.now_ms.swap(now_ms, Ordering::SeqCst);
        if now_ms > prev {
            self.monotonic_ms.fetch_add(now_ms - prev, Ordering::SeqCst);
        }
    }

    /// Sets ONLY the wall clock without moving the monotonic clock (for testing NTP jumps
    /// forward and backward).
    pub fn set_wall_only(&self, now_ms: u64) {
        self.now_ms.store(now_ms, Ordering::SeqCst);
    }

    /// Advances both wall and monotonic clocks forward by `delta_ms` milliseconds.
    pub fn advance_ms(&self, delta_ms: u64) {
        self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
        self.monotonic_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }

    /// Advances ONLY the monotonic clock by `delta_ms` milliseconds.
    pub fn advance_monotonic_ms(&self, delta_ms: u64) {
        self.monotonic_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    fn monotonic_ms(&self) -> u64 {
        self.monotonic_ms.load(Ordering::SeqCst)
    }
}
