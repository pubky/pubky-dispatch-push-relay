//! 10-minute nonce replay protection abstraction and bounded in-memory cache
//! (Wire Format §8.3 rule 5).
//!
//! Live nonces inside their 10-minute window are NEVER evicted under capacity pressure:
//! when full, implementations return [`ReplayError::CapacityExceeded`] so the HTTP layer
//! refuses new webhooks with `503 Service Unavailable`.

use std::collections::HashMap;

use parking_lot::Mutex;
use thiserror::Error;

use crate::store::BoxFuture;

/// Nonce replay window: 10 minutes in milliseconds (Wire Format §8.3 rule 5).
pub const NONCE_TTL_MS: u64 = 10 * 60 * 1_000;

/// Default maximum number of live nonces retained in replay storage.
pub const DEFAULT_MAX_NONCE_ENTRIES: usize = 100_000;

/// Errors returned by [`ReplayStore`] implementations.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// Replay store has reached its maximum live-entry capacity; callers must reject new
    /// webhooks with `503 Service Unavailable` rather than evicting live nonces.
    #[error("replay store has reached its live-nonce capacity")]
    CapacityExceeded,
    /// Underlying storage backend error.
    #[error("replay store backend error: {0}")]
    Backend(String),
}

/// Async abstraction for 10-minute webhook nonce replay protection.
///
/// - SQLite deployments persist nonces in [`crate::store::sqlite::SqliteReplayStore`] so
///   restarts preserve live nonces.
/// - Multi-replica PostgreSQL deployments share a durable table via
///   [`crate::store::postgres::PostgresReplayStore`] using database time.
pub trait ReplayStore: Send + Sync {
    /// Atomically checks whether `nonce` was seen within its TTL.
    ///
    /// Returns:
    /// - `Ok(true)` if unseen (or expired) and newly recorded;
    /// - `Ok(false)` if still live (replay -> `409`), even when the store is at capacity;
    /// - `Err(ReplayError::CapacityExceeded)` if unseen and live count is at capacity (`503`).
    fn check_and_record<'a>(
        &'a self,
        nonce: [u8; 16],
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ReplayError>>;

    /// Prunes entries conservatively expired at `(wall_now_ms, mono_now_ms)`, returning how
    /// many were removed.
    fn prune_expired<'a>(
        &'a self,
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<usize, ReplayError>>;
}

#[derive(Clone, Copy)]
struct NonceExpiry {
    wall_expires_at: u64,
    mono_expires_at: u64,
}

impl NonceExpiry {
    /// Conservative expiry: requires BOTH wall clock and monotonic clock to pass the TTL
    /// so a forward-and-back wall clock jump cannot expire a live nonce.
    const fn is_expired(self, wall_now_ms: u64, mono_now_ms: u64) -> bool {
        wall_now_ms >= self.wall_expires_at && mono_now_ms >= self.mono_expires_at
    }
}

/// Thread-safe, bounded-memory TTL replay cache that never evicts live nonces.
///
/// Rejects new nonces with [`ReplayError::CapacityExceeded`] when full of unexpired entries.
pub struct NonceCache {
    ttl_ms: u64,
    max_entries: usize,
    entries: Mutex<HashMap<[u8; 16], NonceExpiry>>,
}

impl std::fmt::Debug for NonceCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceCache")
            .field("ttl_ms", &self.ttl_ms)
            .field("max_entries", &self.max_entries)
            .field("len", &self.len())
            .finish()
    }
}

impl NonceCache {
    /// Creates a new replay cache with the given TTL (milliseconds) and entry cap.
    ///
    /// A `max_entries` of `0` is clamped to `1`.
    #[must_use]
    pub fn new(ttl_ms: u64, max_entries: usize) -> Self {
        Self {
            ttl_ms,
            max_entries: max_entries.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Checks whether `nonce` is live, refusing new insertions with
    /// [`ReplayError::CapacityExceeded`] instead of evicting live nonces when full.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::CapacityExceeded`] when `nonce` is fresh and `max_entries`
    /// live nonces are already present.
    pub fn check_and_record(
        &self,
        nonce: [u8; 16],
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> Result<bool, ReplayError> {
        let mut map = self.entries.lock();
        if let Some(&exp) = map.get(&nonce)
            && !exp.is_expired(wall_now_ms, mono_now_ms)
        {
            return Ok(false);
        }

        map.retain(|_, exp| !exp.is_expired(wall_now_ms, mono_now_ms));

        if map.len() >= self.max_entries {
            return Err(ReplayError::CapacityExceeded);
        }

        map.insert(
            nonce,
            NonceExpiry {
                wall_expires_at: wall_now_ms.saturating_add(self.ttl_ms),
                mono_expires_at: mono_now_ms.saturating_add(self.ttl_ms),
            },
        );
        Ok(true)
    }

    /// Removes all entries conservatively expired at `(wall_now_ms, mono_now_ms)`.
    pub fn prune_expired(&self, wall_now_ms: u64, mono_now_ms: u64) -> usize {
        let mut map = self.entries.lock();
        let before = map.len();
        map.retain(|_, exp| !exp.is_expired(wall_now_ms, mono_now_ms));
        before.saturating_sub(map.len())
    }

    /// Returns the number of currently tracked nonces.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Returns `true` if no nonces are currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReplayStore for NonceCache {
    fn check_and_record<'a>(
        &'a self,
        nonce: [u8; 16],
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ReplayError>> {
        Box::pin(async move { Self::check_and_record(self, nonce, wall_now_ms, mono_now_ms) })
    }

    fn prune_expired<'a>(
        &'a self,
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<usize, ReplayError>> {
        Box::pin(async move { Ok(Self::prune_expired(self, wall_now_ms, mono_now_ms)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_replay_within_ttl_and_accepts_after_expiry() {
        let cache = NonceCache::new(NONCE_TTL_MS, 100);
        let nonce = [1u8; 16];

        assert!(cache.check_and_record(nonce, 1_000, 0).unwrap());
        assert!(!cache.check_and_record(nonce, 1_000, 0).unwrap());
        assert!(
            !cache
                .check_and_record(nonce, 1_000 + NONCE_TTL_MS - 1, NONCE_TTL_MS - 1)
                .unwrap()
        );
        assert!(
            cache
                .check_and_record(nonce, 1_000 + NONCE_TTL_MS, NONCE_TTL_MS)
                .unwrap()
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn refuses_new_nonces_when_full_without_evicting_live_entries() {
        let cache = NonceCache::new(NONCE_TTL_MS, 2);
        assert!(cache.check_and_record([1; 16], 10, 10).unwrap());
        assert!(cache.check_and_record([2; 16], 20, 20).unwrap());
        assert_eq!(cache.len(), 2);

        // Fresh nonce while full must fail with CapacityExceeded rather than evicting [1; 16].
        assert!(matches!(
            cache.check_and_record([3; 16], 30, 30),
            Err(ReplayError::CapacityExceeded)
        ));
        // Both live nonces are STILL rejected as replays (409).
        assert!(!cache.check_and_record([1; 16], 35, 35).unwrap());
        assert!(!cache.check_and_record([2; 16], 35, 35).unwrap());
    }

    #[test]
    fn wall_clock_jump_forward_and_back_does_not_reopen_replay() {
        let cache = NonceCache::new(NONCE_TTL_MS, 10);
        let nonce = [9u8; 16];
        assert!(cache.check_and_record(nonce, 1_000_000, 0).unwrap());

        // Wall clock jumps +15 minutes while monotonic clock only moved 5 seconds.
        assert_eq!(cache.prune_expired(1_000_000 + 900_000, 5_000), 0);
        // Wall clock jumps back to +2 minutes: nonce is still live!
        assert!(
            !cache
                .check_and_record(nonce, 1_000_000 + 120_000, 10_000)
                .unwrap()
        );
    }
}
