//! 10-minute nonce replay protection abstraction and bounded in-memory cache
//! (Wire Format §8.3 rule 5).
//!
//! Live nonces inside their 10-minute window are NEVER evicted under capacity pressure:
//! - If a single handle reaches its per-handle active-nonce cap, implementations return
//!   [`ReplayError::HandleCapacityExceeded`] so unrelated handles are unaffected.
//! - If the global replay store is full of live nonces, implementations return
//!   [`ReplayError::CapacityExceeded`] so the HTTP layer refuses new webhooks with
//!   `503 Service Unavailable`.

use std::collections::HashMap;

use parking_lot::Mutex;
use ring::digest;
use thiserror::Error;

use crate::store::BoxFuture;

/// Nonce replay window: 10 minutes in milliseconds (Wire Format §8.3 rule 5).
pub const NONCE_TTL_MS: u64 = 10 * 60 * 1_000;

/// Default maximum number of live nonces retained globally in replay storage.
pub const DEFAULT_MAX_NONCE_ENTRIES: usize = 100_000;

/// Default maximum number of live nonces a single handle may hold simultaneously inside
/// the 10-minute replay window (comfortably above `10 * DEFAULT_RATE_LIMIT_PER_MINUTE`).
pub const DEFAULT_MAX_NONCES_PER_HANDLE: usize = 1_000;

const HANDLE_HASH_DOMAIN: &[u8] = b"pubky-dispatch-push-relay/v1/replay-handle:";

/// Computes a fixed 16-byte SHA-256 tag for `handle` so replay storage can enforce
/// per-handle nonce caps without duplicating raw handle strings.
#[must_use]
pub fn handle_replay_hash(handle: &str) -> [u8; 16] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(HANDLE_HASH_DOMAIN);
    ctx.update(handle.as_bytes());
    let full = ctx.finish();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full.as_ref()[..16]);
    out
}

/// Errors returned by [`ReplayStore`] implementations.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// A single handle has reached its maximum active live-nonce cap inside the 10-minute
    /// window, isolating other handles from replay-table exhaustion.
    #[error("handle has reached its live-nonce capacity")]
    HandleCapacityExceeded,
    /// Replay store has reached its maximum global live-entry capacity; callers must reject
    /// new webhooks with `503 Service Unavailable` rather than evicting live nonces.
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
    /// Read-only check returning `Ok(true)` if `nonce` is already live inside its 10-minute
    /// window without modifying replay storage or consuming capacity.
    ///
    /// Used before per-handle rate limiting so replayed nonces always return `409` before
    /// `429` (Wire Format §8.3), while rate-rejected fresh nonces never enter the replay table.
    fn contains_live<'a>(
        &'a self,
        nonce: [u8; 16],
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ReplayError>>;

    /// Atomically checks whether `nonce` was seen within its TTL and, if unseen, records it
    /// under `handle` subject to both per-handle and global live-entry caps.
    ///
    /// Returns:
    /// - `Ok(true)` if unseen (or expired) and newly recorded;
    /// - `Ok(false)` if still live (replay -> `409`), even when the store is at capacity;
    /// - `Err(ReplayError::HandleCapacityExceeded)` if `handle` hit its per-handle live cap;
    /// - `Err(ReplayError::CapacityExceeded)` if unseen and global live count is at capacity (`503`).
    fn check_and_record<'a>(
        &'a self,
        handle: &'a str,
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
struct NonceEntry {
    handle_hash: [u8; 16],
    wall_expires_at: u64,
    mono_expires_at: u64,
}

impl NonceEntry {
    /// Conservative expiry: requires BOTH wall clock and monotonic clock to pass the TTL
    /// so a forward-and-back wall clock jump cannot expire a live nonce.
    const fn is_expired(self, wall_now_ms: u64, mono_now_ms: u64) -> bool {
        wall_now_ms >= self.wall_expires_at && mono_now_ms >= self.mono_expires_at
    }
}

/// Thread-safe, bounded-memory TTL replay cache that never evicts live nonces and enforces
/// both per-handle and global live-nonce caps.
pub struct NonceCache {
    ttl_ms: u64,
    max_entries: usize,
    max_per_handle: usize,
    entries: Mutex<HashMap<[u8; 16], NonceEntry>>,
}

impl std::fmt::Debug for NonceCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceCache")
            .field("ttl_ms", &self.ttl_ms)
            .field("max_entries", &self.max_entries)
            .field("max_per_handle", &self.max_per_handle)
            .field("len", &self.len())
            .finish()
    }
}

impl NonceCache {
    /// Creates a new replay cache with the given TTL (milliseconds) and global entry cap
    /// using [`DEFAULT_MAX_NONCES_PER_HANDLE`].
    ///
    /// A `max_entries` of `0` is clamped to `1`.
    #[must_use]
    pub fn new(ttl_ms: u64, max_entries: usize) -> Self {
        Self::with_limits(ttl_ms, max_entries, DEFAULT_MAX_NONCES_PER_HANDLE)
    }

    /// Creates a new replay cache with explicit global and per-handle live-entry caps.
    #[must_use]
    pub fn with_limits(ttl_ms: u64, max_entries: usize, max_per_handle: usize) -> Self {
        Self {
            ttl_ms,
            max_entries: max_entries.max(1),
            max_per_handle: max_per_handle.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Read-only check returning `true` if `nonce` is currently live.
    #[must_use]
    pub fn contains_live(&self, nonce: [u8; 16], wall_now_ms: u64, mono_now_ms: u64) -> bool {
        let map = self.entries.lock();
        map.get(&nonce)
            .is_some_and(|entry| !entry.is_expired(wall_now_ms, mono_now_ms))
    }

    /// Checks whether `nonce` is live, refusing new insertions with
    /// [`ReplayError::HandleCapacityExceeded`] or [`ReplayError::CapacityExceeded`] instead
    /// of evicting live nonces.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::HandleCapacityExceeded`] if `handle` already has
    /// `max_per_handle` live nonces, or [`ReplayError::CapacityExceeded`] if `max_entries`
    /// live nonces are already present globally.
    pub fn check_and_record(
        &self,
        handle: &str,
        nonce: [u8; 16],
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> Result<bool, ReplayError> {
        let handle_hash = handle_replay_hash(handle);
        let mut map = self.entries.lock();
        if let Some(&entry) = map.get(&nonce)
            && !entry.is_expired(wall_now_ms, mono_now_ms)
        {
            return Ok(false);
        }

        map.retain(|_, entry| !entry.is_expired(wall_now_ms, mono_now_ms));

        let handle_live = map
            .values()
            .filter(|entry| entry.handle_hash == handle_hash)
            .count();
        if handle_live >= self.max_per_handle {
            return Err(ReplayError::HandleCapacityExceeded);
        }

        if map.len() >= self.max_entries {
            return Err(ReplayError::CapacityExceeded);
        }

        map.insert(
            nonce,
            NonceEntry {
                handle_hash,
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
        map.retain(|_, entry| !entry.is_expired(wall_now_ms, mono_now_ms));
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
    fn contains_live<'a>(
        &'a self,
        nonce: [u8; 16],
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ReplayError>> {
        Box::pin(async move { Ok(Self::contains_live(self, nonce, wall_now_ms, mono_now_ms)) })
    }

    fn check_and_record<'a>(
        &'a self,
        handle: &'a str,
        nonce: [u8; 16],
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ReplayError>> {
        Box::pin(
            async move { Self::check_and_record(self, handle, nonce, wall_now_ms, mono_now_ms) },
        )
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

        assert!(!cache.contains_live(nonce, 1_000, 0));
        assert!(cache.check_and_record("h1", nonce, 1_000, 0).unwrap());
        assert!(cache.contains_live(nonce, 1_000, 0));
        assert!(!cache.check_and_record("h1", nonce, 1_000, 0).unwrap());
        assert!(
            !cache
                .check_and_record("h1", nonce, 1_000 + NONCE_TTL_MS - 1, NONCE_TTL_MS - 1)
                .unwrap()
        );
        assert!(
            cache
                .check_and_record("h1", nonce, 1_000 + NONCE_TTL_MS, NONCE_TTL_MS)
                .unwrap()
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn refuses_new_nonces_when_full_and_isolates_per_handle_cap() {
        let cache = NonceCache::with_limits(NONCE_TTL_MS, 4, 2);
        assert!(cache.check_and_record("h1", [1; 16], 10, 10).unwrap());
        assert!(cache.check_and_record("h1", [2; 16], 20, 20).unwrap());

        // h1 hit its per-handle cap (2), while h2 is still unaffected!
        assert!(matches!(
            cache.check_and_record("h1", [3; 16], 30, 30),
            Err(ReplayError::HandleCapacityExceeded)
        ));
        assert!(cache.check_and_record("h2", [3; 16], 30, 30).unwrap());
        assert!(cache.check_and_record("h2", [4; 16], 35, 35).unwrap());
        assert_eq!(cache.len(), 4);

        // Global cap (4) reached: fresh nonce for h3 fails with CapacityExceeded.
        assert!(matches!(
            cache.check_and_record("h3", [5; 16], 40, 40),
            Err(ReplayError::CapacityExceeded)
        ));
        // Live nonces are STILL rejected as replays (409).
        assert!(!cache.check_and_record("h1", [1; 16], 45, 45).unwrap());
        assert!(!cache.check_and_record("h2", [3; 16], 45, 45).unwrap());
    }

    #[test]
    fn wall_clock_jump_forward_and_back_does_not_reopen_replay() {
        let cache = NonceCache::new(NONCE_TTL_MS, 10);
        let nonce = [9u8; 16];
        assert!(cache.check_and_record("h1", nonce, 1_000_000, 0).unwrap());

        // Wall clock jumps +15 minutes while monotonic clock only moved 5 seconds.
        assert_eq!(cache.prune_expired(1_000_000 + 900_000, 5_000), 0);
        // Wall clock jumps back to +2 minutes: nonce is still live!
        assert!(
            !cache
                .check_and_record("h1", nonce, 1_000_000 + 120_000, 10_000)
                .unwrap()
        );
    }
}
