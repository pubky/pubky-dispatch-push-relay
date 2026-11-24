//! Bounded-memory 10-minute nonce replay cache (Wire Format §8.3 rule 5).

use std::collections::{HashMap, VecDeque};

use parking_lot::Mutex;

/// Nonce replay window: 10 minutes in milliseconds (Wire Format §8.3 rule 5).
pub const NONCE_TTL_MS: u64 = 10 * 60 * 1_000;

/// Default maximum number of live nonces retained in memory.
pub const DEFAULT_MAX_NONCE_ENTRIES: usize = 100_000;

struct CacheState {
    entries: HashMap<[u8; 16], u64>,
    expiry_order: VecDeque<([u8; 16], u64)>,
}

/// Thread-safe, bounded-memory TTL cache rejecting replayed 16-byte webhook nonces.
///
/// Because every entry shares a fixed TTL, insertion order equals expiration order,
/// yielding amortized `O(1)` TTL eviction on every lookup.
pub struct NonceCache {
    ttl_ms: u64,
    max_entries: usize,
    state: Mutex<CacheState>,
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
            state: Mutex::new(CacheState {
                entries: HashMap::new(),
                expiry_order: VecDeque::new(),
            }),
        }
    }

    /// Checks whether `nonce` was seen within the last `ttl_ms` at `now_ms`.
    ///
    /// Returns `true` and records the nonce if unseen; returns `false` if replayed.
    pub fn check_and_record(&self, nonce: [u8; 16], now_ms: u64) -> bool {
        let mut state = self.state.lock();
        Self::evict_expired_locked(&mut state, now_ms);

        if let Some(&expires_at) = state.entries.get(&nonce)
            && expires_at > now_ms
        {
            return false;
        }

        while state.entries.len() >= self.max_entries {
            let Some((oldest_nonce, oldest_expiry)) = state.expiry_order.pop_front() else {
                break;
            };
            if state.entries.get(&oldest_nonce) == Some(&oldest_expiry) {
                state.entries.remove(&oldest_nonce);
            }
        }

        let expires_at = now_ms.saturating_add(self.ttl_ms);
        state.entries.insert(nonce, expires_at);
        state.expiry_order.push_back((nonce, expires_at));
        true
    }

    /// Removes all entries expired at or before `now_ms` and returns how many were pruned.
    pub fn prune_expired(&self, now_ms: u64) -> usize {
        let mut state = self.state.lock();
        Self::evict_expired_locked(&mut state, now_ms)
    }

    /// Returns the number of currently tracked nonces.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().entries.len()
    }

    /// Returns `true` if no nonces are currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn evict_expired_locked(state: &mut CacheState, now_ms: u64) -> usize {
        let mut evicted = 0usize;
        while let Some(&(_, expires_at)) = state.expiry_order.front() {
            if expires_at > now_ms {
                break;
            }
            if let Some((nonce, exp)) = state.expiry_order.pop_front()
                && state.entries.get(&nonce) == Some(&exp)
            {
                state.entries.remove(&nonce);
                evicted += 1;
            }
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_replay_within_ttl_and_accepts_after_expiry() {
        let cache = NonceCache::new(NONCE_TTL_MS, 100);
        let nonce = [1u8; 16];

        assert!(cache.check_and_record(nonce, 1_000));
        assert!(!cache.check_and_record(nonce, 1_000));
        assert!(!cache.check_and_record(nonce, 1_000 + NONCE_TTL_MS - 1));
        assert!(cache.check_and_record(nonce, 1_000 + NONCE_TTL_MS));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn enforces_memory_bound_by_evicting_oldest() {
        let cache = NonceCache::new(NONCE_TTL_MS, 2);
        assert!(cache.check_and_record([1; 16], 10));
        assert!(cache.check_and_record([2; 16], 20));
        assert_eq!(cache.len(), 2);

        // Inserting a third evicts [1; 16] to honor max_entries = 2.
        assert!(cache.check_and_record([3; 16], 30));
        assert_eq!(cache.len(), 2);
        assert!(!cache.check_and_record([2; 16], 35));
        assert!(!cache.check_and_record([3; 16], 35));
    }
}
