//! Registration persistence abstraction and SQLite/PostgreSQL backends.
//!
//! Defines [`RegistrationStore`] with SQLite as the zero-config single-instance default
//! and PostgreSQL for stateless multi-replica deployments.

pub mod postgres;
pub mod sqlite;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Returns `true` when `database_url` selects the PostgreSQL backend (`postgres://` or
/// `postgresql://`). Any other value selects SQLite.
#[must_use]
pub fn is_postgres_url(database_url: &str) -> bool {
    database_url.starts_with("postgres://") || database_url.starts_with("postgresql://")
}

/// Boxed `Send` future for object-safe async storage methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Target mobile push platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Apple Push Notification service (iOS / macOS).
    Apns,
    /// Firebase Cloud Messaging (Android).
    Fcm,
}

impl Platform {
    /// Returns the lowercase wire representation (`"apns"` or `"fcm"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::Fcm => "fcm",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Platform {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "apns" => Ok(Self::Apns),
            "fcm" => Ok(Self::Fcm),
            other => Err(StoreError::CorruptData(format!(
                "unknown platform: {other}"
            ))),
        }
    }
}

/// APNs delivery environment for a device token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApnsEnv {
    /// Apple production gateway (`api.push.apple.com`).
    Production,
    /// Apple sandbox gateway (`api.sandbox.push.apple.com`).
    Sandbox,
}

impl ApnsEnv {
    /// Returns the lowercase wire representation (`"production"` or `"sandbox"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Sandbox => "sandbox",
        }
    }
}

impl fmt::Display for ApnsEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ApnsEnv {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "production" => Ok(Self::Production),
            "sandbox" => Ok(Self::Sandbox),
            other => Err(StoreError::CorruptData(format!(
                "unknown apns_env: {other}"
            ))),
        }
    }
}

/// Persisted mapping
/// `handle -> (platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms)`.
///
/// Never stores any Pubky identity, App ID, or source network address.
#[derive(Clone, PartialEq, Eq)]
pub struct Registration {
    /// Cryptographically random opaque handle returned to the client.
    pub handle: String,
    /// Target push platform.
    pub platform: Platform,
    /// Platform-specific device push token.
    pub device_token: String,
    /// 32-byte Ed25519 public push key bound to this handle.
    pub push_key: [u8; 32],
    /// Optional APNs environment override (`None` for FCM or server default).
    pub apns_env: Option<ApnsEnv>,
    /// Creation time in Unix milliseconds (UTC).
    pub created_at_ms: u64,
    /// Last valid webhook or idempotent registration time in Unix milliseconds (UTC).
    pub last_active_at_ms: u64,
}

impl fmt::Debug for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registration")
            .field("handle", &"<redacted>")
            .field("platform", &self.platform)
            .field("device_token", &"<redacted>")
            .field("push_key", &"<redacted>")
            .field("apns_env", &self.apns_env)
            .field("created_at_ms", &self.created_at_ms)
            .field("last_active_at_ms", &self.last_active_at_ms)
            .finish()
    }
}

/// Capacity and expiry bounds enforced atomically on registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistrationLimits {
    /// Maximum total active registrations in the store.
    pub max_registrations: u64,
    /// Maximum active handles bound to a single `push_key`.
    pub max_handles_per_push_key: u32,
    /// Inactivity expiry duration in milliseconds.
    pub ttl_ms: u64,
}

/// Result of an idempotent registration operation.
///
/// Redacts the opaque handle in [`fmt::Debug`] so handles never leak into debug output.
#[derive(Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// A brand-new opaque handle was created.
    Created(String),
    /// An active registration for the same `(platform, device_token, push_key, apns_env)`
    /// already existed and its existing handle was returned unchanged.
    Existing(String),
}

impl fmt::Debug for RegisterOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created(_) => f.write_str("Created(<redacted>)"),
            Self::Existing(_) => f.write_str("Existing(<redacted>)"),
        }
    }
}

impl RegisterOutcome {
    /// Returns the opaque handle string.
    #[must_use]
    pub fn into_handle(self) -> String {
        match self {
            Self::Created(h) | Self::Existing(h) => h,
        }
    }
}

/// Errors returned by [`RegistrationStore`] implementations.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A registration with the same handle already exists.
    #[error("registration handle already exists")]
    DuplicateHandle,
    /// The push key already holds the maximum allowed active handles.
    #[error("push key has reached its maximum active handle quota")]
    PushKeyCapacityExceeded,
    /// Store has reached its configured maximum global registration capacity.
    #[error("registration store has reached its maximum capacity")]
    CapacityExceeded,
    /// Persisted database row contained invalid or corrupted values.
    #[error("corrupt storage record: {0}")]
    CorruptData(String),
    /// Underlying database/IO error.
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// Storage trait for opaque handle registrations.
///
/// Implementations guarantee:
/// - Registering a new device token or push key never overwrites, redirects, or evicts an
///   existing handle.
/// - Re-registering the exact same `(platform, device_token, push_key, apns_env)` while
///   active returns the existing handle idempotently and refreshes `last_active_at_ms`.
/// - Both per-push-key and global capacity caps are enforced atomically.
pub trait RegistrationStore: Send + Sync {
    /// Atomically returns the existing active handle for the same
    /// `(platform, device_token, push_key, apns_env)`, or inserts `candidate` after
    /// verifying per-push-key and global active caps.
    fn register_or_get<'a>(
        &'a self,
        candidate: &'a Registration,
        limits: RegistrationLimits,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<RegisterOutcome, StoreError>>;

    /// Directly persists a new registration, atomically enforcing `max_registrations` when
    /// `Some`. Used by fixtures and low-level store tests.
    fn insert<'a>(
        &'a self,
        registration: &'a Registration,
        max_registrations: Option<u64>,
    ) -> BoxFuture<'a, Result<(), StoreError>>;

    /// Looks up a registration by its opaque handle regardless of inactivity expiry.
    fn get<'a>(
        &'a self,
        handle: &'a str,
    ) -> BoxFuture<'a, Result<Option<Registration>, StoreError>>;

    /// Looks up a registration only if it is active within `ttl_ms` of the authoritative clock
    /// (`now_ms` on SQLite; PostgreSQL `clock_timestamp()` on PostgreSQL).
    fn get_active<'a>(
        &'a self,
        handle: &'a str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> BoxFuture<'a, Result<Option<Registration>, StoreError>>;

    /// Advances `last_active_at_ms` for `handle` after a valid webhook delivery.
    fn touch_last_active<'a>(
        &'a self,
        handle: &'a str,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<(), StoreError>>;

    /// Deletes a registration by handle, returning `true` if a row was removed.
    fn delete<'a>(&'a self, handle: &'a str) -> BoxFuture<'a, Result<bool, StoreError>>;

    /// Deletes a registration by handle ONLY if its `last_active_at_ms <= max_last_active_ms`,
    /// returning `true` if a row was removed and `false` if absent or superseded by a newer
    /// registration/renewal (for example when a delayed APNs `410` carries an older timestamp).
    fn delete_if_not_newer_than<'a>(
        &'a self,
        handle: &'a str,
        max_last_active_ms: u64,
    ) -> BoxFuture<'a, Result<bool, StoreError>>;

    /// Deletes registrations inactive for at least `ttl_ms` relative to the authoritative clock
    /// (`now_ms` on SQLite; PostgreSQL `clock_timestamp()` on PostgreSQL), returning how many
    /// rows were removed.
    fn prune_expired<'a>(
        &'a self,
        now_ms: u64,
        ttl_ms: u64,
    ) -> BoxFuture<'a, Result<usize, StoreError>>;

    /// Verifies storage availability for health checks.
    fn ping<'a>(&'a self) -> BoxFuture<'a, Result<(), StoreError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_debug_redacts_sensitive_fields() {
        let reg = Registration {
            handle: "secret-handle-123".to_owned(),
            platform: Platform::Apns,
            device_token: "deadbeef0123456789abcdef".to_owned(),
            push_key: [0x42; 32],
            apns_env: Some(ApnsEnv::Sandbox),
            created_at_ms: 1_767_225_960_000,
            last_active_at_ms: 1_767_225_960_000,
        };
        let rendered = format!("{reg:?}");
        assert!(!rendered.contains("secret-handle-123"));
        assert!(!rendered.contains("deadbeef"));
        assert!(!rendered.contains("66, 66"));
        assert!(rendered.contains("<redacted>"));

        let created = format!(
            "{:?}",
            RegisterOutcome::Created("secret-handle-1".to_owned())
        );
        let existing = format!(
            "{:?}",
            RegisterOutcome::Existing("secret-handle-2".to_owned())
        );
        assert!(!created.contains("secret-handle-1"));
        assert!(!existing.contains("secret-handle-2"));
        assert_eq!(created, "Created(<redacted>)");
        assert_eq!(existing, "Existing(<redacted>)");
    }

    #[test]
    fn detects_postgres_and_sqlite_urls() {
        assert!(is_postgres_url("postgres://user:pass@localhost:5432/relay"));
        assert!(is_postgres_url("postgresql://localhost/relay"));
        assert!(!is_postgres_url("./data/push-relay.sqlite"));
        assert!(!is_postgres_url("sqlite://relay.db"));
        assert!(!is_postgres_url(":memory:"));
    }
}
