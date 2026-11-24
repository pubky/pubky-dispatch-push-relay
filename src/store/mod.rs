//! Registration persistence abstraction.
//!
//! Defines [`RegistrationStore`] so SQLite is used out of the box and additional backends
//! (such as PostgreSQL) can be plugged in without changing HTTP or push logic.

pub mod sqlite;

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

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

/// Persisted mapping `handle -> (platform, device_token, push_key, apns_env, created_at_ms)`.
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
            .finish()
    }
}

/// Errors returned by [`RegistrationStore`] implementations.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A registration with the same handle already exists.
    #[error("registration handle already exists")]
    DuplicateHandle,
    /// Persisted database row contained invalid or corrupted values.
    #[error("corrupt storage record: {0}")]
    CorruptData(String),
    /// Underlying database/IO error.
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// Storage trait for opaque handle registrations.
///
/// Implementations must guarantee that registering a new handle never overwrites or
/// redirects an existing handle.
pub trait RegistrationStore: Send + Sync {
    /// Persists a new registration. Fails with [`StoreError::DuplicateHandle`] if the
    /// handle already exists.
    fn insert<'a>(
        &'a self,
        registration: &'a Registration,
    ) -> BoxFuture<'a, Result<(), StoreError>>;

    /// Looks up a registration by its opaque handle.
    fn get<'a>(
        &'a self,
        handle: &'a str,
    ) -> BoxFuture<'a, Result<Option<Registration>, StoreError>>;

    /// Deletes a registration by handle, returning `true` if a row was removed.
    fn delete<'a>(&'a self, handle: &'a str) -> BoxFuture<'a, Result<bool, StoreError>>;

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
        };
        let rendered = format!("{reg:?}");
        assert!(!rendered.contains("secret-handle-123"));
        assert!(!rendered.contains("deadbeef"));
        assert!(!rendered.contains("66, 66"));
        assert!(rendered.contains("<redacted>"));
    }
}
