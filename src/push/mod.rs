//! Push delivery backend abstraction and provider implementations.

pub mod apns;
pub mod fcm;
pub mod noop;

use std::sync::Arc;

use thiserror::Error;

use crate::store::{BoxFuture, Platform, Registration};

/// Result of attempting to dispatch a wake push to a mobile platform gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// Upstream push gateway accepted the wake push.
    Delivered,
    /// Upstream push gateway reported that the device token is permanently invalid or
    /// unregistered; the relay should delete the handle.
    InvalidToken {
        /// Upstream provider error reason (contains no device token or user data).
        reason: String,
    },
}

/// Errors returned by [`PushSender`] implementations.
#[derive(Debug, Error)]
pub enum PushError {
    /// No push provider is configured for the requested platform.
    #[error("push provider not configured for platform {0}")]
    PlatformNotConfigured(Platform),
    /// Provider configuration or key material is invalid.
    #[error("invalid push provider configuration: {0}")]
    Config(String),
    /// Failed to obtain or sign provider authentication credentials.
    #[error("push provider authentication failed: {0}")]
    Auth(String),
    /// Transient or unexpected upstream gateway failure.
    #[error("upstream push gateway error: {0}")]
    Upstream(String),
}

/// Abstraction over mobile push notification delivery backends (APNs, FCM, no-op/mock).
pub trait PushSender: Send + Sync {
    /// Dispatches a content-free wake push for `registration`.
    fn send_wake<'a>(
        &'a self,
        registration: &'a Registration,
    ) -> BoxFuture<'a, Result<PushOutcome, PushError>>;
}

/// Composite [`PushSender`] routing APNs and FCM registrations to their respective backends.
#[derive(Default)]
pub struct RouterPushSender {
    apns: Option<Arc<dyn PushSender>>,
    fcm: Option<Arc<dyn PushSender>>,
}

impl std::fmt::Debug for RouterPushSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterPushSender")
            .field("apns_configured", &self.apns.is_some())
            .field("fcm_configured", &self.fcm.is_some())
            .finish()
    }
}

impl RouterPushSender {
    /// Creates an empty router with no configured providers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures the APNs backend.
    #[must_use]
    pub fn with_apns(mut self, sender: Arc<dyn PushSender>) -> Self {
        self.apns = Some(sender);
        self
    }

    /// Configures the FCM backend.
    #[must_use]
    pub fn with_fcm(mut self, sender: Arc<dyn PushSender>) -> Self {
        self.fcm = Some(sender);
        self
    }

    /// Returns `true` if at least one push backend is configured.
    #[must_use]
    pub fn has_any_provider(&self) -> bool {
        self.apns.is_some() || self.fcm.is_some()
    }
}

impl PushSender for RouterPushSender {
    fn send_wake<'a>(
        &'a self,
        registration: &'a Registration,
    ) -> BoxFuture<'a, Result<PushOutcome, PushError>> {
        Box::pin(async move {
            match registration.platform {
                Platform::Apns => match &self.apns {
                    Some(sender) => sender.send_wake(registration).await,
                    None => Err(PushError::PlatformNotConfigured(Platform::Apns)),
                },
                Platform::Fcm => match &self.fcm {
                    Some(sender) => sender.send_wake(registration).await,
                    None => Err(PushError::PlatformNotConfigured(Platform::Fcm)),
                },
            }
        })
    }
}
