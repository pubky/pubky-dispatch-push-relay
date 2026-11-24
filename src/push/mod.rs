//! Push delivery backend abstraction and provider implementations.

pub mod apns;
pub mod fcm;
pub mod noop;

use std::fmt;
use std::sync::Arc;

use thiserror::Error;

use crate::store::{BoxFuture, Platform, Registration};

/// Default per-delivery provider timeout (3.5 s), strictly below the Dispatch service's
/// 5-second webhook timeout (Wire Format §8.2).
pub const DEFAULT_PROVIDER_TIMEOUT_MS: u64 = 3_500;

/// Maximum permitted `PROVIDER_TIMEOUT_MS` so provider calls stay bounded below Dispatch's
/// 5-second webhook timeout.
pub const MAX_PROVIDER_TIMEOUT_MS: u64 = 4_500;

/// Fixed classification for token-specific provider rejections that justify handle pruning.
///
/// Using a closed enum ensures arbitrary provider-supplied response strings are never logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InvalidTokenClass {
    /// APNs `410 Gone` with explicit reason `Unregistered`.
    ApnsUnregistered,
    /// APNs `400 Bad Request` with explicit reason `BadDeviceToken`.
    ApnsBadDeviceToken,
    /// FCM error details containing `errorCode: "UNREGISTERED"`.
    FcmUnregistered,
    /// FCM `400 INVALID_ARGUMENT` explicitly naming an invalid registration token.
    FcmInvalidRegistrationToken,
}

impl InvalidTokenClass {
    /// Returns the fixed snake_case log/metric label for this invalid-token class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApnsUnregistered => "apns_unregistered",
            Self::ApnsBadDeviceToken => "apns_bad_device_token",
            Self::FcmUnregistered => "fcm_unregistered",
            Self::FcmInvalidRegistrationToken => "fcm_invalid_registration_token",
        }
    }
}

impl fmt::Display for InvalidTokenClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Fixed classification for non-pruning upstream provider failures.
///
/// Never carries arbitrary provider-supplied text, URLs, or device tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpstreamErrorClass {
    /// Provider request timed out.
    Timeout,
    /// Network or TLS transport failure.
    Transport,
    /// Provider authentication or token exchange failed.
    Auth,
    /// Provider returned an HTTP 429 rate-limit response.
    Http429,
    /// Provider returned a non-pruning HTTP 4xx response (e.g. 400/403/404/410 without token proof).
    Http4xx,
    /// Provider returned an HTTP 5xx server error.
    Http5xx,
    /// Provider returned a malformed response payload.
    BadResponse,
}

impl UpstreamErrorClass {
    /// Returns the fixed snake_case log/metric label for this upstream error class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Auth => "auth",
            Self::Http429 => "http_429",
            Self::Http4xx => "http_4xx",
            Self::Http5xx => "http_5xx",
            Self::BadResponse => "bad_response",
        }
    }
}

impl fmt::Display for UpstreamErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of attempting to dispatch a wake push to a mobile platform gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// Upstream push gateway accepted the wake push.
    Delivered,
    /// Upstream push gateway returned token-specific evidence that the device token is
    /// permanently invalid or unregistered; the relay should delete the handle.
    InvalidToken {
        /// Fixed token-rejection classification.
        class: InvalidTokenClass,
    },
}

/// Errors returned by [`PushSender`] implementations.
#[derive(Debug, Error)]
pub enum PushError {
    /// No push provider is configured for the requested platform.
    #[error("push provider not configured for platform {0}")]
    PlatformNotConfigured(Platform),
    /// Startup provider configuration or key material is invalid.
    #[error("invalid push provider configuration: {0}")]
    Config(String),
    /// Provider authentication or token exchange failed.
    #[error("push provider authentication failed ({class})")]
    Auth {
        /// Fixed failure classification.
        class: UpstreamErrorClass,
    },
    /// Transient or non-pruning upstream gateway failure.
    #[error("upstream push gateway error ({class})")]
    Upstream {
        /// Fixed failure classification.
        class: UpstreamErrorClass,
        /// Optional upstream HTTP status code.
        status: Option<u16>,
    },
}

impl PushError {
    /// Returns the fixed error class suitable for structured logging without leaking
    /// provider-supplied text.
    #[must_use]
    pub const fn log_class(&self) -> &'static str {
        match self {
            Self::PlatformNotConfigured(_) => "platform_not_configured",
            Self::Config(_) => "config",
            Self::Auth { class } | Self::Upstream { class, .. } => class.as_str(),
        }
    }
}

/// Classifies a non-2xx HTTP status code into a fixed [`UpstreamErrorClass`].
#[must_use]
pub const fn classify_http_status(status: u16) -> UpstreamErrorClass {
    match status {
        429 => UpstreamErrorClass::Http429,
        400..=499 => UpstreamErrorClass::Http4xx,
        _ => UpstreamErrorClass::Http5xx,
    }
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

impl fmt::Debug for RouterPushSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
