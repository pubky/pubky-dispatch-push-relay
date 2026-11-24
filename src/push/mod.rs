//! Push delivery backend abstraction and provider implementations.

pub mod apns;
pub mod fcm;
pub mod noop;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crate::store::{BoxFuture, Platform, Registration};
use crate::time::parse_http_date_ms;

/// Default per-delivery provider timeout (3.5 s), strictly below the Dispatch service's
/// 5-second webhook timeout (Wire Format §8.2).
pub const DEFAULT_PROVIDER_TIMEOUT_MS: u64 = 3_500;

/// Maximum permitted `PROVIDER_TIMEOUT_MS` so provider calls stay bounded below Dispatch's
/// 5-second webhook timeout.
pub const MAX_PROVIDER_TIMEOUT_MS: u64 = 4_500;

/// Maximum backoff duration honoured from a single upstream `Retry-After` header (5 minutes).
pub const MAX_PROVIDER_BACKOFF_MS: u64 = 300_000;

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
    /// Provider is currently backing off after an upstream `Retry-After` response.
    Backoff,
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
            Self::Backoff => "backoff",
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
    /// permanently invalid or unregistered; the relay should delete the handle (subject to
    /// `invalidated_at_ms` when present).
    InvalidToken {
        /// Fixed token-rejection classification.
        class: InvalidTokenClass,
        /// Optional provider invalidation timestamp in Unix milliseconds (e.g. APNs `410`
        /// `timestamp` field). When present, the handle is deleted only if its
        /// `last_active_at_ms <= invalidated_at_ms`.
        invalidated_at_ms: Option<u64>,
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

/// Parses an upstream `Retry-After` header (either integer delta-seconds or an IMF-fixdate
/// HTTP date) into a bounded backoff duration in milliseconds.
///
/// Returns `None` if the header is absent, malformed, or specifies a zero/past delay.
#[must_use]
pub fn parse_retry_after_ms(headers: &reqwest::header::HeaderMap, wall_now_ms: u64) -> Option<u64> {
    let raw = headers.get("retry-after")?.to_str().ok()?.trim();
    if raw.is_empty() {
        return None;
    }

    let delay_ms = if let Ok(secs) = raw.parse::<u64>() {
        secs.saturating_mul(1_000)
    } else {
        let target_ms = parse_http_date_ms(raw)?;
        target_ms.saturating_sub(wall_now_ms)
    };

    if delay_ms == 0 {
        None
    } else {
        Some(delay_ms.min(MAX_PROVIDER_BACKOFF_MS))
    }
}

/// Lock-free monotonic per-provider backoff tracker driven by upstream `Retry-After` headers.
#[derive(Debug, Default)]
pub struct ProviderBackoff {
    until_mono_ms: AtomicU64,
}

impl ProviderBackoff {
    /// Creates an inactive backoff tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            until_mono_ms: AtomicU64::new(0),
        }
    }

    /// Returns `true` if `mono_now_ms` is still inside an active backoff window.
    #[must_use]
    pub fn is_backing_off(&self, mono_now_ms: u64) -> bool {
        self.until_mono_ms.load(Ordering::Acquire) > mono_now_ms
    }

    /// Records a backoff ending at `mono_now_ms + delay_ms`, never shortening an active backoff.
    pub fn record(&self, mono_now_ms: u64, delay_ms: u64) {
        if delay_ms == 0 {
            return;
        }
        let target = mono_now_ms.saturating_add(delay_ms);
        self.until_mono_ms.fetch_max(target, Ordering::Release);
    }
}

/// Abstraction over mobile push notification delivery backends (APNs, FCM, no-op/mock).
pub trait PushSender: Send + Sync {
    /// Dispatches a content-free wake push for `registration`.
    fn send_wake<'a>(
        &'a self,
        registration: &'a Registration,
    ) -> BoxFuture<'a, Result<PushOutcome, PushError>>;

    /// Verifies that the configured provider credentials and signing state are ready to serve.
    ///
    /// # Errors
    ///
    /// Returns [`PushError`] if credentials are missing, cannot sign, or have been rejected by
    /// the upstream provider.
    fn check_ready(&self) -> BoxFuture<'_, Result<(), PushError>> {
        Box::pin(async { Ok(()) })
    }
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

    fn check_ready(&self) -> BoxFuture<'_, Result<(), PushError>> {
        Box::pin(async move {
            if !self.has_any_provider() {
                return Err(PushError::Config("no push providers configured".to_owned()));
            }
            if let Some(apns) = &self.apns {
                apns.check_ready().await?;
            }
            if let Some(fcm) = &self.fcm {
                fcm.check_ready().await?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn parses_retry_after_delta_seconds_http_date_and_caps() {
        let now_ms = 1_767_225_960_000; // Thu, 01 Jan 2026 00:06:00 GMT

        let mut h = HeaderMap::new();
        h.insert("retry-after", HeaderValue::from_static("30"));
        assert_eq!(parse_retry_after_ms(&h, now_ms), Some(30_000));

        h.insert("retry-after", HeaderValue::from_static("999999"));
        assert_eq!(
            parse_retry_after_ms(&h, now_ms),
            Some(MAX_PROVIDER_BACKOFF_MS)
        );

        h.insert("retry-after", HeaderValue::from_static("0"));
        assert_eq!(parse_retry_after_ms(&h, now_ms), None);

        h.insert(
            "retry-after",
            HeaderValue::from_static("Thu, 01 Jan 2026 00:06:45 GMT"),
        );
        assert_eq!(parse_retry_after_ms(&h, now_ms), Some(45_000));

        h.insert(
            "retry-after",
            HeaderValue::from_static("Thu, 01 Jan 2026 00:05:00 GMT"),
        );
        assert_eq!(parse_retry_after_ms(&h, now_ms), None);
    }

    #[test]
    fn provider_backoff_tracks_monotonic_window() {
        let backoff = ProviderBackoff::new();
        assert!(!backoff.is_backing_off(0));
        backoff.record(0, 30_000);
        assert!(backoff.is_backing_off(0));
        assert!(backoff.is_backing_off(29_999));
        assert!(!backoff.is_backing_off(30_000));
    }
}
