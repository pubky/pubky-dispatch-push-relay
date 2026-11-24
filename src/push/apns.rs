//! Apple Push Notification service (APNs) HTTP/2 provider with ES256 JWT authentication.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey as _;
use parking_lot::Mutex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::clock::{Clock, SystemClock};
use crate::crypto::b64_encode;
use crate::push::{
    DEFAULT_PROVIDER_TIMEOUT_MS, InvalidTokenClass, PushError, PushOutcome, PushSender,
    UpstreamErrorClass, classify_http_status,
};
use crate::store::{ApnsEnv, BoxFuture, Registration};

/// Apple APNs production HTTP/2 endpoint.
pub const APNS_PRODUCTION_URL: &str = "https://api.push.apple.com";

/// Apple APNs sandbox HTTP/2 endpoint.
pub const APNS_SANDBOX_URL: &str = "https://api.sandbox.push.apple.com";

/// Lifetime for cached APNs provider JWTs (45 minutes; Apple allows up to 60 minutes
/// and recommends refreshing no more frequently than every 20 minutes).
pub const APNS_JWT_TTL_SECS: u64 = 45 * 60;

/// APNs notification delivery style.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApnsPushMode {
    /// Content-free generic visible notification (`apns-push-type: alert`,
    /// `apns-priority: 10`, `mutable-content: 1`) as required by Spec §9.
    ///
    /// Allows an iOS Notification Service Extension to peek and decrypt locally while
    /// avoiding iOS silent-push throttling.
    #[default]
    Alert,
    /// Opt-in silent background wake push (`apns-push-type: background`,
    /// `apns-priority: 5`, `{"aps":{"content-available":1}}`).
    ///
    /// Note: iOS aggressively throttles or drops silent background pushes under Low Power
    /// Mode or background budget limits.
    Background,
}

/// Configuration for [`ApnsSender`].
#[derive(Clone)]
pub struct ApnsConfig {
    /// 10-character Apple Developer Team ID (`iss` claim).
    pub team_id: String,
    /// 10-character APNs Auth Key ID (`kid` header).
    pub key_id: String,
    /// App bundle identifier (`apns-topic` header).
    pub bundle_id: String,
    /// PKCS#8 PEM-encoded P-256 private key (`.p8` file contents).
    pub private_key_pem: Zeroizing<String>,
    /// Default APNs environment used when a registration omits `apns_env`.
    pub default_env: ApnsEnv,
    /// Generic visible alert (default per Spec §9) or opt-in silent background wake mode.
    pub push_mode: ApnsPushMode,
    /// Production gateway base URL (overrideable for testing).
    pub production_url: String,
    /// Sandbox gateway base URL (overrideable for testing).
    pub sandbox_url: String,
    /// Upstream HTTP request timeout (defaults to 3.5 s, strictly below Dispatch's 5 s timeout).
    pub timeout: Duration,
}

impl fmt::Debug for ApnsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApnsConfig")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .field("bundle_id", &self.bundle_id)
            .field("private_key_pem", &"<redacted>")
            .field("default_env", &self.default_env)
            .field("push_mode", &self.push_mode)
            .field("production_url", &self.production_url)
            .field("sandbox_url", &self.sandbox_url)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl ApnsConfig {
    /// Creates an [`ApnsConfig`] with default Apple gateway URLs, visible alert mode
    /// (Spec §9), and a 3.5-second timeout.
    #[must_use]
    pub fn new(
        team_id: String,
        key_id: String,
        bundle_id: String,
        private_key_pem: Zeroizing<String>,
        default_env: ApnsEnv,
    ) -> Self {
        Self {
            team_id,
            key_id,
            bundle_id,
            private_key_pem,
            default_env,
            push_mode: ApnsPushMode::Alert,
            production_url: APNS_PRODUCTION_URL.to_owned(),
            sandbox_url: APNS_SANDBOX_URL.to_owned(),
            timeout: Duration::from_millis(DEFAULT_PROVIDER_TIMEOUT_MS),
        }
    }
}

struct CachedJwt {
    token: Zeroizing<String>,
    issued_at_secs: u64,
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'static str,
    kid: &'a str,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    iat: u64,
}

#[derive(Deserialize)]
struct ApnsErrorBody {
    reason: Option<String>,
}

/// APNs HTTP/2 wake push provider.
pub struct ApnsSender {
    client: Client,
    signing_key: SigningKey,
    team_id: String,
    key_id: String,
    bundle_id: String,
    default_env: ApnsEnv,
    push_mode: ApnsPushMode,
    production_url: String,
    sandbox_url: String,
    clock: Arc<dyn Clock>,
    cached_jwt: Mutex<Option<CachedJwt>>,
}

impl fmt::Debug for ApnsSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApnsSender")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .field("bundle_id", &self.bundle_id)
            .field("default_env", &self.default_env)
            .field("push_mode", &self.push_mode)
            .finish()
    }
}

impl ApnsSender {
    /// Constructs a new [`ApnsSender`] backed by the system clock.
    ///
    /// Validates the `.p8` P-256 signing key immediately at startup.
    ///
    /// # Errors
    ///
    /// Returns [`PushError::Config`] if configuration fields are empty, the `.p8` key
    /// cannot be parsed, or the HTTP client cannot be built.
    pub fn new(config: ApnsConfig) -> Result<Self, PushError> {
        Self::with_clock(config, Arc::new(SystemClock))
    }

    /// Constructs a new [`ApnsSender`] with a custom [`Clock`] (for deterministic tests).
    ///
    /// # Errors
    ///
    /// Returns [`PushError::Config`] if configuration or key material is invalid.
    pub fn with_clock(config: ApnsConfig, clock: Arc<dyn Clock>) -> Result<Self, PushError> {
        if config.team_id.trim().is_empty()
            || config.key_id.trim().is_empty()
            || config.bundle_id.trim().is_empty()
        {
            return Err(PushError::Config(
                "APNs team_id, key_id, and bundle_id must be non-empty".to_owned(),
            ));
        }

        let signing_key = SigningKey::from_pkcs8_pem(config.private_key_pem.as_str())
            .map_err(|_| PushError::Config("invalid APNs .p8 PKCS#8 PEM P-256 key".to_owned()))?;

        // Exercise signing at startup so key issues fail immediately rather than on first push.
        let _: Signature = signing_key.sign(b"apns-startup-check");

        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| PushError::Config("failed to build APNs HTTP client".to_owned()))?;

        Ok(Self {
            client,
            signing_key,
            team_id: config.team_id,
            key_id: config.key_id,
            bundle_id: config.bundle_id,
            default_env: config.default_env,
            push_mode: config.push_mode,
            production_url: config.production_url.trim_end_matches('/').to_owned(),
            sandbox_url: config.sandbox_url.trim_end_matches('/').to_owned(),
            clock,
            cached_jwt: Mutex::new(None),
        })
    }

    /// Returns a cached or freshly signed ES256 provider JWT.
    fn bearer_jwt(&self) -> Result<Zeroizing<String>, PushError> {
        let now_secs = self.clock.now_ms() / 1_000;
        let mut guard = self.cached_jwt.lock();
        if let Some(cached) = guard.as_ref()
            && now_secs >= cached.issued_at_secs
            && now_secs - cached.issued_at_secs < APNS_JWT_TTL_SECS
        {
            return Ok(cached.token.clone());
        }

        let token = self.sign_jwt(now_secs)?;
        *guard = Some(CachedJwt {
            token: token.clone(),
            issued_at_secs: now_secs,
        });
        Ok(token)
    }

    fn invalidate_jwt(&self) {
        *self.cached_jwt.lock() = None;
    }

    fn sign_jwt(&self, iat_secs: u64) -> Result<Zeroizing<String>, PushError> {
        let header_json = serde_json::to_vec(&JwtHeader {
            alg: "ES256",
            kid: &self.key_id,
        })
        .map_err(|_| PushError::Auth {
            class: UpstreamErrorClass::Auth,
        })?;
        let claims_json = serde_json::to_vec(&JwtClaims {
            iss: &self.team_id,
            iat: iat_secs,
        })
        .map_err(|_| PushError::Auth {
            class: UpstreamErrorClass::Auth,
        })?;

        let signing_input = format!("{}.{}", b64_encode(&header_json), b64_encode(&claims_json));
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_bytes = signature.to_bytes();
        Ok(Zeroizing::new(format!(
            "{signing_input}.{}",
            b64_encode(sig_bytes.as_ref())
        )))
    }

    fn wake_payload(&self) -> (&'static str, &'static str, &'static [u8]) {
        match self.push_mode {
            ApnsPushMode::Alert => (
                "alert",
                "10",
                br#"{"aps":{"mutable-content":1,"alert":{"title":"New notification","body":"Open the app to view."}}}"#,
            ),
            ApnsPushMode::Background => (
                "background",
                "5",
                br#"{"aps":{"content-available":1}}"#,
            ),
        }
    }

    async fn send_once(&self, registration: &Registration) -> Result<ApnsResponse, PushError> {
        let env = registration.apns_env.unwrap_or(self.default_env);
        let base_url = match env {
            ApnsEnv::Production => &self.production_url,
            ApnsEnv::Sandbox => &self.sandbox_url,
        };
        let url = format!("{base_url}/3/device/{}", registration.device_token);
        let jwt = self.bearer_jwt()?;
        let auth_header = Zeroizing::new(format!("bearer {}", jwt.as_str()));
        let (push_type, priority, body) = self.wake_payload();

        let response = self
            .client
            .post(&url)
            .header("authorization", auth_header.as_str())
            .header("apns-topic", &self.bundle_id)
            .header("apns-push-type", push_type)
            .header("apns-priority", priority)
            .header("apns-collapse-id", "pubky-dispatch-wake")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| PushError::Upstream {
                class: if e.is_timeout() {
                    UpstreamErrorClass::Timeout
                } else {
                    UpstreamErrorClass::Transport
                },
                status: None,
            })?;

        let status = response.status();
        if status.is_success() {
            return Ok(ApnsResponse::Outcome(PushOutcome::Delivered));
        }

        let status_code = status.as_u16();
        let reason = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ApnsErrorBody>(&bytes).ok())
            .and_then(|body| body.reason);

        if status_code == 403 && reason.as_deref() == Some("ExpiredProviderToken") {
            return Ok(ApnsResponse::ExpiredToken);
        }

        if let Some(class) = classify_invalid_apns_token(status_code, reason.as_deref()) {
            return Ok(ApnsResponse::Outcome(PushOutcome::InvalidToken { class }));
        }

        Err(PushError::Upstream {
            class: classify_http_status(status_code),
            status: Some(status_code),
        })
    }
}

enum ApnsResponse {
    Outcome(PushOutcome),
    ExpiredToken,
}

/// Requires explicit token-specific APNs evidence before deleting a handle:
/// - `410 Gone` with JSON `reason == "Unregistered"`
/// - `400 Bad Request` with JSON `reason == "BadDeviceToken"`
///
/// Every other response (including `410` without `Unregistered` and `400 DeviceTokenNotForTopic`,
/// which can reflect server topic misconfiguration) preserves the registration.
fn classify_invalid_apns_token(status: u16, reason: Option<&str>) -> Option<InvalidTokenClass> {
    match (status, reason) {
        (410, Some("Unregistered")) => Some(InvalidTokenClass::ApnsUnregistered),
        (400, Some("BadDeviceToken")) => Some(InvalidTokenClass::ApnsBadDeviceToken),
        _ => None,
    }
}

impl PushSender for ApnsSender {
    fn send_wake<'a>(
        &'a self,
        registration: &'a Registration,
    ) -> BoxFuture<'a, Result<PushOutcome, PushError>> {
        Box::pin(async move {
            match self.send_once(registration).await? {
                ApnsResponse::Outcome(outcome) => Ok(outcome),
                ApnsResponse::ExpiredToken => {
                    self.invalidate_jwt();
                    match self.send_once(registration).await? {
                        ApnsResponse::Outcome(outcome) => Ok(outcome),
                        ApnsResponse::ExpiredToken => Err(PushError::Auth {
                            class: UpstreamErrorClass::Auth,
                        }),
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apns_config_defaults_to_alert_and_redacts_private_key() {
        let cfg = ApnsConfig::new(
            "TEAM123456".to_owned(),
            "KEY1234567".to_owned(),
            "com.example.app".to_owned(),
            Zeroizing::new(
                "-----BEGIN PRIVATE KEY-----\nSUPERSECRET\n-----END PRIVATE KEY-----".to_owned(),
            ),
            ApnsEnv::Production,
        );
        assert_eq!(cfg.push_mode, ApnsPushMode::Alert);
        assert_eq!(
            cfg.timeout,
            Duration::from_millis(DEFAULT_PROVIDER_TIMEOUT_MS)
        );
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("SUPERSECRET"));
        assert!(shown.contains("<redacted>"));
    }

    #[test]
    fn classifies_only_token_specific_apns_errors_as_invalid() {
        assert_eq!(
            classify_invalid_apns_token(410, Some("Unregistered")),
            Some(InvalidTokenClass::ApnsUnregistered)
        );
        assert_eq!(
            classify_invalid_apns_token(400, Some("BadDeviceToken")),
            Some(InvalidTokenClass::ApnsBadDeviceToken)
        );

        // Ambiguous or configuration-related errors must NOT prune handles.
        for (status, reason) in [
            (410, None),
            (410, Some("Other")),
            (400, Some("DeviceTokenNotForTopic")),
            (400, Some("BadTopic")),
            (400, None),
            (403, Some("InvalidProviderToken")),
            (429, Some("TooManyRequests")),
            (500, Some("InternalServerError")),
            (503, Some("ServiceUnavailable")),
        ] {
            assert_eq!(
                classify_invalid_apns_token(status, reason),
                None,
                "expected non-pruning for ({status}, {reason:?})"
            );
        }
    }
}
