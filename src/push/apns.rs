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
use crate::push::{PushError, PushOutcome, PushSender};
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
    /// Silent background wake push (`apns-push-type: background`, `apns-priority: 5`,
    /// `{"aps":{"content-available":1}}`).
    #[default]
    Background,
    /// Content-free alert wake push (`apns-push-type: alert`, `apns-priority: 10`,
    /// `mutable-content: 1`) for apps using an iOS Notification Service Extension.
    Alert,
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
    /// Silent background wake (default) or alert wake mode.
    pub push_mode: ApnsPushMode,
    /// Production gateway base URL (overrideable for testing).
    pub production_url: String,
    /// Sandbox gateway base URL (overrideable for testing).
    pub sandbox_url: String,
    /// Upstream HTTP request timeout.
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
    /// Creates an [`ApnsConfig`] with default Apple gateway URLs and a 10-second timeout.
    #[must_use]
    pub fn new(
        team_id: String,
        key_id: String,
        bundle_id: String,
        private_key_pem: String,
        default_env: ApnsEnv,
    ) -> Self {
        Self {
            team_id,
            key_id,
            bundle_id,
            private_key_pem: Zeroizing::new(private_key_pem),
            default_env,
            push_mode: ApnsPushMode::Background,
            production_url: APNS_PRODUCTION_URL.to_owned(),
            sandbox_url: APNS_SANDBOX_URL.to_owned(),
            timeout: Duration::from_secs(10),
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
            .map_err(|e| PushError::Config(format!("invalid APNs .p8 PKCS#8 PEM key: {e}")))?;

        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| PushError::Config(format!("failed to build APNs HTTP client: {e}")))?;

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
        .map_err(|e| PushError::Auth(format!("failed to encode APNs JWT header: {e}")))?;
        let claims_json = serde_json::to_vec(&JwtClaims {
            iss: &self.team_id,
            iat: iat_secs,
        })
        .map_err(|e| PushError::Auth(format!("failed to encode APNs JWT claims: {e}")))?;

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
            ApnsPushMode::Background => (
                "background",
                "5",
                br#"{"aps":{"content-available":1}}"#,
            ),
            ApnsPushMode::Alert => (
                "alert",
                "10",
                br#"{"aps":{"mutable-content":1,"content-available":1,"alert":{"title":"New activity","body":"Open the app to check for updates."}}}"#,
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
        let (push_type, priority, body) = self.wake_payload();

        let response = self
            .client
            .post(&url)
            .header("authorization", format!("bearer {}", jwt.as_str()))
            .header("apns-topic", &self.bundle_id)
            .header("apns-push-type", push_type)
            .header("apns-priority", priority)
            .header("apns-collapse-id", "pubky-dispatch-wake")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                PushError::Upstream(format!("APNs request failed: {}", e.without_url()))
            })?;

        let status = response.status();
        if status.is_success() {
            return Ok(ApnsResponse::Outcome(PushOutcome::Delivered));
        }

        let error_reason = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ApnsErrorBody>(&bytes).ok())
            .and_then(|body| body.reason)
            .unwrap_or_else(|| format!("http_{}", status.as_u16()));

        if status.as_u16() == 403 && error_reason == "ExpiredProviderToken" {
            return Ok(ApnsResponse::ExpiredToken);
        }

        if is_invalid_apns_token(status.as_u16(), &error_reason) {
            return Ok(ApnsResponse::Outcome(PushOutcome::InvalidToken {
                reason: error_reason,
            }));
        }

        Err(PushError::Upstream(format!(
            "APNs rejected push with status {} ({error_reason})",
            status.as_u16()
        )))
    }
}

enum ApnsResponse {
    Outcome(PushOutcome),
    ExpiredToken,
}

fn is_invalid_apns_token(status: u16, reason: &str) -> bool {
    if status == 410 {
        return true;
    }
    status == 400
        && matches!(
            reason,
            "BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered"
        )
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
                        ApnsResponse::ExpiredToken => Err(PushError::Auth(
                            "APNs rejected refreshed provider JWT".to_owned(),
                        )),
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
    fn apns_config_debug_redacts_private_key() {
        let cfg = ApnsConfig::new(
            "TEAM123456".to_owned(),
            "KEY1234567".to_owned(),
            "com.example.app".to_owned(),
            "-----BEGIN PRIVATE KEY-----\nSUPERSECRET\n-----END PRIVATE KEY-----".to_owned(),
            ApnsEnv::Production,
        );
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("SUPERSECRET"));
        assert!(shown.contains("<redacted>"));
    }
}
