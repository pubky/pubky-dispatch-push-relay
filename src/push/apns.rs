//! Apple Push Notification service (APNs) HTTP/2 provider with ES256 JWT authentication.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use parking_lot::Mutex;
use reqwest::Client;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
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
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
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

        let rng = SystemRandom::new();
        let key_pair = parse_p256_pkcs8_pem(config.private_key_pem.as_str(), &rng)?;

        // Exercise signing at startup so key issues fail immediately rather than on first push.
        key_pair.sign(&rng, b"apns-startup-check").map_err(|_| {
            PushError::Config("APNs P-256 key failed ES256 startup check".to_owned())
        })?;

        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| PushError::Config("failed to build APNs HTTP client".to_owned()))?;

        Ok(Self {
            client,
            key_pair,
            rng,
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
        let signature = self
            .key_pair
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|_| PushError::Auth {
                class: UpstreamErrorClass::Auth,
            })?;
        Ok(Zeroizing::new(format!(
            "{signing_input}.{}",
            b64_encode(signature.as_ref())
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

/// Parses a PKCS#8 (`PRIVATE KEY`) PEM P-256 private key (Apple `.p8` format) into a
/// [`ring::signature::EcdsaKeyPair`], zeroizing intermediate DER bytes on drop.
fn parse_p256_pkcs8_pem(pem: &str, rng: &SystemRandom) -> Result<EcdsaKeyPair, PushError> {
    const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
    const END: &str = "-----END PRIVATE KEY-----";

    let trimmed = pem.trim();
    let (_, after_begin) = trimmed.split_once(BEGIN).ok_or_else(|| {
        PushError::Config("APNs .p8 key must be PKCS#8 PRIVATE KEY PEM".to_owned())
    })?;
    let (body, _) = after_begin
        .split_once(END)
        .ok_or_else(|| PushError::Config("missing PEM END marker in APNs .p8 key".to_owned()))?;

    let compact = Zeroizing::new(
        body.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    );
    let der = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .map_err(|_| PushError::Config("invalid base64 in APNs .p8 PEM key".to_owned()))?,
    );

    if let Ok(kp) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, rng) {
        return Ok(kp);
    }

    // Apple Developer Portal `.p8` files often include a redundant `[0] namedCurve` tag
    // inside the inner SEC1 ECPrivateKey (`MIGTAgEA...`), which `ring::from_pkcs8` rejects.
    // Extract the 32-byte private scalar and 65-byte uncompressed public key from that layout.
    if let Some((priv_key, pub_key)) = parse_apple_p8_pkcs8_with_named_curve(&der) {
        return EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            priv_key,
            pub_key,
            rng,
        )
        .map_err(|_| PushError::Config("invalid APNs .p8 PKCS#8 PEM P-256 key".to_owned()));
    }

    Err(PushError::Config(
        "invalid APNs .p8 PKCS#8 PEM P-256 key".to_owned(),
    ))
}

/// Parses Apple's 138-byte PKCS#8 P-256 DER (`MIGTAgEA...`) carrying both `[0] namedCurve`
/// and `[1] publicKey` inside the inner SEC1 `ECPrivateKey`.
fn parse_apple_p8_pkcs8_with_named_curve(der: &[u8]) -> Option<(&[u8], &[u8])> {
    // Prefix: SEQUENCE (147) { INTEGER 0, AlgorithmIdentifier(ecPublicKey, prime256v1),
    // OCTET STRING (121) { SEQUENCE (119) { INTEGER 1, OCTET STRING (32) ... } } }
    const PREFIX: &[u8] = &[
        0x30, 0x81, 0x93, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x79, 0x30,
        0x77, 0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    // Middle: [0] prime256v1 OID + [1] BIT STRING (65-byte uncompressed point)
    const MIDDLE: &[u8] = &[
        0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03,
        0x42, 0x00,
    ];
    let expected_len = PREFIX.len() + 32 + MIDDLE.len() + 65;
    if der.len() != expected_len {
        return None;
    }
    if !der.starts_with(PREFIX) {
        return None;
    }
    let priv_start = PREFIX.len();
    let mid_start = priv_start + 32;
    let pub_start = mid_start + MIDDLE.len();
    if der.get(mid_start..pub_start) != Some(MIDDLE) {
        return None;
    }
    let priv_key = der.get(priv_start..mid_start)?;
    let pub_key = der.get(pub_start..)?;
    if pub_key.first() != Some(&0x04) {
        return None;
    }
    Some((priv_key, pub_key))
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

    #[test]
    fn parses_both_openssl_and_apple_p8_pkcs8_layouts() {
        let rng = SystemRandom::new();
        // OpenSSL 3 PKCS#8 P-256 layout (`MIGHAgEA...`, without inner `[0] namedCurve`).
        let openssl_pem = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqqAO++8h+XsXLStn
Gp0X0DGtKQytjLTKJkmEHtPgH82hRANCAATDU5zOZ/4OQlLrWs54n25PpWLNjV8R
JuPZpk8VOSsbnrqvn8wbb67SMGiIvO0fc+LfUdrStgDJKPZM4+epIvG/
-----END PRIVATE KEY-----";
        let kp1 = parse_p256_pkcs8_pem(openssl_pem, &rng).unwrap();

        // Apple Developer Portal `.p8` PKCS#8 layout (`MIGTAgEA...`, with inner `[0] namedCurve`).
        let openssl_der = base64::engine::general_purpose::STANDARD
            .decode(
                openssl_pem
                    .lines()
                    .filter(|l| !l.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
        let priv_key = &openssl_der[36..68];
        let pub_key = &openssl_der[73..138];
        let mut apple_der = Vec::new();
        apple_der.extend_from_slice(&[
            0x30, 0x81, 0x93, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04,
            0x79, 0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20,
        ]);
        apple_der.extend_from_slice(priv_key);
        apple_der.extend_from_slice(&[
            0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44,
            0x03, 0x42, 0x00,
        ]);
        apple_der.extend_from_slice(pub_key);
        let apple_b64 = base64::engine::general_purpose::STANDARD.encode(&apple_der);
        assert!(apple_b64.starts_with("MIGTAgEA"));
        let apple_pem =
            format!("-----BEGIN PRIVATE KEY-----\n{apple_b64}\n-----END PRIVATE KEY-----");
        let kp2 = parse_p256_pkcs8_pem(&apple_pem, &rng).unwrap();

        use ring::signature::KeyPair as _;
        assert_eq!(kp1.public_key().as_ref(), kp2.public_key().as_ref());
    }
}
