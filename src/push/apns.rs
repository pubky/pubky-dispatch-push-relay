//! Apple Push Notification service (APNs) HTTP/2 provider with ES256 JWT authentication.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    DEFAULT_PROVIDER_TIMEOUT_MS, InvalidTokenClass, ProviderBackoff, PushError, PushOutcome,
    PushSender, UpstreamErrorClass, classify_http_status, parse_retry_after_ms,
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
    generation: u64,
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
    timestamp: Option<u64>,
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
    next_jwt_gen: AtomicU64,
    backoff: ProviderBackoff,
    auth_healthy: AtomicBool,
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
            next_jwt_gen: AtomicU64::new(0),
            backoff: ProviderBackoff::new(),
            auth_healthy: AtomicBool::new(true),
        })
    }

    /// Returns a cached or freshly signed ES256 provider JWT together with its generation.
    fn bearer_jwt(&self) -> Result<(Zeroizing<String>, u64), PushError> {
        let now_secs = self.clock.now_ms() / 1_000;
        let mut guard = self.cached_jwt.lock();
        if let Some(cached) = guard.as_ref()
            && now_secs >= cached.issued_at_secs
            && now_secs - cached.issued_at_secs < APNS_JWT_TTL_SECS
        {
            return Ok((cached.token.clone(), cached.generation));
        }

        let token = self.sign_jwt(now_secs)?;
        let generation = self.next_jwt_gen.fetch_add(1, Ordering::Relaxed) + 1;
        *guard = Some(CachedJwt {
            token: token.clone(),
            issued_at_secs: now_secs,
            generation,
        });
        Ok((token, generation))
    }

    /// Invalidates the cached JWT only if it still matches `failed_generation`, preventing
    /// a stale concurrent auth error from evicting a freshly refreshed JWT.
    fn invalidate_jwt_if_generation(&self, failed_generation: u64) {
        let mut guard = self.cached_jwt.lock();
        if guard
            .as_ref()
            .is_some_and(|cached| cached.generation == failed_generation)
        {
            *guard = None;
        }
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
        if self.backoff.is_backing_off(self.clock.monotonic_ms()) {
            return Err(PushError::Upstream {
                class: UpstreamErrorClass::Backoff,
                status: None,
            });
        }

        let env = registration.apns_env.unwrap_or(self.default_env);
        let base_url = match env {
            ApnsEnv::Production => &self.production_url,
            ApnsEnv::Sandbox => &self.sandbox_url,
        };
        let url = format!("{base_url}/3/device/{}", registration.device_token);
        let (jwt, generation) = self.bearer_jwt()?;
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
            self.auth_healthy.store(true, Ordering::Relaxed);
            return Ok(ApnsResponse::Outcome(PushOutcome::Delivered));
        }

        let status_code = status.as_u16();
        // Only trigger provider-wide backoff on server-wide 500/503 responses.
        // Apple documents 429 TooManyRequests as per-device-token, so one noisy device
        // must not pause unrelated devices on this provider.
        if matches!(status_code, 500 | 503)
            && let Some(delay_ms) = parse_retry_after_ms(response.headers(), self.clock.now_ms())
        {
            self.backoff.record(self.clock.monotonic_ms(), delay_ms);
        }

        let err_body = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ApnsErrorBody>(&bytes).ok());
        let reason = err_body.as_ref().and_then(|b| b.reason.as_deref());
        let invalidation_ts = err_body.as_ref().and_then(|b| b.timestamp);

        if status_code == 403 && reason == Some("ExpiredProviderToken") {
            return Ok(ApnsResponse::ExpiredToken { generation });
        }

        if status_code == 403
            && matches!(
                reason,
                Some("InvalidProviderToken" | "MissingProviderToken")
            )
        {
            self.auth_healthy.store(false, Ordering::Relaxed);
        }

        if let Some(class) = classify_invalid_apns_token(status_code, reason) {
            let invalidated_at_ms = match class {
                InvalidTokenClass::ApnsUnregistered => invalidation_ts,
                _ => None,
            };
            return Ok(ApnsResponse::Outcome(PushOutcome::InvalidToken {
                class,
                invalidated_at_ms,
            }));
        }

        Err(PushError::Upstream {
            class: classify_http_status(status_code),
            status: Some(status_code),
        })
    }
}

enum ApnsResponse {
    Outcome(PushOutcome),
    ExpiredToken { generation: u64 },
}

/// Parses a PKCS#8 (`PRIVATE KEY`) PEM P-256 private key (Apple `.p8` format) into a
/// [`ring::signature::EcdsaKeyPair`], zeroizing intermediate key bytes on drop.
///
/// Accepts OpenSSL 3 PKCS#8 P-256 keys directly via `ring::EcdsaKeyPair::from_pkcs8` and
/// Apple `.p8` keys that include both inner `[0] namedCurve` and embedded `[1] publicKey`.
/// Keys omitting an embedded public key are rejected with a startup configuration error.
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

    let (priv_scalar, embedded_pub) = extract_p256_pkcs8_key(&der)
        .ok_or_else(|| PushError::Config("invalid APNs .p8 PKCS#8 PEM P-256 key".to_owned()))?;
    let pub_bytes = embedded_pub.ok_or_else(|| {
        PushError::Config(
            "APNs .p8 PKCS#8 key omits embedded publicKey; re-encode with \
             `openssl ec -in AuthKey.p8 | openssl pkey -out AuthKey-with-pub.p8`"
                .to_owned(),
        )
    })?;

    EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        priv_scalar.as_ref(),
        pub_bytes,
        rng,
    )
    .map_err(|_| PushError::Config("invalid APNs .p8 PKCS#8 PEM P-256 key".to_owned()))
}

/// OID 1.2.840.10045.2.1 (`id-ecPublicKey`) TLV bytes.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// OID 1.2.840.10045.3.1.7 (`prime256v1` / NIST P-256) TLV bytes.
const OID_PRIME256V1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Parses an ASN.1 DER TLV element, returning `(tag, value_slice, remainder)`.
fn der_read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&len_byte, rest) = rest.split_first()?;
    let (len, rest) = if len_byte & 0x80 == 0 {
        (usize::from(len_byte), rest)
    } else {
        let num_bytes = usize::from(len_byte & 0x7f);
        if num_bytes == 0 || num_bytes > 2 || rest.len() < num_bytes {
            return None;
        }
        let mut len = 0usize;
        for &b in &rest[..num_bytes] {
            len = (len << 8) | usize::from(b);
        }
        (len, &rest[num_bytes..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

type ExtractedP256Key<'a> = (Zeroizing<[u8; 32]>, Option<&'a [u8]>);

/// Extracts the 32-byte big-endian P-256 private scalar (wrapped in [`Zeroizing`]) and an
/// optional 65-byte uncompressed public key from an RFC 5958 PKCS#8 `PrivateKeyInfo` DER blob.
fn extract_p256_pkcs8_key(der: &[u8]) -> Option<ExtractedP256Key<'_>> {
    let (tag, seq, trailing) = der_read_tlv(der)?;
    if tag != 0x30 || !trailing.is_empty() {
        return None;
    }

    // 1. version INTEGER (0 or 1)
    let (v_tag, v_val, rest) = der_read_tlv(seq)?;
    if v_tag != 0x02 || !matches!(v_val, [0x00] | [0x01]) {
        return None;
    }

    // 2. privateKeyAlgorithm SEQUENCE { id-ecPublicKey, prime256v1 }
    let (alg_tag, alg_val, rest) = der_read_tlv(rest)?;
    if alg_tag != 0x30 {
        return None;
    }
    let alg_expected_len = OID_EC_PUBLIC_KEY.len() + OID_PRIME256V1.len();
    if alg_val.len() != alg_expected_len
        || !alg_val.starts_with(OID_EC_PUBLIC_KEY)
        || !alg_val.ends_with(OID_PRIME256V1)
    {
        return None;
    }

    // 3. privateKey OCTET STRING wrapping SEC1 ECPrivateKey
    let (pk_tag, pk_octets, mut outer_rest) = der_read_tlv(rest)?;
    if pk_tag != 0x04 {
        return None;
    }

    // Optional RFC 5958 [0] attributes / [1] publicKey BIT STRING
    let mut outer_pub: Option<&[u8]> = None;
    while !outer_rest.is_empty() {
        let (opt_tag, opt_val, next) = der_read_tlv(outer_rest)?;
        if opt_tag == 0x81 {
            // IMPLICIT BIT STRING: leading unused-bits byte 0x00 followed by 65-byte uncompressed point
            if opt_val.len() == 66 && opt_val[0] == 0x00 && opt_val[1] == 0x04 {
                outer_pub = Some(&opt_val[1..]);
            }
        }
        outer_rest = next;
    }

    // Parse inner SEC1 ECPrivateKey SEQUENCE
    let (ec_tag, ec_seq, ec_trailing) = der_read_tlv(pk_octets)?;
    if ec_tag != 0x30 || !ec_trailing.is_empty() {
        return None;
    }
    let (ec_ver_tag, ec_ver_val, ec_rest) = der_read_tlv(ec_seq)?;
    if ec_ver_tag != 0x02 || ec_ver_val != [0x01] {
        return None;
    }
    let (priv_tag, priv_val, mut ec_rest) = der_read_tlv(ec_rest)?;
    if priv_tag != 0x04 || priv_val.is_empty() || priv_val.len() > 32 {
        return None;
    }
    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar[32 - priv_val.len()..].copy_from_slice(priv_val);

    let mut inner_pub: Option<&[u8]> = None;
    while !ec_rest.is_empty() {
        let (opt_tag, opt_val, next) = der_read_tlv(ec_rest)?;
        match opt_tag {
            // Optional [0] namedCurve MUST match prime256v1 if present
            0xa0 => {
                if opt_val != OID_PRIME256V1 {
                    return None;
                }
            }
            // Optional [1] publicKey BIT STRING
            0xa1 => {
                let (bs_tag, bs_val, bs_trail) = der_read_tlv(opt_val)?;
                if bs_tag != 0x03 || !bs_trail.is_empty() || bs_val.len() != 66 || bs_val[0] != 0x00
                {
                    return None;
                }
                if bs_val[1] != 0x04 {
                    return None;
                }
                inner_pub = Some(&bs_val[1..]);
            }
            _ => return None,
        }
        ec_rest = next;
    }

    Some((scalar, inner_pub.or(outer_pub)))
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
                ApnsResponse::ExpiredToken { generation } => {
                    self.invalidate_jwt_if_generation(generation);
                    match self.send_once(registration).await? {
                        ApnsResponse::Outcome(outcome) => Ok(outcome),
                        ApnsResponse::ExpiredToken { .. } => {
                            self.auth_healthy.store(false, Ordering::Relaxed);
                            Err(PushError::Auth {
                                class: UpstreamErrorClass::Auth,
                            })
                        }
                    }
                }
            }
        })
    }

    fn check_ready(&self) -> BoxFuture<'_, Result<(), PushError>> {
        Box::pin(async move {
            if !self.auth_healthy.load(Ordering::Relaxed) {
                return Err(PushError::Auth {
                    class: UpstreamErrorClass::Auth,
                });
            }
            self.bearer_jwt().map(|_| ())
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

        // PKCS#8 v1 omitting `[1] publicKey` (`MEECAQAw...`) is rejected cleanly at startup
        // with guidance on re-encoding via OpenSSL (no custom curve math in the relay).
        let mut pkcs8_v1_no_pub = Vec::new();
        pkcs8_v1_no_pub.extend_from_slice(&[
            0x30, 0x41, // SEQUENCE (65)
            0x02, 0x01, 0x00, // version 0
            0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // ecPublicKey + prime256v1
            0x04, 0x27, // OCTET STRING (39)
            0x30, 0x25, // ECPrivateKey SEQUENCE (37)
            0x02, 0x01, 0x01, // version 1
            0x04, 0x20, // privateKey OCTET STRING (32)
        ]);
        pkcs8_v1_no_pub.extend_from_slice(priv_key);
        let no_pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pkcs8_v1_no_pub);
        let no_pub_pem =
            format!("-----BEGIN PRIVATE KEY-----\n{no_pub_b64}\n-----END PRIVATE KEY-----");
        let err = parse_p256_pkcs8_pem(&no_pub_pem, &rng).unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, PushError::Config(_))
                && msg.contains("publicKey")
                && msg.contains("openssl"),
            "expected clear startup config error for key lacking publicKey, got: {msg}"
        );
    }
}
