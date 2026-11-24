//! Firebase Cloud Messaging (FCM) HTTP v1 provider with Google Service Account OAuth2
//! signed using `ring::signature::RsaKeyPair`.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use reqwest::Client;
use ring::rand::SystemRandom;
use ring::signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::clock::{Clock, SystemClock};
use crate::crypto::b64_encode;
use crate::push::{
    DEFAULT_PROVIDER_TIMEOUT_MS, InvalidTokenClass, ProviderBackoff, PushError, PushOutcome,
    PushSender, UpstreamErrorClass, classify_http_status, parse_retry_after_ms,
};
use crate::store::{BoxFuture, Registration};

/// Default FCM HTTP v1 API base URL.
pub const FCM_API_BASE_URL: &str = "https://fcm.googleapis.com";

/// Default Google OAuth2 token exchange URL.
pub const DEFAULT_GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Required OAuth2 scope for FCM HTTP v1.
const FCM_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// Collapse key used to coalesce queued Android wake pushes while a device is offline.
pub const FCM_COLLAPSE_KEY: &str = "pubky-dispatch-wake";

/// Refresh cached OAuth2 access tokens this many seconds before expiry.
const TOKEN_REFRESH_MARGIN_SECS: u64 = 120;

/// Minimum RSA modulus length in bits (2048 bits) required by RS256 best practices.
const MIN_RSA_MODULUS_BITS: usize = 2048;

/// Protobuf `@type` URL identifying typed Firebase Cloud Messaging v1 error details.
const FCM_ERROR_DETAIL_TYPE: &str = "type.googleapis.com/google.firebase.fcm.v1.FcmError";

/// Google service account credentials JSON structure.
#[derive(Clone, Deserialize)]
pub struct FcmServiceAccount {
    /// Firebase / Google Cloud project ID.
    pub project_id: String,
    /// Service account email (`iss` claim).
    pub client_email: String,
    /// PKCS#8 (or PKCS#1) PEM-encoded RSA private key (at least 2048 bits).
    #[serde(deserialize_with = "deserialize_zeroizing")]
    pub private_key: Zeroizing<String>,
    /// OAuth2 token URI (defaults to Google's production token endpoint).
    pub token_uri: Option<String>,
}

fn deserialize_zeroizing<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

impl fmt::Debug for FcmServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FcmServiceAccount")
            .field("project_id", &self.project_id)
            .field("client_email", &self.client_email)
            .field("private_key", &"<redacted>")
            .field("token_uri", &self.token_uri)
            .finish()
    }
}

/// Configuration for [`FcmSender`].
#[derive(Clone, Debug)]
pub struct FcmConfig {
    /// Parsed Google service account credentials.
    pub service_account: FcmServiceAccount,
    /// FCM HTTP v1 API base URL (overrideable for testing).
    pub api_base_url: String,
    /// Upstream HTTP request timeout (defaults to 3.5 s, strictly below Dispatch's 5 s timeout).
    pub timeout: Duration,
}

impl FcmConfig {
    /// Creates an [`FcmConfig`] from service account credentials with default URLs and
    /// a 3.5-second timeout.
    #[must_use]
    pub fn new(service_account: FcmServiceAccount) -> Self {
        Self {
            service_account,
            api_base_url: FCM_API_BASE_URL.to_owned(),
            timeout: Duration::from_millis(DEFAULT_PROVIDER_TIMEOUT_MS),
        }
    }
}

struct CachedAccessToken {
    token: Zeroizing<String>,
    expires_at_secs: u64,
    generation: u64,
}

#[derive(Serialize)]
struct JwtHeader {
    alg: &'static str,
    typ: &'static str,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'static str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    #[serde(deserialize_with = "deserialize_zeroizing")]
    access_token: Zeroizing<String>,
    expires_in: Option<u64>,
}

#[derive(Serialize)]
struct FcmSendRequest<'a> {
    message: FcmMessage<'a>,
}

#[derive(Serialize)]
struct FcmMessage<'a> {
    token: &'a str,
    data: FcmWakeData,
    android: FcmAndroidConfig,
}

#[derive(Serialize)]
struct FcmWakeData {
    #[serde(rename = "type")]
    kind: &'static str,
    v: &'static str,
}

#[derive(Serialize)]
struct FcmAndroidConfig {
    collapse_key: &'static str,
    priority: &'static str,
}

#[derive(Deserialize)]
struct FcmErrorEnvelope {
    error: Option<FcmErrorBody>,
}

#[derive(Deserialize)]
struct FcmErrorBody {
    message: Option<String>,
    status: Option<String>,
    #[serde(default)]
    details: Vec<FcmErrorDetail>,
}

#[derive(Deserialize)]
struct FcmErrorDetail {
    #[serde(rename = "@type")]
    detail_type: Option<String>,
    #[serde(rename = "errorCode")]
    error_code: Option<String>,
}

/// FCM HTTP v1 data-only high-priority wake push provider.
pub struct FcmSender {
    client: Client,
    key_pair: RsaKeyPair,
    rng: SystemRandom,
    project_id: String,
    client_email: String,
    token_uri: String,
    api_base_url: String,
    clock: Arc<dyn Clock>,
    token_cache: Mutex<Option<CachedAccessToken>>,
    next_token_gen: AtomicU64,
    backoff: ProviderBackoff,
    auth_healthy: AtomicBool,
}

impl fmt::Debug for FcmSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FcmSender")
            .field("project_id", &self.project_id)
            .field("client_email", &self.client_email)
            .field("token_uri", &self.token_uri)
            .field("api_base_url", &self.api_base_url)
            .finish()
    }
}

impl FcmSender {
    /// Constructs a new [`FcmSender`] backed by the system clock.
    ///
    /// Parses and validates the service account RSA key (requiring at least 2048 bits)
    /// and exercises RS256 signing at startup so invalid or undersized keys fail loudly
    /// before serving traffic.
    ///
    /// # Errors
    ///
    /// Returns [`PushError::Config`] if credentials or key material are invalid or undersized.
    pub fn new(config: FcmConfig) -> Result<Self, PushError> {
        Self::with_clock(config, Arc::new(SystemClock))
    }

    /// Constructs a new [`FcmSender`] with a custom [`Clock`] (for deterministic tests).
    ///
    /// # Errors
    ///
    /// Returns [`PushError::Config`] if credentials or key material are invalid or undersized.
    pub fn with_clock(config: FcmConfig, clock: Arc<dyn Clock>) -> Result<Self, PushError> {
        let sa = config.service_account;
        if sa.project_id.trim().is_empty() || sa.client_email.trim().is_empty() {
            return Err(PushError::Config(
                "FCM project_id and client_email must be non-empty".to_owned(),
            ));
        }

        let key_pair = parse_rsa_pem(sa.private_key.as_str())?;
        let modulus_bits =
            rsa_public_key_modulus_bits(key_pair.public_key().as_ref()).ok_or_else(|| {
                PushError::Config("failed to inspect FCM service account RSA modulus".to_owned())
            })?;
        if modulus_bits < MIN_RSA_MODULUS_BITS {
            return Err(PushError::Config(format!(
                "FCM service account RSA key must be at least {MIN_RSA_MODULUS_BITS} bits (got {modulus_bits} bits)"
            )));
        }
        let modulus_len = key_pair.public().modulus_len();

        let rng = SystemRandom::new();
        let mut probe_sig = vec![0u8; modulus_len];
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                b"fcm-startup-check",
                &mut probe_sig,
            )
            .map_err(|_| {
                PushError::Config(
                    "FCM service account RSA key failed RS256 startup self-test".to_owned(),
                )
            })?;

        let token_uri = sa
            .token_uri
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_GOOGLE_TOKEN_URI.to_owned());

        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| PushError::Config("failed to build FCM HTTP client".to_owned()))?;

        Ok(Self {
            client,
            key_pair,
            rng,
            project_id: sa.project_id,
            client_email: sa.client_email,
            token_uri,
            api_base_url: config.api_base_url.trim_end_matches('/').to_owned(),
            clock,
            token_cache: Mutex::new(None),
            next_token_gen: AtomicU64::new(0),
            backoff: ProviderBackoff::new(),
            auth_healthy: AtomicBool::new(true),
        })
    }

    fn build_jwt_assertion(&self, now_secs: u64) -> Result<Zeroizing<String>, PushError> {
        let header_json = serde_json::to_vec(&JwtHeader {
            alg: "RS256",
            typ: "JWT",
        })
        .map_err(|_| PushError::Auth {
            class: UpstreamErrorClass::Auth,
        })?;

        let claims_json = serde_json::to_vec(&JwtClaims {
            iss: &self.client_email,
            scope: FCM_OAUTH_SCOPE,
            aud: &self.token_uri,
            iat: now_secs,
            exp: now_secs.saturating_add(3600),
        })
        .map_err(|_| PushError::Auth {
            class: UpstreamErrorClass::Auth,
        })?;

        let signing_input = format!("{}.{}", b64_encode(&header_json), b64_encode(&claims_json));
        let mut signature = vec![0u8; self.key_pair.public().modulus_len()];
        self.key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &self.rng,
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| PushError::Auth {
                class: UpstreamErrorClass::Auth,
            })?;
        Ok(Zeroizing::new(format!(
            "{signing_input}.{}",
            b64_encode(&signature)
        )))
    }

    async fn access_token(&self) -> Result<(Zeroizing<String>, u64), PushError> {
        let mut cache = self.token_cache.lock().await;
        let now_secs = self.clock.now_ms() / 1_000;

        if let Some(cached) = cache.as_ref()
            && now_secs.saturating_add(TOKEN_REFRESH_MARGIN_SECS) < cached.expires_at_secs
        {
            return Ok((cached.token.clone(), cached.generation));
        }

        if self.backoff.is_backing_off(self.clock.monotonic_ms()) {
            return Err(PushError::Upstream {
                class: UpstreamErrorClass::Backoff,
                status: None,
            });
        }

        let assertion = self.build_jwt_assertion(now_secs)?;
        let form_body = Zeroizing::new(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
            assertion.as_str()
        ));

        let response = self
            .client
            .post(&self.token_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form_body.as_bytes().to_vec())
            .send()
            .await
            .map_err(|e| PushError::Auth {
                class: if e.is_timeout() {
                    UpstreamErrorClass::Timeout
                } else {
                    UpstreamErrorClass::Transport
                },
            })?;

        let status = response.status();
        if !status.is_success() {
            let status_code = status.as_u16();
            // OAuth token exchange throttling / server unavailability is provider-wide.
            if matches!(status_code, 429 | 500 | 503)
                && let Some(delay_ms) =
                    parse_retry_after_ms(response.headers(), self.clock.now_ms())
            {
                self.backoff.record(self.clock.monotonic_ms(), delay_ms);
            }
            if matches!(status_code, 400 | 401 | 403) {
                self.auth_healthy.store(false, Ordering::Relaxed);
            }
            return Err(PushError::Auth {
                class: classify_http_status(status_code),
            });
        }

        let raw_body = Zeroizing::new(
            response
                .bytes()
                .await
                .map_err(|_| PushError::Auth {
                    class: UpstreamErrorClass::BadResponse,
                })?
                .to_vec(),
        );
        let parsed: OAuthTokenResponse =
            serde_json::from_slice(&raw_body).map_err(|_| PushError::Auth {
                class: UpstreamErrorClass::BadResponse,
            })?;

        if parsed.access_token.is_empty() {
            return Err(PushError::Auth {
                class: UpstreamErrorClass::BadResponse,
            });
        }

        let ttl_secs = parsed.expires_in.unwrap_or(3600);
        let token = parsed.access_token;
        let generation = self.next_token_gen.fetch_add(1, Ordering::Relaxed) + 1;
        *cache = Some(CachedAccessToken {
            token: token.clone(),
            expires_at_secs: now_secs.saturating_add(ttl_secs),
            generation,
        });
        self.auth_healthy.store(true, Ordering::Relaxed);
        Ok((token, generation))
    }

    /// Invalidates the cached OAuth2 access token only if its generation matches
    /// `failed_generation`, preventing a stale concurrent 401 from wiping a fresh token.
    async fn invalidate_access_token_if_generation(&self, failed_generation: u64) {
        let mut cache = self.token_cache.lock().await;
        if cache
            .as_ref()
            .is_some_and(|cached| cached.generation == failed_generation)
        {
            *cache = None;
        }
    }

    async fn send_once(&self, registration: &Registration) -> Result<FcmResponse, PushError> {
        if self.backoff.is_backing_off(self.clock.monotonic_ms()) {
            return Err(PushError::Upstream {
                class: UpstreamErrorClass::Backoff,
                status: None,
            });
        }

        let (access_token, generation) = self.access_token().await?;
        let auth_header = Zeroizing::new(format!("Bearer {}", access_token.as_str()));
        let url = format!(
            "{}/v1/projects/{}/messages:send",
            self.api_base_url, self.project_id
        );

        let payload = FcmSendRequest {
            message: FcmMessage {
                token: &registration.device_token,
                data: FcmWakeData {
                    kind: "wake",
                    v: "1",
                },
                android: FcmAndroidConfig {
                    collapse_key: FCM_COLLAPSE_KEY,
                    priority: "HIGH",
                },
            },
        };

        let response = self
            .client
            .post(&url)
            .header("authorization", auth_header.as_str())
            .header("content-type", "application/json; charset=utf-8")
            .json(&payload)
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
            return Ok(FcmResponse::Outcome(PushOutcome::Delivered));
        }

        let status_code = status.as_u16();
        if status_code == 401 {
            return Ok(FcmResponse::Unauthorized { generation });
        }

        // Only trigger provider-wide backoff on server-wide 500/503 responses.
        // HTTP 429 on /messages:send (QUOTA_EXCEEDED) can be device-scoped and must not
        // pause delivery to unrelated devices.
        if matches!(status_code, 500 | 503)
            && let Some(delay_ms) = parse_retry_after_ms(response.headers(), self.clock.now_ms())
        {
            self.backoff.record(self.clock.monotonic_ms(), delay_ms);
        }

        let body_bytes = response.bytes().await.unwrap_or_default();
        if let Some(class) = classify_invalid_fcm_token(status_code, &body_bytes) {
            return Ok(FcmResponse::Outcome(PushOutcome::InvalidToken {
                class,
                invalidated_at_ms: None,
            }));
        }

        Err(PushError::Upstream {
            class: classify_http_status(status_code),
            status: Some(status_code),
        })
    }
}

enum FcmResponse {
    Outcome(PushOutcome),
    Unauthorized { generation: u64 },
}

/// Parses a PKCS#8 (`PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`) PEM private key into a
/// [`ring::signature::RsaKeyPair`], zeroizing intermediate DER bytes on drop.
fn parse_rsa_pem(pem: &str) -> Result<RsaKeyPair, PushError> {
    let trimmed = pem.trim();
    let (is_pkcs8, begin, end) = if trimmed.contains("-----BEGIN PRIVATE KEY-----") {
        (
            true,
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
        )
    } else if trimmed.contains("-----BEGIN RSA PRIVATE KEY-----") {
        (
            false,
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
        )
    } else {
        return Err(PushError::Config(
            "FCM private key must be PKCS#8 (PRIVATE KEY) or PKCS#1 (RSA PRIVATE KEY) PEM"
                .to_owned(),
        ));
    };

    let (_, after_begin) = trimmed
        .split_once(begin)
        .ok_or_else(|| PushError::Config("missing PEM BEGIN marker".to_owned()))?;
    let (body, _) = after_begin
        .split_once(end)
        .ok_or_else(|| PushError::Config("missing PEM END marker".to_owned()))?;

    let compact: Zeroizing<String> = Zeroizing::new(
        body.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    );
    let der = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .map_err(|_| PushError::Config("invalid base64 in FCM RSA PEM key".to_owned()))?,
    );

    let key_pair = if is_pkcs8 {
        RsaKeyPair::from_pkcs8(&der)
    } else {
        RsaKeyPair::from_der(&der)
    };

    key_pair.map_err(|_| {
        PushError::Config(
            "invalid or undersized FCM RSA private key (must be valid RSA >= 2048 bits)".to_owned(),
        )
    })
}

fn der_read_tlv(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    if *input.first()? != expected_tag {
        return None;
    }
    let len_byte = *input.get(1)?;
    let (len, hdr_len) = if len_byte < 0x80 {
        (usize::from(len_byte), 2usize)
    } else {
        let num_octets = usize::from(len_byte & 0x7f);
        if num_octets == 0 || num_octets > 4 || input.len() < 2 + num_octets {
            return None;
        }
        let mut len = 0usize;
        for &b in &input[2..2 + num_octets] {
            len = (len << 8) | usize::from(b);
        }
        (len, 2 + num_octets)
    };
    let end = hdr_len.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    Some((&input[hdr_len..end], &input[end..]))
}

/// Extracts the exact RSA modulus bit length from a DER-encoded `RSAPublicKey`
/// (`SEQUENCE { INTEGER modulus, INTEGER publicExponent }`).
fn rsa_public_key_modulus_bits(public_key_der: &[u8]) -> Option<usize> {
    let (seq_body, trailing) = der_read_tlv(public_key_der, 0x30)?;
    if !trailing.is_empty() {
        return None;
    }
    let (modulus_bytes, _) = der_read_tlv(seq_body, 0x02)?;
    let trimmed = modulus_bytes
        .iter()
        .position(|&b| b != 0)
        .map_or(&[][..], |idx| &modulus_bytes[idx..]);
    let (&first, rest) = trimmed.split_first()?;
    let leading_bits = 8usize.saturating_sub(first.leading_zeros() as usize);
    Some(rest.len().saturating_mul(8).saturating_add(leading_bits))
}

/// Requires explicit, typed token-specific FCM evidence before deleting a handle:
/// - `error.details` contains a typed `type.googleapis.com/google.firebase.fcm.v1.FcmError`
///   entry with `errorCode == "UNREGISTERED"`
/// - `400 INVALID_ARGUMENT` whose message explicitly names the registration token
///
/// Generic HTTP 404 / `NOT_FOUND`, untyped `UNREGISTERED` details, and non-token
/// `INVALID_ARGUMENT` responses MUST NOT delete a healthy handle.
fn classify_invalid_fcm_token(status: u16, body: &[u8]) -> Option<InvalidTokenClass> {
    let envelope = serde_json::from_slice::<FcmErrorEnvelope>(body).ok()?;
    let err = envelope.error?;

    for detail in &err.details {
        if detail.detail_type.as_deref() == Some(FCM_ERROR_DETAIL_TYPE)
            && detail.error_code.as_deref() == Some("UNREGISTERED")
        {
            return Some(InvalidTokenClass::FcmUnregistered);
        }
    }

    let is_invalid_argument = err.status.as_deref() == Some("INVALID_ARGUMENT")
        || err.details.iter().any(|d| {
            d.detail_type.as_deref() == Some(FCM_ERROR_DETAIL_TYPE)
                && d.error_code.as_deref() == Some("INVALID_ARGUMENT")
        });
    if status == 400
        && is_invalid_argument
        && err
            .message
            .as_deref()
            .is_some_and(|m| m.to_ascii_lowercase().contains("registration token"))
    {
        return Some(InvalidTokenClass::FcmInvalidRegistrationToken);
    }

    None
}

impl PushSender for FcmSender {
    fn send_wake<'a>(
        &'a self,
        registration: &'a Registration,
    ) -> BoxFuture<'a, Result<PushOutcome, PushError>> {
        Box::pin(async move {
            match self.send_once(registration).await? {
                FcmResponse::Outcome(outcome) => Ok(outcome),
                FcmResponse::Unauthorized { generation } => {
                    self.invalidate_access_token_if_generation(generation).await;
                    match self.send_once(registration).await? {
                        FcmResponse::Outcome(outcome) => Ok(outcome),
                        FcmResponse::Unauthorized {
                            generation: retry_gen,
                        } => {
                            self.invalidate_access_token_if_generation(retry_gen).await;
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
            self.build_jwt_assertion(self.clock.now_ms() / 1_000)?;
            if !self.auth_healthy.load(Ordering::Relaxed) {
                // Probe OAuth token exchange so a drained replica recovers cleanly once
                // provider credential issues clear without needing delivery traffic.
                self.access_token().await?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only 1024-bit RSA key used strictly to verify startup rejection of undersized keys.
    const TEST_UNDERSIZED_RSA_1024_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALh3Y8d9XAVxFmFY
u7h4gJrRKltFKfh95+ZAI55G5l+4iFca1HeLFBseQsIQoa1HYHFzGJjgaXXsxui4
sb7Exzh0gRDp4/ZZUyFiBLIOwVQlVTXFmi6msD78dNw25dp/5KSsN2/Q2ofJDo/D
Gyy2U3uHMOklbxZIhdovo7I09rR5AgMBAAECgYEAk1iidg3XfG1JoDadtAtlRsT/
HWqQzPHdU9k12k7t49Xl6hX/UwHf7I1ua8+XJW9XRSfXpP3Un6Kje+9T43sRWdZs
edAvHn8Q1DBfNLTAYKuXOkp7wXkBYxFsb9etXOiAVnWLxy/5MbZC2olBhBoFVXQw
24unrLCTT1iIQxve9VECQQDk2Pouq9H3w5xIj+h6iW5xKRUwTQJb++NXMfc3xiJw
BkHabeOMX1znP3pJ/rXgvQgYOkeuhKXvzu7o+4cqf28lAkEAzlpgZ5nlHq4NraxL
3Ekfo4lFxmd/Wp477uQ0BIWQw7no5+3hAc92XudesIC7dOe8AxZ1MgaSIJCKa51P
AhBpxQJBANMcvx9S7m3sjD38U/DG25WU2rEmOaj1o/IKbA+NvrMtco64lRQn3SKP
Upb0XICoodEH4pzCTfn+IjPX5gd0a+kCQC4QktDN1A4DQN5yRgUI9d0l+cOOuylZ
hXuQyePwhR6MU+fifIZQ79XDxKmWM0KnsJrn2oWuXdSTL7NSTJ7jVxkCQBvF2LsD
HbPtvmny0Cbd0bxjgjFW8wv3lebTtDTaJD3kbcsqcRu7K1dcXTfYBosNqWwNkHKs
QYdbWZeUcYGQqAY=
-----END PRIVATE KEY-----";

    /// Test-only 2047-bit RSA key (256 bytes with leading byte < 0x80) used to verify exact
    /// 2048-bit minimum enforcement at startup.
    const TEST_UNDERSIZED_RSA_2047_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAEx9r+2rETWev9Ao
Na8jhZ12NJMaQn9T/3MSdeKhV0CQ9kGc8uXGCK15Db1POMQXZMy59EU7vS8Q3xth
sTmjrqc4rqaMInvnlN0plW5sEk4uFUkj5KDfPKax8NHTIGclJ4g92b5n57tn4+7V
gq3Wb+hCaybtCMmzwslI5Kj6Qw3iU9MLbfkGv+hc3p/mM+obaEejwt3R0s0Npt9F
xAvOfuA40nfrKFKvlGPo2zo0ajUNVOPVfitqS0s2bGROYpxDTRvLcHGFFNGgsnj+
ALF8atV0in4tbVg4FJ9PsWhF2X6FnF2K/E9SET1AZIpjm4OimEHQOvCfghD78j6F
tHKApz8CAwEAAQKCAQANwmo8OZKN77GXczQ8/gnSCmpor8eYefawr3hvPRCh97Gk
meQDuzziX60+CZsvgvnJ7gVn0tg0ODe6CDfGI5COWh7orLqjSUQ5CHrt8xjT4WxI
zOEaoy2Y2td0FyN0CnXzBxU9MBm6V3TkCJpKRRG6WQBHb0ouZly6spcXYnVfcMsp
BftLFdRrzrXFuyfayZpHzyx1G9taSjbAxqM0kr7O84W9vUD12ODKRskl5tMrEhdM
WdL4krI+tfVcp7F8aVvT+7XOlAPqI+0y0tsbGbow3lYem2unRk+a+rg8ui28D5q5
p/siuBe05icCxkRCC7t3Fy9sWGOP1FVQEGVoBdHBAoGBAMDUQBJxQZcYmmwN5jGH
4ZQt6IwS/teRaJ6TmuB9GZMw/S0gSc9l7+iTglZQ5Vov5M4Xev1QB99M3DBUlwz4
B/SF9l0JLBzmwmar1D7hHGZC/7FxrFexAp0aNMaiwOrMettibwboFdeT4so4fan6
g/aRnS0UIfwdSQJKbnIpY8GhAoGAZYyoCrSALltXfOAca/bKg+Ayr17T7URXEvU7
k9CXceQJfZN/wrJ3/040oVfiDQwlG/jHs67787RXwewJdUzJytJBATQ8KdZUSfYH
pOPsHiO9uWOtyloDIjz7Z1d6wnpsEGjG8sKxzbc5FHKS0THpaxmn5GrQx/umJN1c
hSMxfN8CgYBHJcliRKGT04MevV4jBmToHKxCCrw247L7V7D8hYwLMDcqEFDLkmwb
n1mm6YBGb4d3t1gs4PuWm7BesMdvBJFC2q7VEw5Qt6Ag6+OLM9obrTrUyQFy9Z/m
QYYZiHGv8LSf/8jBfp6YhTtXq9JKBmHsdzvMJzKG6HNIwhfQTY8+IQKBgCbD7Ro5
EX2gzOMUwoTMbz6shWzA7HH01rCcASRKSqXlgWH4vpraekhx2FGHNPn6Guh0rfd/
4xqDS8TxkCLBL39HiB0njZgDA6ZAT2a4w1g2GKT+0kce2XdmhCpNEMXQ6hPRi7D8
ddesDBQsMLO/M/X4k0j1JcJR5HjKMBl699dNAoGBAKvWyd8OytNGtP5wr1n94nwh
LGsosuiinlexQg05D4b9dv/n4qsgGCnfSFn6f14IS7i1e7HRfwbI613GOfz5i/On
igWqs1q23JbnaCCk9sM1kr0wa98e5et6m5moPBycDqavy+iY/jo8FBxjV4ZbE8MD
kadWJGam6nLOthuqBlX3
-----END PRIVATE KEY-----";

    #[test]
    fn service_account_debug_redacts_private_key() {
        let sa = FcmServiceAccount {
            project_id: "demo-project".to_owned(),
            client_email: "push@demo-project.iam.gserviceaccount.com".to_owned(),
            private_key: Zeroizing::new("SUPER_SECRET_RSA_KEY".to_owned()),
            token_uri: None,
        };
        let shown = format!("{sa:?}");
        assert!(!shown.contains("SUPER_SECRET_RSA_KEY"));
        assert!(shown.contains("<redacted>"));
    }

    #[test]
    fn rejects_undersized_rsa_key_at_startup_without_panicking() {
        for (bits, pem) in [
            (1024, TEST_UNDERSIZED_RSA_1024_PEM),
            (2047, TEST_UNDERSIZED_RSA_2047_PEM),
        ] {
            let cfg = FcmConfig::new(FcmServiceAccount {
                project_id: "demo-project".to_owned(),
                client_email: "push@demo-project.iam.gserviceaccount.com".to_owned(),
                private_key: Zeroizing::new(pem.to_owned()),
                token_uri: None,
            });
            let err =
                FcmSender::new(cfg).expect_err(&format!("{bits}-bit RSA key must fail at startup"));
            assert!(matches!(err, PushError::Config(_)));
        }
    }

    #[test]
    fn classifies_only_token_specific_fcm_errors_as_invalid() {
        let unregistered = br#"{
            "error": {
                "code": 404,
                "message": "Requested entity was not found.",
                "status": "NOT_FOUND",
                "details": [{
                    "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                    "errorCode": "UNREGISTERED"
                }]
            }
        }"#;
        assert_eq!(
            classify_invalid_fcm_token(404, unregistered),
            Some(InvalidTokenClass::FcmUnregistered)
        );

        let invalid_token = br#"{
            "error": {
                "code": 400,
                "message": "The registration token is not a valid FCM registration token",
                "status": "INVALID_ARGUMENT"
            }
        }"#;
        assert_eq!(
            classify_invalid_fcm_token(400, invalid_token),
            Some(InvalidTokenClass::FcmInvalidRegistrationToken)
        );

        // Untyped UNREGISTERED detail or wrong @type must NOT prune healthy registrations.
        let untyped_unregistered = br#"{
            "error": {
                "code": 404,
                "message": "Requested entity was not found.",
                "status": "NOT_FOUND",
                "details": [{
                    "errorCode": "UNREGISTERED"
                }]
            }
        }"#;
        assert_eq!(classify_invalid_fcm_token(404, untyped_unregistered), None);

        let wrong_type_unregistered = br#"{
            "error": {
                "code": 404,
                "status": "NOT_FOUND",
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "errorCode": "UNREGISTERED"
                }]
            }
        }"#;
        assert_eq!(
            classify_invalid_fcm_token(404, wrong_type_unregistered),
            None
        );

        // Generic 404 / NOT_FOUND without UNREGISTERED must NOT prune healthy registrations.
        let generic_404 = br#"{
            "error": {
                "code": 404,
                "message": "Project not found.",
                "status": "NOT_FOUND"
            }
        }"#;
        assert_eq!(classify_invalid_fcm_token(404, generic_404), None);
        assert_eq!(
            classify_invalid_fcm_token(404, b"<html>404 Not Found</html>"),
            None
        );
        assert_eq!(classify_invalid_fcm_token(404, b""), None);

        // Generic 400 unrelated to registration token must NOT prune.
        let other_bad_request = br#"{
            "error": {
                "code": 400,
                "message": "Invalid JSON payload received",
                "status": "INVALID_ARGUMENT"
            }
        }"#;
        assert_eq!(classify_invalid_fcm_token(400, other_bad_request), None);
    }
}
