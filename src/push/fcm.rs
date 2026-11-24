//! Firebase Cloud Messaging (FCM) HTTP v1 provider with Google Service Account OAuth2
//! signed using `ring::signature::RsaKeyPair`.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use reqwest::Client;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::clock::{Clock, SystemClock};
use crate::crypto::b64_encode;
use crate::push::{
    DEFAULT_PROVIDER_TIMEOUT_MS, InvalidTokenClass, PushError, PushOutcome, PushSender,
    UpstreamErrorClass, classify_http_status,
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

/// Minimum RSA modulus length in bytes (2048 bits) required by `ring` and RS256 best practices.
const MIN_RSA_MODULUS_BYTES: usize = 256;

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
        let modulus_len = key_pair.public().modulus_len();
        if modulus_len < MIN_RSA_MODULUS_BYTES {
            return Err(PushError::Config(
                "FCM service account RSA key must be at least 2048 bits".to_owned(),
            ));
        }

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

    async fn access_token(&self) -> Result<Zeroizing<String>, PushError> {
        let mut cache = self.token_cache.lock().await;
        let now_secs = self.clock.now_ms() / 1_000;

        if let Some(cached) = cache.as_ref()
            && now_secs.saturating_add(TOKEN_REFRESH_MARGIN_SECS) < cached.expires_at_secs
        {
            return Ok(cached.token.clone());
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
            return Err(PushError::Auth {
                class: classify_http_status(status.as_u16()),
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
        *cache = Some(CachedAccessToken {
            token: token.clone(),
            expires_at_secs: now_secs.saturating_add(ttl_secs),
        });
        Ok(token)
    }

    async fn invalidate_access_token(&self) {
        *self.token_cache.lock().await = None;
    }

    async fn send_once(&self, registration: &Registration) -> Result<FcmResponse, PushError> {
        let access_token = self.access_token().await?;
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
            return Ok(FcmResponse::Outcome(PushOutcome::Delivered));
        }

        let status_code = status.as_u16();
        if status_code == 401 {
            return Ok(FcmResponse::Unauthorized);
        }

        let body_bytes = response.bytes().await.unwrap_or_default();
        if let Some(class) = classify_invalid_fcm_token(status_code, &body_bytes) {
            return Ok(FcmResponse::Outcome(PushOutcome::InvalidToken { class }));
        }

        Err(PushError::Upstream {
            class: classify_http_status(status_code),
            status: Some(status_code),
        })
    }
}

enum FcmResponse {
    Outcome(PushOutcome),
    Unauthorized,
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

/// Requires explicit token-specific FCM evidence before deleting a handle:
/// - `error.details` contains an `FcmError` with `errorCode == "UNREGISTERED"`
/// - `400 INVALID_ARGUMENT` whose message explicitly names the registration token
///
/// Generic HTTP 404 or `NOT_FOUND` responses without `errorCode: "UNREGISTERED"` (such as
/// misconfigured project IDs or upstream proxy errors) MUST NOT delete a healthy handle.
fn classify_invalid_fcm_token(status: u16, body: &[u8]) -> Option<InvalidTokenClass> {
    let envelope = serde_json::from_slice::<FcmErrorEnvelope>(body).ok()?;
    let err = envelope.error?;

    for detail in &err.details {
        if detail.error_code.as_deref() == Some("UNREGISTERED") {
            return Some(InvalidTokenClass::FcmUnregistered);
        }
    }

    let is_invalid_argument = err.status.as_deref() == Some("INVALID_ARGUMENT")
        || err
            .details
            .iter()
            .any(|d| d.error_code.as_deref() == Some("INVALID_ARGUMENT"));
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
                FcmResponse::Unauthorized => {
                    self.invalidate_access_token().await;
                    match self.send_once(registration).await? {
                        FcmResponse::Outcome(outcome) => Ok(outcome),
                        FcmResponse::Unauthorized => Err(PushError::Auth {
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
        let cfg = FcmConfig::new(FcmServiceAccount {
            project_id: "demo-project".to_owned(),
            client_email: "push@demo-project.iam.gserviceaccount.com".to_owned(),
            private_key: Zeroizing::new(TEST_UNDERSIZED_RSA_1024_PEM.to_owned()),
            token_uri: None,
        });
        let err = FcmSender::new(cfg).expect_err("1024-bit RSA key must fail at startup");
        assert!(matches!(err, PushError::Config(_)));
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
