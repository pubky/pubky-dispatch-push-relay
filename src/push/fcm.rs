//! Firebase Cloud Messaging (FCM) HTTP v1 provider with Google Service Account OAuth2.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::clock::{Clock, SystemClock};
use crate::crypto::b64_encode;
use crate::push::{PushError, PushOutcome, PushSender};
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

/// Google service account credentials JSON structure.
#[derive(Clone, Deserialize)]
pub struct FcmServiceAccount {
    /// Firebase / Google Cloud project ID.
    pub project_id: String,
    /// Service account email (`iss` claim).
    pub client_email: String,
    /// PKCS#8 PEM-encoded RSA private key.
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
    /// Upstream HTTP request timeout.
    pub timeout: Duration,
}

impl FcmConfig {
    /// Creates an [`FcmConfig`] from service account credentials with default URLs.
    #[must_use]
    pub fn new(service_account: FcmServiceAccount) -> Self {
        Self {
            service_account,
            api_base_url: FCM_API_BASE_URL.to_owned(),
            timeout: Duration::from_secs(10),
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
    access_token: String,
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
    signing_key: SigningKey<Sha256>,
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
    /// # Errors
    ///
    /// Returns [`PushError::Config`] if credentials or key material are invalid.
    pub fn new(config: FcmConfig) -> Result<Self, PushError> {
        Self::with_clock(config, Arc::new(SystemClock))
    }

    /// Constructs a new [`FcmSender`] with a custom [`Clock`] (for deterministic tests).
    ///
    /// # Errors
    ///
    /// Returns [`PushError::Config`] if credentials or key material are invalid.
    pub fn with_clock(config: FcmConfig, clock: Arc<dyn Clock>) -> Result<Self, PushError> {
        let sa = config.service_account;
        if sa.project_id.trim().is_empty() || sa.client_email.trim().is_empty() {
            return Err(PushError::Config(
                "FCM project_id and client_email must be non-empty".to_owned(),
            ));
        }

        let private_key = RsaPrivateKey::from_pkcs8_pem(sa.private_key.as_str()).map_err(|e| {
            PushError::Config(format!("invalid FCM service account RSA private key: {e}"))
        })?;
        let signing_key = SigningKey::<Sha256>::new(private_key);

        let token_uri = sa
            .token_uri
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_GOOGLE_TOKEN_URI.to_owned());

        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| PushError::Config(format!("failed to build FCM HTTP client: {e}")))?;

        Ok(Self {
            client,
            signing_key,
            project_id: sa.project_id,
            client_email: sa.client_email,
            token_uri,
            api_base_url: config.api_base_url.trim_end_matches('/').to_owned(),
            clock,
            token_cache: Mutex::new(None),
        })
    }

    fn build_jwt_assertion(&self, now_secs: u64) -> Result<String, PushError> {
        let header_json = serde_json::to_vec(&JwtHeader {
            alg: "RS256",
            typ: "JWT",
        })
        .map_err(|e| PushError::Auth(format!("failed to encode FCM JWT header: {e}")))?;

        let claims_json = serde_json::to_vec(&JwtClaims {
            iss: &self.client_email,
            scope: FCM_OAUTH_SCOPE,
            aud: &self.token_uri,
            iat: now_secs,
            exp: now_secs.saturating_add(3600),
        })
        .map_err(|e| PushError::Auth(format!("failed to encode FCM JWT claims: {e}")))?;

        let signing_input = format!("{}.{}", b64_encode(&header_json), b64_encode(&claims_json));
        let signature = self.signing_key.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            b64_encode(signature.to_bytes().as_ref())
        ))
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
        let form_body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
        );

        let response = self
            .client
            .post(&self.token_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .map_err(|e| {
                PushError::Auth(format!(
                    "OAuth2 token exchange request failed: {}",
                    e.without_url()
                ))
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(PushError::Auth(format!(
                "OAuth2 token endpoint returned HTTP {}",
                status.as_u16()
            )));
        }

        let parsed: OAuthTokenResponse = response
            .json()
            .await
            .map_err(|e| PushError::Auth(format!("invalid OAuth2 token response: {e}")))?;

        if parsed.access_token.is_empty() {
            return Err(PushError::Auth(
                "OAuth2 token response contained an empty access_token".to_owned(),
            ));
        }

        let ttl_secs = parsed.expires_in.unwrap_or(3600);
        let token = Zeroizing::new(parsed.access_token);
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
            .header("authorization", format!("Bearer {}", access_token.as_str()))
            .header("content-type", "application/json; charset=utf-8")
            .json(&payload)
            .send()
            .await
            .map_err(|e| PushError::Upstream(format!("FCM request failed: {}", e.without_url())))?;

        let status = response.status();
        if status.is_success() {
            return Ok(FcmResponse::Outcome(PushOutcome::Delivered));
        }

        if status.as_u16() == 401 {
            return Ok(FcmResponse::Unauthorized);
        }

        let body_bytes = response.bytes().await.unwrap_or_default();
        if let Some(reason) = detect_invalid_fcm_token(status.as_u16(), &body_bytes) {
            return Ok(FcmResponse::Outcome(PushOutcome::InvalidToken { reason }));
        }

        let summary = parse_error_summary(status.as_u16(), &body_bytes);
        Err(PushError::Upstream(format!(
            "FCM rejected push with status {} ({summary})",
            status.as_u16()
        )))
    }
}

enum FcmResponse {
    Outcome(PushOutcome),
    Unauthorized,
}

fn detect_invalid_fcm_token(status: u16, body: &[u8]) -> Option<String> {
    let envelope = serde_json::from_slice::<FcmErrorEnvelope>(body).ok();
    let error = envelope.and_then(|e| e.error);

    if let Some(err) = error {
        for detail in &err.details {
            if let Some(code) = detail.error_code.as_deref()
                && code == "UNREGISTERED"
            {
                return Some(code.to_owned());
            }
        }
        if status == 404 || err.status.as_deref() == Some("NOT_FOUND") {
            return Some(err.status.unwrap_or_else(|| "NOT_FOUND".to_owned()));
        }
        if status == 400
            && err.status.as_deref() == Some("INVALID_ARGUMENT")
            && err
                .message
                .as_deref()
                .is_some_and(|m| m.to_ascii_lowercase().contains("registration token"))
        {
            return Some("INVALID_REGISTRATION_TOKEN".to_owned());
        }
        return None;
    }

    if status == 404 {
        return Some("NOT_FOUND".to_owned());
    }
    None
}

fn parse_error_summary(status: u16, body: &[u8]) -> String {
    serde_json::from_slice::<FcmErrorEnvelope>(body)
        .ok()
        .and_then(|e| e.error)
        .and_then(|e| {
            e.details
                .into_iter()
                .find_map(|d| d.error_code)
                .or(e.status)
        })
        .unwrap_or_else(|| format!("http_{status}"))
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
                        FcmResponse::Unauthorized => Err(PushError::Auth(
                            "FCM rejected refreshed OAuth2 access token".to_owned(),
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
    fn detects_unregistered_and_invalid_token_responses() {
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
            detect_invalid_fcm_token(404, unregistered).as_deref(),
            Some("UNREGISTERED")
        );

        let invalid_token = br#"{
            "error": {
                "code": 400,
                "message": "The registration token is not a valid FCM registration token",
                "status": "INVALID_ARGUMENT"
            }
        }"#;
        assert_eq!(
            detect_invalid_fcm_token(400, invalid_token).as_deref(),
            Some("INVALID_REGISTRATION_TOKEN")
        );

        // Generic 400 unrelated to registration token must NOT prune the handle.
        let other_bad_request = br#"{
            "error": {
                "code": 400,
                "message": "Invalid JSON payload received",
                "status": "INVALID_ARGUMENT"
            }
        }"#;
        assert_eq!(detect_invalid_fcm_token(400, other_bad_request), None);
    }
}
