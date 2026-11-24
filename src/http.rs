//! Axum HTTP router and handlers for `POST /v1/register`, `POST /v1/hook`, and `GET /health`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::config::RelaySettings;
use crate::crypto::{
    b64_decode_array, generate_handle, validate_public_key, verify_webhook_signature,
};
use crate::error::ApiError;
use crate::json::{check_strict_json, parse_strict_json};
use crate::push::{PushError, PushOutcome, PushSender};
use crate::rate_limit::RateLimiter;
use crate::replay::{NONCE_TTL_MS, NonceCache};
use crate::store::{ApnsEnv, Platform, Registration, RegistrationStore, StoreError};
use crate::time::parse_rfc3339;

/// Allowed clock skew for webhook timestamps: ±5 minutes (Wire Format §8.3 rule 4).
pub const MAX_TIMESTAMP_SKEW_MS: u64 = 5 * 60 * 1_000;

/// Maximum permitted length of a device push token.
const MAX_DEVICE_TOKEN_LEN: usize = 4096;

/// Maximum retries if CSPRNG handle generation ever collides with an existing handle.
const MAX_HANDLE_GENERATION_ATTEMPTS: usize = 3;

/// Shared runtime state for the push relay HTTP service.
#[derive(Clone)]
pub struct RelayState {
    store: Arc<dyn RegistrationStore>,
    push: Arc<dyn PushSender>,
    clock: Arc<dyn Clock>,
    replay: Arc<NonceCache>,
    rate_limiter: Arc<RateLimiter>,
    settings: Arc<RelaySettings>,
}

impl std::fmt::Debug for RelayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayState")
            .field("settings", &self.settings)
            .field("replay", &self.replay)
            .field("rate_limiter", &self.rate_limiter)
            .finish()
    }
}

impl RelayState {
    /// Creates a new [`RelayState`] with fresh replay cache and per-handle rate limiter.
    #[must_use]
    pub fn new(
        store: Arc<dyn RegistrationStore>,
        push: Arc<dyn PushSender>,
        clock: Arc<dyn Clock>,
        settings: RelaySettings,
    ) -> Self {
        let replay = Arc::new(NonceCache::new(
            NONCE_TTL_MS,
            settings.nonce_cache_max_entries,
        ));
        let rate_limiter = Arc::new(RateLimiter::new(
            settings.rate_limit_per_minute,
            settings.rate_limit_max_handles,
        ));
        Self {
            store,
            push,
            clock,
            replay,
            rate_limiter,
            settings: Arc::new(settings),
        }
    }

    /// Prunes expired entries from the in-memory replay cache and rate limiter.
    pub fn prune_caches(&self) {
        let now_ms = self.clock.now_ms();
        let evicted_nonces = self.replay.prune_expired(now_ms);
        let evicted_handles = self.rate_limiter.prune_expired(now_ms);
        if evicted_nonces > 0 || evicted_handles > 0 {
            tracing::debug!(
                evicted_nonces,
                evicted_handles,
                "pruned expired in-memory cache entries"
            );
        }
    }

    /// Returns a reference to the backing [`RegistrationStore`].
    #[must_use]
    pub fn store(&self) -> &Arc<dyn RegistrationStore> {
        &self.store
    }

    /// Returns a reference to the [`NonceCache`].
    #[must_use]
    pub fn replay_cache(&self) -> &Arc<NonceCache> {
        &self.replay
    }

    /// Returns a reference to the per-handle [`RateLimiter`].
    #[must_use]
    pub fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate_limiter
    }
}

/// Builds the Axum HTTP [`Router`] exposing `/v1/register`, `/v1/hook`, and `/health`.
pub fn router(state: RelayState) -> Router {
    Router::new()
        .route("/v1/register", post(handle_register))
        .route("/v1/hook", post(handle_hook))
        .route("/health", get(handle_health))
        .fallback(handle_not_found)
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    platform: Platform,
    device_token: String,
    push_key: String,
    #[serde(default)]
    apns_env: Option<ApnsEnv>,
}

#[derive(Serialize)]
struct RegisterResponse {
    handle: String,
}

#[derive(Deserialize)]
struct WebhookBody {
    v: u64,
    handle: String,
    ts: String,
    nonce: String,
}

#[derive(Serialize)]
struct HookResponse {
    delivered: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pruned: bool,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn handle_not_found() -> ApiError {
    ApiError::not_found("route not found")
}

async fn handle_health(State(state): State<RelayState>) -> (StatusCode, Json<HealthResponse>) {
    match state.store.ping().await {
        Ok(()) => (StatusCode::OK, Json(HealthResponse { status: "ok" })),
        Err(err) => {
            tracing::error!(error = %err, "health check failed: storage ping error");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    status: "unhealthy",
                }),
            )
        }
    }
}

async fn handle_register(
    State(state): State<RelayState>,
    body: Body,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let raw = read_bounded_body(body, state.settings.max_body_bytes).await?;
    let req: RegisterRequest =
        parse_strict_json(&raw).map_err(|e| ApiError::bad_request(e.to_string()))?;

    validate_device_token(req.platform, &req.device_token)?;

    let apns_env = match (req.platform, req.apns_env) {
        (Platform::Apns, Some(env)) => Some(env),
        (Platform::Apns, None) => Some(state.settings.default_apns_env),
        (Platform::Fcm, None) => None,
        (Platform::Fcm, Some(_)) => {
            return Err(ApiError::bad_request(
                "apns_env is only permitted when platform is \"apns\"",
            ));
        }
    };

    let push_key = b64_decode_array::<32>(&req.push_key)
        .map_err(|e| ApiError::bad_request(format!("invalid push_key: {e}")))?;
    validate_public_key(&push_key)
        .map_err(|e| ApiError::bad_request(format!("invalid push_key: {e}")))?;

    let created_at_ms = state.clock.now_ms();

    for _ in 0..MAX_HANDLE_GENERATION_ATTEMPTS {
        let handle = generate_handle().map_err(|err| {
            tracing::error!(error = %err, "failed to generate random handle");
            ApiError::internal()
        })?;
        let registration = Registration {
            handle: handle.clone(),
            platform: req.platform,
            device_token: req.device_token.clone(),
            push_key,
            apns_env,
            created_at_ms,
        };

        match state.store.insert(&registration).await {
            Ok(()) => {
                tracing::info!(platform = %req.platform, "registered push handle");
                return Ok((StatusCode::OK, Json(RegisterResponse { handle })));
            }
            Err(StoreError::DuplicateHandle) => continue,
            Err(err) => {
                tracing::error!(error = %err, "failed to persist push registration");
                return Err(ApiError::internal());
            }
        }
    }

    tracing::error!("exhausted random handle generation attempts");
    Err(ApiError::internal())
}

async fn handle_hook(
    State(state): State<RelayState>,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<HookResponse>), ApiError> {
    let raw = read_bounded_body(body, state.settings.max_body_bytes).await?;

    // Rule 1 (Wire Format §8.3): valid webhook JSON with v == 1 (else 400).
    check_strict_json(&raw).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let webhook: WebhookBody = serde_json::from_slice(&raw)
        .map_err(|e| ApiError::bad_request(format!("invalid webhook body: {e}")))?;

    if webhook.v != 1 {
        return Err(ApiError::bad_request("unsupported webhook version"));
    }
    if webhook.handle.is_empty() || has_control_chars(&webhook.handle) {
        return Err(ApiError::bad_request("invalid handle"));
    }
    let ts_ms = parse_rfc3339(&webhook.ts)
        .map_err(|e| ApiError::bad_request(format!("invalid ts: {e}")))?;
    let nonce = b64_decode_array::<16>(&webhook.nonce)
        .map_err(|e| ApiError::bad_request(format!("invalid nonce: {e}")))?;

    // Rule 2 (Wire Format §8.3): handle must be known (else 404).
    let registration = state
        .store
        .get(&webhook.handle)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "storage lookup failed on webhook");
            ApiError::internal()
        })?
        .ok_or_else(|| ApiError::not_found("unknown push handle"))?;

    // Rule 3 (Wire Format §8.3): signature header verifies with bound push_key over
    // lp(label, relay_origin, raw_body) (else 401).
    let signature = extract_signature_header(&headers, &state.settings.protocol.signature_header)?;
    verify_webhook_signature(
        &registration.push_key,
        &state.settings.protocol.signing_label,
        &state.settings.relay_origin,
        &raw,
        &signature,
    )
    .map_err(|_| ApiError::bad_signature("webhook signature verification failed"))?;

    // Rule 4 (Wire Format §8.3): ts within ±5 minutes of relay clock (else 401).
    let now_ms = state.clock.now_ms();
    if now_ms.abs_diff(ts_ms) > MAX_TIMESTAMP_SKEW_MS {
        return Err(ApiError::stale_timestamp(
            "webhook timestamp outside ±5 minute window",
        ));
    }

    // Rule 5 (Wire Format §8.3): nonce unseen in the last 10 minutes (else 409).
    if !state.replay.check_and_record(nonce, now_ms) {
        return Err(ApiError::nonce_replay());
    }

    // Rule 6 (Wire Format §8.3): per-handle per-minute rate limit (else 429).
    if let Err(retry_after) = state.rate_limiter.check_and_record(&webhook.handle, now_ms) {
        return Err(ApiError::rate_limited(retry_after));
    }

    // Dispatch content-free wake push to APNs or FCM.
    match state.push.send_wake(&registration).await {
        Ok(PushOutcome::Delivered) => {
            tracing::debug!(platform = %registration.platform, "dispatched wake push");
            Ok((
                StatusCode::OK,
                Json(HookResponse {
                    delivered: true,
                    pruned: false,
                }),
            ))
        }
        Ok(PushOutcome::InvalidToken { reason }) => {
            if let Err(err) = state.store.delete(&registration.handle).await {
                tracing::error!(
                    platform = %registration.platform,
                    error = %err,
                    "failed to delete handle after invalid device token"
                );
                return Err(ApiError::internal());
            }
            state.rate_limiter.remove_handle(&registration.handle);
            tracing::info!(
                platform = %registration.platform,
                reason = %reason,
                "pruned handle after upstream reported invalid device token"
            );
            Ok((
                StatusCode::OK,
                Json(HookResponse {
                    delivered: false,
                    pruned: true,
                }),
            ))
        }
        Err(PushError::PlatformNotConfigured(platform)) => {
            tracing::warn!(platform = %platform, "push backend not configured for platform");
            Err(ApiError::unavailable(format!(
                "push backend not configured for {platform}"
            )))
        }
        Err(err) => {
            tracing::warn!(
                platform = %registration.platform,
                error = %err,
                "wake push delivery failed"
            );
            Err(ApiError::upstream("upstream push delivery failed"))
        }
    }
}

async fn read_bounded_body(body: Body, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    let bytes = axum::body::to_bytes(body, max_bytes)
        .await
        .map_err(|_| ApiError::too_large(max_bytes))?;
    Ok(bytes.to_vec())
}

fn extract_signature_header(headers: &HeaderMap, header_name: &str) -> Result<[u8; 64], ApiError> {
    let name = HeaderName::from_bytes(header_name.as_bytes()).map_err(|_| ApiError::internal())?;
    let mut values = headers.get_all(&name).iter();
    let Some(first) = values.next() else {
        return Err(ApiError::bad_signature("missing signature header"));
    };
    if values.next().is_some() {
        return Err(ApiError::bad_signature("duplicate signature header"));
    }
    let text = first
        .to_str()
        .map_err(|_| ApiError::bad_signature("non-ASCII signature header"))?;
    b64_decode_array::<64>(text).map_err(|_| ApiError::bad_signature("malformed signature header"))
}

fn validate_device_token(platform: Platform, token: &str) -> Result<(), ApiError> {
    if token.is_empty() || token.len() > MAX_DEVICE_TOKEN_LEN {
        return Err(ApiError::bad_request(
            "device_token must be between 1 and 4096 bytes",
        ));
    }
    if has_control_chars(token) || token.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(ApiError::bad_request(
            "device_token must not contain whitespace or control characters",
        ));
    }
    match platform {
        Platform::Apns => {
            // APNs tokens are hex-encoded bytes placed in `/3/device/{token}`.
            if token.len() < 32
                || token.len() > 512
                || !token.len().is_multiple_of(2)
                || !token.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(ApiError::bad_request(
                    "APNs device_token must be an even-length hexadecimal string (32..=512 chars)",
                ));
            }
        }
        Platform::Fcm => {
            if !token.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
                return Err(ApiError::bad_request(
                    "FCM device_token must contain only printable ASCII characters",
                ));
            }
        }
    }
    Ok(())
}

fn has_control_chars(text: &str) -> bool {
    text.chars().any(|c| c.is_control())
}
