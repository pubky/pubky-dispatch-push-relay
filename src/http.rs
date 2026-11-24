//! Axum HTTP router and handlers for `POST /v1/register`, `POST /v1/hook`, `/health*`, and `/metrics`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::client_ip::ip_rate_limit_key;
use crate::clock::Clock;
use crate::config::RelaySettings;
use crate::crypto::{
    b64_decode_array, b64_encode, generate_handle, validate_public_key, verify_webhook_signature,
};
use crate::error::ApiError;
use crate::json::{check_strict_json, parse_strict_json};
use crate::metrics::{ProviderCallOutcome, RegistrationOutcome, RelayMetrics, WebhookOutcome};
use crate::push::{PushError, PushOutcome, PushSender, UpstreamErrorClass};
use crate::rate_limit::{RateLimitStore, RateLimiter};
use crate::replay::{NONCE_TTL_MS, NonceCache, ReplayError, ReplayStore};
use crate::store::{
    ApnsEnv, Platform, RegisterOutcome, Registration, RegistrationStore, StoreError,
};
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
    replay: Arc<dyn ReplayStore>,
    rate_limiter: Arc<dyn RateLimitStore>,
    register_ip_limiter: Arc<dyn RateLimitStore>,
    register_key_limiter: Arc<dyn RateLimitStore>,
    register_global_limiter: Arc<dyn RateLimitStore>,
    concurrency: Arc<Semaphore>,
    metrics: Arc<RelayMetrics>,
    settings: Arc<RelaySettings>,
}

impl std::fmt::Debug for RelayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayState")
            .field("settings", &self.settings)
            .finish()
    }
}

/// Bundle of rate-limit stores injected into [`RelayState::with_backends`].
pub struct RateLimitBackends {
    /// Per-handle webhook push rate limiter (Wire Format §8.3 rule 6).
    pub hook_per_handle: Arc<dyn RateLimitStore>,
    /// Per-client-IP registration rate limiter.
    pub register_per_ip: Arc<dyn RateLimitStore>,
    /// Per-push-key registration rate limiter.
    pub register_per_key: Arc<dyn RateLimitStore>,
    /// Global registration rate limiter.
    pub register_global: Arc<dyn RateLimitStore>,
}

impl RelayState {
    /// Creates a new [`RelayState`] using in-memory replay cache and rate limiters
    /// (for unit tests and direct embedding).
    ///
    /// For durable SQLite deployments, construct a [`crate::store::sqlite::SqliteReplayStore`]
    /// and pass it via [`Self::with_backends`].
    #[must_use]
    pub fn new(
        store: Arc<dyn RegistrationStore>,
        push: Arc<dyn PushSender>,
        clock: Arc<dyn Clock>,
        settings: RelaySettings,
    ) -> Self {
        let replay: Arc<dyn ReplayStore> = Arc::new(NonceCache::new(
            NONCE_TTL_MS,
            settings.nonce_cache_max_entries,
        ));
        let limiters = Self::in_memory_limiters(&settings);
        Self::with_backends(store, push, clock, replay, limiters, settings)
    }

    /// Creates in-memory sliding-window [`RateLimitBackends`] sized from `settings`.
    #[must_use]
    pub fn in_memory_limiters(settings: &RelaySettings) -> RateLimitBackends {
        RateLimitBackends {
            hook_per_handle: Arc::new(RateLimiter::new(
                settings.rate_limit_per_minute,
                settings.rate_limit_max_handles,
            )),
            register_per_ip: Arc::new(RateLimiter::new(
                settings.register_ip_rate_limit_per_minute,
                settings.rate_limit_max_handles,
            )),
            register_per_key: Arc::new(RateLimiter::new(
                settings.register_key_rate_limit_per_minute,
                settings.rate_limit_max_handles,
            )),
            register_global: Arc::new(RateLimiter::new(settings.register_rate_limit_per_minute, 1)),
        }
    }

    /// Creates a new [`RelayState`] with custom [`ReplayStore`] and [`RateLimitBackends`]
    /// implementations (SQLite durable replay or PostgreSQL multi-replica backends).
    #[must_use]
    pub fn with_backends(
        store: Arc<dyn RegistrationStore>,
        push: Arc<dyn PushSender>,
        clock: Arc<dyn Clock>,
        replay: Arc<dyn ReplayStore>,
        limiters: RateLimitBackends,
        settings: RelaySettings,
    ) -> Self {
        let concurrency = Arc::new(Semaphore::new(settings.max_concurrent_requests.max(1)));
        Self {
            store,
            push,
            clock,
            replay,
            rate_limiter: limiters.hook_per_handle,
            register_ip_limiter: limiters.register_per_ip,
            register_key_limiter: limiters.register_per_key,
            register_global_limiter: limiters.register_global,
            concurrency,
            metrics: Arc::new(RelayMetrics::new()),
            settings: Arc::new(settings),
        }
    }

    /// Prunes expired entries from replay storage, rate limiters, and inactive registrations.
    pub async fn prune_caches(&self) {
        let wall_now_ms = self.clock.now_ms();
        let mono_now_ms = self.clock.monotonic_ms();

        let evicted_nonces = match self.replay.prune_expired(wall_now_ms, mono_now_ms).await {
            Ok(n) => n,
            Err(err) => {
                tracing::warn!(error = %err, "failed to prune expired replay nonces");
                0
            }
        };
        let evicted_handles = match self.rate_limiter.prune_expired(mono_now_ms).await {
            Ok(n) => n,
            Err(err) => {
                tracing::warn!(error = %err, "failed to prune expired hook rate limits");
                0
            }
        };
        for (name, limiter) in [
            ("register_ip", &self.register_ip_limiter),
            ("register_key", &self.register_key_limiter),
            ("register_global", &self.register_global_limiter),
        ] {
            if let Err(err) = limiter.prune_expired(mono_now_ms).await {
                tracing::warn!(scope = name, error = %err, "failed to prune rate limits");
            }
        }
        let cutoff_ms = wall_now_ms.saturating_sub(self.settings.registration_ttl_ms);
        let evicted_registrations = match self.store.prune_expired(cutoff_ms).await {
            Ok(n) => n,
            Err(err) => {
                tracing::warn!(error = %err, "failed to prune inactive registrations");
                0
            }
        };
        if evicted_nonces > 0 || evicted_handles > 0 || evicted_registrations > 0 {
            tracing::debug!(
                evicted_nonces,
                evicted_handles,
                evicted_registrations,
                "pruned expired entries"
            );
        }
    }

    /// Returns a reference to the backing [`RegistrationStore`].
    #[must_use]
    pub fn store(&self) -> &Arc<dyn RegistrationStore> {
        &self.store
    }

    /// Returns a reference to the [`ReplayStore`].
    #[must_use]
    pub fn replay_store(&self) -> &Arc<dyn ReplayStore> {
        &self.replay
    }

    /// Returns a reference to the per-handle [`RateLimitStore`].
    #[must_use]
    pub fn rate_limiter(&self) -> &Arc<dyn RateLimitStore> {
        &self.rate_limiter
    }

    /// Returns a reference to the [`RelayMetrics`] registry.
    #[must_use]
    pub fn metrics(&self) -> &Arc<RelayMetrics> {
        &self.metrics
    }
}

/// Builds the Axum HTTP [`Router`] exposing `/v1/register`, `/v1/hook`, `/health`,
/// `/health/ready`, and `/health/live`.
///
/// `/v1/*` routes are guarded by both a non-blocking concurrency cap (`503` when full)
/// and an overall request deadline (`408` on slowloris/stalled clients). Health endpoints
/// stay outside the `/v1/*` concurrency semaphore so probes remain responsive.
pub fn router(state: RelayState) -> Router {
    let api = Router::new()
        .route("/v1/register", post(handle_register))
        .route("/v1/hook", post(handle_hook))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_concurrency_and_deadline,
        ));

    Router::new()
        .merge(api)
        .route("/health", get(handle_readiness))
        .route("/health/ready", get(handle_readiness))
        .route("/health/live", get(handle_liveness))
        .fallback(handle_not_found)
        .with_state(state)
}

/// Builds the operator Axum [`Router`] exposing Prometheus metrics on `GET /metrics`.
///
/// Intended to be bound on a private/loopback listener (`METRICS_BIND_ADDR`) separate
/// from public traffic.
pub fn metrics_router(state: RelayState) -> Router {
    Router::new()
        .route("/metrics", get(handle_metrics))
        .with_state(state)
}

async fn enforce_concurrency_and_deadline(
    State(state): State<RelayState>,
    req: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = state.concurrency.clone().try_acquire_owned() else {
        return ApiError::unavailable("server at concurrency limit").into_response();
    };

    match tokio::time::timeout(state.settings.request_timeout, next.run(req)).await {
        Ok(response) => response,
        Err(_) => ApiError::request_timeout().into_response(),
    }
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

async fn handle_liveness() -> (StatusCode, Json<HealthResponse>) {
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

async fn handle_readiness(State(state): State<RelayState>) -> (StatusCode, Json<HealthResponse>) {
    if let Err(err) = state.store.ping().await {
        tracing::error!(error = %err, "readiness check failed: storage ping error");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "unhealthy",
            }),
        );
    }
    if let Err(err) = state.push.check_ready() {
        tracing::error!(
            class = err.log_class(),
            "readiness check failed: push provider credentials not ready"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "unhealthy",
            }),
        );
    }
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

async fn handle_metrics(State(state): State<RelayState>) -> Response {
    let body = state.metrics.render_prometheus();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

async fn handle_register(
    State(state): State<RelayState>,
    req: Request,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let wall_now_ms = state.clock.now_ms();
    let mono_now_ms = state.clock.monotonic_ms();

    // 1. Per-client-IP rate limit first so one abusive IP cannot burn the global quota.
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |ci| ci.0.ip());
    let (parts, body) = req.into_parts();
    let client_ip = state.settings.trusted_proxies.extract_client_ip(
        peer_ip,
        &parts.headers,
        &state.settings.trusted_proxy_header,
    );
    let ip_key = ip_rate_limit_key(client_ip);
    match state
        .register_ip_limiter
        .check_and_record(&ip_key, mono_now_ms)
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(retry_after)) => {
            state
                .metrics
                .inc_registration(RegistrationOutcome::RateLimitedIp);
            return Err(ApiError::rate_limited_with_message(
                retry_after,
                "client address registration rate limit exceeded",
            ));
        }
        Err(err) => {
            state
                .metrics
                .inc_registration(RegistrationOutcome::InternalError);
            tracing::error!(error = %err, "per-IP registration rate-limit check failed");
            return Err(ApiError::internal());
        }
    }

    let raw = match read_bounded_body(body, state.settings.max_body_bytes).await {
        Ok(b) => b,
        Err(err) => {
            state
                .metrics
                .inc_registration(RegistrationOutcome::BadRequest);
            return Err(err);
        }
    };
    let req: RegisterRequest = match parse_strict_json(&raw) {
        Ok(v) => v,
        Err(e) => {
            state
                .metrics
                .inc_registration(RegistrationOutcome::BadRequest);
            return Err(ApiError::bad_request(e.to_string()));
        }
    };

    if let Err(err) = validate_device_token(req.platform, &req.device_token) {
        state
            .metrics
            .inc_registration(RegistrationOutcome::BadRequest);
        return Err(err);
    }

    let apns_env = match (req.platform, req.apns_env) {
        (Platform::Apns, Some(env)) => Some(env),
        (Platform::Apns, None) => Some(state.settings.default_apns_env),
        (Platform::Fcm, None) => None,
        (Platform::Fcm, Some(_)) => {
            state
                .metrics
                .inc_registration(RegistrationOutcome::BadRequest);
            return Err(ApiError::bad_request(
                "apns_env is only permitted when platform is \"apns\"",
            ));
        }
    };

    let push_key = match b64_decode_array::<32>(&req.push_key) {
        Ok(k) => k,
        Err(e) => {
            state
                .metrics
                .inc_registration(RegistrationOutcome::BadRequest);
            return Err(ApiError::bad_request(format!("invalid push_key: {e}")));
        }
    };
    if let Err(e) = validate_public_key(&push_key) {
        state
            .metrics
            .inc_registration(RegistrationOutcome::BadRequest);
        return Err(ApiError::bad_request(format!("invalid push_key: {e}")));
    }

    // 2. Per-push-key rate limit so distributed callers targeting one key cannot burn global quota.
    let key_bucket = b64_encode(&push_key);
    match state
        .register_key_limiter
        .check_and_record(&key_bucket, mono_now_ms)
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(retry_after)) => {
            state
                .metrics
                .inc_registration(RegistrationOutcome::RateLimitedKey);
            return Err(ApiError::rate_limited_with_message(
                retry_after,
                "push key registration rate limit exceeded",
            ));
        }
        Err(err) => {
            state
                .metrics
                .inc_registration(RegistrationOutcome::InternalError);
            tracing::error!(error = %err, "per-key registration rate-limit check failed");
            return Err(ApiError::internal());
        }
    }

    // 3. Global registration rate limit.
    match state
        .register_global_limiter
        .check_and_record("register", mono_now_ms)
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(retry_after)) => {
            state
                .metrics
                .inc_registration(RegistrationOutcome::RateLimitedGlobal);
            return Err(ApiError::rate_limited_with_message(
                retry_after,
                "global registration rate limit exceeded",
            ));
        }
        Err(err) => {
            state
                .metrics
                .inc_registration(RegistrationOutcome::InternalError);
            tracing::error!(error = %err, "global registration rate-limit check failed");
            return Err(ApiError::internal());
        }
    }

    let limits = state.settings.registration_limits();

    for _ in 0..MAX_HANDLE_GENERATION_ATTEMPTS {
        let handle = match generate_handle() {
            Ok(h) => h,
            Err(err) => {
                state
                    .metrics
                    .inc_registration(RegistrationOutcome::InternalError);
                tracing::error!(error = %err, "failed to generate random handle");
                return Err(ApiError::internal());
            }
        };
        let candidate = Registration {
            handle,
            platform: req.platform,
            device_token: req.device_token.clone(),
            push_key,
            apns_env,
            created_at_ms: wall_now_ms,
            last_active_at_ms: wall_now_ms,
        };

        match state
            .store
            .register_or_get(&candidate, limits, wall_now_ms)
            .await
        {
            Ok(RegisterOutcome::Created(handle)) => {
                state.metrics.inc_registration(RegistrationOutcome::Created);
                tracing::info!(platform = %req.platform, outcome = "created", "registered push handle");
                return Ok((StatusCode::OK, Json(RegisterResponse { handle })));
            }
            Ok(RegisterOutcome::Existing(handle)) => {
                state
                    .metrics
                    .inc_registration(RegistrationOutcome::Existing);
                tracing::info!(platform = %req.platform, outcome = "existing", "re-registered existing push handle");
                return Ok((StatusCode::OK, Json(RegisterResponse { handle })));
            }
            Err(StoreError::DuplicateHandle) => continue,
            Err(StoreError::PushKeyCapacityExceeded) => {
                state
                    .metrics
                    .inc_registration(RegistrationOutcome::QuotaExceeded);
                tracing::warn!(platform = %req.platform, "rejected registration: push key handle quota exceeded");
                return Err(ApiError::quota_exceeded(
                    "push key has reached its maximum active handles",
                ));
            }
            Err(StoreError::CapacityExceeded) => {
                state
                    .metrics
                    .inc_registration(RegistrationOutcome::CapacityExceeded);
                tracing::warn!(
                    "rejected registration: maximum global registration capacity reached"
                );
                return Err(ApiError::unavailable("registration capacity exceeded"));
            }
            Err(err) => {
                state
                    .metrics
                    .inc_registration(RegistrationOutcome::InternalError);
                tracing::error!(error = %err, "failed to persist push registration");
                return Err(ApiError::internal());
            }
        }
    }

    state
        .metrics
        .inc_registration(RegistrationOutcome::InternalError);
    tracing::error!("exhausted random handle generation attempts");
    Err(ApiError::internal())
}

async fn handle_hook(
    State(state): State<RelayState>,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<HookResponse>), ApiError> {
    let raw = match read_bounded_body(body, state.settings.max_body_bytes).await {
        Ok(b) => b,
        Err(err) => {
            state.metrics.inc_webhook(WebhookOutcome::BadRequest);
            return Err(err);
        }
    };

    // Rule 1 (Wire Format §8.3): valid webhook JSON with v == 1 (else 400).
    // Note: Wire Format §1.7 allows any JSON string for `handle`; unknown handles
    // (including empty or control-character strings) fall through to Rule 2 (404).
    if let Err(e) = check_strict_json(&raw) {
        state.metrics.inc_webhook(WebhookOutcome::BadRequest);
        return Err(ApiError::bad_request(e.to_string()));
    }
    let webhook: WebhookBody = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => {
            state.metrics.inc_webhook(WebhookOutcome::BadRequest);
            return Err(ApiError::bad_request(format!("invalid webhook body: {e}")));
        }
    };

    if webhook.v != 1 {
        state.metrics.inc_webhook(WebhookOutcome::BadRequest);
        return Err(ApiError::bad_request("unsupported webhook version"));
    }
    let ts_ms = match parse_rfc3339(&webhook.ts) {
        Ok(ms) => ms,
        Err(e) => {
            state.metrics.inc_webhook(WebhookOutcome::BadRequest);
            return Err(ApiError::bad_request(format!("invalid ts: {e}")));
        }
    };
    let nonce = match b64_decode_array::<16>(&webhook.nonce) {
        Ok(n) => n,
        Err(e) => {
            state.metrics.inc_webhook(WebhookOutcome::BadRequest);
            return Err(ApiError::bad_request(format!("invalid nonce: {e}")));
        }
    };

    let wall_now_ms = state.clock.now_ms();
    let mono_now_ms = state.clock.monotonic_ms();
    let active_cutoff_ms = wall_now_ms.saturating_sub(state.settings.registration_ttl_ms);

    // Rule 2 (Wire Format §8.3): handle must be known and not expired (else 404).
    let registration = match state
        .store
        .get_active(&webhook.handle, active_cutoff_ms)
        .await
    {
        Ok(Some(reg)) => reg,
        Ok(None) => {
            state.metrics.inc_webhook(WebhookOutcome::UnknownHandle);
            return Err(ApiError::not_found("unknown push handle"));
        }
        Err(err) => {
            state.metrics.inc_webhook(WebhookOutcome::InternalError);
            tracing::error!(error = %err, "storage lookup failed on webhook");
            return Err(ApiError::internal());
        }
    };

    // Rule 3 (Wire Format §8.3): signature header verifies with bound push_key over
    // lp(label, relay_origin, raw_body) (else 401).
    let signature =
        match extract_signature_header(&headers, &state.settings.protocol.signature_header) {
            Ok(sig) => sig,
            Err(err) => {
                state.metrics.inc_webhook(WebhookOutcome::BadSignature);
                return Err(err);
            }
        };
    if verify_webhook_signature(
        &registration.push_key,
        &state.settings.protocol.signing_label,
        &state.settings.relay_origin,
        &raw,
        &signature,
    )
    .is_err()
    {
        state.metrics.inc_webhook(WebhookOutcome::BadSignature);
        return Err(ApiError::bad_signature(
            "webhook signature verification failed",
        ));
    }

    // Rule 4 (Wire Format §8.3): ts within ±5 minutes of relay clock (else 401).
    if wall_now_ms.abs_diff(ts_ms) > MAX_TIMESTAMP_SKEW_MS {
        state.metrics.inc_webhook(WebhookOutcome::StaleTimestamp);
        return Err(ApiError::stale_timestamp(
            "webhook timestamp outside ±5 minute window",
        ));
    }

    // Rule 5 (Wire Format §8.3): nonce unseen in the last 10 minutes (else 409; 503 if full).
    match state
        .replay
        .check_and_record(nonce, wall_now_ms, mono_now_ms)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            state.metrics.inc_webhook(WebhookOutcome::NonceReplay);
            return Err(ApiError::nonce_replay());
        }
        Err(ReplayError::CapacityExceeded) => {
            state
                .metrics
                .inc_webhook(WebhookOutcome::ReplayCapacityExceeded);
            tracing::warn!("replay store at live-nonce capacity; refusing webhook");
            return Err(ApiError::unavailable(
                "replay cache at capacity; retry later",
            ));
        }
        Err(ReplayError::Backend(err)) => {
            state.metrics.inc_webhook(WebhookOutcome::InternalError);
            tracing::error!(error = %err, "replay cache lookup failed on webhook");
            return Err(ApiError::internal());
        }
    }

    // Rule 6 (Wire Format §8.3): per-handle per-minute rate limit (else 429).
    match state
        .rate_limiter
        .check_and_record(&webhook.handle, mono_now_ms)
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(retry_after)) => {
            state.metrics.inc_webhook(WebhookOutcome::RateLimited);
            return Err(ApiError::rate_limited(retry_after));
        }
        Err(err) => {
            state.metrics.inc_webhook(WebhookOutcome::InternalError);
            tracing::error!(error = %err, "rate-limit check failed on webhook");
            return Err(ApiError::internal());
        }
    }

    // Dispatch content-free wake push bounded strictly below Dispatch's 5-second timeout.
    let started = Instant::now();
    let delivery = tokio::time::timeout(
        state.settings.provider_timeout,
        state.push.send_wake(&registration),
    )
    .await;
    let elapsed = started.elapsed();

    match delivery {
        Err(_) => {
            state.metrics.inc_webhook(WebhookOutcome::ProviderTimeout);
            state.metrics.observe_provider_latency(
                registration.platform,
                ProviderCallOutcome::Timeout,
                elapsed,
            );
            touch_handle_best_effort(&state, &registration.handle, wall_now_ms).await;
            tracing::warn!(
                platform = %registration.platform,
                class = "timeout",
                "wake push delivery exceeded provider timeout"
            );
            Err(ApiError::upstream("upstream push provider timed out"))
        }
        Ok(Ok(PushOutcome::Delivered)) => {
            state.metrics.inc_webhook(WebhookOutcome::Delivered);
            state.metrics.observe_provider_latency(
                registration.platform,
                ProviderCallOutcome::Delivered,
                elapsed,
            );
            touch_handle_best_effort(&state, &registration.handle, wall_now_ms).await;
            tracing::debug!(platform = %registration.platform, "dispatched wake push");
            Ok((
                StatusCode::OK,
                Json(HookResponse {
                    delivered: true,
                    pruned: false,
                }),
            ))
        }
        Ok(Ok(PushOutcome::InvalidToken { class })) => {
            state.metrics.observe_provider_latency(
                registration.platform,
                ProviderCallOutcome::Pruned,
                elapsed,
            );
            if let Err(err) = state.store.delete(&registration.handle).await {
                state.metrics.inc_webhook(WebhookOutcome::InternalError);
                tracing::error!(
                    platform = %registration.platform,
                    error = %err,
                    "failed to delete handle after invalid device token"
                );
                return Err(ApiError::internal());
            }
            if let Err(err) = state.rate_limiter.remove_key(&registration.handle).await {
                tracing::warn!(
                    platform = %registration.platform,
                    error = %err,
                    "failed to clear rate-limit state for pruned handle"
                );
            }
            state.metrics.inc_webhook(WebhookOutcome::Pruned);
            tracing::info!(
                platform = %registration.platform,
                class = %class.as_str(),
                "pruned handle after token-specific rejection"
            );
            Ok((
                StatusCode::OK,
                Json(HookResponse {
                    delivered: false,
                    pruned: true,
                }),
            ))
        }
        Ok(Err(PushError::PlatformNotConfigured(platform))) => {
            state.metrics.inc_webhook(WebhookOutcome::UpstreamFailure);
            touch_handle_best_effort(&state, &registration.handle, wall_now_ms).await;
            tracing::warn!(platform = %platform, "push backend not configured for platform");
            Err(ApiError::unavailable(format!(
                "push backend not configured for {platform}"
            )))
        }
        Ok(Err(err)) => {
            let is_backoff = matches!(
                err,
                PushError::Upstream {
                    class: UpstreamErrorClass::Backoff,
                    ..
                }
            );
            if is_backoff {
                state.metrics.inc_webhook(WebhookOutcome::ProviderBackoff);
                state.metrics.observe_provider_latency(
                    registration.platform,
                    ProviderCallOutcome::Backoff,
                    elapsed,
                );
            } else {
                state.metrics.inc_webhook(WebhookOutcome::UpstreamFailure);
                state.metrics.observe_provider_latency(
                    registration.platform,
                    ProviderCallOutcome::Error,
                    elapsed,
                );
            }
            touch_handle_best_effort(&state, &registration.handle, wall_now_ms).await;
            tracing::warn!(
                platform = %registration.platform,
                class = err.log_class(),
                "wake push delivery failed"
            );
            Err(ApiError::upstream("upstream push delivery failed"))
        }
    }
}

async fn touch_handle_best_effort(state: &RelayState, handle: &str, wall_now_ms: u64) {
    if let Err(err) = state.store.touch_last_active(handle, wall_now_ms).await {
        tracing::warn!(error = %err, "failed to update registration last_active_at_ms");
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
    text.chars().any(char::is_control)
}
