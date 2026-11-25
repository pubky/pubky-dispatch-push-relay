//! End-to-end HTTP API integration tests covering registration, every Wire Format §8.3
//! status code, handle-to-key binding isolation, durable replay protection, mixed-case
//! relay origins, provider timeouts, slow-client caps, tiered rate limits, idempotent
//! re-registration, inactivity expiry, and the official webhook test vector.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use pubky_dispatch_push_relay::client_ip::TrustedProxies;
use pubky_dispatch_push_relay::clock::{Clock as _, FixedClock};
use pubky_dispatch_push_relay::config::RelaySettings;
use pubky_dispatch_push_relay::crypto::{
    SIGNATURE_HEADER, SIGNING_LABEL, b64_decode_array, b64_encode, relay_origin, sign_webhook,
};
use pubky_dispatch_push_relay::http::{
    MAX_TIMESTAMP_SKEW_MS, RateLimitBackends, RelayState, metrics_router, router,
};
use pubky_dispatch_push_relay::metrics::{RegistrationOutcome, WebhookOutcome};
use pubky_dispatch_push_relay::push::noop::RecordingSender;
use pubky_dispatch_push_relay::push::{InvalidTokenClass, PushOutcome, UpstreamErrorClass};
use pubky_dispatch_push_relay::rate_limit::RateLimiter;
use pubky_dispatch_push_relay::replay::NONCE_TTL_MS;
use pubky_dispatch_push_relay::store::sqlite::{SqliteReplayStore, SqliteStore};
use pubky_dispatch_push_relay::store::{
    ApnsEnv, BoxFuture, Platform, RegisterOutcome, Registration, RegistrationLimits,
    RegistrationStore, StoreError,
};
use pubky_dispatch_push_relay::time::format_rfc3339;

const TEST_ORIGIN: &str = "https://push.example";
const BASE_TIME_MS: u64 = 1_767_225_960_000; // 2026-01-01T00:06:00.000Z

struct TestApp {
    state: RelayState,
    router: Router,
    store: Arc<SqliteStore>,
    replay: Arc<SqliteReplayStore>,
    sender: Arc<RecordingSender>,
    clock: Arc<FixedClock>,
    origin: String,
}

impl TestApp {
    async fn new(settings: RelaySettings) -> Self {
        let store = Arc::new(SqliteStore::in_memory().await.unwrap());
        let replay = Arc::new(
            SqliteReplayStore::with_limits(
                store.pool().clone(),
                NONCE_TTL_MS,
                settings.nonce_cache_max_entries,
                settings.max_nonces_per_handle,
            )
            .await
            .unwrap(),
        );
        let limiters = RelayState::in_memory_limiters(&settings);
        let sender = Arc::new(RecordingSender::new());
        let clock = Arc::new(FixedClock::new(BASE_TIME_MS));
        let origin = settings.relay_origin.clone();
        let state = RelayState::with_backends(
            store.clone(),
            sender.clone(),
            clock.clone(),
            replay.clone(),
            limiters,
            settings,
        );
        let router = router(state.clone());
        Self {
            state,
            router,
            store,
            replay,
            sender,
            clock,
            origin,
        }
    }

    async fn default_dispatch() -> Self {
        let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
        settings.rate_limit_per_minute = 3;
        settings.register_ip_rate_limit_per_minute = 100;
        settings.register_key_rate_limit_per_minute = 100;
        settings.register_rate_limit_per_minute = 200;
        Self::new(settings).await
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, headers, json)
    }

    async fn register(
        &self,
        platform: &str,
        device_token: &str,
        key: &SigningKey,
        apns_env: Option<&str>,
    ) -> (StatusCode, Value) {
        let (status, _, body) = self
            .register_from(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                None,
                platform,
                device_token,
                key,
                apns_env,
            )
            .await;
        (status, body)
    }

    async fn register_from(
        &self,
        peer_ip: IpAddr,
        forwarded_for: Option<&str>,
        platform: &str,
        device_token: &str,
        key: &SigningKey,
        apns_env: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let mut payload = json!({
            "platform": platform,
            "device_token": device_token,
            "push_key": b64_encode(&key.verifying_key().to_bytes()),
        });
        if let Some(env) = apns_env {
            payload["apns_env"] = json!(env);
        }
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/register")
            .header("content-type", "application/json");
        if let Some(xff) = forwarded_for {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut req = builder.body(Body::from(payload.to_string())).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer_ip, 44321)));
        self.send(req).await
    }

    async fn post_signed_hook(
        &self,
        signing_key: &SigningKey,
        handle: &str,
        ts_ms: u64,
        nonce: [u8; 16],
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let raw_body = format!(
            r#"{{"v":1,"handle":"{handle}","ts":"{}","nonce":"{}"}}"#,
            format_rfc3339(ts_ms),
            b64_encode(&nonce),
        );
        let sig = sign_webhook(
            signing_key,
            SIGNING_LABEL,
            &self.origin,
            raw_body.as_bytes(),
        );
        let req = Request::builder()
            .method("POST")
            .uri("/v1/hook")
            .header("content-type", "application/json")
            .header(SIGNATURE_HEADER, b64_encode(&sig))
            .body(Body::from(raw_body))
            .unwrap();
        self.send(req).await
    }
}

fn key_from_seed(seed_byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed_byte; 32])
}

fn apns_token(ch: char) -> String {
    std::iter::repeat_n(ch, 64).collect()
}

struct FailingStore;

impl RegistrationStore for FailingStore {
    fn register_or_get<'a>(
        &'a self,
        _: &'a Registration,
        _: RegistrationLimits,
        _: u64,
    ) -> BoxFuture<'a, Result<RegisterOutcome, StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn insert<'a>(
        &'a self,
        _: &'a Registration,
        _: Option<u64>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn get<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Option<Registration>, StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn get_active<'a>(
        &'a self,
        _: &'a str,
        _: u64,
        _: u64,
    ) -> BoxFuture<'a, Result<Option<Registration>, StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn touch_last_active<'a>(
        &'a self,
        _: &'a str,
        _: u64,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn delete<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn delete_if_not_newer_than<'a>(
        &'a self,
        _: &'a str,
        _: u64,
    ) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn prune_expired<'a>(&'a self, _: u64, _: u64) -> BoxFuture<'a, Result<usize, StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn ping<'a>(&'a self) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
}

#[tokio::test]
async fn health_endpoint_reports_ok_and_unhealthy() {
    let app = TestApp::default_dispatch().await;
    for path in ["/health", "/health/ready", "/health/live"] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = app.send(req).await;
        assert_eq!(status, StatusCode::OK, "expected 200 on {path}");
        assert_eq!(body["status"], "ok");
    }

    // Provider credential failure flips /health and /health/ready to 503 while /health/live stays 200.
    app.sender.set_ready(false);
    for path in ["/health", "/health/ready"] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = app.send(req).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "expected 503 on {path} when provider not ready"
        );
        assert_eq!(body["status"], "unhealthy");
    }
    let (live_status, _, _) = app
        .send(
            Request::builder()
                .method("GET")
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(live_status, StatusCode::OK);
    app.sender.set_ready(true);

    // Storage failure also flips /health and /health/ready to 503.
    let failing_state = RelayState::new(
        Arc::new(FailingStore),
        Arc::new(RecordingSender::new()),
        Arc::new(FixedClock::new(BASE_TIME_MS)),
        RelaySettings::new(TEST_ORIGIN).unwrap(),
    );
    for path in ["/health", "/health/ready"] {
        let resp = router(failing_state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[tokio::test]
async fn register_validates_inputs_is_idempotent_and_never_redirects_handles() {
    let app = TestApp::default_dispatch().await;
    let key1 = key_from_seed(1);
    let key2 = key_from_seed(2);
    let token = apns_token('a');

    // First registration gets fresh handle with default production APNs env.
    let (s1, b1) = app.register("apns", &token, &key1, None).await;
    assert_eq!(s1, StatusCode::OK);
    let h1 = b1["handle"].as_str().unwrap().to_owned();
    assert_eq!(h1.len(), 22);
    let r1 = app.store.get(&h1).await.unwrap().unwrap();
    assert_eq!(r1.apns_env, Some(ApnsEnv::Production));

    // Re-registering the exact same (platform, device_token, push_key, apns_env) is idempotent.
    let (s1_dup, b1_dup) = app
        .register("apns", &token, &key1, Some("production"))
        .await;
    assert_eq!(s1_dup, StatusCode::OK);
    assert_eq!(b1_dup["handle"].as_str().unwrap(), h1);

    // Re-registering same device_token under a different push_key issues a NEW handle without modifying h1.
    let (s2, b2) = app.register("apns", &token, &key2, Some("sandbox")).await;
    assert_eq!(s2, StatusCode::OK);
    let h2 = b2["handle"].as_str().unwrap().to_owned();
    assert_ne!(h1, h2);
    let r1_after = app.store.get(&h1).await.unwrap().unwrap();
    let r2 = app.store.get(&h2).await.unwrap().unwrap();
    assert_eq!(r1_after.push_key, key1.verifying_key().to_bytes());
    assert_eq!(r1_after.apns_env, Some(ApnsEnv::Production));
    assert_eq!(r2.push_key, key2.verifying_key().to_bytes());
    assert_eq!(r2.apns_env, Some(ApnsEnv::Sandbox));

    // Valid FCM registration.
    let (sf, bf) = app
        .register("fcm", "fcm_token:APA91bExample-123_456", &key1, None)
        .await;
    assert_eq!(sf, StatusCode::OK);
    let rf = app
        .store
        .get(bf["handle"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rf.platform, Platform::Fcm);
    assert_eq!(rf.apns_env, None);

    // Invalid inputs -> 400.
    let valid_key_b64 = b64_encode(&key1.verifying_key().to_bytes());
    let bad_payloads = [
        json!({"platform":"fcm","device_token":"tok123","push_key":valid_key_b64,"apns_env":"sandbox"}).to_string(),
        json!({"platform":"apns","device_token":"../../etc/passwd00000000000000000000","push_key":valid_key_b64}).to_string(),
        json!({"platform":"apns","device_token":"deadbeef","push_key":valid_key_b64}).to_string(),
        json!({"platform":"fcm","device_token":"bad token","push_key":valid_key_b64}).to_string(),
        json!({"platform":"webpush","device_token":"abc","push_key":valid_key_b64}).to_string(),
        json!({"platform":"fcm","device_token":"tok123","push_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}).to_string(),
        json!({"platform":"fcm","device_token":"tok123","push_key":"8P_______________________________________38"}).to_string(),
        json!({"platform":"fcm","device_token":"tok123","push_key":format!("{valid_key_b64}=")}).to_string(),
        json!({"platform":"fcm","device_token":"tok123","push_key":valid_key_b64,"pubky_id":"abc"}).to_string(),
        format!(r#"{{"platform":"fcm","platform":"fcm","device_token":"tok","push_key":"{valid_key_b64}"}}"#),
    ];

    for bad in bad_payloads {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/register")
            .header("content-type", "application/json")
            .body(Body::from(bad.clone()))
            .unwrap();
        let (status, _, _) = app.send(req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "expected 400 for {bad}");
    }

    // Oversized body -> 413.
    let huge = vec![b' '; 20 * 1024];
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .body(Body::from(huge))
        .unwrap();
    let (status, _, body) = app.send(req).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["code"], "too_large");
}

#[tokio::test]
async fn hook_enforces_all_six_wire_format_8_3_rules_and_ordering() {
    let app = TestApp::default_dispatch().await;
    let key = key_from_seed(11);
    let wrong_key = key_from_seed(22);

    let (status, reg) = app.register("apns", &apns_token('b'), &key, None).await;
    assert_eq!(status, StatusCode::OK);
    let handle = reg["handle"].as_str().unwrap().to_owned();

    // --- Rule 1: invalid body / v != 1 -> 400 ---
    let ts_ok = format_rfc3339(BASE_TIME_MS);
    let nonce_ok = b64_encode(&[1u8; 16]);
    let mut bom_body = vec![0xEF, 0xBB, 0xBF];
    bom_body.extend_from_slice(
        format!(r#"{{"v":1,"handle":"{handle}","ts":"{ts_ok}","nonce":"{nonce_ok}"}}"#).as_bytes(),
    );

    let bad_bodies: Vec<Vec<u8>> = vec![
        b"not json".to_vec(),
        bom_body,
        format!(r#"{{"v":2,"handle":"unknown","ts":"{ts_ok}","nonce":"{nonce_ok}"}}"#).into_bytes(),
        format!(r#"{{"v":1.0,"handle":"{handle}","ts":"{ts_ok}","nonce":"{nonce_ok}"}}"#)
            .into_bytes(),
        format!(r#"{{"v":1,"\u0076":1,"handle":"{handle}","ts":"{ts_ok}","nonce":"{nonce_ok}"}}"#)
            .into_bytes(),
        format!(r#"{{"v":1,"handle":123,"ts":"{ts_ok}","nonce":"{nonce_ok}"}}"#).into_bytes(),
        format!(
            r#"{{"v":1,"handle":"{handle}","ts":"2026-01-01T00:06:00+00:00","nonce":"{nonce_ok}"}}"#
        )
        .into_bytes(),
        format!(r#"{{"v":1,"handle":"{handle}","ts":"{ts_ok}","nonce":"short"}}"#).into_bytes(),
        format!(r#"{{"v":1,"handle":"{handle}","ts":"{ts_ok}","nonce":"{nonce_ok}"}} trailing"#)
            .into_bytes(),
    ];
    for raw in bad_bodies {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/hook")
            .body(Body::from(raw))
            .unwrap();
        let (s, _, b) = app.send(req).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "expected 400, got {b}");
        assert_eq!(b["code"], "bad_request");
    }

    // --- Rule 2: unknown handle -> 404 (checked before signature), including empty, NUL-byte, or control-char strings per Wire §1.7 / §8.3 ---
    for unknown_handle in [
        "unknownHandle123456789",
        "",
        r"\u0007bad",
        r"bad\u0000handle",
    ] {
        let unknown_body =
            format!(r#"{{"v":1,"handle":"{unknown_handle}","ts":"{ts_ok}","nonce":"{nonce_ok}"}}"#);
        let (s, _, b) = app
            .send(
                Request::builder()
                    .method("POST")
                    .uri("/v1/hook")
                    .body(Body::from(unknown_body))
                    .unwrap(),
            )
            .await;
        assert_eq!(
            s,
            StatusCode::NOT_FOUND,
            "unknown handle {unknown_handle:?} must return 404 per Wire §8.3, got {b}"
        );
        assert_eq!(b["code"], "not_found");
    }

    // --- Rule 3: signature verification -> 401 ---
    let valid_raw = format!(r#"{{"v":1,"handle":"{handle}","ts":"{ts_ok}","nonce":"{nonce_ok}"}}"#);
    let good_sig = b64_encode(&sign_webhook(
        &key,
        SIGNING_LABEL,
        TEST_ORIGIN,
        valid_raw.as_bytes(),
    ));

    // Missing header, duplicate header, wrong key, wrong origin, wrong label
    for req in [
        Request::builder()
            .method("POST")
            .uri("/v1/hook")
            .body(Body::from(valid_raw.clone()))
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/v1/hook")
            .header(SIGNATURE_HEADER, &good_sig)
            .header(SIGNATURE_HEADER, &good_sig)
            .body(Body::from(valid_raw.clone()))
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/v1/hook")
            .header(
                SIGNATURE_HEADER,
                b64_encode(&sign_webhook(
                    &wrong_key,
                    SIGNING_LABEL,
                    TEST_ORIGIN,
                    valid_raw.as_bytes(),
                )),
            )
            .body(Body::from(valid_raw.clone()))
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/v1/hook")
            .header(
                SIGNATURE_HEADER,
                b64_encode(&sign_webhook(
                    &key,
                    SIGNING_LABEL,
                    "https://other.example",
                    valid_raw.as_bytes(),
                )),
            )
            .body(Body::from(valid_raw.clone()))
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/v1/hook")
            .header(
                SIGNATURE_HEADER,
                b64_encode(&sign_webhook(
                    &key,
                    "pubky-dispatch/v2/push",
                    TEST_ORIGIN,
                    valid_raw.as_bytes(),
                )),
            )
            .body(Body::from(valid_raw.clone()))
            .unwrap(),
    ] {
        let (s, _, b) = app.send(req).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_eq!(b["code"], "bad_signature");
    }

    // Rejected signatures did not pollute nonce cache or rate limiter.
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [1u8; 16])
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["delivered"], true);

    // --- Rule 4: timestamp outside ±5 minutes -> 401 stale_timestamp ---
    let (s, _, b) = app
        .post_signed_hook(
            &key,
            &handle,
            BASE_TIME_MS - MAX_TIMESTAMP_SKEW_MS - 1,
            [2u8; 16],
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["code"], "stale_timestamp");

    let (s, _, b) = app
        .post_signed_hook(
            &key,
            &handle,
            BASE_TIME_MS + MAX_TIMESTAMP_SKEW_MS + 1,
            [3u8; 16],
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["code"], "stale_timestamp");

    // Exact ±5 minute boundaries succeed.
    let (s, _, _) = app
        .post_signed_hook(
            &key,
            &handle,
            BASE_TIME_MS - MAX_TIMESTAMP_SKEW_MS,
            [4u8; 16],
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    let (s, _, _) = app
        .post_signed_hook(
            &key,
            &handle,
            BASE_TIME_MS + MAX_TIMESTAMP_SKEW_MS,
            [5u8; 16],
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // --- Rule 5: nonce replay within 10 minutes -> 409 (before Rule 6 rate limit) ---
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [1u8; 16])
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(b["code"], "nonce_replay");

    // --- Rule 6: per-handle per-minute rate limit -> 429 ---
    let (s, headers, b) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [6u8; 16])
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b["code"], "rate_limited");
    assert!(b["retry_after"].as_u64().unwrap() >= 1);
    assert!(headers.get("retry-after").is_some());

    // Advance 60 seconds: rate limit resets, while nonce [1; 16] is still live.
    app.clock.advance_ms(60_000);
    let now = BASE_TIME_MS + 60_000;
    let (s, _, _) = app.post_signed_hook(&key, &handle, now, [1u8; 16]).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, _) = app.post_signed_hook(&key, &handle, now, [7u8; 16]).await;
    assert_eq!(s, StatusCode::OK);

    // Advance past 10 minutes: nonce [1; 16] expires and is accepted again.
    app.clock.set(BASE_TIME_MS + NONCE_TTL_MS);
    let (s, _, _) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS + NONCE_TTL_MS, [1u8; 16])
        .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn mixed_case_relay_origin_matches_service_signature_exactly() {
    let settings = RelaySettings::new("https://Push.Example").unwrap();
    let app = TestApp::new(settings).await;
    let key = key_from_seed(71);
    let (_, reg) = app.register("fcm", "fcm_mixed_case", &key, None).await;
    let handle = reg["handle"].as_str().unwrap();

    // Service signs using relay_origin("https://Push.Example/v1/hook") -> "https://Push.Example".
    let derived = relay_origin("https://Push.Example/v1/hook").unwrap();
    assert_eq!(derived, "https://Push.Example");

    let raw_body = format!(
        r#"{{"v":1,"handle":"{handle}","ts":"{}","nonce":"{}"}}"#,
        format_rfc3339(BASE_TIME_MS),
        b64_encode(&[71u8; 16]),
    );
    let sig_exact = sign_webhook(&key, SIGNING_LABEL, &derived, raw_body.as_bytes());
    let (s, _, _) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header(SIGNATURE_HEADER, b64_encode(&sig_exact))
                .body(Body::from(raw_body.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // Signature over lowercased origin fails against mixed-case configured origin.
    let raw_body2 = format!(
        r#"{{"v":1,"handle":"{handle}","ts":"{}","nonce":"{}"}}"#,
        format_rfc3339(BASE_TIME_MS),
        b64_encode(&[72u8; 16]),
    );
    let sig_lower = sign_webhook(
        &key,
        SIGNING_LABEL,
        "https://push.example",
        raw_body2.as_bytes(),
    );
    let (s, _, b) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header(SIGNATURE_HEADER, b64_encode(&sig_lower))
                .body(Body::from(raw_body2))
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["code"], "bad_signature");
}

#[tokio::test]
async fn replay_cache_refuses_new_webhooks_with_503_when_full_and_survives_sqlite_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("durable.sqlite");
    let path_str = db_path.to_str().unwrap().to_owned();

    let key = key_from_seed(73);
    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.nonce_cache_max_entries = 2;

    let handle = {
        let store = Arc::new(SqliteStore::open(&path_str).await.unwrap());
        let replay = Arc::new(
            SqliteReplayStore::new(store.pool().clone(), settings.nonce_cache_max_entries)
                .await
                .unwrap(),
        );
        let clock = Arc::new(FixedClock::new(BASE_TIME_MS));
        let sender = Arc::new(RecordingSender::new());
        let state = RelayState::with_backends(
            store,
            sender,
            clock.clone(),
            replay,
            RelayState::in_memory_limiters(&settings),
            settings.clone(),
        );
        let app = router(state);

        let reg_body = json!({
            "platform": "fcm",
            "device_token": "tok-restart",
            "push_key": b64_encode(&key.verifying_key().to_bytes()),
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/register")
                    .header("content-type", "application/json")
                    .body(Body::from(reg_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let handle = serde_json::from_slice::<Value>(&bytes).unwrap()["handle"]
            .as_str()
            .unwrap()
            .to_owned();

        // Fill replay store to capacity (2 live nonces).
        for n in [1u8, 2u8] {
            let body = format!(
                r#"{{"v":1,"handle":"{handle}","ts":"{}","nonce":"{}"}}"#,
                format_rfc3339(BASE_TIME_MS),
                b64_encode(&[n; 16]),
            );
            let sig = sign_webhook(&key, SIGNING_LABEL, TEST_ORIGIN, body.as_bytes());
            let r = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/hook")
                        .header(SIGNATURE_HEADER, b64_encode(&sig))
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK);
        }

        // Third fresh nonce MUST receive 503 (never evicting live nonces 1 or 2).
        let body3 = format!(
            r#"{{"v":1,"handle":"{handle}","ts":"{}","nonce":"{}"}}"#,
            format_rfc3339(BASE_TIME_MS),
            b64_encode(&[3u8; 16]),
        );
        let sig3 = sign_webhook(&key, SIGNING_LABEL, TEST_ORIGIN, body3.as_bytes());
        let r3 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/hook")
                    .header(SIGNATURE_HEADER, b64_encode(&sig3))
                    .body(Body::from(body3))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r3.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Live nonce 1 is still rejected with 409 even while full.
        let body1 = format!(
            r#"{{"v":1,"handle":"{handle}","ts":"{}","nonce":"{}"}}"#,
            format_rfc3339(BASE_TIME_MS),
            b64_encode(&[1u8; 16]),
        );
        let sig1 = sign_webhook(&key, SIGNING_LABEL, TEST_ORIGIN, body1.as_bytes());
        let r1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/hook")
                    .header(SIGNATURE_HEADER, b64_encode(&sig1))
                    .body(Body::from(body1))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::CONFLICT);
        handle
    };

    // Simulate relay restart by reopening the same SQLite database file cleanly.
    let store2 = Arc::new(SqliteStore::open(&path_str).await.unwrap());
    let replay2 = Arc::new(
        SqliteReplayStore::new(store2.pool().clone(), settings.nonce_cache_max_entries)
            .await
            .unwrap(),
    );
    let clock2 = Arc::new(FixedClock::new(BASE_TIME_MS + 60_000));
    let state2 = RelayState::with_backends(
        store2,
        Arc::new(RecordingSender::new()),
        clock2,
        replay2,
        RelayState::in_memory_limiters(&settings),
        settings,
    );
    let app2 = router(state2);

    // Replaying nonce 1 after restart MUST still return 409!
    let replay_body = format!(
        r#"{{"v":1,"handle":"{handle}","ts":"{}","nonce":"{}"}}"#,
        format_rfc3339(BASE_TIME_MS + 60_000),
        b64_encode(&[1u8; 16]),
    );
    let replay_sig = sign_webhook(&key, SIGNING_LABEL, TEST_ORIGIN, replay_body.as_bytes());
    let r = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header(SIGNATURE_HEADER, b64_encode(&replay_sig))
                .body(Body::from(replay_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn provider_timeout_returns_502_and_preserves_handle() {
    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.provider_timeout = Duration::from_millis(100);
    let app = TestApp::new(settings).await;
    let key = key_from_seed(75);
    let (_, reg) = app.register("fcm", "fcm-slow-tok", &key, None).await;
    let handle = reg["handle"].as_str().unwrap().to_owned();

    // Provider sleeps longer than provider_timeout: relay answers 502 promptly and keeps handle.
    app.sender
        .enqueue_delayed_outcome(Duration::from_millis(500), PushOutcome::Delivered);
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [75u8; 16])
        .await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_eq!(b["code"], "upstream_error");
    assert!(app.store.get(&handle).await.unwrap().is_some());

    // Subsequent webhook succeeds cleanly.
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [76u8; 16])
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["delivered"], true);
}

#[tokio::test]
async fn slow_client_body_hits_408_and_concurrency_cap_sheds_with_503() {
    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.request_timeout = Duration::from_millis(120);
    settings.max_concurrent_requests = 1;
    let app = TestApp::new(settings).await;

    // 1. Slowloris body stream that never finishes triggers 408 request_timeout.
    let pending_stream = futures_util_pending_body();
    let slow_req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .body(pending_stream)
        .unwrap();
    let (s, _, b) = app.send(slow_req).await;
    assert_eq!(s, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(b["code"], "request_timeout");

    // 2. With max_concurrent_requests = 1 held by an in-flight slow request, a second
    //    /v1/register immediately returns 503 while /health still returns 200.
    let r1 = app.router.clone();
    let in_flight = tokio::spawn(async move {
        r1.oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/register")
                .body(futures_util_pending_body())
                .unwrap(),
        )
        .await
        .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let (s_shed, b_shed) = app
        .register("fcm", "shed-tok", &key_from_seed(77), None)
        .await;
    assert_eq!(s_shed, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b_shed["code"], "unavailable");

    // Health check stays responsive outside the /v1/* concurrency semaphore.
    let (s_health, _, _) = app
        .send(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(s_health, StatusCode::OK);

    assert_eq!(
        in_flight.await.unwrap().status(),
        StatusCode::REQUEST_TIMEOUT
    );
}

fn futures_util_pending_body() -> Body {
    struct PendingStream;
    impl http_body::Body for PendingStream {
        type Data = axum::body::Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Pending
        }
    }
    Body::new(PendingStream)
}

#[tokio::test]
async fn register_enforces_per_ip_per_key_global_rate_limits_and_trusted_proxies() {
    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.register_ip_rate_limit_per_minute = 2;
    settings.register_key_rate_limit_per_minute = 3;
    settings.register_rate_limit_per_minute = 5;
    settings.trusted_proxies = TrustedProxies::parse_csv("10.0.0.0/8").unwrap();
    let app = TestApp::new(settings).await;

    let key_a = key_from_seed(81);
    let key_b = key_from_seed(82);
    let ip_attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let ip_victim = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    let ip_proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));

    // Untrusted attacker tries spoofing different X-Forwarded-For values: ignored!
    assert_eq!(
        app.register_from(ip_attacker, Some("1.1.1.1"), "fcm", "t1", &key_a, None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        app.register_from(ip_attacker, Some("2.2.2.2"), "fcm", "t2", &key_a, None)
            .await
            .0,
        StatusCode::OK
    );
    let (s, headers, b) = app
        .register_from(ip_attacker, Some("3.3.3.3"), "fcm", "t3", &key_a, None)
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b["code"], "rate_limited");
    assert!(headers.get("retry-after").is_some());

    // Another client IP is unaffected because per-IP blocked the attacker before global!
    // Requests via trusted proxy 10.0.0.5 parse X-Forwarded-For strictly right-to-left,
    // skipping trusted hops and ignoring malformed attacker entries to the left.
    assert_eq!(
        app.register_from(
            ip_proxy,
            Some("garbage, 203.0.113.1, 10.0.0.9"),
            "fcm",
            "t4",
            &key_a,
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    // key_a has now used 3/3 of its per-push-key rate limit across two IPs; 4th hits per-key 429!
    let (s, _, b) = app
        .register_from(ip_victim, None, "fcm", "t5", &key_a, None)
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b["code"], "rate_limited");

    // key_b from ip_victim still works (global has used 3/5 so far: t1, t2, t4).
    assert_eq!(
        app.register_from(ip_proxy, Some("203.0.113.2"), "fcm", "t6", &key_b, None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        app.register_from(ip_proxy, Some("203.0.113.3"), "fcm", "t7", &key_b, None)
            .await
            .0,
        StatusCode::OK
    );
    // Global limit (5/min) is now reached even for a fresh IP and fresh key!
    let (s, headers, b) = app
        .register_from(
            ip_proxy,
            Some("203.0.113.4"),
            "fcm",
            "t8",
            &key_from_seed(83),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b["code"], "rate_limited");
    assert!(headers.get("retry-after").is_some());
}

#[tokio::test]
async fn register_caps_handles_per_key_without_eviction_and_expires_idle_registrations() {
    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.max_handles_per_push_key = 2;
    settings.registration_ttl_ms = 600_000; // 10 minutes for test determinism
    settings.register_ip_rate_limit_per_minute = 100;
    settings.register_key_rate_limit_per_minute = 100;
    let app = TestApp::new(settings).await;
    let key = key_from_seed(85);

    let (s1, b1) = app.register("fcm", "dev-1", &key, None).await;
    assert_eq!(s1, StatusCode::OK);
    let h1 = b1["handle"].as_str().unwrap().to_owned();

    let (s2, b2) = app.register("fcm", "dev-2", &key, None).await;
    assert_eq!(s2, StatusCode::OK);
    let h2 = b2["handle"].as_str().unwrap().to_owned();

    // 3rd distinct device under the same push_key returns 429 quota_exceeded without evicting h1/h2.
    let (s3, b3) = app.register("fcm", "dev-3", &key, None).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b3["code"], "quota_exceeded");
    assert!(app.store.get(&h1).await.unwrap().is_some());
    assert!(app.store.get(&h2).await.unwrap().is_some());

    // Advance 5 minutes and send a valid webhook to h1 (refreshing h1's last_active_at_ms).
    app.clock.advance_ms(300_000);
    let t_mid = BASE_TIME_MS + 300_000;
    let (sh, _, _) = app.post_signed_hook(&key, &h1, t_mid, [85u8; 16]).await;
    assert_eq!(sh, StatusCode::OK);

    // Advance another 6 minutes (total 11 min since h2 was registered, 6 min since h1's webhook).
    // h2 is now expired -> 404 on webhook; h1 is still active -> 200 on webhook!
    app.clock.advance_ms(360_000);
    let t_late = t_mid + 360_000;
    let (sh2, _, _) = app.post_signed_hook(&key, &h2, t_late, [86u8; 16]).await;
    assert_eq!(sh2, StatusCode::NOT_FOUND);
    let (sh1, _, _) = app.post_signed_hook(&key, &h1, t_late, [87u8; 16]).await;
    assert_eq!(sh1, StatusCode::OK);

    // Because h2 expired, dev-3 can now register cleanly under the same push key!
    let (s3_ok, _) = app.register("fcm", "dev-3", &key, None).await;
    assert_eq!(s3_ok, StatusCode::OK);
    assert!(app.store.get(&h2).await.unwrap().is_none());
}

#[tokio::test]
async fn webhook_preserves_exact_raw_bytes_and_ignores_unknown_members() {
    let app = TestApp::default_dispatch().await;
    let key = key_from_seed(33);
    let (_, reg) = app.register("fcm", "fcm_token_xyz", &key, None).await;
    let handle = reg["handle"].as_str().unwrap();

    let raw_body = format!(
        "{{ \"extra\": true, \"nonce\": \"{}\", \"ts\": \"{}\", \"handle\": \"{handle}\", \"v\": 1 }}",
        b64_encode(&[9u8; 16]),
        format_rfc3339(BASE_TIME_MS),
    );
    let sig = sign_webhook(&key, SIGNING_LABEL, TEST_ORIGIN, raw_body.as_bytes());
    let (s, _, _) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header(SIGNATURE_HEADER, b64_encode(&sig))
                .body(Body::from(raw_body))
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn handle_to_key_binding_isolation() {
    let app = TestApp::default_dispatch().await;
    let key_a = key_from_seed(41);
    let key_b = key_from_seed(42);
    let shared_token = apns_token('c');

    let (_, reg_a) = app.register("apns", &shared_token, &key_a, None).await;
    let (_, reg_b) = app.register("apns", &shared_token, &key_b, None).await;
    let handle_a = reg_a["handle"].as_str().unwrap().to_owned();
    let handle_b = reg_b["handle"].as_str().unwrap().to_owned();

    let (s, _, _) = app
        .post_signed_hook(&key_b, &handle_a, BASE_TIME_MS, [10; 16])
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _, _) = app
        .post_signed_hook(&key_a, &handle_b, BASE_TIME_MS, [11; 16])
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _, _) = app
        .post_signed_hook(&key_a, &handle_a, BASE_TIME_MS, [10; 16])
        .await;
    assert_eq!(s, StatusCode::OK);

    let (s, _, _) = app
        .post_signed_hook(&key_b, &handle_b, BASE_TIME_MS, [11; 16])
        .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn verifies_official_dispatch_webhook_vector_end_to_end() {
    const VECTOR_BODY: &str = r#"{"v":1,"handle":"dH9r2POzhkcCmW_2TUIRFQ","ts":"2026-01-01T00:06:00.000Z","nonce":"dgOrMASIWFmulwUPwzWlpQ"}"#;
    const VECTOR_SIG: &str =
        "1v9TMYsaXAjcvHnXWQYYOkVazExu5r1f6Vvj_mx0GKpjz0tV5eq_VGPzzgrBhqxdaOVC5P-4ZGAq2Y0D4fHuAg";
    const VECTOR_KEY: &str = "A_K47RLrjHBBJq2U9QpYGAjLCAIXJMic1XscmVFqPBc";
    const VECTOR_ORIGIN: &str = "https://push.example";

    let settings = RelaySettings::new(VECTOR_ORIGIN).unwrap();
    let app = TestApp::new(settings).await;

    app.store
        .insert(
            &Registration {
                handle: "dH9r2POzhkcCmW_2TUIRFQ".to_owned(),
                platform: Platform::Apns,
                device_token: apns_token('f'),
                push_key: b64_decode_array::<32>(VECTOR_KEY).unwrap(),
                apns_env: Some(ApnsEnv::Production),
                created_at_ms: BASE_TIME_MS,
                last_active_at_ms: BASE_TIME_MS,
            },
            None,
        )
        .await
        .unwrap();

    let (status, _, body) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header("content-type", "application/json")
                .header(SIGNATURE_HEADER, VECTOR_SIG)
                .body(Body::from(VECTOR_BODY))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    let (status, _, body) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header("content-type", "application/json")
                .header(SIGNATURE_HEADER, VECTOR_SIG)
                .body(Body::from(VECTOR_BODY))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "nonce_replay");
}

#[tokio::test]
async fn upstream_error_returns_502_and_invalid_token_prunes_handle() {
    let app = TestApp::default_dispatch().await;
    let key = key_from_seed(55);
    let (_, reg) = app.register("fcm", "fcm_live_token", &key, None).await;
    let handle = reg["handle"].as_str().unwrap().to_owned();

    app.sender
        .enqueue_upstream_error(UpstreamErrorClass::Http5xx);
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [20; 16])
        .await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_eq!(b["code"], "upstream_error");
    assert!(app.store.get(&handle).await.unwrap().is_some());

    app.sender.enqueue_outcome(PushOutcome::InvalidToken {
        class: InvalidTokenClass::FcmUnregistered,
        invalidated_at_ms: None,
    });
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [21; 16])
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["delivered"], false);
    assert_eq!(b["pruned"], true);
    assert!(app.store.get(&handle).await.unwrap().is_none());

    let before = app.sender.recorded().len();
    let (s, _, _) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [22; 16])
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(app.sender.recorded().len(), before);
}

#[tokio::test]
async fn register_enforces_max_registrations_cap_and_recovers_after_prune() {
    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.max_registrations = 2;
    settings.register_ip_rate_limit_per_minute = 100;
    settings.register_key_rate_limit_per_minute = 100;
    let app = TestApp::new(settings).await;
    let key = key_from_seed(62);

    let (s1, b1) = app.register("fcm", "cap_token_1", &key, None).await;
    assert_eq!(s1, StatusCode::OK);
    let handle1 = b1["handle"].as_str().unwrap().to_owned();

    let (s2, b2) = app.register("fcm", "cap_token_2", &key, None).await;
    assert_eq!(s2, StatusCode::OK);
    let handle2 = b2["handle"].as_str().unwrap().to_owned();

    let (s3, b3) = app.register("fcm", "cap_token_3", &key, None).await;
    assert_eq!(s3, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b3["code"], "unavailable");

    app.sender.enqueue_outcome(PushOutcome::InvalidToken {
        class: InvalidTokenClass::FcmUnregistered,
        invalidated_at_ms: None,
    });
    let (sh, _, bh) = app
        .post_signed_hook(&key, &handle1, BASE_TIME_MS, [90; 16])
        .await;
    assert_eq!(sh, StatusCode::OK);
    assert_eq!(bh["pruned"], true);

    let (s4, b4) = app.register("fcm", "cap_token_3", &key, None).await;
    assert_eq!(s4, StatusCode::OK);
    let handle3 = b4["handle"].as_str().unwrap().to_owned();

    assert_eq!(
        app.replay.row_count().await.unwrap(),
        1,
        "expected recorded nonce row in SQLite before prune_caches"
    );

    // Advance clock past both nonce TTL (10 min) and registration inactivity TTL, then sweep:
    // verify expired nonces and expired registrations are actually removed from storage.
    let after_ttl = BASE_TIME_MS + 91 * 24 * 60 * 60 * 1_000;
    app.clock.set(after_ttl);
    app.state.prune_caches().await;
    assert!(
        app.store.get(&handle2).await.unwrap().is_none(),
        "prune_caches must delete expired handle2"
    );
    assert!(
        app.store.get(&handle3).await.unwrap().is_none(),
        "prune_caches must delete expired handle3"
    );
    assert_eq!(
        app.replay.row_count().await.unwrap(),
        0,
        "prune_caches must actually delete expired nonce rows from webhook_nonces"
    );
    assert!(
        app.state
            .replay_store()
            .check_and_record(&handle1, [90; 16], after_ttl, app.clock.monotonic_ms())
            .await
            .unwrap(),
        "expired nonce [90; 16] can be re-recorded after prune"
    );
}

#[tokio::test]
async fn metrics_endpoint_tracks_all_outcomes_and_omits_sensitive_labels() {
    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.rate_limit_per_minute = 2;
    let app = TestApp::new(settings).await;
    let key = key_from_seed(95);
    let secret_token = "secret-device-token-never-in-metrics";
    let push_key_b64 = b64_encode(key.verifying_key().as_bytes());

    // Registrations: created, existing, bad_request.
    let (s1, reg) = app.register("fcm", secret_token, &key, None).await;
    assert_eq!(s1, StatusCode::OK);
    let handle = reg["handle"].as_str().unwrap().to_owned();
    let (s2, _) = app.register("fcm", secret_token, &key, None).await;
    assert_eq!(s2, StatusCode::OK);
    let (s_bad, _) = app
        .register("fcm", "bad token with space", &key, None)
        .await;
    assert_eq!(s_bad, StatusCode::BAD_REQUEST);

    // Webhook Rule 1 (bad_request)
    let (s, _, _) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .body(Body::from("not-json"))
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Webhook Rule 2 (unknown_handle)
    let (s, _, _) = app
        .post_signed_hook(&key, "missing-handle", BASE_TIME_MS, [1; 16])
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Webhook Rule 3 (bad_signature)
    let (s, _, _) = app
        .post_signed_hook(&key_from_seed(96), &handle, BASE_TIME_MS, [2; 16])
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Webhook Rule 4 (stale_timestamp)
    let (s, _, _) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS - 10 * 60 * 1_000, [3; 16])
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Webhook Delivered
    let (s, _, _) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [4; 16])
        .await;
    assert_eq!(s, StatusCode::OK);

    // Webhook Rule 5 (nonce_replay)
    let (s, _, _) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [4; 16])
        .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Webhook UpstreamFailure (502)
    app.sender
        .enqueue_upstream_error(UpstreamErrorClass::Http5xx);
    let (s, _, _) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [5; 16])
        .await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);

    // Webhook Rule 6 (rate_limited — 2/min limit now hit)
    let (s, _, _) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [6; 16])
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);

    // Advance 61s, then trigger Pruned
    let t_next = BASE_TIME_MS + 61_000;
    app.clock.set(t_next);
    app.sender.enqueue_outcome(PushOutcome::InvalidToken {
        class: InvalidTokenClass::FcmUnregistered,
        invalidated_at_ms: None,
    });
    let (s, _, _) = app.post_signed_hook(&key, &handle, t_next, [7; 16]).await;
    assert_eq!(s, StatusCode::OK);

    // Scrape GET /metrics via metrics_router.
    let resp = metrics_router(app.state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(content_type.starts_with("text/plain; version=0.0.4"));
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    // Assert every counter and latency observation.
    assert_eq!(
        app.state
            .metrics()
            .registration_count(RegistrationOutcome::Created),
        1
    );
    assert_eq!(
        app.state
            .metrics()
            .registration_count(RegistrationOutcome::Existing),
        1
    );
    assert_eq!(
        app.state
            .metrics()
            .registration_count(RegistrationOutcome::BadRequest),
        1
    );
    for (outcome, expected) in [
        (WebhookOutcome::BadRequest, 1),
        (WebhookOutcome::UnknownHandle, 1),
        (WebhookOutcome::BadSignature, 1),
        (WebhookOutcome::StaleTimestamp, 1),
        (WebhookOutcome::NonceReplay, 1),
        (WebhookOutcome::RateLimited, 1),
        (WebhookOutcome::Delivered, 1),
        (WebhookOutcome::UpstreamFailure, 1),
        (WebhookOutcome::Pruned, 1),
    ] {
        assert_eq!(
            app.state.metrics().webhook_count(outcome),
            expected,
            "mismatch for webhook metric {outcome:?}"
        );
        assert!(body.contains(&format!(
            "push_relay_webhooks_total{{outcome=\"{}\"}} {expected}",
            outcome.as_str()
        )));
    }
    assert!(body.contains(
        "push_relay_provider_latency_seconds_count{platform=\"fcm\",outcome=\"delivered\"} 1"
    ));
    assert!(body.contains(
        "push_relay_provider_latency_seconds_count{platform=\"fcm\",outcome=\"error\"} 1"
    ));
    assert!(body.contains(
        "push_relay_provider_latency_seconds_count{platform=\"fcm\",outcome=\"pruned\"} 1"
    ));

    // Sensitive identifiers MUST NEVER appear anywhere in metrics exposition.
    assert!(!body.contains(&handle));
    assert!(!body.contains(secret_token));
    assert!(!body.contains(&push_key_b64));
    assert!(!body.contains("127.0.0.1"));
}

#[tokio::test]
async fn rate_limited_hooks_preserve_409_order_do_not_fill_replay_and_isolate_per_handle() {
    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.rate_limit_per_minute = 2;
    settings.max_nonces_per_handle = 3;
    settings.nonce_cache_max_entries = 10;
    let app = TestApp::new(settings).await;

    let key_noisy = key_from_seed(101);
    let key_victim = key_from_seed(102);
    let (_, reg_noisy) = app.register("fcm", "noisy-tok", &key_noisy, None).await;
    let (_, reg_victim) = app.register("fcm", "victim-tok", &key_victim, None).await;
    let h_noisy = reg_noisy["handle"].as_str().unwrap().to_owned();
    let h_victim = reg_victim["handle"].as_str().unwrap().to_owned();

    // Consume h_noisy's 2/min rate limit.
    assert_eq!(
        app.post_signed_hook(&key_noisy, &h_noisy, BASE_TIME_MS, [1; 16])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        app.post_signed_hook(&key_noisy, &h_noisy, BASE_TIME_MS, [2; 16])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(app.replay.row_count().await.unwrap(), 2);

    // 1. Wire §8.3 order preserved: replaying a seen nonce while rate-limited returns 409 (not 429).
    let (s, _, b) = app
        .post_signed_hook(&key_noisy, &h_noisy, BASE_TIME_MS, [1; 16])
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(b["code"], "nonce_replay");

    // 2. A fresh signed webhook rejected by Rule 6 (429) STILL records its nonce (Rule 5 before
    //    Rule 6), so it can never be replayed after the minute resets.
    let (s, headers, b) = app
        .post_signed_hook(&key_noisy, &h_noisy, BASE_TIME_MS, [3; 16])
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b["code"], "rate_limited");
    assert!(headers.get("retry-after").is_some());
    assert_eq!(app.replay.row_count().await.unwrap(), 3);

    // 3. Further fresh nonces from h_noisy hit the per-handle active-nonce cap (3) and return
    //    429 WITHOUT growing the shared replay table beyond max_nonces_per_handle!
    for i in 10u8..30u8 {
        let (s, _, b) = app
            .post_signed_hook(&key_noisy, &h_noisy, BASE_TIME_MS, [i; 16])
            .await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(b["code"], "rate_limited");
    }
    assert_eq!(
        app.replay.row_count().await.unwrap(),
        3,
        "per-handle nonce cap must bound rows inserted by a noisy handle"
    );

    // 4. Unrelated handle is completely isolated from h_noisy's per-handle replay cap.
    let (s_victim, _, b_victim) = app
        .post_signed_hook(&key_victim, &h_victim, BASE_TIME_MS, [5; 16])
        .await;
    assert_eq!(s_victim, StatusCode::OK);
    assert_eq!(b_victim["delivered"], true);
    let deliveries_before_replay = app.sender.recorded().len();

    // 5. Advance 61s so h_noisy's 1-minute rate window resets (BASE_TIME_MS is still within the
    //    ±5 minute timestamp window) and replay the EXACT rate-rejected signed request [3; 16]:
    //    MUST return 409 nonce_replay and MUST NOT deliver!
    let t_next = BASE_TIME_MS + 61_000;
    app.clock.set(t_next);
    let (s_replay, _, b_replay) = app
        .post_signed_hook(&key_noisy, &h_noisy, BASE_TIME_MS, [3; 16])
        .await;
    assert_eq!(s_replay, StatusCode::CONFLICT);
    assert_eq!(b_replay["code"], "nonce_replay");
    assert_eq!(
        app.sender.recorded().len(),
        deliveries_before_replay,
        "rate-rejected webhook must never be delivered on replay after the rate window resets"
    );
}

#[tokio::test]
async fn register_global_limit_blocks_before_creating_ip_or_key_buckets() {
    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.register_rate_limit_per_minute = 2;
    settings.register_ip_rate_limit_per_minute = 10;
    settings.register_key_rate_limit_per_minute = 10;

    let store = Arc::new(SqliteStore::in_memory().await.unwrap());
    let replay = Arc::new(
        SqliteReplayStore::with_limits(
            store.pool().clone(),
            NONCE_TTL_MS,
            settings.nonce_cache_max_entries,
            settings.max_nonces_per_handle,
        )
        .await
        .unwrap(),
    );
    let ip_limiter = Arc::new(RateLimiter::new(
        settings.register_ip_rate_limit_per_minute,
        100,
    ));
    let key_limiter = Arc::new(RateLimiter::new(
        settings.register_key_rate_limit_per_minute,
        100,
    ));
    let global_limiter = Arc::new(RateLimiter::new(settings.register_rate_limit_per_minute, 1));
    let limiters = RateLimitBackends {
        hook_per_handle: Arc::new(RateLimiter::new(settings.rate_limit_per_minute, 100)),
        register_per_ip: ip_limiter.clone(),
        register_per_key: key_limiter.clone(),
        register_global: global_limiter,
    };

    let state = RelayState::with_backends(
        store,
        Arc::new(RecordingSender::new()),
        Arc::new(FixedClock::new(BASE_TIME_MS)),
        replay,
        limiters,
        settings,
    );
    let app = router(state);

    let send_reg = |ip_last: u8, seed: u8, token: &str| {
        let app = app.clone();
        let token = token.to_owned();
        async move {
            let key = key_from_seed(seed);
            let payload = json!({
                "platform": "fcm",
                "device_token": token,
                "push_key": b64_encode(&key.verifying_key().to_bytes()),
            });
            let mut req = Request::builder()
                .method("POST")
                .uri("/v1/register")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, ip_last)),
                44321,
            )));
            app.oneshot(req).await.unwrap().status()
        }
    };

    // First 2 registrations succeed and saturate the global registration cap.
    assert_eq!(send_reg(1, 111, "tok-1").await, StatusCode::OK);
    assert_eq!(send_reg(2, 112, "tok-2").await, StatusCode::OK);
    let ip_buckets_at_cap = ip_limiter.tracked_handles();
    let key_buckets_at_cap = key_limiter.tracked_handles();
    assert_eq!(ip_buckets_at_cap, 2);
    assert_eq!(key_buckets_at_cap, 2);

    // Additional requests from fresh IPs and fresh push keys MUST fail at global check BEFORE
    // inserting any per-IP or per-key buckets.
    for i in 3u8..10u8 {
        assert_eq!(
            send_reg(i, 120 + i, &format!("tok-{i}")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert_eq!(
        ip_limiter.tracked_handles(),
        ip_buckets_at_cap,
        "global limit must short-circuit before creating per-IP buckets"
    );
    assert_eq!(
        key_limiter.tracked_handles(),
        key_buckets_at_cap,
        "global limit must short-circuit before creating per-key buckets"
    );
}

#[tokio::test]
async fn stale_apns_410_timestamp_preserves_reregistered_handle() {
    let app = TestApp::default_dispatch().await;
    let key = key_from_seed(131);
    let token = apns_token('d');

    // Register at T0.
    let (s, reg) = app.register("apns", &token, &key, None).await;
    assert_eq!(s, StatusCode::OK);
    let handle = reg["handle"].as_str().unwrap().to_owned();

    // Re-register the same device at T0 + 5_000ms (updating last_active_at_ms to T0 + 5_000).
    let t_renew = BASE_TIME_MS + 5_000;
    app.clock.set(t_renew);
    let (s2, reg2) = app.register("apns", &token, &key, None).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(reg2["handle"].as_str().unwrap(), handle);

    // Delayed APNs 410 Unregistered with timestamp older than last_active_at_ms MUST NOT delete.
    app.sender.enqueue_outcome(PushOutcome::InvalidToken {
        class: InvalidTokenClass::ApnsUnregistered,
        invalidated_at_ms: Some(BASE_TIME_MS + 1_000),
    });
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, t_renew, [131; 16])
        .await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_eq!(b["code"], "upstream_error");
    assert!(
        app.store.get(&handle).await.unwrap().is_some(),
        "stale APNs 410 timestamp must preserve re-registered handle"
    );

    // APNs 410 Unregistered with timestamp >= last_active_at_ms prunes cleanly.
    app.sender.enqueue_outcome(PushOutcome::InvalidToken {
        class: InvalidTokenClass::ApnsUnregistered,
        invalidated_at_ms: Some(t_renew),
    });
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, t_renew, [132; 16])
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["delivered"], false);
    assert_eq!(b["pruned"], true);
    assert!(app.store.get(&handle).await.unwrap().is_none());
}

#[test]
fn cli_binary_help_hides_secret_env_values_when_set() {
    let secret_db = "postgres://relay:SUPER_SECRET_DB_PASS@db.internal/relay";
    let secret_apns_path = "/run/secrets/SUPER_SECRET_APNS_KEY.p8";
    let secret_fcm_path = "/run/secrets/SUPER_SECRET_FCM_SA.json";
    let secret_apns_pem = "SUPER_SECRET_INLINE_APNS_PEM_MATERIAL";
    let secret_fcm_json = "SUPER_SECRET_INLINE_FCM_JSON_MATERIAL";

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pubky-dispatch-push-relay"))
        .arg("--help")
        .env("DATABASE_URL", secret_db)
        .env("APNS_KEY_PATH", secret_apns_path)
        .env("FCM_SERVICE_ACCOUNT_PATH", secret_fcm_path)
        .env("APNS_KEY_PEM", secret_apns_pem)
        .env("FCM_SERVICE_ACCOUNT_JSON", secret_fcm_json)
        .output()
        .expect("run binary --help");
    assert!(output.status.success(), "--help must exit 0");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [
        secret_db,
        secret_apns_path,
        secret_fcm_path,
        secret_apns_pem,
        secret_fcm_json,
    ] {
        assert!(
            !combined.contains(secret),
            "binary --help leaked env secret {secret:?}"
        );
    }
}
