//! End-to-end HTTP API integration tests covering registration, every Wire Format §8.3
//! status code, handle-to-key binding isolation, and the official webhook test vector.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use pubky_dispatch_push_relay::clock::FixedClock;
use pubky_dispatch_push_relay::config::{ProtocolConfig, RelaySettings};
use pubky_dispatch_push_relay::crypto::{
    SIGNATURE_HEADER, SIGNING_LABEL, b64_decode_array, b64_encode, sign_webhook,
};
use pubky_dispatch_push_relay::http::{MAX_TIMESTAMP_SKEW_MS, RelayState, router};
use pubky_dispatch_push_relay::push::PushOutcome;
use pubky_dispatch_push_relay::push::noop::RecordingSender;
use pubky_dispatch_push_relay::replay::NONCE_TTL_MS;
use pubky_dispatch_push_relay::store::sqlite::SqliteStore;
use pubky_dispatch_push_relay::store::{
    ApnsEnv, BoxFuture, Platform, Registration, RegistrationStore, StoreError,
};
use pubky_dispatch_push_relay::time::format_rfc3339;

const TEST_ORIGIN: &str = "https://push.example";
const BASE_TIME_MS: u64 = 1_767_225_960_000; // 2026-01-01T00:06:00.000Z

struct TestApp {
    router: Router,
    store: Arc<SqliteStore>,
    sender: Arc<RecordingSender>,
    clock: Arc<FixedClock>,
}

impl TestApp {
    async fn new(settings: RelaySettings) -> Self {
        let store = Arc::new(SqliteStore::in_memory().await.unwrap());
        let sender = Arc::new(RecordingSender::new());
        let clock = Arc::new(FixedClock::new(BASE_TIME_MS));
        let state = RelayState::new(store.clone(), sender.clone(), clock.clone(), settings);
        let router = router(state);
        Self {
            router,
            store,
            sender,
            clock,
        }
    }

    async fn default_dispatch() -> Self {
        let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
        settings.rate_limit_per_minute = 3;
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
        let mut payload = json!({
            "platform": platform,
            "device_token": device_token,
            "push_key": b64_encode(&key.verifying_key().to_bytes()),
        });
        if let Some(env) = apns_env {
            payload["apns_env"] = json!(env);
        }
        let req = Request::builder()
            .method("POST")
            .uri("/v1/register")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();
        let (status, _, body) = self.send(req).await;
        (status, body)
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
        let sig = sign_webhook(signing_key, SIGNING_LABEL, TEST_ORIGIN, raw_body.as_bytes());
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
    fn insert<'a>(&'a self, _: &'a Registration) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn get<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Option<Registration>, StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn delete<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
    fn ping<'a>(&'a self) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Err(StoreError::Backend("offline".to_owned())) })
    }
}

#[tokio::test]
async fn health_endpoint_reports_ok_and_unhealthy() {
    let app = TestApp::default_dispatch().await;
    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = app.send(req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    // Unhealthy storage returns 503.
    let failing_state = RelayState::new(
        Arc::new(FailingStore),
        Arc::new(RecordingSender::new()),
        Arc::new(FixedClock::new(BASE_TIME_MS)),
        RelaySettings::new(TEST_ORIGIN).unwrap(),
    );
    let resp = router(failing_state)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn register_validates_inputs_and_never_redirects_handles() {
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

    // Re-registering the exact same device_token issues a NEW random handle without modifying h1.
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
        // apns_env on fcm
        json!({"platform":"fcm","device_token":"tok123","push_key":valid_key_b64,"apns_env":"sandbox"}).to_string(),
        // non-hex APNs token / path injection attempt
        json!({"platform":"apns","device_token":"../../etc/passwd00000000000000000000","push_key":valid_key_b64}).to_string(),
        // short APNs token
        json!({"platform":"apns","device_token":"deadbeef","push_key":valid_key_b64}).to_string(),
        // whitespace in FCM token
        json!({"platform":"fcm","device_token":"bad token","push_key":valid_key_b64}).to_string(),
        // unknown platform
        json!({"platform":"webpush","device_token":"abc","push_key":valid_key_b64}).to_string(),
        // small-order Ed25519 identity point as push_key
        json!({"platform":"fcm","device_token":"tok123","push_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}).to_string(),
        // non-canonical y+p public key
        json!({"platform":"fcm","device_token":"tok123","push_key":"8P_______________________________________38"}).to_string(),
        // padded base64 push_key
        json!({"platform":"fcm","device_token":"tok123","push_key":format!("{valid_key_b64}=")}).to_string(),
        // unknown field (e.g., pubky_id must not be accepted)
        json!({"platform":"fcm","device_token":"tok123","push_key":valid_key_b64,"pubky_id":"abc"}).to_string(),
        // duplicate JSON key
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

    // --- Rule 1: invalid body / v != 1 -> 400 (even if handle is unknown and sig is missing) ---
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
        format!(r#"{{"v":1,"handle":"","ts":"{ts_ok}","nonce":"{nonce_ok}"}}"#).into_bytes(),
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

    // --- Rule 2: unknown handle -> 404 (checked before signature) ---
    let unknown_body = format!(
        r#"{{"v":1,"handle":"unknownHandle123456789","ts":"{ts_ok}","nonce":"{nonce_ok}"}}"#
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/hook")
        .body(Body::from(unknown_body))
        .unwrap();
    let (s, _, b) = app.send(req).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(b["code"], "not_found");

    // --- Rule 3: bad signature / missing header / wrong origin / wrong label -> 401 ---
    let valid_raw = format!(r#"{{"v":1,"handle":"{handle}","ts":"{ts_ok}","nonce":"{nonce_ok}"}}"#);

    // Missing header
    let (s, _, b) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .body(Body::from(valid_raw.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["code"], "bad_signature");

    // Duplicate signature header
    let good_sig = b64_encode(&sign_webhook(
        &key,
        SIGNING_LABEL,
        TEST_ORIGIN,
        valid_raw.as_bytes(),
    ));
    let (s, _, b) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header(SIGNATURE_HEADER, &good_sig)
                .header(SIGNATURE_HEADER, &good_sig)
                .body(Body::from(valid_raw.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["code"], "bad_signature");

    // Wrong key
    let wrong_key_sig = b64_encode(&sign_webhook(
        &wrong_key,
        SIGNING_LABEL,
        TEST_ORIGIN,
        valid_raw.as_bytes(),
    ));
    let (s, _, b) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header(SIGNATURE_HEADER, wrong_key_sig)
                .body(Body::from(valid_raw.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["code"], "bad_signature");

    // Wrong origin
    let wrong_origin_sig = b64_encode(&sign_webhook(
        &key,
        SIGNING_LABEL,
        "https://other.example",
        valid_raw.as_bytes(),
    ));
    let (s, _, b) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header(SIGNATURE_HEADER, wrong_origin_sig)
                .body(Body::from(valid_raw.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["code"], "bad_signature");

    // Wrong signing label (old Switch label against Dispatch relay)
    let wrong_label_sig = b64_encode(&sign_webhook(
        &key,
        "pubky-switch/v1/push",
        TEST_ORIGIN,
        valid_raw.as_bytes(),
    ));
    let (s, _, b) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header(SIGNATURE_HEADER, wrong_label_sig)
                .body(Body::from(valid_raw.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(b["code"], "bad_signature");

    // None of the rejected signatures should have polluted the nonce cache or rate limiter:
    // the exact same nonce_ok with a valid signature MUST succeed now!
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [1u8; 16])
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["delivered"], true);
    assert_eq!(app.sender.recorded().len(), 1);

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

    // --- Rule 5: nonce replay within 10 minutes -> 409 (checked before Rule 6 rate limit) ---
    // Note: handle is now at 3/3 requests for this minute, so a replayed nonce MUST still
    // produce 409 (Rule 5) rather than 429 (Rule 6)!
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

    // Advance 60 seconds: rate limit resets, while nonce [1; 16] is still inside 10-min TTL.
    app.clock.advance_ms(60_000);
    let now = BASE_TIME_MS + 60_000;
    let (s, _, _) = app.post_signed_hook(&key, &handle, now, [1u8; 16]).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, _) = app.post_signed_hook(&key, &handle, now, [7u8; 16]).await;
    assert_eq!(s, StatusCode::OK);

    // Advance past 10 minutes from BASE_TIME_MS: nonce [1; 16] expires and is accepted again.
    app.clock.set(BASE_TIME_MS + NONCE_TTL_MS);
    let (s, _, _) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS + NONCE_TTL_MS, [1u8; 16])
        .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn webhook_preserves_exact_raw_bytes_and_ignores_unknown_members() {
    let app = TestApp::default_dispatch().await;
    let key = key_from_seed(33);
    let (_, reg) = app.register("fcm", "fcm_token_xyz", &key, None).await;
    let handle = reg["handle"].as_str().unwrap();

    // Pretty-printed JSON with extra unknown member; signature covers exact bytes.
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

    // Cross-key attempts fail with 401.
    let (s, _, _) = app
        .post_signed_hook(&key_b, &handle_a, BASE_TIME_MS, [10; 16])
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _, _) = app
        .post_signed_hook(&key_a, &handle_b, BASE_TIME_MS, [11; 16])
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Matching keys succeed independently.
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
async fn verifies_official_switch_webhook_vector_end_to_end() {
    // Official webhook vector from `spec/vectors/http.json` (`webhook`).
    const VECTOR_BODY: &str = r#"{"v":1,"handle":"iUsOsTv5mB7OMLMdQZi8QA","ts":"2026-01-01T00:06:00.000Z","nonce":"vX9AwGixjY0MiVA86rs3Gw"}"#;
    const VECTOR_SIG: &str =
        "yf38KwoGUEG-DWIt_eTjVx_E7dca-MzSOGhiQV-yoO4xITjyfNErlKcU2xJyoZo4lRy-K3i_dijEWpU76EBdCQ";
    const VECTOR_KEY: &str = "L6IOM-v3HiTYgBIMYK5KXA6oVE6lcRcBsruRMkqbGjI";
    const VECTOR_ORIGIN: &str = "https://push.example";

    let mut settings = RelaySettings::new(VECTOR_ORIGIN).unwrap();
    settings.protocol = ProtocolConfig::custom("Switch-Signature", "pubky-switch/v1/push");
    let app = TestApp::new(settings).await;

    // Bind the exact vector handle to the exact vector public key.
    app.store
        .insert(&Registration {
            handle: "iUsOsTv5mB7OMLMdQZi8QA".to_owned(),
            platform: Platform::Apns,
            device_token: apns_token('f'),
            push_key: b64_decode_array::<32>(VECTOR_KEY).unwrap(),
            apns_env: Some(ApnsEnv::Production),
            created_at_ms: BASE_TIME_MS,
        })
        .await
        .unwrap();

    let (status, _, body) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header("content-type", "application/json")
                .header("Switch-Signature", VECTOR_SIG)
                .body(Body::from(VECTOR_BODY))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["delivered"], true);
    assert_eq!(app.sender.recorded().len(), 1);

    // Replaying the exact official vector is rejected with 409.
    let (status, _, body) = app
        .send(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header("content-type", "application/json")
                .header("Switch-Signature", VECTOR_SIG)
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

    // Transient upstream failure returns 502 and preserves the handle.
    app.sender.enqueue_upstream_error("temporary 503");
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [20; 16])
        .await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
    assert_eq!(b["code"], "upstream_error");
    assert!(app.store.get(&handle).await.unwrap().is_some());

    // Invalid/unregistered token deletes the handle cleanly.
    app.sender.enqueue_outcome(PushOutcome::InvalidToken {
        reason: "UNREGISTERED".to_owned(),
    });
    let (s, _, b) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [21; 16])
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["delivered"], false);
    assert_eq!(b["pruned"], true);
    assert!(app.store.get(&handle).await.unwrap().is_none());

    // Next webhook for the pruned handle immediately returns 404 without calling push sender.
    let before = app.sender.recorded().len();
    let (s, _, _) = app
        .post_signed_hook(&key, &handle, BASE_TIME_MS, [22; 16])
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(app.sender.recorded().len(), before);
}
