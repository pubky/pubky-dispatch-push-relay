//! Mock HTTP server tests for APNs (ES256 JWT, silent wake payload, sandbox/prod routing,
//! JWT caching/refresh, dead-token pruning) and FCM HTTP v1 (RS256 service-account OAuth2
//! exchange, token caching/refresh, data-only high-priority payload, unregistered pruning).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::EncodePrivateKey as _;
use parking_lot::Mutex;
use rand_core::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::net::TcpListener;
use tower::ServiceExt as _;
use zeroize::Zeroizing;

use pubky_dispatch_push_relay::clock::FixedClock;
use pubky_dispatch_push_relay::config::RelaySettings;
use pubky_dispatch_push_relay::crypto::{
    SIGNATURE_HEADER, SIGNING_LABEL, b64_decode, b64_encode, sign_webhook,
};
use pubky_dispatch_push_relay::http::{RelayState, router};
use pubky_dispatch_push_relay::push::apns::{APNS_JWT_TTL_SECS, ApnsConfig, ApnsSender};
use pubky_dispatch_push_relay::push::fcm::{FcmConfig, FcmSender, FcmServiceAccount};
use pubky_dispatch_push_relay::push::{PushOutcome, PushSender, RouterPushSender};
use pubky_dispatch_push_relay::store::sqlite::SqliteStore;
use pubky_dispatch_push_relay::store::{ApnsEnv, Platform, Registration, RegistrationStore as _};
use pubky_dispatch_push_relay::time::format_rfc3339;

const RELAY_ORIGIN: &str = "https://push.example";
const NOW_MS: u64 = 1_767_225_960_000;

async fn spawn_mock_server(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[derive(Clone, Debug)]
struct CapturedApnsReq {
    env_tag: &'static str,
    device_token: String,
    authorization: String,
    topic: String,
    push_type: String,
    priority: String,
    collapse_id: String,
    body: Value,
}

#[derive(Clone)]
struct MockApnsState {
    env_tag: &'static str,
    captured: Arc<Mutex<Vec<CapturedApnsReq>>>,
    responses: Arc<Mutex<VecDeque<(StatusCode, Value)>>>,
}

async fn mock_apns_handler(
    State(state): State<MockApnsState>,
    Path(device_token): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> (StatusCode, Json<Value>) {
    let header_str = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    state.captured.lock().push(CapturedApnsReq {
        env_tag: state.env_tag,
        device_token,
        authorization: header_str("authorization"),
        topic: header_str("apns-topic"),
        push_type: header_str("apns-push-type"),
        priority: header_str("apns-priority"),
        collapse_id: header_str("apns-collapse-id"),
        body: parsed,
    });

    match state.responses.lock().pop_front() {
        Some((status, val)) => (status, Json(val)),
        None => (StatusCode::OK, Json(json!({}))),
    }
}

fn verify_es256_jwt(jwt: &str, verifying_key: &p256::ecdsa::VerifyingKey) -> (Value, Value) {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated parts");

    let header: Value = serde_json::from_slice(&b64_decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&b64_decode(parts[1]).unwrap()).unwrap();
    let sig_bytes = b64_decode(parts[2]).unwrap();
    assert_eq!(
        sig_bytes.len(),
        64,
        "ES256 JWS signature must be 64 raw bytes"
    );

    let sig = p256::ecdsa::Signature::from_slice(&sig_bytes).unwrap();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .expect("ES256 JWT signature must verify");
    (header, claims)
}

#[tokio::test]
async fn apns_formats_silent_wake_signs_es256_caches_jwt_and_prunes_dead_tokens() {
    // Generate an ephemeral P-256 keypair in PKCS#8 PEM format (just like Apple's .p8).
    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let verifying_key = *signing_key.verifying_key();
    let pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let prod_responses = Arc::new(Mutex::new(VecDeque::new()));
    let sandbox_responses = Arc::new(Mutex::new(VecDeque::new()));

    let prod_url = spawn_mock_server(
        Router::new()
            .route("/3/device/{token}", post(mock_apns_handler))
            .with_state(MockApnsState {
                env_tag: "production",
                captured: captured.clone(),
                responses: prod_responses.clone(),
            }),
    )
    .await;

    let sandbox_url = spawn_mock_server(
        Router::new()
            .route("/3/device/{token}", post(mock_apns_handler))
            .with_state(MockApnsState {
                env_tag: "sandbox",
                captured: captured.clone(),
                responses: sandbox_responses.clone(),
            }),
    )
    .await;

    let clock = Arc::new(FixedClock::new(NOW_MS));
    let mut apns_cfg = ApnsConfig::new(
        "TEAM987654".to_owned(),
        "KEY1234567".to_owned(),
        "to.bitkit.app".to_owned(),
        pem,
        ApnsEnv::Production,
    );
    apns_cfg.production_url = prod_url;
    apns_cfg.sandbox_url = sandbox_url;

    let apns_sender = Arc::new(ApnsSender::with_clock(apns_cfg, clock.clone()).unwrap());
    let store = Arc::new(SqliteStore::in_memory().await.unwrap());
    let push = Arc::new(RouterPushSender::new().with_apns(apns_sender));
    let state = RelayState::new(
        store.clone(),
        push,
        clock.clone(),
        RelaySettings::new(RELAY_ORIGIN).unwrap(),
    );
    let app = router(state);

    // Register a production iOS device and a sandbox iOS device via HTTP.
    let push_key = SigningKey::from_bytes(&[77u8; 32]);
    let prod_token = "aa".repeat(32);
    let sandbox_token = "bb".repeat(32);

    let prod_handle = register_via_http(&app, "apns", &prod_token, &push_key, None).await;
    let sandbox_handle =
        register_via_http(&app, "apns", &sandbox_token, &push_key, Some("sandbox")).await;

    // 1. Trigger production wake push and verify headers, content-free payload, and ES256 JWT.
    let (s, body) = send_hook_via_http(&app, &push_key, &prod_handle, NOW_MS, [1; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    // 2. Trigger sandbox wake push within 45 min: hits sandbox URL and reuses cached JWT!
    let (s, body) = send_hook_via_http(&app, &push_key, &sandbox_handle, NOW_MS, [2; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    {
        let reqs = captured.lock();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].env_tag, "production");
        assert_eq!(reqs[0].device_token, prod_token);
        assert_eq!(reqs[0].topic, "to.bitkit.app");
        assert_eq!(reqs[0].push_type, "background");
        assert_eq!(reqs[0].priority, "5");
        assert_eq!(reqs[0].collapse_id, "pubky-dispatch-wake");
        assert_eq!(reqs[0].body, json!({"aps": {"content-available": 1}}));

        assert_eq!(reqs[1].env_tag, "sandbox");
        assert_eq!(reqs[1].device_token, sandbox_token);
        assert_eq!(
            reqs[0].authorization, reqs[1].authorization,
            "JWT should be cached within 45-minute TTL"
        );

        let jwt = reqs[0]
            .authorization
            .strip_prefix("bearer ")
            .expect("bearer prefix");
        let (hdr, claims) = verify_es256_jwt(jwt, &verifying_key);
        assert_eq!(hdr["alg"], "ES256");
        assert_eq!(hdr["kid"], "KEY1234567");
        assert_eq!(claims["iss"], "TEAM987654");
        assert_eq!(claims["iat"], NOW_MS / 1_000);
    }

    // 3. Advance clock past JWT TTL -> fresh JWT is minted with updated `iat`.
    let later_ms = NOW_MS + (APNS_JWT_TTL_SECS + 5) * 1_000;
    clock.set(later_ms);
    let (s, _) = send_hook_via_http(&app, &push_key, &prod_handle, later_ms, [3; 16]).await;
    assert_eq!(s, StatusCode::OK);
    {
        let reqs = captured.lock();
        assert_eq!(reqs.len(), 3);
        assert_ne!(reqs[0].authorization, reqs[2].authorization);
        let jwt = reqs[2].authorization.strip_prefix("bearer ").unwrap();
        let (_, claims) = verify_es256_jwt(jwt, &verifying_key);
        assert_eq!(claims["iat"], later_ms / 1_000);
    }

    // 4. ExpiredProviderToken (403) triggers automatic JWT invalidation and single retry.
    prod_responses.lock().push_back((
        StatusCode::FORBIDDEN,
        json!({"reason": "ExpiredProviderToken"}),
    ));
    prod_responses.lock().push_back((StatusCode::OK, json!({})));
    let (s, body) = send_hook_via_http(&app, &push_key, &prod_handle, later_ms, [4; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    // 5. APNs 410 Unregistered prunes the handle from SQLite cleanly.
    prod_responses
        .lock()
        .push_back((StatusCode::GONE, json!({"reason": "Unregistered"})));
    let (s, body) = send_hook_via_http(&app, &push_key, &prod_handle, later_ms, [5; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], false);
    assert_eq!(body["pruned"], true);
    assert!(store.get(&prod_handle).await.unwrap().is_none());

    // Subsequent webhook for the pruned handle immediately returns 404.
    let (s, _) = send_hook_via_http(&app, &push_key, &prod_handle, later_ms, [6; 16]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // 6. APNs 400 BadDeviceToken also prunes the sandbox handle.
    sandbox_responses
        .lock()
        .push_back((StatusCode::BAD_REQUEST, json!({"reason": "BadDeviceToken"})));
    let (s, body) = send_hook_via_http(&app, &push_key, &sandbox_handle, later_ms, [7; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["pruned"], true);
    assert!(store.get(&sandbox_handle).await.unwrap().is_none());
}

#[derive(Clone)]
struct MockFcmState {
    token_requests: Arc<Mutex<Vec<String>>>,
    token_counter: Arc<AtomicUsize>,
    fcm_requests: Arc<Mutex<Vec<(String, String, Value)>>>,
    fcm_responses: Arc<Mutex<VecDeque<(StatusCode, Value)>>>,
}

async fn mock_oauth_handler(
    State(state): State<MockFcmState>,
    body: axum::body::Bytes,
) -> (StatusCode, Json<Value>) {
    let form = String::from_utf8(body.to_vec()).unwrap();
    state.token_requests.lock().push(form);
    let n = state.token_counter.fetch_add(1, Ordering::SeqCst) + 1;
    (
        StatusCode::OK,
        Json(json!({
            "access_token": format!("mock-oauth-token-{n}"),
            "expires_in": 3600,
            "token_type": "Bearer"
        })),
    )
}

async fn mock_fcm_send_handler(
    State(state): State<MockFcmState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> (StatusCode, Json<Value>) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    state.fcm_requests.lock().push((project_id, auth, parsed));

    match state.fcm_responses.lock().pop_front() {
        Some((status, val)) => (status, Json(val)),
        None => (
            StatusCode::OK,
            Json(json!({"name": "projects/demo-proj/messages/1"})),
        ),
    }
}

fn verify_rs256_jwt(jwt: &str, verifying_key: &RsaVerifyingKey<Sha256>) -> (Value, Value) {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&b64_decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&b64_decode(parts[1]).unwrap()).unwrap();
    let sig_bytes = b64_decode(parts[2]).unwrap();
    let sig = RsaSignature::try_from(sig_bytes.as_slice()).unwrap();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .expect("RS256 OAuth2 assertion signature must verify");
    (header, claims)
}

#[tokio::test]
async fn fcm_exchanges_rs256_oauth_caches_token_sends_data_only_and_prunes_unregistered() {
    let rsa_priv = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let rsa_verifying = RsaVerifyingKey::<Sha256>::new(rsa_priv.to_public_key());
    let rsa_pem = rsa_priv
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();

    let mock_state = MockFcmState {
        token_requests: Arc::new(Mutex::new(Vec::new())),
        token_counter: Arc::new(AtomicUsize::new(0)),
        fcm_requests: Arc::new(Mutex::new(Vec::new())),
        fcm_responses: Arc::new(Mutex::new(VecDeque::new())),
    };

    let base_url = spawn_mock_server(
        Router::new()
            .route("/oauth2/token", post(mock_oauth_handler))
            .route(
                "/v1/projects/{project}/messages:send",
                post(mock_fcm_send_handler),
            )
            .with_state(mock_state.clone()),
    )
    .await;

    let token_uri = format!("{base_url}/oauth2/token");
    let clock = Arc::new(FixedClock::new(NOW_MS));
    let mut fcm_cfg = FcmConfig::new(FcmServiceAccount {
        project_id: "demo-dispatch-proj".to_owned(),
        client_email: "relay@demo-dispatch-proj.iam.gserviceaccount.com".to_owned(),
        private_key: Zeroizing::new(rsa_pem),
        token_uri: Some(token_uri.clone()),
    });
    fcm_cfg.api_base_url = base_url;

    let fcm_sender = Arc::new(FcmSender::with_clock(fcm_cfg, clock.clone()).unwrap());
    let store = Arc::new(SqliteStore::in_memory().await.unwrap());
    let push = Arc::new(RouterPushSender::new().with_fcm(fcm_sender.clone()));
    let state = RelayState::new(
        store.clone(),
        push,
        clock.clone(),
        RelaySettings::new(RELAY_ORIGIN).unwrap(),
    );
    let app = router(state);

    let push_key = SigningKey::from_bytes(&[88u8; 32]);
    let fcm_token = "fcm_device:APA91bTestRegistrationToken_12345";
    let handle = register_via_http(&app, "fcm", fcm_token, &push_key, None).await;

    // 1. First wake push triggers OAuth2 exchange and delivers data-only HIGH-priority message.
    let (s, body) = send_hook_via_http(&app, &push_key, &handle, NOW_MS, [30; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    // 2. Second wake push reuses the cached OAuth2 access token (still only 1 token request!).
    let (s, body) = send_hook_via_http(&app, &push_key, &handle, NOW_MS, [31; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    {
        let oauth_reqs = mock_state.token_requests.lock();
        assert_eq!(oauth_reqs.len(), 1, "OAuth2 token should be cached");
        assert!(oauth_reqs[0].starts_with(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        ));
        let assertion = oauth_reqs[0].split("assertion=").nth(1).unwrap();
        let (hdr, claims) = verify_rs256_jwt(assertion, &rsa_verifying);
        assert_eq!(hdr["alg"], "RS256");
        assert_eq!(hdr["typ"], "JWT");
        assert_eq!(
            claims["iss"],
            "relay@demo-dispatch-proj.iam.gserviceaccount.com"
        );
        assert_eq!(
            claims["scope"],
            "https://www.googleapis.com/auth/firebase.messaging"
        );
        assert_eq!(claims["aud"], token_uri);
        assert_eq!(claims["iat"], NOW_MS / 1_000);
        assert_eq!(claims["exp"], NOW_MS / 1_000 + 3600);

        let fcm_reqs = mock_state.fcm_requests.lock();
        assert_eq!(fcm_reqs.len(), 2);
        assert_eq!(fcm_reqs[0].0, "demo-dispatch-proj");
        assert_eq!(fcm_reqs[0].1, "Bearer mock-oauth-token-1");
        assert_eq!(fcm_reqs[1].1, "Bearer mock-oauth-token-1");
        assert_eq!(
            fcm_reqs[0].2,
            json!({
                "message": {
                    "token": fcm_token,
                    "data": { "type": "wake", "v": "1" },
                    "android": { "priority": "HIGH" }
                }
            })
        );
        // Strictly data-only: no notification field.
        assert!(fcm_reqs[0].2["message"].get("notification").is_none());
    }

    // 3. Advance clock into the 120-second refresh margin -> exchanges a fresh OAuth2 token.
    let refreshed_ms = NOW_MS + (3600 - 100) * 1_000;
    clock.set(refreshed_ms);
    let (s, _) = send_hook_via_http(&app, &push_key, &handle, refreshed_ms, [32; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(mock_state.token_requests.lock().len(), 2);
    assert_eq!(
        mock_state.fcm_requests.lock().last().unwrap().1,
        "Bearer mock-oauth-token-2"
    );

    // 4. FCM 401 Unauthorized invalidates cache, refreshes OAuth2 token, and retries once.
    mock_state.fcm_responses.lock().push_back((
        StatusCode::UNAUTHORIZED,
        json!({"error": {"status": "UNAUTHENTICATED"}}),
    ));
    mock_state
        .fcm_responses
        .lock()
        .push_back((StatusCode::OK, json!({"name": "ok"})));
    let (s, body) = send_hook_via_http(&app, &push_key, &handle, refreshed_ms, [33; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);
    assert_eq!(mock_state.token_requests.lock().len(), 3);
    assert_eq!(
        mock_state.fcm_requests.lock().last().unwrap().1,
        "Bearer mock-oauth-token-3"
    );

    // 5. FCM 404 UNREGISTERED prunes the handle from SQLite cleanly.
    mock_state.fcm_responses.lock().push_back((
        StatusCode::NOT_FOUND,
        json!({
            "error": {
                "code": 404,
                "message": "Requested entity was not found.",
                "status": "NOT_FOUND",
                "details": [{
                    "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                    "errorCode": "UNREGISTERED"
                }]
            }
        }),
    ));
    let (s, body) = send_hook_via_http(&app, &push_key, &handle, refreshed_ms, [34; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], false);
    assert_eq!(body["pruned"], true);
    assert!(store.get(&handle).await.unwrap().is_none());

    // Subsequent webhook returns 404 without calling FCM.
    let fcm_calls_before = mock_state.fcm_requests.lock().len();
    let (s, _) = send_hook_via_http(&app, &push_key, &handle, refreshed_ms, [35; 16]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(mock_state.fcm_requests.lock().len(), fcm_calls_before);

    // Direct PushSender unit sanity check on unregistered outcome.
    mock_state.fcm_responses.lock().push_back((
        StatusCode::NOT_FOUND,
        json!({"error": {"status": "NOT_FOUND"}}),
    ));
    let outcome = fcm_sender
        .send_wake(&Registration {
            handle: "direct".to_owned(),
            platform: Platform::Fcm,
            device_token: fcm_token.to_owned(),
            push_key: [1; 32],
            apns_env: None,
            created_at_ms: NOW_MS,
        })
        .await
        .unwrap();
    assert_eq!(
        outcome,
        PushOutcome::InvalidToken {
            reason: "NOT_FOUND".to_owned()
        }
    );
}

async fn register_via_http(
    app: &Router,
    platform: &str,
    device_token: &str,
    key: &SigningKey,
    apns_env: Option<&str>,
) -> String {
    let mut payload = json!({
        "platform": platform,
        "device_token": device_token,
        "push_key": b64_encode(&key.verifying_key().to_bytes()),
    });
    if let Some(env) = apns_env {
        payload["apns_env"] = json!(env);
    }
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/register")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val: Value = serde_json::from_slice(&bytes).unwrap();
    val["handle"].as_str().unwrap().to_owned()
}

async fn send_hook_via_http(
    app: &Router,
    key: &SigningKey,
    handle: &str,
    ts_ms: u64,
    nonce: [u8; 16],
) -> (StatusCode, Value) {
    let raw_body = format!(
        r#"{{"v":1,"handle":"{handle}","ts":"{}","nonce":"{}"}}"#,
        format_rfc3339(ts_ms),
        b64_encode(&nonce),
    );
    let sig = sign_webhook(key, SIGNING_LABEL, RELAY_ORIGIN, raw_body.as_bytes());
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/hook")
                .header("content-type", "application/json")
                .header(SIGNATURE_HEADER, b64_encode(&sig))
                .body(Body::from(raw_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val: Value = serde_json::from_slice(&bytes).unwrap();
    (status, val)
}
