//! Mock HTTP server tests for APNs (default visible alert + opt-in silent wake, ES256 JWT,
//! token caching/refresh, and every APNs response class) and FCM HTTP v1 (ring RS256 OAuth2
//! exchange, token caching/refresh, data-only high-priority wake with collapse_key, and
//! every FCM response class).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::EncodePrivateKey as _;
use parking_lot::Mutex;
use rand_core::OsRng;
use ring::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt as _;
use zeroize::Zeroizing;

use pubky_dispatch_push_relay::clock::FixedClock;
use pubky_dispatch_push_relay::config::RelaySettings;
use pubky_dispatch_push_relay::crypto::{
    SIGNATURE_HEADER, SIGNING_LABEL, b64_decode, b64_encode, sign_webhook,
};
use pubky_dispatch_push_relay::http::{RelayState, router};
use pubky_dispatch_push_relay::push::RouterPushSender;
use pubky_dispatch_push_relay::push::apns::{
    APNS_JWT_TTL_SECS, ApnsConfig, ApnsPushMode, ApnsSender,
};
use pubky_dispatch_push_relay::push::fcm::{FcmConfig, FcmSender, FcmServiceAccount};
use pubky_dispatch_push_relay::store::sqlite::SqliteStore;
use pubky_dispatch_push_relay::store::{ApnsEnv, RegistrationStore as _};
use pubky_dispatch_push_relay::time::format_rfc3339;

const RELAY_ORIGIN: &str = "https://push.example";
const NOW_MS: u64 = 1_767_225_960_000;

/// Dummy test-only 2048-bit RSA PKCS#8 private key for mock FCM OAuth2 JWT tests.
const TEST_RSA_2048_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDVcAjjYJwY/gZs
ivFLVOrQUzx33FrP9u2mrO0KvPbmtoTpGrHMQUH3mtO8Byyrvis7KICjGiGTqVXm
2bzpem9L71xUFW6CrdFzYkZEqfrxJNbjn1OG7xe/uc6epNaIXdhLCBZIHi621zc8
CdqLtUyvL1cJUxvg6pIySh8mqo8MlgRtzGRAhU0AjvM9uoCbCr4tn8glJhWXPePH
fB32SFoexVa5sJRw8a/9I2xOv3POWmbSb5svTY4TERmuKzvBjwd1t2YVJ2nB8aiz
J0T/qgiXhLkrFEUTzbKL071RVz+IOD8ZvLFUET4Gmv3IpCPFUwYHskve+l+IJs2B
Xcp0mfdPAgMBAAECggEAObP+UyqtSPx0VCgEMC+XBBdcw7LpQkwp1+Psefi4b4ts
x3CWHPiPkxdiovT1mMDjAy1iCbZo2XjwZmb7ccvOByOBPKJGrEG93In3IV0rIMKq
7gMHG/XL3+Ol/rHl5hwo+7AGBh1S18+7eRnY4eh0APC1gSnc4aPJPptXbKaz4dy2
QTRUeJ0hf1D2N6yAUcLry0vqFXGQ7GX3/1lGMhKZ4ZJmIUJ82sPhU052ckdtgbiC
Yf9bjwJpaRDNWP8mTBNbEJizbsC81fzTc7b9fkyyC7iGi37xm/UkpAS+VnUTSSWf
jv+S4UzFYybu7+RK6+/Ofl3vtfvLzKk+MebIYbCpYQKBgQD7PGcEpOIa2fRi85w5
plkbuS3r3E+BhI4E8+pf0qPPL5Zk4u2TRyh2y2wgtj58mMl/Tqt/MTEunjczDE2I
pT6wwf5Jqzslr8lwjApaOWA4d+neXEzz9NDCu0YL2aZygTo+ZiZveXVPe05j6Fx9
GJV1x+lS5LmMrNUbetUKN/1DWQKBgQDZfCT+ye++LhTc+TIhLvYn/EtoRYyJ33B+
QxCqaXJgvfBFYrOok0dqgShJau9MUt4WUh/dQGa/hKekjCDPH4bDs+3C3oymr7z9
dG91dlslc2X/elkz5JrZ5NG9rHcgOBNKLZMNKWquXVkcvUvqhaHQ473JyiWE203W
9+1PGPeC5wKBgHRuVb/NOgv/nkaNZ4VAFmPGugVooGABsl+ROrkVwVyvTR+MG1X5
0ELdm0q9qs/LbvZU2x2jCov0Ptilhvkgu6DnBpXViR+6C7zg6ZtOo80HpZarZ+5X
MrhMWfX79Ct0wC1S4dUfkMI4/udGNDa1Qe7HqtYDsgoDvu9xSXHm6LRhAoGANOMU
mAUBUO0h066huyIRaB3ZNI0dJPX6BCpI5jfoQZBO2oCrEcZm6oZoBpqDgLryGNl1
uDcOBWq73a7Z16RiADtECUxXRb2cpsHmzNiwR4YtepgFEzJ3WZ9kRcyn12Trg/Fb
PishLy+yGOQLjwdaF1MadvS6dPljj3AQ/Fgk8GcCgYBgQ8ZclEg/smIw0bhhcTih
+wJnLZ9IXdmCI5e3lcTZlNSCmX+J/T0seePqEB6PfAI3RkdhLYdrdS3yYwoD+ElD
mGP/1qtb888qUbpevW/CI8vT5SkK/DN0o8bO8P5gVO3VwoRGJVthrfUgwzkcpRkl
13Ig2sqgfsPWX8HHueUGvQ==
-----END PRIVATE KEY-----";

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
    responses: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
}

async fn mock_apns_handler(
    State(state): State<MockApnsState>,
    Path(device_token): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> (StatusCode, String) {
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
        Some(pair) => pair,
        None => (StatusCode::OK, "{}".to_owned()),
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
async fn apns_defaults_to_visible_alert_caches_jwt_and_classifies_every_response() {
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
        "com.example.wallet".to_owned(),
        Zeroizing::new(pem.clone()),
        ApnsEnv::Production,
    );
    apns_cfg.production_url = prod_url.clone();
    apns_cfg.sandbox_url = sandbox_url.clone();

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

    let push_key = SigningKey::from_bytes(&[77u8; 32]);
    let prod_token = "aa".repeat(32);
    let sandbox_token = "bb".repeat(32);

    let prod_handle = register_via_http(&app, "apns", &prod_token, &push_key, None).await;
    let sandbox_handle =
        register_via_http(&app, "apns", &sandbox_token, &push_key, Some("sandbox")).await;

    // 1. Default APNs mode sends a content-free generic visible alert (Spec §9).
    let (s, body) = send_hook_via_http(&app, &push_key, &prod_handle, NOW_MS, [1; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    // 2. Advance clock by 5 seconds (so an uncached JWT would have a different `iat`)
    //    and send sandbox wake push: JWT must still match the cached one!
    let t_plus_5s = NOW_MS + 5_000;
    clock.set(t_plus_5s);
    let (s, body) = send_hook_via_http(&app, &push_key, &sandbox_handle, t_plus_5s, [2; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    {
        let reqs = captured.lock();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].env_tag, "production");
        assert_eq!(reqs[0].device_token, prod_token);
        assert_eq!(reqs[0].topic, "com.example.wallet");
        assert_eq!(reqs[0].push_type, "alert");
        assert_eq!(reqs[0].priority, "10");
        assert_eq!(reqs[0].collapse_id, "pubky-dispatch-wake");
        assert_eq!(
            reqs[0].body,
            json!({
                "aps": {
                    "mutable-content": 1,
                    "alert": {
                        "title": "New notification",
                        "body": "Open the app to view."
                    }
                }
            })
        );

        assert_eq!(reqs[1].env_tag, "sandbox");
        assert_eq!(reqs[1].device_token, sandbox_token);
        assert_eq!(
            reqs[0].authorization, reqs[1].authorization,
            "JWT must be reused from cache even after iat advances 5s"
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

    // 3. Advance clock past JWT TTL -> fresh JWT minted with updated `iat`.
    let later_ms = NOW_MS + (APNS_JWT_TTL_SECS + 5) * 1_000;
    clock.set(later_ms);
    let (s, _) = send_hook_via_http(&app, &push_key, &prod_handle, later_ms, [3; 16]).await;
    assert_eq!(s, StatusCode::OK);
    {
        let reqs = captured.lock();
        assert_ne!(reqs[0].authorization, reqs[2].authorization);
        let jwt = reqs[2].authorization.strip_prefix("bearer ").unwrap();
        let (_, claims) = verify_es256_jwt(jwt, &verifying_key);
        assert_eq!(claims["iat"], later_ms / 1_000);
    }

    // 4. Non-pruning APNs answer classes MUST keep the handle and answer 502.
    let non_pruning_cases = [
        (StatusCode::GONE, "<html>generic 410</html>".to_owned()),
        (StatusCode::GONE, json!({"reason": "Other"}).to_string()),
        (
            StatusCode::BAD_REQUEST,
            json!({"reason": "DeviceTokenNotForTopic"}).to_string(),
        ),
        (
            StatusCode::BAD_REQUEST,
            json!({"reason": "BadTopic"}).to_string(),
        ),
        (
            StatusCode::FORBIDDEN,
            json!({"reason": "InvalidProviderToken"}).to_string(),
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            json!({"reason": "TooManyRequests"}).to_string(),
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"reason": "InternalServerError"}).to_string(),
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"reason": "ServiceUnavailable"}).to_string(),
        ),
    ];
    for (i, (status, body_str)) in non_pruning_cases.into_iter().enumerate() {
        prod_responses.lock().push_back((status, body_str));
        let nonce = [10u8 + u8::try_from(i).unwrap(); 16];
        let (s, b) = send_hook_via_http(&app, &push_key, &prod_handle, later_ms, nonce).await;
        assert_eq!(
            s,
            StatusCode::BAD_GATEWAY,
            "APNs {status} must return 502 and keep handle (body: {b})"
        );
        assert!(
            store.get(&prod_handle).await.unwrap().is_some(),
            "healthy handle must survive APNs {status}"
        );
    }

    // 5. ExpiredProviderToken (403) refreshes JWT and retries once.
    prod_responses.lock().push_back((
        StatusCode::FORBIDDEN,
        json!({"reason": "ExpiredProviderToken"}).to_string(),
    ));
    prod_responses
        .lock()
        .push_back((StatusCode::OK, "{}".to_owned()));
    let (s, body) = send_hook_via_http(&app, &push_key, &prod_handle, later_ms, [40; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    // 6. Token-specific APNs 410 Unregistered prunes the handle.
    prod_responses.lock().push_back((
        StatusCode::GONE,
        json!({"reason": "Unregistered"}).to_string(),
    ));
    let (s, body) = send_hook_via_http(&app, &push_key, &prod_handle, later_ms, [41; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], false);
    assert_eq!(body["pruned"], true);
    assert!(store.get(&prod_handle).await.unwrap().is_none());

    let (s, _) = send_hook_via_http(&app, &push_key, &prod_handle, later_ms, [42; 16]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // 7. Token-specific APNs 400 BadDeviceToken prunes the sandbox handle.
    sandbox_responses.lock().push_back((
        StatusCode::BAD_REQUEST,
        json!({"reason": "BadDeviceToken"}).to_string(),
    ));
    let (s, body) = send_hook_via_http(&app, &push_key, &sandbox_handle, later_ms, [43; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["pruned"], true);
    assert!(store.get(&sandbox_handle).await.unwrap().is_none());

    // 8. Opt-in Background mode sends silent content-available wake push.
    let mut bg_cfg = ApnsConfig::new(
        "TEAM987654".to_owned(),
        "KEY1234567".to_owned(),
        "com.example.wallet".to_owned(),
        Zeroizing::new(pem),
        ApnsEnv::Production,
    );
    bg_cfg.push_mode = ApnsPushMode::Background;
    bg_cfg.production_url = prod_url;
    bg_cfg.sandbox_url = sandbox_url;
    let bg_store = Arc::new(SqliteStore::in_memory().await.unwrap());
    let bg_app = router(RelayState::new(
        bg_store,
        Arc::new(RouterPushSender::new().with_apns(Arc::new(
            ApnsSender::with_clock(bg_cfg, clock.clone()).unwrap(),
        ))),
        clock,
        RelaySettings::new(RELAY_ORIGIN).unwrap(),
    ));
    let bg_handle = register_via_http(&bg_app, "apns", &"cc".repeat(32), &push_key, None).await;
    let (s, _) = send_hook_via_http(&bg_app, &push_key, &bg_handle, later_ms, [44; 16]).await;
    assert_eq!(s, StatusCode::OK);
    let last = captured.lock().last().unwrap().clone();
    assert_eq!(last.push_type, "background");
    assert_eq!(last.priority, "5");
    assert_eq!(last.body, json!({"aps": {"content-available": 1}}));
}

#[derive(Clone)]
struct MockFcmState {
    token_requests: Arc<Mutex<Vec<String>>>,
    token_counter: Arc<AtomicUsize>,
    fcm_requests: Arc<Mutex<Vec<(String, String, Value)>>>,
    fcm_responses: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
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
) -> (StatusCode, String) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    state.fcm_requests.lock().push((project_id, auth, parsed));

    match state.fcm_responses.lock().pop_front() {
        Some(pair) => pair,
        None => (
            StatusCode::OK,
            json!({"name": "projects/demo-proj/messages/1"}).to_string(),
        ),
    }
}

fn rsa_public_der_from_pkcs8_pem(pem: &str) -> Vec<u8> {
    let inner = pem
        .split("-----BEGIN PRIVATE KEY-----")
        .nth(1)
        .unwrap()
        .split("-----END PRIVATE KEY-----")
        .next()
        .unwrap();
    let compact: String = inner.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(compact)
        .unwrap();
    let kp = RsaKeyPair::from_pkcs8(&der).unwrap();
    kp.public_key().as_ref().to_vec()
}

fn verify_rs256_jwt_with_ring(jwt: &str, public_der: &[u8]) -> (Value, Value) {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&b64_decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&b64_decode(parts[1]).unwrap()).unwrap();
    let sig_bytes = b64_decode(parts[2]).unwrap();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let verifier = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_der);
    verifier
        .verify(signing_input.as_bytes(), &sig_bytes)
        .expect("ring RS256 OAuth2 assertion signature must verify");
    (header, claims)
}

#[tokio::test]
async fn fcm_signs_with_ring_caches_token_coalesces_bursts_and_classifies_every_response() {
    let public_der = rsa_public_der_from_pkcs8_pem(TEST_RSA_2048_PEM);

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
        private_key: Zeroizing::new(TEST_RSA_2048_PEM.to_owned()),
        token_uri: Some(token_uri.clone()),
    });
    fcm_cfg.api_base_url = base_url;

    let fcm_sender = Arc::new(FcmSender::with_clock(fcm_cfg, clock.clone()).unwrap());
    let store = Arc::new(SqliteStore::in_memory().await.unwrap());
    let push = Arc::new(RouterPushSender::new().with_fcm(fcm_sender));
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
    let handle2 = register_via_http(
        &app,
        "fcm",
        "fcm_device:second_token_67890",
        &push_key,
        None,
    )
    .await;

    // 1. First push exchanges ring-signed RS256 JWT; second push reuses cached OAuth2 token.
    let (s, body) = send_hook_via_http(&app, &push_key, &handle, NOW_MS, [30; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    let (s, body) = send_hook_via_http(&app, &push_key, &handle, NOW_MS, [31; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);

    {
        let oauth_reqs = mock_state.token_requests.lock();
        assert_eq!(oauth_reqs.len(), 1, "OAuth2 token should be cached");
        let assertion = oauth_reqs[0].split("assertion=").nth(1).unwrap();
        let (hdr, claims) = verify_rs256_jwt_with_ring(assertion, &public_der);
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

        let fcm_reqs = mock_state.fcm_requests.lock();
        assert_eq!(fcm_reqs.len(), 2);
        assert_eq!(
            fcm_reqs[0].2,
            json!({
                "message": {
                    "token": fcm_token,
                    "data": { "type": "wake", "v": "1" },
                    "android": {
                        "collapse_key": "pubky-dispatch-wake",
                        "priority": "HIGH"
                    }
                }
            })
        );
        assert!(fcm_reqs[0].2["message"].get("notification").is_none());
    }

    // 2. Non-pruning FCM answer classes (including generic 404!) MUST keep the handle and answer 502.
    let non_pruning_cases = [
        (
            StatusCode::NOT_FOUND,
            json!({
                "error": {
                    "code": 404,
                    "message": "Project not found.",
                    "status": "NOT_FOUND"
                }
            })
            .to_string(),
        ),
        (
            StatusCode::NOT_FOUND,
            "<html>404 Not Found</html>".to_owned(),
        ),
        (
            StatusCode::BAD_REQUEST,
            json!({
                "error": {
                    "code": 400,
                    "message": "Invalid JSON payload received.",
                    "status": "INVALID_ARGUMENT"
                }
            })
            .to_string(),
        ),
        (
            StatusCode::FORBIDDEN,
            json!({
                "error": {
                    "code": 403,
                    "status": "PERMISSION_DENIED",
                    "details": [{ "errorCode": "SENDER_ID_MISMATCH" }]
                }
            })
            .to_string(),
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            json!({
                "error": {
                    "code": 429,
                    "status": "RESOURCE_EXHAUSTED",
                    "details": [{ "errorCode": "QUOTA_EXCEEDED" }]
                }
            })
            .to_string(),
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": {"code": 500, "status": "INTERNAL"}}).to_string(),
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": {"code": 503, "status": "UNAVAILABLE"}}).to_string(),
        ),
    ];

    for (i, (status, body_str)) in non_pruning_cases.into_iter().enumerate() {
        mock_state
            .fcm_responses
            .lock()
            .push_back((status, body_str));
        let nonce = [50u8 + u8::try_from(i).unwrap(); 16];
        let (s, _) = send_hook_via_http(&app, &push_key, &handle, NOW_MS, nonce).await;
        assert_eq!(
            s,
            StatusCode::BAD_GATEWAY,
            "FCM {status} without token-specific proof must return 502"
        );
        assert!(
            store.get(&handle).await.unwrap().is_some(),
            "healthy handle must survive non-pruning FCM {status}"
        );
    }

    // 3. Advance clock into refresh margin -> refreshes OAuth2 token; 401 retries once.
    let refreshed_ms = NOW_MS + (3600 - 100) * 1_000;
    clock.set(refreshed_ms);
    let (s, _) = send_hook_via_http(&app, &push_key, &handle, refreshed_ms, [70; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(mock_state.token_requests.lock().len(), 2);

    mock_state.fcm_responses.lock().push_back((
        StatusCode::UNAUTHORIZED,
        json!({"error": {"status": "UNAUTHENTICATED"}}).to_string(),
    ));
    mock_state
        .fcm_responses
        .lock()
        .push_back((StatusCode::OK, json!({"name": "ok"}).to_string()));
    let (s, body) = send_hook_via_http(&app, &push_key, &handle, refreshed_ms, [71; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], true);
    assert_eq!(mock_state.token_requests.lock().len(), 3);

    // 4. Token-specific FCM 404 UNREGISTERED prunes handle.
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
        })
        .to_string(),
    ));
    let (s, body) = send_hook_via_http(&app, &push_key, &handle, refreshed_ms, [72; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["delivered"], false);
    assert_eq!(body["pruned"], true);
    assert!(store.get(&handle).await.unwrap().is_none());

    let fcm_calls_before = mock_state.fcm_requests.lock().len();
    let (s, _) = send_hook_via_http(&app, &push_key, &handle, refreshed_ms, [73; 16]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(mock_state.fcm_requests.lock().len(), fcm_calls_before);

    // 5. Token-specific FCM 400 INVALID_ARGUMENT naming the registration token prunes handle2.
    mock_state.fcm_responses.lock().push_back((
        StatusCode::BAD_REQUEST,
        json!({
            "error": {
                "code": 400,
                "message": "The registration token is not a valid FCM registration token",
                "status": "INVALID_ARGUMENT"
            }
        })
        .to_string(),
    ));
    let (s, body) = send_hook_via_http(&app, &push_key, &handle2, refreshed_ms, [74; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["pruned"], true);
    assert!(store.get(&handle2).await.unwrap().is_none());
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
