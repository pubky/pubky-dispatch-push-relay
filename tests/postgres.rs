//! PostgreSQL storage, replay-cache, rate-limiter, and multi-replica HTTP integration tests.
//!
//! Guarded by `TEST_DATABASE_URL`. When unset locally, tests return early without touching
//! any local database; set `REQUIRE_POSTGRES_TESTS=1` (as in CI) to fail instead of skipping.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use sqlx::postgres::{PgPool, PgPoolOptions};
use tower::ServiceExt as _;

use pubky_dispatch_push_relay::clock::FixedClock;
use pubky_dispatch_push_relay::config::RelaySettings;
use pubky_dispatch_push_relay::crypto::{
    SIGNATURE_HEADER, SIGNING_LABEL, b64_encode, sign_webhook,
};
use pubky_dispatch_push_relay::http::{RelayState, router};
use pubky_dispatch_push_relay::push::PushOutcome;
use pubky_dispatch_push_relay::push::noop::RecordingSender;
use pubky_dispatch_push_relay::rate_limit::RateLimitStore;
use pubky_dispatch_push_relay::replay::{NONCE_TTL_MS, ReplayStore};
use pubky_dispatch_push_relay::store::postgres::{
    PostgresRateLimitStore, PostgresReplayStore, PostgresStore,
};
use pubky_dispatch_push_relay::store::{
    ApnsEnv, Platform, Registration, RegistrationStore, StoreError,
};
use pubky_dispatch_push_relay::time::format_rfc3339;

const TEST_ORIGIN: &str = "https://push.example";
const BASE_TIME_MS: u64 = 1_767_225_960_000;

struct TestSchema {
    admin_pool: PgPool,
    pool: PgPool,
    schema_name: String,
}

impl TestSchema {
    async fn setup() -> Option<Self> {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            assert!(
                std::env::var("REQUIRE_POSTGRES_TESTS").is_err(),
                "REQUIRE_POSTGRES_TESTS is set but TEST_DATABASE_URL is missing"
            );
            return None;
        };

        let mut raw = [0u8; 8];
        getrandom::fill(&mut raw).unwrap();
        let schema_name = format!("relay_test_{}", hex::encode(raw));

        let admin_pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("connect to TEST_DATABASE_URL");

        sqlx::query(&format!("CREATE SCHEMA {schema_name}"))
            .execute(&admin_pool)
            .await
            .expect("create isolated test schema");

        let set_path = format!("SET search_path TO {schema_name}");
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(move |conn, _meta| {
                let sql = set_path.clone();
                Box::pin(async move {
                    sqlx::query(&sql).execute(conn).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("connect isolated schema pool");

        Some(Self {
            admin_pool,
            pool,
            schema_name,
        })
    }

    async fn teardown(self) {
        self.pool.close().await;
        sqlx::query(&format!(
            "DROP SCHEMA IF EXISTS {} CASCADE",
            self.schema_name
        ))
        .execute(&self.admin_pool)
        .await
        .expect("drop isolated test schema");
        self.admin_pool.close().await;
    }
}

fn sample_reg(handle: &str) -> Registration {
    Registration {
        handle: handle.to_owned(),
        platform: Platform::Apns,
        device_token: "aa".repeat(32),
        push_key: [9u8; 32],
        apns_env: Some(ApnsEnv::Production),
        created_at_ms: BASE_TIME_MS,
    }
}

async fn send_json(
    app: &Router,
    request: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, json)
}

async fn register_device(
    app: &Router,
    token: &str,
    key: &SigningKey,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let payload = json!({
        "platform": "fcm",
        "device_token": token,
        "push_key": b64_encode(&key.verifying_key().to_bytes()),
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();
    send_json(app, req).await
}

async fn send_signed_hook(
    app: &Router,
    key: &SigningKey,
    handle: &str,
    ts_ms: u64,
    nonce: [u8; 16],
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let raw_body = format!(
        r#"{{"v":1,"handle":"{handle}","ts":"{}","nonce":"{}"}}"#,
        format_rfc3339(ts_ms),
        b64_encode(&nonce),
    );
    let sig = sign_webhook(key, SIGNING_LABEL, TEST_ORIGIN, raw_body.as_bytes());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/hook")
        .header("content-type", "application/json")
        .header(SIGNATURE_HEADER, b64_encode(&sig))
        .body(Body::from(raw_body))
        .unwrap();
    send_json(app, req).await
}

#[tokio::test]
async fn postgres_store_crud_duplicate_and_concurrent_capacity_cap() {
    let Some(schema) = TestSchema::setup().await else {
        return;
    };

    let store = Arc::new(PostgresStore::from_pool(schema.pool.clone()).await.unwrap());
    store.ping().await.unwrap();

    // Basic CRUD + duplicate rejection.
    let reg = sample_reg("pg-handle-1");
    store.insert(&reg, Some(10)).await.unwrap();
    assert_eq!(store.get("pg-handle-1").await.unwrap().unwrap(), reg);
    assert!(matches!(
        store.insert(&reg, Some(10)).await,
        Err(StoreError::DuplicateHandle)
    ));
    assert!(store.delete("pg-handle-1").await.unwrap());
    assert!(!store.delete("pg-handle-1").await.unwrap());
    assert!(store.get("pg-handle-1").await.unwrap().is_none());

    // Concurrency test: 20 simultaneous inserts racing against cap = 5 must allow strictly 5.
    let mut tasks = Vec::new();
    for i in 0..20 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            let r = sample_reg(&format!("race-handle-{i}"));
            store.insert(&r, Some(5)).await
        }));
    }

    let mut succeeded = 0usize;
    let mut cap_exceeded = 0usize;
    for task in tasks {
        match task.await.unwrap() {
            Ok(()) => succeeded += 1,
            Err(StoreError::CapacityExceeded) => cap_exceeded += 1,
            Err(other) => panic!("unexpected store error: {other}"),
        }
    }
    assert_eq!(succeeded, 5, "advisory lock must cap total rows at 5");
    assert_eq!(cap_exceeded, 15);

    // Deleting one row allows another insert.
    let mut deleted = false;
    for i in 0..20 {
        if store.delete(&format!("race-handle-{i}")).await.unwrap() {
            deleted = true;
            break;
        }
    }
    assert!(deleted);
    store
        .insert(&sample_reg("post-delete-handle"), Some(5))
        .await
        .unwrap();

    schema.teardown().await;
}

#[tokio::test]
async fn postgres_replay_store_concurrent_and_ttl_expiry() {
    let Some(schema) = TestSchema::setup().await else {
        return;
    };

    let replay = Arc::new(PostgresReplayStore::new(schema.pool.clone()).await.unwrap());
    let nonce = [0xAB; 16];

    // 10 concurrent replicas receiving the same fresh nonce: strictly 1 succeeds.
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let replay = replay.clone();
        tasks.push(tokio::spawn(async move {
            replay.check_and_record(nonce, BASE_TIME_MS).await.unwrap()
        }));
    }
    let mut accepted = 0usize;
    for task in tasks {
        if task.await.unwrap() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 1);

    // Replay at t + TTL - 1 ms still rejected.
    assert!(
        !replay
            .check_and_record(nonce, BASE_TIME_MS + NONCE_TTL_MS - 1)
            .await
            .unwrap()
    );

    // Even before background pruning runs, once TTL has elapsed the expired row is replaced.
    assert!(
        replay
            .check_and_record(nonce, BASE_TIME_MS + NONCE_TTL_MS)
            .await
            .unwrap()
    );

    // Pruning before expiry deletes 0; pruning at expiry deletes 1.
    assert_eq!(
        replay
            .prune_expired(BASE_TIME_MS + 2 * NONCE_TTL_MS - 1)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        replay
            .prune_expired(BASE_TIME_MS + 2 * NONCE_TTL_MS)
            .await
            .unwrap(),
        1
    );

    schema.teardown().await;
}

#[tokio::test]
async fn postgres_rate_limit_store_concurrent_and_sliding_window() {
    let Some(schema) = TestSchema::setup().await else {
        return;
    };

    let hook_limiter = Arc::new(
        PostgresRateLimitStore::new(schema.pool.clone(), "hook", 4)
            .await
            .unwrap(),
    );
    let reg_limiter = Arc::new(
        PostgresRateLimitStore::new(schema.pool.clone(), "register", 2)
            .await
            .unwrap(),
    );

    // 12 concurrent requests against limit = 4: strictly 4 pass, 8 return Retry-After >= 1.
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let limiter = hook_limiter.clone();
        tasks.push(tokio::spawn(async move {
            limiter
                .check_and_record("handle-a", BASE_TIME_MS)
                .await
                .unwrap()
        }));
    }
    let mut ok_count = 0usize;
    let mut limited_count = 0usize;
    for task in tasks {
        match task.await.unwrap() {
            Ok(()) => ok_count += 1,
            Err(retry_after) => {
                assert!(retry_after >= 1);
                limited_count += 1;
            }
        }
    }
    assert_eq!(ok_count, 4);
    assert_eq!(limited_count, 8);

    // Scope isolation: "register" scope is independent of "hook" scope for the same key.
    assert_eq!(
        reg_limiter
            .check_and_record("handle-a", BASE_TIME_MS)
            .await
            .unwrap(),
        Ok(())
    );

    // After 60 seconds, sliding window resets.
    assert_eq!(
        hook_limiter
            .check_and_record("handle-a", BASE_TIME_MS + 60_000)
            .await
            .unwrap(),
        Ok(())
    );

    // remove_key clears the bucket immediately.
    hook_limiter.remove_key("handle-a").await.unwrap();
    for _ in 0..4 {
        assert_eq!(
            hook_limiter
                .check_and_record("handle-a", BASE_TIME_MS + 60_000)
                .await
                .unwrap(),
            Ok(())
        );
    }

    // prune_expired drops buckets once past their 60s expiry.
    assert_eq!(
        hook_limiter
            .prune_expired(BASE_TIME_MS + 120_000)
            .await
            .unwrap(),
        1
    );

    schema.teardown().await;
}

#[tokio::test]
async fn multi_replica_http_routers_share_registrations_replay_and_rate_limits() {
    let Some(schema) = TestSchema::setup().await else {
        return;
    };

    let clock = Arc::new(FixedClock::new(BASE_TIME_MS));
    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.rate_limit_per_minute = 3;
    settings.register_rate_limit_per_minute = 4;
    settings.max_registrations = 2;

    // Build two completely independent replicas sharing only PostgreSQL.
    let build_replica = |pool: PgPool, clock: Arc<FixedClock>, settings: RelaySettings| async move {
        let store = Arc::new(PostgresStore::from_pool(pool.clone()).await.unwrap());
        let replay: Arc<dyn ReplayStore> =
            Arc::new(PostgresReplayStore::new(pool.clone()).await.unwrap());
        let hook_limiter: Arc<dyn RateLimitStore> = Arc::new(
            PostgresRateLimitStore::new(pool.clone(), "hook", settings.rate_limit_per_minute)
                .await
                .unwrap(),
        );
        let reg_limiter: Arc<dyn RateLimitStore> = Arc::new(
            PostgresRateLimitStore::new(pool, "register", settings.register_rate_limit_per_minute)
                .await
                .unwrap(),
        );
        let sender = Arc::new(RecordingSender::new());
        let state = RelayState::with_backends(
            store,
            sender.clone(),
            clock,
            replay,
            hook_limiter,
            reg_limiter,
            settings,
        );
        let app = router(state.clone());
        (state, app, sender)
    };

    let (state_a, replica_a, sender_a) =
        build_replica(schema.pool.clone(), clock.clone(), settings.clone()).await;
    let (_state_b, replica_b, sender_b) =
        build_replica(schema.pool.clone(), clock.clone(), settings).await;

    // Health checks pass on both replicas.
    for replica in [&replica_a, &replica_b] {
        let (s, _, b) = send_json(
            replica,
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["status"], "ok");
    }

    let push_key = SigningKey::from_bytes(&[42u8; 32]);

    // 1. Register on replica A, deliver webhook via replica B.
    let (s, _, b) = register_device(&replica_a, "fcm-multi-1", &push_key).await;
    assert_eq!(s, StatusCode::OK);
    let handle1 = b["handle"].as_str().unwrap().to_owned();

    let (s, _, b) = send_signed_hook(&replica_b, &push_key, &handle1, BASE_TIME_MS, [1; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["delivered"], true);
    assert_eq!(sender_b.recorded().len(), 1);

    // 2. Replaying the same webhook against replica A returns 409 (shared replay table).
    let (s, _, b) = send_signed_hook(&replica_a, &push_key, &handle1, BASE_TIME_MS, [1; 16]).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(b["code"], "nonce_replay");

    // 3. Per-handle rate limit (3/min) is shared across replicas A and B.
    let (s, _, _) = send_signed_hook(&replica_a, &push_key, &handle1, BASE_TIME_MS, [2; 16]).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = send_signed_hook(&replica_b, &push_key, &handle1, BASE_TIME_MS, [3; 16]).await;
    assert_eq!(s, StatusCode::OK);
    let (s, headers, b) =
        send_signed_hook(&replica_a, &push_key, &handle1, BASE_TIME_MS, [4; 16]).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b["code"], "rate_limited");
    assert!(headers.get("retry-after").is_some());
    assert_eq!(sender_a.recorded().len(), 1);
    assert_eq!(sender_b.recorded().len(), 2);

    // 4. MAX_REGISTRATIONS = 2 is shared across replicas A and B.
    let (s, _, _) = register_device(&replica_b, "fcm-multi-2", &push_key).await;
    assert_eq!(s, StatusCode::OK);

    let (s, _, b) = register_device(&replica_a, "fcm-multi-3", &push_key).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b["code"], "unavailable");

    // 5. Pruning handle1 via replica B frees a slot for replica A (after advancing clock 60s
    // so both per-handle and global registration rate limits reset).
    clock.advance_ms(60_000);
    let t2 = BASE_TIME_MS + 60_000;
    sender_b.enqueue_outcome(PushOutcome::InvalidToken {
        reason: "UNREGISTERED".to_owned(),
    });
    let (s, _, b) = send_signed_hook(&replica_b, &push_key, &handle1, t2, [5; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["pruned"], true);

    let (s, _, _) = register_device(&replica_a, "fcm-multi-3", &push_key).await;
    assert_eq!(s, StatusCode::OK);

    // 6. Global registration rate limit (4/min) is shared across replicas A and B.
    // We already used 1 slot at t2 on replica A; send 3 more across B/A/B (hitting 503
    // cap after quota check), then the 5th request hits 429 before touching storage.
    let (s, _, _) = register_device(&replica_b, "fcm-multi-4", &push_key).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let (s, _, _) = register_device(&replica_a, "fcm-multi-5", &push_key).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let (s, _, _) = register_device(&replica_b, "fcm-multi-6", &push_key).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let (s, headers, b) = register_device(&replica_a, "fcm-multi-7", &push_key).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b["code"], "rate_limited");
    assert!(headers.get("retry-after").is_some());

    // 7. Background cache sweep prunes expired Postgres UNLOGGED rows cleanly.
    clock.advance_ms(NONCE_TTL_MS + 60_000);
    state_a.prune_caches().await;

    schema.teardown().await;
}
