//! PostgreSQL storage, durable replay-cache, rate-limiter, clock-skew, and multi-replica
//! HTTP integration tests.
//!
//! Guarded by `TEST_DATABASE_URL`. When unset locally, tests return early without touching
//! any local database; set `REQUIRE_POSTGRES_TESTS=1` (as in CI) to fail instead of skipping.

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
use sqlx::postgres::{PgPool, PgPoolOptions};
use tower::ServiceExt as _;

use pubky_dispatch_push_relay::clock::{Clock as _, FixedClock, SystemClock};
use pubky_dispatch_push_relay::config::RelaySettings;
use pubky_dispatch_push_relay::crypto::{
    SIGNATURE_HEADER, SIGNING_LABEL, b64_encode, sign_webhook,
};
use pubky_dispatch_push_relay::http::{RateLimitBackends, RelayState, router};
use pubky_dispatch_push_relay::push::noop::RecordingSender;
use pubky_dispatch_push_relay::push::{InvalidTokenClass, PushOutcome};
use pubky_dispatch_push_relay::rate_limit::RateLimitStore;
use pubky_dispatch_push_relay::replay::{ReplayError, ReplayStore};
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

fn resolve_test_database_url(
    url: Option<&str>,
    require: Option<&str>,
) -> Result<Option<String>, &'static str> {
    let required = require.is_some_and(|v| !v.trim().is_empty() && v.trim() != "0");
    match url.map(str::trim).filter(|s| !s.is_empty()) {
        Some(valid) => Ok(Some(valid.to_owned())),
        None if required => Err("REQUIRE_POSTGRES_TESTS is set but TEST_DATABASE_URL is missing"),
        None => Ok(None),
    }
}

impl TestSchema {
    async fn setup() -> Option<Self> {
        let url_var = std::env::var("TEST_DATABASE_URL").ok();
        let req_var = std::env::var("REQUIRE_POSTGRES_TESTS").ok();
        let url = resolve_test_database_url(url_var.as_deref(), req_var.as_deref())
            .expect("PostgreSQL tests required in CI");
        let url = url?;

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
        last_active_at_ms: BASE_TIME_MS,
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

async fn register_device_from(
    app: &Router,
    ip: IpAddr,
    token: &str,
    key: &SigningKey,
) -> (StatusCode, axum::http::HeaderMap, Value) {
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
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, 50000)));
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
async fn postgres_replay_table_is_durable_bounded_and_uses_database_time() {
    let Some(schema) = TestSchema::setup().await else {
        return;
    };

    // Short 400 ms TTL with live cap = 2 to test durability, cap, and DB-clock expiry.
    let replay = Arc::new(
        PostgresReplayStore::with_ttl(schema.pool.clone(), 400, 2)
            .await
            .unwrap(),
    );

    // Verify webhook_nonces is a permanent WAL-logged table ('p'), NOT UNLOGGED ('u').
    let persistence: String = sqlx::query_scalar(
        "SELECT c.relpersistence::TEXT \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = $1 AND c.relname = 'webhook_nonces'",
    )
    .bind(&schema.schema_name)
    .fetch_one(&schema.pool)
    .await
    .unwrap();
    assert_eq!(persistence, "p", "webhook_nonces must be durable (logged)");

    let nonce = [0xAB; 16];

    // 10 concurrent replicas receiving the same fresh nonce: strictly 1 succeeds.
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let replay = replay.clone();
        tasks.push(tokio::spawn(async move {
            replay.check_and_record(nonce, 0, 0).await.unwrap()
        }));
    }
    let mut accepted = 0usize;
    for task in tasks {
        if task.await.unwrap() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 1);

    // Fill second slot -> third fresh nonce returns CapacityExceeded (503), never evicting live nonces.
    assert!(replay.check_and_record([0xCD; 16], 0, 0).await.unwrap());
    assert!(matches!(
        replay.check_and_record([0xEF; 16], 0, 0).await,
        Err(ReplayError::CapacityExceeded)
    ));
    // Live nonce still rejected as replay (409) even while at capacity.
    assert!(!replay.check_and_record(nonce, 0, 0).await.unwrap());

    // A skewed replica claiming a far-future wall clock (+1 hour) CANNOT prune live nonces!
    let far_future = SystemClock.now_ms() + 3_600_000;
    assert_eq!(
        replay.prune_expired(far_future, far_future).await.unwrap(),
        0
    );
    assert!(
        !replay
            .check_and_record(nonce, far_future, far_future)
            .await
            .unwrap()
    );

    // After the real DB 400 ms TTL elapses, the expired row is pruned cleanly.
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert_eq!(replay.prune_expired(0, 0).await.unwrap(), 2);
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_nonces")
        .fetch_one(&schema.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);

    schema.teardown().await;
}

#[tokio::test]
async fn postgres_rate_limit_store_concurrent_durable_and_sliding_window() {
    let Some(schema) = TestSchema::setup().await else {
        return;
    };

    let hook_limiter = Arc::new(
        PostgresRateLimitStore::with_window(schema.pool.clone(), "hook", 400, 4)
            .await
            .unwrap(),
    );
    let reg_limiter = Arc::new(
        PostgresRateLimitStore::with_window(schema.pool.clone(), "register_global", 400, 2)
            .await
            .unwrap(),
    );

    let persistence: String = sqlx::query_scalar(
        "SELECT c.relpersistence::TEXT \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = $1 AND c.relname = 'rate_limit_buckets'",
    )
    .bind(&schema.schema_name)
    .fetch_one(&schema.pool)
    .await
    .unwrap();
    assert_eq!(persistence, "p", "rate_limit_buckets must be durable");

    let mut tasks = Vec::new();
    for _ in 0..12 {
        let limiter = hook_limiter.clone();
        tasks.push(tokio::spawn(async move {
            limiter.check_and_record("handle-a", 0).await.unwrap()
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

    // Scope isolation.
    assert_eq!(
        reg_limiter.check_and_record("handle-a", 0).await.unwrap(),
        Ok(())
    );

    // Wait for real DB 400 ms sliding window to roll over and verify prune deletes row.
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert_eq!(hook_limiter.prune_expired(0).await.unwrap(), 1);
    assert_eq!(
        hook_limiter.check_and_record("handle-a", 0).await.unwrap(),
        Ok(())
    );

    // remove_key clears bucket immediately.
    hook_limiter.remove_key("handle-a").await.unwrap();
    for _ in 0..4 {
        assert_eq!(
            hook_limiter.check_and_record("handle-a", 0).await.unwrap(),
            Ok(())
        );
    }

    schema.teardown().await;
}

#[tokio::test]
async fn multi_replica_http_routers_share_state_and_tolerate_replica_clock_skew() {
    let Some(schema) = TestSchema::setup().await else {
        return;
    };

    let now = SystemClock.now_ms();
    let clock_a = Arc::new(FixedClock::new(now));
    // Replica B's local clock is 20 minutes ahead: its prune MUST NOT drop Replica A's live nonces!
    let clock_skewed = Arc::new(FixedClock::new(now + 20 * 60 * 1_000));
    let clock_b = Arc::new(FixedClock::new(now));

    let mut settings = RelaySettings::new(TEST_ORIGIN).unwrap();
    settings.rate_limit_per_minute = 3;
    settings.register_ip_rate_limit_per_minute = 20;
    settings.register_key_rate_limit_per_minute = 20;
    settings.register_rate_limit_per_minute = 20;
    settings.max_handles_per_push_key = 32;
    settings.max_registrations = 2;

    let build_replica = |pool: PgPool, clock: Arc<FixedClock>, settings: RelaySettings| async move {
        let store = Arc::new(PostgresStore::from_pool(pool.clone()).await.unwrap());
        let replay: Arc<dyn ReplayStore> = Arc::new(
            PostgresReplayStore::new(pool.clone(), settings.nonce_cache_max_entries)
                .await
                .unwrap(),
        );
        let limiters = RateLimitBackends {
            hook_per_handle: Arc::new(
                PostgresRateLimitStore::new(pool.clone(), "hook", settings.rate_limit_per_minute)
                    .await
                    .unwrap(),
            ),
            register_per_ip: Arc::new(
                PostgresRateLimitStore::new(
                    pool.clone(),
                    "register_ip",
                    settings.register_ip_rate_limit_per_minute,
                )
                .await
                .unwrap(),
            ),
            register_per_key: Arc::new(
                PostgresRateLimitStore::new(
                    pool.clone(),
                    "register_key",
                    settings.register_key_rate_limit_per_minute,
                )
                .await
                .unwrap(),
            ),
            register_global: Arc::new(
                PostgresRateLimitStore::new(
                    pool,
                    "register_global",
                    settings.register_rate_limit_per_minute,
                )
                .await
                .unwrap(),
            ),
        };
        let sender = Arc::new(RecordingSender::new());
        let state =
            RelayState::with_backends(store, sender.clone(), clock, replay, limiters, settings);
        let app = router(state.clone());
        (state, app, sender)
    };

    let (state_a, replica_a, sender_a) =
        build_replica(schema.pool.clone(), clock_a.clone(), settings.clone()).await;
    let (_state_b, replica_b, sender_b) =
        build_replica(schema.pool.clone(), clock_b.clone(), settings.clone()).await;
    let (state_skewed, _replica_skewed, _sender_skewed) =
        build_replica(schema.pool.clone(), clock_skewed, settings).await;

    let push_key = SigningKey::from_bytes(&[42u8; 32]);
    let ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

    // 1. Register on replica A, deliver webhook via replica B.
    let (s, _, b) = register_device_from(&replica_a, ip1, "fcm-multi-1", &push_key).await;
    assert_eq!(s, StatusCode::OK);
    let handle1 = b["handle"].as_str().unwrap().to_owned();

    // Idempotent re-registration on replica B returns the exact same handle!
    let (s, _, b) = register_device_from(&replica_b, ip2, "fcm-multi-1", &push_key).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["handle"].as_str().unwrap(), handle1);

    let (s, _, b) = send_signed_hook(&replica_b, &push_key, &handle1, now, [1; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["delivered"], true);

    // 2. Skewed replica (+20 min ahead!) runs prune_caches(): MUST NOT drop live nonce [1; 16]!
    state_skewed.prune_caches().await;
    let (s, _, b) = send_signed_hook(&replica_a, &push_key, &handle1, now, [1; 16]).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(b["code"], "nonce_replay");

    // 3. Per-handle rate limit (3/min) is shared across replicas A and B.
    let (s, _, _) = send_signed_hook(&replica_a, &push_key, &handle1, now, [2; 16]).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = send_signed_hook(&replica_b, &push_key, &handle1, now, [3; 16]).await;
    assert_eq!(s, StatusCode::OK);
    let (s, headers, b) = send_signed_hook(&replica_a, &push_key, &handle1, now, [4; 16]).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b["code"], "rate_limited");
    assert!(headers.get("retry-after").is_some());
    assert_eq!(sender_a.recorded().len(), 1);
    assert_eq!(sender_b.recorded().len(), 2);

    // 4. MAX_REGISTRATIONS = 2 shared across replicas A and B; pruning on B frees slot for A.
    let (s, _, _) = register_device_from(&replica_b, ip1, "fcm-multi-2", &push_key).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, b) = register_device_from(&replica_a, ip2, "fcm-multi-3", &push_key).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b["code"], "unavailable");

    // Clear handle1 via token-specific rejection on replica B (after clearing handle1 rate bucket).
    sqlx::query("DELETE FROM rate_limit_buckets WHERE scope = 'hook'")
        .execute(&schema.pool)
        .await
        .unwrap();
    sender_b.enqueue_outcome(PushOutcome::InvalidToken {
        class: InvalidTokenClass::FcmUnregistered,
    });
    let (s, _, b) = send_signed_hook(&replica_b, &push_key, &handle1, now, [5; 16]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["pruned"], true);

    let (s, _, _) = register_device_from(&replica_a, ip2, "fcm-multi-3", &push_key).await;
    assert_eq!(s, StatusCode::OK);

    // 5. Final sweep actually deletes expired nonces and expired rate-limit buckets in PostgreSQL.
    sqlx::query("UPDATE webhook_nonces SET expires_at_ms = 1")
        .execute(&schema.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE rate_limit_buckets SET expires_at_ms = 1")
        .execute(&schema.pool)
        .await
        .unwrap();
    let nonces_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_nonces")
        .fetch_one(&schema.pool)
        .await
        .unwrap();
    let buckets_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rate_limit_buckets")
        .fetch_one(&schema.pool)
        .await
        .unwrap();
    assert!(nonces_before > 0, "expected nonces before sweep");
    assert!(buckets_before > 0, "expected rate buckets before sweep");

    state_a.prune_caches().await;

    let nonces_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_nonces")
        .fetch_one(&schema.pool)
        .await
        .unwrap();
    let buckets_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rate_limit_buckets")
        .fetch_one(&schema.pool)
        .await
        .unwrap();
    assert_eq!(nonces_after, 0, "prune_caches must delete expired nonces");
    assert_eq!(
        buckets_after, 0,
        "prune_caches must delete expired rate-limit buckets"
    );

    schema.teardown().await;
}

#[test]
fn require_postgres_tests_fails_loudly_when_url_missing() {
    assert_eq!(resolve_test_database_url(None, None), Ok(None));
    assert_eq!(resolve_test_database_url(Some(""), Some("0")), Ok(None));
    assert!(resolve_test_database_url(None, Some("1")).is_err());
    assert!(resolve_test_database_url(Some("   "), Some("1")).is_err());
    assert_eq!(
        resolve_test_database_url(Some("postgres://u:p@localhost/db"), Some("1")),
        Ok(Some("postgres://u:p@localhost/db".to_owned()))
    );
}

#[tokio::test]
async fn postgres_versioned_migrations_are_recorded_idempotent_and_checksum_verified() {
    let Some(schema) = TestSchema::setup().await else {
        return;
    };

    let _store1 = PostgresStore::from_pool(schema.pool.clone()).await.unwrap();
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT version, description, checksum FROM schema_migrations ORDER BY version",
    )
    .fetch_all(&schema.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, 1);
    assert_eq!(rows[0].1, "initial");
    assert_eq!(rows[0].2.len(), 64);

    // Second startup is idempotent.
    let _store2 = PostgresStore::from_pool(schema.pool.clone()).await.unwrap();

    // Tampering with checksum makes migration verification fail loudly.
    sqlx::query("UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1")
        .execute(&schema.pool)
        .await
        .unwrap();
    let err = PostgresStore::from_pool(schema.pool.clone())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("checksum mismatch"));

    schema.teardown().await;
}
