//! PostgreSQL backends for [`RegistrationStore`], [`ReplayStore`], and [`RateLimitStore`].
//!
//! Enables stateless multi-replica deployments without Redis:
//! - `registrations` stores persistent handle bindings and enforces `MAX_REGISTRATIONS`
//!   atomically using `pg_advisory_xact_lock`.
//! - `webhook_nonces` (`UNLOGGED`) provides atomic cross-replica 10-minute nonce replay
//!   protection with TTL expiry.
//! - `rate_limit_buckets` (`UNLOGGED`) provides atomic cross-replica sliding-window rate
//!   limiting for both per-handle hooks and global registrations.

use std::str::FromStr;
use std::time::Duration;

use sqlx::Row as _;
use sqlx::postgres::{PgPool, PgPoolOptions};

use super::{ApnsEnv, BoxFuture, Platform, Registration, RegistrationStore, StoreError};
use crate::rate_limit::{RATE_WINDOW_MS, RateLimitError, RateLimitStore};
use crate::replay::{NONCE_TTL_MS, ReplayError, ReplayStore};

/// Fixed 64-bit PostgreSQL advisory lock key serializing `MAX_REGISTRATIONS` checks.
const REGISTRATION_CAP_LOCK_KEY: i64 = 0x5044_5052_5245_4731;

/// Fixed 64-bit PostgreSQL advisory lock key serializing idempotent DDL across replicas.
const SCHEMA_INIT_LOCK_KEY: i64 = 0x5044_5052_4444_4C31;

/// Maximum retry attempts if a rate-limit bucket row is concurrently pruned between
/// `INSERT ... ON CONFLICT DO NOTHING` and `SELECT ... FOR UPDATE`.
const MAX_BUCKET_LOCK_ATTEMPTS: usize = 3;

const REGISTRATIONS_TABLE_SQL: &str = r"
CREATE TABLE IF NOT EXISTS registrations (
    handle        TEXT PRIMARY KEY NOT NULL,
    platform      TEXT NOT NULL CHECK (platform IN ('apns', 'fcm')),
    device_token  TEXT NOT NULL,
    push_key      BYTEA NOT NULL CHECK (octet_length(push_key) = 32),
    apns_env      TEXT CHECK (apns_env IS NULL OR apns_env IN ('production', 'sandbox')),
    created_at_ms BIGINT NOT NULL
);
";

const NONCES_TABLE_SQL: &str = r"
CREATE UNLOGGED TABLE IF NOT EXISTS webhook_nonces (
    nonce         BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(nonce) = 16),
    expires_at_ms BIGINT NOT NULL
);
";

const NONCES_INDEX_SQL: &str = r"
CREATE INDEX IF NOT EXISTS idx_webhook_nonces_expires_at
    ON webhook_nonces (expires_at_ms);
";

const RATE_LIMIT_TABLE_SQL: &str = r"
CREATE UNLOGGED TABLE IF NOT EXISTS rate_limit_buckets (
    scope         TEXT NOT NULL,
    bucket_key    TEXT NOT NULL,
    timestamps    BIGINT[] NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    PRIMARY KEY (scope, bucket_key)
);
";

const RATE_LIMIT_INDEX_SQL: &str = r"
CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_expires_at
    ON rate_limit_buckets (expires_at_ms);
";

/// PostgreSQL-backed [`RegistrationStore`].
#[derive(Clone, Debug)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Connects to PostgreSQL at `database_url` and initializes the `registrations` schema.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] if connecting or schema creation fails.
    pub async fn open(database_url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await
            .map_err(map_store_err)?;
        let store = Self { pool };
        store.init_schema().await?;
        Ok(store)
    }

    /// Wraps an existing [`PgPool`] and ensures the `registrations` table exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] if schema initialization fails.
    pub async fn from_pool(pool: PgPool) -> Result<Self, StoreError> {
        let store = Self { pool };
        store.init_schema().await?;
        Ok(store)
    }

    /// Initializes the `registrations` table if it does not already exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] if the DDL query fails.
    pub async fn init_schema(&self) -> Result<(), StoreError> {
        run_ddl(&self.pool, &[REGISTRATIONS_TABLE_SQL])
            .await
            .map_err(|e| StoreError::Backend(format!("failed to initialize schema: {e}")))?;
        Ok(())
    }

    /// Returns a reference to the underlying [`PgPool`] so [`PostgresReplayStore`] and
    /// [`PostgresRateLimitStore`] can share the same connection pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

impl RegistrationStore for PostgresStore {
    fn insert<'a>(
        &'a self,
        registration: &'a Registration,
        max_registrations: Option<u64>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let created_at_ms = i64::try_from(registration.created_at_ms)
                .map_err(|_| StoreError::CorruptData("created_at_ms overflows i64".to_owned()))?;
            let apns_env = registration.apns_env.map(ApnsEnv::as_str);

            if let Some(cap) = max_registrations {
                let mut tx = self.pool.begin().await.map_err(map_store_err)?;
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(REGISTRATION_CAP_LOCK_KEY)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_store_err)?;

                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM registrations")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(map_store_err)?;

                let count_u64 = u64::try_from(count).unwrap_or(u64::MAX);
                if count_u64 >= cap {
                    let _ = tx.rollback().await;
                    return Err(StoreError::CapacityExceeded);
                }

                let res = sqlx::query(
                    "INSERT INTO registrations \
                     (handle, platform, device_token, push_key, apns_env, created_at_ms) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(&registration.handle)
                .bind(registration.platform.as_str())
                .bind(&registration.device_token)
                .bind(registration.push_key.as_slice())
                .bind(apns_env)
                .bind(created_at_ms)
                .execute(&mut *tx)
                .await;

                match res {
                    Ok(_) => {
                        tx.commit().await.map_err(map_store_err)?;
                        Ok(())
                    }
                    Err(err) => {
                        let _ = tx.rollback().await;
                        Err(classify_insert_err(err))
                    }
                }
            } else {
                let res = sqlx::query(
                    "INSERT INTO registrations \
                     (handle, platform, device_token, push_key, apns_env, created_at_ms) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(&registration.handle)
                .bind(registration.platform.as_str())
                .bind(&registration.device_token)
                .bind(registration.push_key.as_slice())
                .bind(apns_env)
                .bind(created_at_ms)
                .execute(&self.pool)
                .await;

                match res {
                    Ok(_) => Ok(()),
                    Err(err) => Err(classify_insert_err(err)),
                }
            }
        })
    }

    fn get<'a>(
        &'a self,
        handle: &'a str,
    ) -> BoxFuture<'a, Result<Option<Registration>, StoreError>> {
        Box::pin(async move {
            let row = sqlx::query(
                "SELECT handle, platform, device_token, push_key, apns_env, created_at_ms \
                 FROM registrations WHERE handle = $1",
            )
            .bind(handle)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_store_err)?;

            let Some(row) = row else {
                return Ok(None);
            };

            let handle: String = row
                .try_get("handle")
                .map_err(|e| StoreError::CorruptData(e.to_string()))?;
            let platform_str: String = row
                .try_get("platform")
                .map_err(|e| StoreError::CorruptData(e.to_string()))?;
            let platform = Platform::from_str(&platform_str)?;
            let device_token: String = row
                .try_get("device_token")
                .map_err(|e| StoreError::CorruptData(e.to_string()))?;
            let key_vec: Vec<u8> = row
                .try_get("push_key")
                .map_err(|e| StoreError::CorruptData(e.to_string()))?;
            let push_key: [u8; 32] = key_vec
                .try_into()
                .map_err(|_| StoreError::CorruptData("push_key is not 32 bytes".to_owned()))?;
            let apns_env_str: Option<String> = row
                .try_get("apns_env")
                .map_err(|e| StoreError::CorruptData(e.to_string()))?;
            let apns_env = apns_env_str.as_deref().map(ApnsEnv::from_str).transpose()?;
            let created_i64: i64 = row
                .try_get("created_at_ms")
                .map_err(|e| StoreError::CorruptData(e.to_string()))?;
            let created_at_ms = u64::try_from(created_i64)
                .map_err(|_| StoreError::CorruptData("negative created_at_ms".to_owned()))?;

            Ok(Some(Registration {
                handle,
                platform,
                device_token,
                push_key,
                apns_env,
                created_at_ms,
            }))
        })
    }

    fn delete<'a>(&'a self, handle: &'a str) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let res = sqlx::query("DELETE FROM registrations WHERE handle = $1")
                .bind(handle)
                .execute(&self.pool)
                .await
                .map_err(map_store_err)?;
            Ok(res.rows_affected() > 0)
        })
    }

    fn ping<'a>(&'a self) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            sqlx::query("SELECT 1")
                .execute(&self.pool)
                .await
                .map_err(map_store_err)?;
            Ok(())
        })
    }
}

/// PostgreSQL `UNLOGGED`-table [`ReplayStore`] for cross-replica 10-minute nonce replay
/// protection.
#[derive(Clone, Debug)]
pub struct PostgresReplayStore {
    pool: PgPool,
    ttl_ms: u64,
}

impl PostgresReplayStore {
    /// Initializes the `UNLOGGED` `webhook_nonces` table and returns a replay store using
    /// the standard 10-minute [`NONCE_TTL_MS`] window.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::Backend`] if schema initialization fails.
    pub async fn new(pool: PgPool) -> Result<Self, ReplayError> {
        Self::with_ttl(pool, NONCE_TTL_MS).await
    }

    /// Initializes the `UNLOGGED` `webhook_nonces` table with a custom TTL in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::Backend`] if schema initialization fails.
    pub async fn with_ttl(pool: PgPool, ttl_ms: u64) -> Result<Self, ReplayError> {
        run_ddl(&pool, &[NONCES_TABLE_SQL, NONCES_INDEX_SQL])
            .await
            .map_err(|e| {
                ReplayError::Backend(format!("failed to initialize webhook_nonces: {e}"))
            })?;
        Ok(Self { pool, ttl_ms })
    }
}

impl ReplayStore for PostgresReplayStore {
    fn check_and_record<'a>(
        &'a self,
        nonce: [u8; 16],
        now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ReplayError>> {
        Box::pin(async move {
            let now_i64 = i64::try_from(now_ms)
                .map_err(|_| ReplayError::Backend("now_ms overflows i64".to_owned()))?;
            let expires_at = i64::try_from(now_ms.saturating_add(self.ttl_ms)).unwrap_or(i64::MAX);

            // Atomic upsert: inserts if absent, or replaces an expired unpruned row, and
            // does nothing (rows_affected == 0) when a live entry already exists.
            let done = sqlx::query(
                "INSERT INTO webhook_nonces (nonce, expires_at_ms) \
                 VALUES ($1, $2) \
                 ON CONFLICT (nonce) DO UPDATE \
                     SET expires_at_ms = EXCLUDED.expires_at_ms \
                     WHERE webhook_nonces.expires_at_ms <= $3",
            )
            .bind(nonce.as_slice())
            .bind(expires_at)
            .bind(now_i64)
            .execute(&self.pool)
            .await
            .map_err(|e| ReplayError::Backend(e.to_string()))?;

            Ok(done.rows_affected() > 0)
        })
    }

    fn prune_expired<'a>(&'a self, now_ms: u64) -> BoxFuture<'a, Result<usize, ReplayError>> {
        Box::pin(async move {
            let now_i64 = i64::try_from(now_ms).unwrap_or(i64::MAX);
            let done = sqlx::query("DELETE FROM webhook_nonces WHERE expires_at_ms <= $1")
                .bind(now_i64)
                .execute(&self.pool)
                .await
                .map_err(|e| ReplayError::Backend(e.to_string()))?;
            Ok(usize::try_from(done.rows_affected()).unwrap_or(usize::MAX))
        })
    }
}

/// PostgreSQL `UNLOGGED`-table [`RateLimitStore`] implementing an atomic sliding window
/// shared across replicas.
#[derive(Clone, Debug)]
pub struct PostgresRateLimitStore {
    pool: PgPool,
    scope: String,
    window_ms: u64,
    max_per_window: usize,
}

impl PostgresRateLimitStore {
    /// Initializes the `UNLOGGED` `rate_limit_buckets` table and returns a 1-minute
    /// sliding-window rate limiter isolated under `scope` (e.g. `"hook"` or `"register"`).
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitError::Backend`] if schema initialization fails.
    pub async fn new(
        pool: PgPool,
        scope: impl Into<String>,
        max_per_minute: u32,
    ) -> Result<Self, RateLimitError> {
        Self::with_window(pool, scope, RATE_WINDOW_MS, max_per_minute).await
    }

    /// Initializes the `UNLOGGED` `rate_limit_buckets` table with a custom window duration.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitError::Backend`] if schema initialization fails.
    pub async fn with_window(
        pool: PgPool,
        scope: impl Into<String>,
        window_ms: u64,
        max_per_window: u32,
    ) -> Result<Self, RateLimitError> {
        run_ddl(&pool, &[RATE_LIMIT_TABLE_SQL, RATE_LIMIT_INDEX_SQL])
            .await
            .map_err(|e| {
                RateLimitError::Backend(format!("failed to initialize rate_limit_buckets: {e}"))
            })?;
        Ok(Self {
            pool,
            scope: scope.into(),
            window_ms: window_ms.max(1),
            max_per_window: usize::try_from(max_per_window).unwrap_or(usize::MAX),
        })
    }
}

impl RateLimitStore for PostgresRateLimitStore {
    fn check_and_record<'a>(
        &'a self,
        key: &'a str,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<Result<(), u64>, RateLimitError>> {
        Box::pin(async move {
            if self.max_per_window == 0 {
                return Ok(Err(self.window_ms.div_ceil(1_000).max(1)));
            }

            let now_i64 = i64::try_from(now_ms)
                .map_err(|_| RateLimitError::Backend("now_ms overflows i64".to_owned()))?;
            let cutoff_i64 = i64::try_from(now_ms.saturating_sub(self.window_ms)).unwrap_or(0);
            let expires_at_i64 =
                i64::try_from(now_ms.saturating_add(self.window_ms)).unwrap_or(i64::MAX);

            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| RateLimitError::Backend(e.to_string()))?;

            let mut locked_timestamps: Option<Vec<i64>> = None;
            for _ in 0..MAX_BUCKET_LOCK_ATTEMPTS {
                sqlx::query(
                    "INSERT INTO rate_limit_buckets (scope, bucket_key, timestamps, expires_at_ms) \
                     VALUES ($1, $2, ARRAY[]::BIGINT[], $3) \
                     ON CONFLICT (scope, bucket_key) DO NOTHING",
                )
                .bind(&self.scope)
                .bind(key)
                .bind(expires_at_i64)
                .execute(&mut *tx)
                .await
                .map_err(|e| RateLimitError::Backend(e.to_string()))?;

                let row = sqlx::query(
                    "SELECT timestamps FROM rate_limit_buckets \
                     WHERE scope = $1 AND bucket_key = $2 \
                     FOR UPDATE",
                )
                .bind(&self.scope)
                .bind(key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| RateLimitError::Backend(e.to_string()))?;

                if let Some(row) = row {
                    let ts: Vec<i64> = row
                        .try_get("timestamps")
                        .map_err(|e| RateLimitError::Backend(e.to_string()))?;
                    locked_timestamps = Some(ts);
                    break;
                }
            }

            let Some(existing) = locked_timestamps else {
                let _ = tx.rollback().await;
                return Err(RateLimitError::Backend(
                    "failed to lock rate_limit_buckets row".to_owned(),
                ));
            };

            let mut active: Vec<i64> = existing.into_iter().filter(|&ts| ts > cutoff_i64).collect();

            if active.len() >= self.max_per_window {
                let oldest_ms = active
                    .iter()
                    .copied()
                    .min()
                    .and_then(|v| u64::try_from(v).ok())
                    .unwrap_or(now_ms);
                let wait_ms = oldest_ms
                    .saturating_add(self.window_ms)
                    .saturating_sub(now_ms);
                let retry_after_secs = wait_ms.div_ceil(1_000).max(1);
                let _ = tx.rollback().await;
                return Ok(Err(retry_after_secs));
            }

            active.push(now_i64);

            sqlx::query(
                "UPDATE rate_limit_buckets \
                 SET timestamps = $3, expires_at_ms = $4 \
                 WHERE scope = $1 AND bucket_key = $2",
            )
            .bind(&self.scope)
            .bind(key)
            .bind(&active)
            .bind(expires_at_i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| RateLimitError::Backend(e.to_string()))?;

            tx.commit()
                .await
                .map_err(|e| RateLimitError::Backend(e.to_string()))?;
            Ok(Ok(()))
        })
    }

    fn remove_key<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), RateLimitError>> {
        Box::pin(async move {
            sqlx::query("DELETE FROM rate_limit_buckets WHERE scope = $1 AND bucket_key = $2")
                .bind(&self.scope)
                .bind(key)
                .execute(&self.pool)
                .await
                .map_err(|e| RateLimitError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn prune_expired<'a>(&'a self, now_ms: u64) -> BoxFuture<'a, Result<usize, RateLimitError>> {
        Box::pin(async move {
            let now_i64 = i64::try_from(now_ms).unwrap_or(i64::MAX);
            let done = sqlx::query(
                "DELETE FROM rate_limit_buckets WHERE scope = $1 AND expires_at_ms <= $2",
            )
            .bind(&self.scope)
            .bind(now_i64)
            .execute(&self.pool)
            .await
            .map_err(|e| RateLimitError::Backend(e.to_string()))?;
            Ok(usize::try_from(done.rows_affected()).unwrap_or(usize::MAX))
        })
    }
}

async fn run_ddl(pool: &PgPool, statements: &[&str]) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(SCHEMA_INIT_LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    for stmt in statements {
        sqlx::query(stmt).execute(&mut *tx).await?;
    }
    tx.commit().await
}

fn map_store_err(err: sqlx::Error) -> StoreError {
    StoreError::Backend(err.to_string())
}

fn classify_insert_err(err: sqlx::Error) -> StoreError {
    match err {
        sqlx::Error::Database(db_err)
            if db_err.is_unique_violation() || db_err.code().as_deref() == Some("23505") =>
        {
            StoreError::DuplicateHandle
        }
        other => StoreError::Backend(other.to_string()),
    }
}
