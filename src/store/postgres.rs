//! PostgreSQL backends for [`RegistrationStore`], durable [`ReplayStore`], and
//! durable [`RateLimitStore`].
//!
//! Enables stateless multi-replica deployments without Redis:
//! - `registrations` stores persistent handle bindings, enforces per-key and global caps
//!   atomically via `pg_advisory_xact_lock`, supports idempotent re-registration, and
//!   tracks `last_active_at_ms` for inactivity expiry.
//! - `webhook_nonces` (durable WAL-logged table) provides atomic cross-replica 10-minute
//!   nonce replay protection using PostgreSQL's `clock_timestamp()` and a hard row cap
//!   (returning `503` instead of evicting live nonces).
//! - `rate_limit_buckets` (durable WAL-logged table) provides atomic cross-replica
//!   sliding-window rate limiting using PostgreSQL's `clock_timestamp()`.

use std::str::FromStr;
use std::time::Duration;

use ring::digest::{SHA256, digest};
use sqlx::Row as _;
use sqlx::postgres::{PgPool, PgPoolOptions};

use super::{
    ApnsEnv, BoxFuture, Platform, RegisterOutcome, Registration, RegistrationLimits,
    RegistrationStore, StoreError,
};
use crate::rate_limit::{RATE_WINDOW_MS, RateLimitError, RateLimitStore};
use crate::replay::{NONCE_TTL_MS, ReplayError, ReplayStore};

/// Fixed 64-bit PostgreSQL advisory lock key serializing registration cap checks.
const REGISTRATION_CAP_LOCK_KEY: i64 = 0x5044_5052_5245_4731;

/// Fixed 64-bit PostgreSQL advisory lock key serializing nonce cap checks.
const NONCE_CAP_LOCK_KEY: i64 = 0x5044_5052_4E4F_4E31;

/// Fixed 64-bit PostgreSQL advisory lock key serializing versioned migrations across replicas.
const SCHEMA_INIT_LOCK_KEY: i64 = 0x5044_5052_4444_4C31;

/// Maximum retry attempts if a rate-limit bucket row is concurrently pruned between
/// `INSERT ... ON CONFLICT DO NOTHING` and `SELECT ... FOR UPDATE`.
const MAX_BUCKET_LOCK_ATTEMPTS: usize = 3;

struct SqlMigration {
    version: i64,
    description: &'static str,
    sql: &'static str,
}

const POSTGRES_MIGRATIONS: &[SqlMigration] = &[SqlMigration {
    version: 1,
    description: "initial",
    sql: include_str!("../../migrations/postgres/0001_initial.sql"),
}];

const PG_SCHEMA_MIGRATIONS_TABLE_SQL: &str = r"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version       BIGINT PRIMARY KEY NOT NULL,
    description   TEXT NOT NULL,
    checksum      TEXT NOT NULL,
    applied_at_ms BIGINT NOT NULL
);
";

/// SQL expression returning PostgreSQL's own UTC epoch milliseconds so replica clock
/// skew cannot expire or prune entries still live on other replicas.
const PG_NOW_MS_SQL: &str = "SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT";

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

    /// Applies all pending versioned PostgreSQL schema migrations under an advisory lock.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] if running migrations or verifying checksums fails.
    pub async fn init_schema(&self) -> Result<(), StoreError> {
        apply_postgres_migrations(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(format!("failed to apply postgres migrations: {e}")))
    }

    /// Returns a reference to the underlying [`PgPool`] so [`PostgresReplayStore`] and
    /// [`PostgresRateLimitStore`] can share the same connection pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn decode_row(row: &sqlx::postgres::PgRow) -> Result<Registration, StoreError> {
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
    let last_active_i64: i64 = row
        .try_get("last_active_at_ms")
        .map_err(|e| StoreError::CorruptData(e.to_string()))?;
    let last_active_at_ms = u64::try_from(last_active_i64)
        .map_err(|_| StoreError::CorruptData("negative last_active_at_ms".to_owned()))?;

    Ok(Registration {
        handle,
        platform,
        device_token,
        push_key,
        apns_env,
        created_at_ms,
        last_active_at_ms,
    })
}

impl RegistrationStore for PostgresStore {
    fn register_or_get<'a>(
        &'a self,
        candidate: &'a Registration,
        limits: RegistrationLimits,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<RegisterOutcome, StoreError>> {
        Box::pin(async move {
            let now_i64 = i64::try_from(now_ms)
                .map_err(|_| StoreError::CorruptData("now_ms overflows i64".to_owned()))?;
            let cutoff_i64 = i64::try_from(now_ms.saturating_sub(limits.ttl_ms)).unwrap_or(0);
            let apns_env = candidate.apns_env.map(ApnsEnv::as_str);

            let mut tx = self.pool.begin().await.map_err(map_store_err)?;
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(REGISTRATION_CAP_LOCK_KEY)
                .execute(&mut *tx)
                .await
                .map_err(map_store_err)?;

            // 1. Idempotent re-registration for active (platform, device_token, push_key, apns_env).
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT handle FROM registrations \
                 WHERE platform = $1 AND device_token = $2 AND push_key = $3 \
                   AND apns_env IS NOT DISTINCT FROM $4 AND last_active_at_ms > $5 \
                 LIMIT 1",
            )
            .bind(candidate.platform.as_str())
            .bind(&candidate.device_token)
            .bind(candidate.push_key.as_slice())
            .bind(apns_env)
            .bind(cutoff_i64)
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_store_err)?;

            if let Some(handle) = existing {
                sqlx::query(
                    "UPDATE registrations \
                     SET last_active_at_ms = GREATEST(last_active_at_ms, $1) \
                     WHERE handle = $2",
                )
                .bind(now_i64)
                .bind(&handle)
                .execute(&mut *tx)
                .await
                .map_err(map_store_err)?;
                tx.commit().await.map_err(map_store_err)?;
                return Ok(RegisterOutcome::Existing(handle));
            }

            // 2. Reclaim expired rows before checking active quotas.
            sqlx::query("DELETE FROM registrations WHERE last_active_at_ms <= $1")
                .bind(cutoff_i64)
                .execute(&mut *tx)
                .await
                .map_err(map_store_err)?;

            // 3. Enforce per-push-key active handle cap (never evicts existing handles).
            let key_count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM registrations WHERE push_key = $1")
                    .bind(candidate.push_key.as_slice())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(map_store_err)?;
            if u64::try_from(key_count).unwrap_or(u64::MAX)
                >= u64::from(limits.max_handles_per_push_key)
            {
                let _ = tx.rollback().await;
                return Err(StoreError::PushKeyCapacityExceeded);
            }

            // 4. Enforce global capacity cap.
            let total_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM registrations")
                .fetch_one(&mut *tx)
                .await
                .map_err(map_store_err)?;
            if u64::try_from(total_count).unwrap_or(u64::MAX) >= limits.max_registrations {
                let _ = tx.rollback().await;
                return Err(StoreError::CapacityExceeded);
            }

            // 5. Insert fresh handle.
            let res = sqlx::query(
                "INSERT INTO registrations \
                 (handle, platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&candidate.handle)
            .bind(candidate.platform.as_str())
            .bind(&candidate.device_token)
            .bind(candidate.push_key.as_slice())
            .bind(apns_env)
            .bind(now_i64)
            .bind(now_i64)
            .execute(&mut *tx)
            .await;

            match res {
                Ok(_) => {
                    tx.commit().await.map_err(map_store_err)?;
                    Ok(RegisterOutcome::Created(candidate.handle.clone()))
                }
                Err(err) => {
                    let _ = tx.rollback().await;
                    Err(classify_insert_err(err))
                }
            }
        })
    }

    fn insert<'a>(
        &'a self,
        registration: &'a Registration,
        max_registrations: Option<u64>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let created_at_ms = i64::try_from(registration.created_at_ms)
                .map_err(|_| StoreError::CorruptData("created_at_ms overflows i64".to_owned()))?;
            let last_active_at_ms =
                i64::try_from(registration.last_active_at_ms).map_err(|_| {
                    StoreError::CorruptData("last_active_at_ms overflows i64".to_owned())
                })?;
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

                if u64::try_from(count).unwrap_or(u64::MAX) >= cap {
                    let _ = tx.rollback().await;
                    return Err(StoreError::CapacityExceeded);
                }

                let res = sqlx::query(
                    "INSERT INTO registrations \
                     (handle, platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(&registration.handle)
                .bind(registration.platform.as_str())
                .bind(&registration.device_token)
                .bind(registration.push_key.as_slice())
                .bind(apns_env)
                .bind(created_at_ms)
                .bind(last_active_at_ms)
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
                     (handle, platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(&registration.handle)
                .bind(registration.platform.as_str())
                .bind(&registration.device_token)
                .bind(registration.push_key.as_slice())
                .bind(apns_env)
                .bind(created_at_ms)
                .bind(last_active_at_ms)
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
                "SELECT handle, platform, device_token, push_key, apns_env, \
                        created_at_ms, last_active_at_ms \
                 FROM registrations WHERE handle = $1",
            )
            .bind(handle)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_store_err)?;

            row.as_ref().map(decode_row).transpose()
        })
    }

    fn get_active<'a>(
        &'a self,
        handle: &'a str,
        active_cutoff_ms: u64,
    ) -> BoxFuture<'a, Result<Option<Registration>, StoreError>> {
        Box::pin(async move {
            let cutoff_i64 = i64::try_from(active_cutoff_ms).unwrap_or(i64::MAX);
            let row = sqlx::query(
                "SELECT handle, platform, device_token, push_key, apns_env, \
                        created_at_ms, last_active_at_ms \
                 FROM registrations WHERE handle = $1 AND last_active_at_ms > $2",
            )
            .bind(handle)
            .bind(cutoff_i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_store_err)?;

            row.as_ref().map(decode_row).transpose()
        })
    }

    fn touch_last_active<'a>(
        &'a self,
        handle: &'a str,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let now_i64 = i64::try_from(now_ms).unwrap_or(i64::MAX);
            sqlx::query(
                "UPDATE registrations \
                 SET last_active_at_ms = GREATEST(last_active_at_ms, $1) \
                 WHERE handle = $2",
            )
            .bind(now_i64)
            .bind(handle)
            .execute(&self.pool)
            .await
            .map_err(map_store_err)?;
            Ok(())
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

    fn prune_expired<'a>(&'a self, cutoff_ms: u64) -> BoxFuture<'a, Result<usize, StoreError>> {
        Box::pin(async move {
            let cutoff_i64 = i64::try_from(cutoff_ms).unwrap_or(i64::MAX);
            let res = sqlx::query("DELETE FROM registrations WHERE last_active_at_ms <= $1")
                .bind(cutoff_i64)
                .execute(&self.pool)
                .await
                .map_err(map_store_err)?;
            Ok(usize::try_from(res.rows_affected()).unwrap_or(usize::MAX))
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

/// Durable PostgreSQL [`ReplayStore`] using database time (`clock_timestamp()`) and a
/// strict live-entry row cap.
///
/// Replica clocks are ignored for expiry and pruning so one skewed or jumping replica
/// cannot prune or expire another replica's live nonces.
#[derive(Clone, Debug)]
pub struct PostgresReplayStore {
    pool: PgPool,
    ttl_ms: u64,
    max_entries: usize,
}

impl PostgresReplayStore {
    /// Initializes the durable `webhook_nonces` table using the standard 10-minute
    /// [`NONCE_TTL_MS`] window and `max_entries` cap.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::Backend`] if schema initialization fails.
    pub async fn new(pool: PgPool, max_entries: usize) -> Result<Self, ReplayError> {
        Self::with_ttl(pool, NONCE_TTL_MS, max_entries).await
    }

    /// Initializes the durable `webhook_nonces` table with a custom TTL and cap.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::Backend`] if schema initialization fails.
    pub async fn with_ttl(
        pool: PgPool,
        ttl_ms: u64,
        max_entries: usize,
    ) -> Result<Self, ReplayError> {
        apply_postgres_migrations(&pool).await.map_err(|e| {
            ReplayError::Backend(format!("failed to apply postgres migrations: {e}"))
        })?;
        Ok(Self {
            pool,
            ttl_ms,
            max_entries: max_entries.max(1),
        })
    }
}

impl ReplayStore for PostgresReplayStore {
    fn check_and_record<'a>(
        &'a self,
        nonce: [u8; 16],
        _wall_now_ms: u64,
        _mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ReplayError>> {
        Box::pin(async move {
            let ttl_i64 = i64::try_from(self.ttl_ms).unwrap_or(i64::MAX);

            // Fast-path replay check using PostgreSQL's authoritative database time.
            let already_live: Option<bool> = sqlx::query_scalar(
                "SELECT (expires_at_ms > (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT) \
                 FROM webhook_nonces WHERE nonce = $1",
            )
            .bind(nonce.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ReplayError::Backend(e.to_string()))?;

            if already_live == Some(true) {
                return Ok(false);
            }

            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| ReplayError::Backend(e.to_string()))?;

            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(NONCE_CAP_LOCK_KEY)
                .execute(&mut *tx)
                .await
                .map_err(|e| ReplayError::Backend(e.to_string()))?;

            let db_now_ms: i64 = sqlx::query_scalar(PG_NOW_MS_SQL)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| ReplayError::Backend(e.to_string()))?;
            let expires_at = db_now_ms.saturating_add(ttl_i64);

            let existing_exp: Option<i64> =
                sqlx::query_scalar("SELECT expires_at_ms FROM webhook_nonces WHERE nonce = $1")
                    .bind(nonce.as_slice())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;

            if let Some(exp) = existing_exp {
                if exp > db_now_ms {
                    let _ = tx.rollback().await;
                    return Ok(false);
                }
                sqlx::query("UPDATE webhook_nonces SET expires_at_ms = $2 WHERE nonce = $1")
                    .bind(nonce.as_slice())
                    .bind(expires_at)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;
                return Ok(true);
            }

            let live_count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM webhook_nonces WHERE expires_at_ms > $1")
                    .bind(db_now_ms)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;

            if usize::try_from(live_count).unwrap_or(usize::MAX) >= self.max_entries {
                // Reclaim expired rows if any, but NEVER evict a live nonce.
                sqlx::query("DELETE FROM webhook_nonces WHERE expires_at_ms <= $1")
                    .bind(db_now_ms)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;
                return Err(ReplayError::CapacityExceeded);
            }

            sqlx::query("INSERT INTO webhook_nonces (nonce, expires_at_ms) VALUES ($1, $2)")
                .bind(nonce.as_slice())
                .bind(expires_at)
                .execute(&mut *tx)
                .await
                .map_err(|e| ReplayError::Backend(e.to_string()))?;

            tx.commit()
                .await
                .map_err(|e| ReplayError::Backend(e.to_string()))?;
            Ok(true)
        })
    }

    fn prune_expired<'a>(
        &'a self,
        _wall_now_ms: u64,
        _mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<usize, ReplayError>> {
        Box::pin(async move {
            let done = sqlx::query(
                "DELETE FROM webhook_nonces \
                 WHERE expires_at_ms <= (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT",
            )
            .execute(&self.pool)
            .await
            .map_err(|e| ReplayError::Backend(e.to_string()))?;
            Ok(usize::try_from(done.rows_affected()).unwrap_or(usize::MAX))
        })
    }
}

/// Durable PostgreSQL [`RateLimitStore`] implementing an atomic sliding window using
/// PostgreSQL's own `clock_timestamp()` so replica clock skew cannot prune active buckets.
#[derive(Clone, Debug)]
pub struct PostgresRateLimitStore {
    pool: PgPool,
    scope: String,
    window_ms: u64,
    max_per_window: usize,
}

impl PostgresRateLimitStore {
    /// Initializes the durable `rate_limit_buckets` table and returns a 1-minute
    /// sliding-window rate limiter isolated under `scope`.
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

    /// Initializes the durable `rate_limit_buckets` table with a custom window duration.
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
        apply_postgres_migrations(&pool).await.map_err(|e| {
            RateLimitError::Backend(format!("failed to apply postgres migrations: {e}"))
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
        _now_ms: u64,
    ) -> BoxFuture<'a, Result<Result<(), u64>, RateLimitError>> {
        Box::pin(async move {
            if self.max_per_window == 0 {
                return Ok(Err(self.window_ms.div_ceil(1_000).max(1)));
            }

            let window_i64 = i64::try_from(self.window_ms).unwrap_or(i64::MAX);

            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| RateLimitError::Backend(e.to_string()))?;

            let db_now_i64: i64 = sqlx::query_scalar(PG_NOW_MS_SQL)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| RateLimitError::Backend(e.to_string()))?;
            let db_now_u64 = u64::try_from(db_now_i64).unwrap_or(0);
            let cutoff_i64 = db_now_i64.saturating_sub(window_i64);
            let expires_at_i64 = db_now_i64.saturating_add(window_i64);

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
                    .unwrap_or(db_now_u64);
                let wait_ms = oldest_ms
                    .saturating_add(self.window_ms)
                    .saturating_sub(db_now_u64);
                let retry_after_secs = wait_ms.div_ceil(1_000).max(1);
                let _ = tx.rollback().await;
                return Ok(Err(retry_after_secs));
            }

            active.push(db_now_i64);

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

    fn prune_expired<'a>(&'a self, _now_ms: u64) -> BoxFuture<'a, Result<usize, RateLimitError>> {
        Box::pin(async move {
            let done = sqlx::query(
                "DELETE FROM rate_limit_buckets \
                 WHERE scope = $1 \
                   AND expires_at_ms <= (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT",
            )
            .bind(&self.scope)
            .execute(&self.pool)
            .await
            .map_err(|e| RateLimitError::Backend(e.to_string()))?;
            Ok(usize::try_from(done.rows_affected()).unwrap_or(usize::MAX))
        })
    }
}

fn migration_checksum_hex(sql: &str) -> String {
    let sum = digest(&SHA256, sql.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in sum.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

async fn apply_postgres_migrations(pool: &PgPool) -> Result<(), String> {
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(SCHEMA_INIT_LOCK_KEY)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    sqlx::query(PG_SCHEMA_MIGRATIONS_TABLE_SQL)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    let now_ms: i64 = sqlx::query_scalar(PG_NOW_MS_SQL)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    for migration in POSTGRES_MIGRATIONS {
        let expected_checksum = migration_checksum_hex(migration.sql);
        let existing: Option<String> =
            sqlx::query_scalar("SELECT checksum FROM schema_migrations WHERE version = $1")
                .bind(migration.version)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;

        if let Some(found) = existing {
            if found != expected_checksum {
                return Err(format!(
                    "PostgreSQL migration {} ({}) checksum mismatch: database has {found}, binary expects {expected_checksum}",
                    migration.version, migration.description
                ));
            }
            continue;
        }

        sqlx::raw_sql(migration.sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                format!(
                    "failed to apply PostgreSQL migration {} ({}): {e}",
                    migration.version, migration.description
                )
            })?;

        sqlx::query(
            "INSERT INTO schema_migrations (version, description, checksum, applied_at_ms) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(migration.version)
        .bind(migration.description)
        .bind(&expected_checksum)
        .bind(now_ms)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }

    tx.commit().await.map_err(|e| e.to_string())
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
