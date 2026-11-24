//! SQLite implementations of [`RegistrationStore`] and durable [`ReplayStore`].

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::Row as _;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

use super::{
    ApnsEnv, BoxFuture, Platform, RegisterOutcome, Registration, RegistrationLimits,
    RegistrationStore, StoreError,
};
use crate::replay::{NONCE_TTL_MS, ReplayError, ReplayStore};

const REGISTRATIONS_TABLE_SQL: &str = r"
CREATE TABLE IF NOT EXISTS registrations (
    handle            TEXT PRIMARY KEY NOT NULL,
    platform          TEXT NOT NULL CHECK (platform IN ('apns', 'fcm')),
    device_token      TEXT NOT NULL,
    push_key          BLOB NOT NULL CHECK (length(push_key) = 32),
    apns_env          TEXT CHECK (apns_env IS NULL OR apns_env IN ('production', 'sandbox')),
    created_at_ms     INTEGER NOT NULL,
    last_active_at_ms INTEGER NOT NULL
) STRICT;
";

const REGISTRATIONS_INDEX_KEY_SQL: &str = r"
CREATE INDEX IF NOT EXISTS idx_registrations_push_key
    ON registrations (push_key);
";

const REGISTRATIONS_INDEX_ACTIVE_SQL: &str = r"
CREATE INDEX IF NOT EXISTS idx_registrations_last_active
    ON registrations (last_active_at_ms);
";

const NONCES_TABLE_SQL: &str = r"
CREATE TABLE IF NOT EXISTS webhook_nonces (
    nonce           BLOB PRIMARY KEY NOT NULL CHECK (length(nonce) = 16),
    expires_at_ms   INTEGER NOT NULL,
    boot_id         BLOB NOT NULL CHECK (length(boot_id) = 16),
    mono_expires_ms INTEGER NOT NULL
) STRICT;
";

const NONCES_INDEX_SQL: &str = r"
CREATE INDEX IF NOT EXISTS idx_webhook_nonces_expires_at
    ON webhook_nonces (expires_at_ms);
";

/// SQLite-backed [`RegistrationStore`].
#[derive(Clone, Debug)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Opens (and initializes if needed) a SQLite database at `path_or_url`.
    ///
    /// Accepts filesystem paths (e.g. `./data/push-relay.sqlite`), `sqlite://...` URLs,
    /// or `:memory:` for ephemeral storage.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] if the database cannot be opened or initialized.
    pub async fn open(path_or_url: &str) -> Result<Self, StoreError> {
        let is_memory = path_or_url == ":memory:" || path_or_url == "sqlite::memory:";

        let options = if is_memory {
            SqliteConnectOptions::from_str("sqlite::memory:")
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .busy_timeout(Duration::from_secs(5))
        } else {
            let file_path = path_or_url
                .strip_prefix("sqlite://")
                .or_else(|| path_or_url.strip_prefix("sqlite:"))
                .unwrap_or(path_or_url);
            if let Some(parent) = Path::new(file_path).parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)
                    .map_err(|e| StoreError::Backend(format!("failed to create db dir: {e}")))?;
            }
            SqliteConnectOptions::new()
                .filename(file_path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal)
                .busy_timeout(Duration::from_secs(5))
        };

        let max_connections = if is_memory { 1 } else { 8 };
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

        for stmt in [
            REGISTRATIONS_TABLE_SQL,
            REGISTRATIONS_INDEX_KEY_SQL,
            REGISTRATIONS_INDEX_ACTIVE_SQL,
        ] {
            sqlx::query(stmt)
                .execute(&pool)
                .await
                .map_err(|e| StoreError::Backend(format!("failed to initialize schema: {e}")))?;
        }

        Ok(Self { pool })
    }

    /// Creates an ephemeral in-memory SQLite store for tests and local experiments.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] if initialization fails.
    pub async fn in_memory() -> Result<Self, StoreError> {
        Self::open(":memory:").await
    }

    /// Returns a reference to the underlying [`SqlitePool`] so [`SqliteReplayStore`] can
    /// persist nonces in the same SQLite database file.
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn decode_row(row: &sqlx::sqlite::SqliteRow) -> Result<Registration, StoreError> {
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

impl RegistrationStore for SqliteStore {
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

            let mut tx = self
                .pool
                .begin_with("BEGIN IMMEDIATE")
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            // 1. Idempotent re-registration: return existing active handle for the same
            //    (platform, device_token, push_key, apns_env).
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT handle FROM registrations \
                 WHERE platform = ?1 AND device_token = ?2 AND push_key = ?3 \
                   AND apns_env IS ?4 AND last_active_at_ms > ?5 \
                 LIMIT 1",
            )
            .bind(candidate.platform.as_str())
            .bind(&candidate.device_token)
            .bind(candidate.push_key.as_slice())
            .bind(apns_env)
            .bind(cutoff_i64)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

            if let Some(handle) = existing {
                sqlx::query(
                    "UPDATE registrations \
                     SET last_active_at_ms = MAX(last_active_at_ms, ?1) \
                     WHERE handle = ?2",
                )
                .bind(now_i64)
                .bind(&handle)
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                return Ok(RegisterOutcome::Existing(handle));
            }

            // 2. Reclaim expired registrations so stale entries never block active ones.
            sqlx::query("DELETE FROM registrations WHERE last_active_at_ms <= ?1")
                .bind(cutoff_i64)
                .execute(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;

            // 3. Enforce per-push-key active handle cap (never evicts existing handles).
            let key_count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM registrations WHERE push_key = ?1")
                    .bind(candidate.push_key.as_slice())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
            if u64::try_from(key_count).unwrap_or(u64::MAX)
                >= u64::from(limits.max_handles_per_push_key)
            {
                let _ = tx.rollback().await;
                return Err(StoreError::PushKeyCapacityExceeded);
            }

            // 4. Enforce global registration capacity cap.
            let total_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM registrations")
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            if u64::try_from(total_count).unwrap_or(u64::MAX) >= limits.max_registrations {
                let _ = tx.rollback().await;
                return Err(StoreError::CapacityExceeded);
            }

            // 5. Insert fresh handle.
            let res = sqlx::query(
                "INSERT INTO registrations \
                 (handle, platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
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
                    tx.commit()
                        .await
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    Ok(RegisterOutcome::Created(candidate.handle.clone()))
                }
                Err(sqlx::Error::Database(db_err))
                    if db_err.is_unique_violation()
                        || matches!(db_err.code().as_deref(), Some("1555" | "2067")) =>
                {
                    let _ = tx.rollback().await;
                    Err(StoreError::DuplicateHandle)
                }
                Err(err) => {
                    let _ = tx.rollback().await;
                    Err(StoreError::Backend(err.to_string()))
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

            let result = if let Some(cap) = max_registrations {
                let cap_i64 = i64::try_from(cap).unwrap_or(i64::MAX);
                sqlx::query(
                    "INSERT INTO registrations \
                     (handle, platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms) \
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 \
                     WHERE (SELECT COUNT(*) FROM registrations) < ?8",
                )
                .bind(&registration.handle)
                .bind(registration.platform.as_str())
                .bind(&registration.device_token)
                .bind(registration.push_key.as_slice())
                .bind(apns_env)
                .bind(created_at_ms)
                .bind(last_active_at_ms)
                .bind(cap_i64)
                .execute(&self.pool)
                .await
            } else {
                sqlx::query(
                    "INSERT INTO registrations \
                     (handle, platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .bind(&registration.handle)
                .bind(registration.platform.as_str())
                .bind(&registration.device_token)
                .bind(registration.push_key.as_slice())
                .bind(apns_env)
                .bind(created_at_ms)
                .bind(last_active_at_ms)
                .execute(&self.pool)
                .await
            };

            match result {
                Ok(done) if done.rows_affected() == 0 => Err(StoreError::CapacityExceeded),
                Ok(_) => Ok(()),
                Err(sqlx::Error::Database(db_err))
                    if db_err.is_unique_violation()
                        || matches!(db_err.code().as_deref(), Some("1555" | "2067")) =>
                {
                    Err(StoreError::DuplicateHandle)
                }
                Err(err) => Err(StoreError::Backend(err.to_string())),
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
                 FROM registrations WHERE handle = ?1",
            )
            .bind(handle)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

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
                 FROM registrations WHERE handle = ?1 AND last_active_at_ms > ?2",
            )
            .bind(handle)
            .bind(cutoff_i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

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
                 SET last_active_at_ms = MAX(last_active_at_ms, ?1) \
                 WHERE handle = ?2",
            )
            .bind(now_i64)
            .bind(handle)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn delete<'a>(&'a self, handle: &'a str) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let res = sqlx::query("DELETE FROM registrations WHERE handle = ?1")
                .bind(handle)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(res.rows_affected() > 0)
        })
    }

    fn prune_expired<'a>(&'a self, cutoff_ms: u64) -> BoxFuture<'a, Result<usize, StoreError>> {
        Box::pin(async move {
            let cutoff_i64 = i64::try_from(cutoff_ms).unwrap_or(i64::MAX);
            let res = sqlx::query("DELETE FROM registrations WHERE last_active_at_ms <= ?1")
                .bind(cutoff_i64)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(usize::try_from(res.rows_affected()).unwrap_or(usize::MAX))
        })
    }

    fn ping<'a>(&'a self) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            sqlx::query("SELECT 1")
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }
}

/// Durable SQLite-backed [`ReplayStore`].
///
/// Persists webhook nonces to disk so restarts preserve the 10-minute replay window,
/// enforces a hard live-entry cap without ever evicting live nonces (`503` when full),
/// and guards in-process entries with monotonic time so forward-and-back wall-clock jumps
/// cannot reopen a replay.
#[derive(Clone, Debug)]
pub struct SqliteReplayStore {
    pool: SqlitePool,
    ttl_ms: u64,
    max_entries: usize,
    boot_id: [u8; 16],
}

impl SqliteReplayStore {
    /// Initializes the durable `webhook_nonces` table on `pool` using the standard
    /// 10-minute [`NONCE_TTL_MS`] window and `max_entries` cap.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::Backend`] if schema initialization or RNG fails.
    pub async fn new(pool: SqlitePool, max_entries: usize) -> Result<Self, ReplayError> {
        Self::with_ttl(pool, NONCE_TTL_MS, max_entries).await
    }

    /// Initializes the durable `webhook_nonces` table with a custom TTL and cap.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::Backend`] if schema initialization or RNG fails.
    pub async fn with_ttl(
        pool: SqlitePool,
        ttl_ms: u64,
        max_entries: usize,
    ) -> Result<Self, ReplayError> {
        let mut boot_id = [0u8; 16];
        getrandom::fill(&mut boot_id)
            .map_err(|_| ReplayError::Backend("failed to generate boot_id".to_owned()))?;

        for stmt in [NONCES_TABLE_SQL, NONCES_INDEX_SQL] {
            sqlx::query(stmt)
                .execute(&pool)
                .await
                .map_err(|e| ReplayError::Backend(format!("failed to init webhook_nonces: {e}")))?;
        }

        Ok(Self {
            pool,
            ttl_ms,
            max_entries: max_entries.max(1),
            boot_id,
        })
    }
}

impl ReplayStore for SqliteReplayStore {
    fn check_and_record<'a>(
        &'a self,
        nonce: [u8; 16],
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ReplayError>> {
        Box::pin(async move {
            let wall_i64 = i64::try_from(wall_now_ms)
                .map_err(|_| ReplayError::Backend("wall_now_ms overflows i64".to_owned()))?;
            let mono_i64 = i64::try_from(mono_now_ms)
                .map_err(|_| ReplayError::Backend("mono_now_ms overflows i64".to_owned()))?;
            let wall_exp =
                i64::try_from(wall_now_ms.saturating_add(self.ttl_ms)).unwrap_or(i64::MAX);
            let mono_exp =
                i64::try_from(mono_now_ms.saturating_add(self.ttl_ms)).unwrap_or(i64::MAX);

            let mut tx = self
                .pool
                .begin_with("BEGIN IMMEDIATE")
                .await
                .map_err(|e| ReplayError::Backend(e.to_string()))?;

            // Prune entries that are conservatively expired.
            sqlx::query(
                "DELETE FROM webhook_nonces \
                 WHERE (boot_id != ?1 AND expires_at_ms <= ?2) \
                    OR (boot_id = ?1 AND expires_at_ms <= ?2 AND mono_expires_ms <= ?3)",
            )
            .bind(self.boot_id.as_slice())
            .bind(wall_i64)
            .bind(mono_i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| ReplayError::Backend(e.to_string()))?;

            // If still present after conservative pruning, the nonce is live -> replay (409).
            let exists: Option<i64> =
                sqlx::query_scalar("SELECT 1 FROM webhook_nonces WHERE nonce = ?1")
                    .bind(nonce.as_slice())
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;

            if exists.is_some() {
                tx.commit()
                    .await
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;
                return Ok(false);
            }

            // Never evict live nonces when full; refuse new webhooks with 503.
            let live_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_nonces")
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| ReplayError::Backend(e.to_string()))?;
            if usize::try_from(live_count).unwrap_or(usize::MAX) >= self.max_entries {
                tx.commit()
                    .await
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;
                return Err(ReplayError::CapacityExceeded);
            }

            sqlx::query(
                "INSERT INTO webhook_nonces (nonce, expires_at_ms, boot_id, mono_expires_ms) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(nonce.as_slice())
            .bind(wall_exp)
            .bind(self.boot_id.as_slice())
            .bind(mono_exp)
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
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<usize, ReplayError>> {
        Box::pin(async move {
            let wall_i64 = i64::try_from(wall_now_ms).unwrap_or(i64::MAX);
            let mono_i64 = i64::try_from(mono_now_ms).unwrap_or(i64::MAX);
            let res = sqlx::query(
                "DELETE FROM webhook_nonces \
                 WHERE (boot_id != ?1 AND expires_at_ms <= ?2) \
                    OR (boot_id = ?1 AND expires_at_ms <= ?2 AND mono_expires_ms <= ?3)",
            )
            .bind(self.boot_id.as_slice())
            .bind(wall_i64)
            .bind(mono_i64)
            .execute(&self.pool)
            .await
            .map_err(|e| ReplayError::Backend(e.to_string()))?;
            Ok(usize::try_from(res.rows_affected()).unwrap_or(usize::MAX))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(handle: &str) -> Registration {
        Registration {
            handle: handle.to_owned(),
            platform: Platform::Apns,
            device_token: "a".repeat(64),
            push_key: [7u8; 32],
            apns_env: Some(ApnsEnv::Production),
            created_at_ms: 1_767_225_960_000,
            last_active_at_ms: 1_767_225_960_000,
        }
    }

    #[tokio::test]
    async fn insert_get_delete_and_duplicate_rejection() {
        let store = SqliteStore::in_memory().await.unwrap();
        store.ping().await.unwrap();

        let reg = sample("handle-1");
        store.insert(&reg, None).await.unwrap();

        let loaded = store.get("handle-1").await.unwrap().unwrap();
        assert_eq!(loaded, reg);

        assert!(matches!(
            store.insert(&reg, None).await,
            Err(StoreError::DuplicateHandle)
        ));

        let second = sample("handle-2");
        store.insert(&second, None).await.unwrap();
        assert_eq!(store.get("handle-1").await.unwrap().unwrap(), reg);
        assert_eq!(store.get("handle-2").await.unwrap().unwrap(), second);

        assert!(store.delete("handle-1").await.unwrap());
        assert!(!store.delete("handle-1").await.unwrap());
        assert!(store.get("handle-1").await.unwrap().is_none());
        assert!(store.get("handle-2").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn enforces_max_registrations_cap_and_reclaims_space_on_delete() {
        let store = SqliteStore::in_memory().await.unwrap();

        assert!(matches!(
            store.insert(&sample("h0"), Some(0)).await,
            Err(StoreError::CapacityExceeded)
        ));

        store.insert(&sample("h1"), Some(2)).await.unwrap();
        store.insert(&sample("h2"), Some(2)).await.unwrap();
        assert!(matches!(
            store.insert(&sample("h3"), Some(2)).await,
            Err(StoreError::CapacityExceeded)
        ));

        assert!(store.delete("h1").await.unwrap());
        store.insert(&sample("h3"), Some(2)).await.unwrap();
        assert!(store.get("h3").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn register_or_get_is_idempotent_caps_per_key_and_expires_idle_rows() {
        let store = SqliteStore::in_memory().await.unwrap();
        let limits = RegistrationLimits {
            max_registrations: 100,
            max_handles_per_push_key: 2,
            ttl_ms: 10_000,
        };

        let mut c1 = sample("h-1");
        c1.device_token = "a".repeat(64);
        let r1 = store.register_or_get(&c1, limits, 1_000).await.unwrap();
        assert_eq!(r1, RegisterOutcome::Created("h-1".to_owned()));

        // Re-registering same (platform, token, push_key, apns_env) returns existing handle.
        let mut c1_dup = sample("h-1-new");
        c1_dup.device_token = "a".repeat(64);
        let r1_again = store.register_or_get(&c1_dup, limits, 2_000).await.unwrap();
        assert_eq!(r1_again, RegisterOutcome::Existing("h-1".to_owned()));
        assert_eq!(
            store.get("h-1").await.unwrap().unwrap().last_active_at_ms,
            2_000
        );

        // Second distinct token under the same push key succeeds.
        let mut c2 = sample("h-2");
        c2.device_token = "b".repeat(64);
        let r2 = store.register_or_get(&c2, limits, 2_000).await.unwrap();
        assert_eq!(r2, RegisterOutcome::Created("h-2".to_owned()));

        // Third distinct token under the same push key is refused without evicting h-1 or h-2.
        let mut c3 = sample("h-3");
        c3.device_token = "c".repeat(64);
        assert!(matches!(
            store.register_or_get(&c3, limits, 2_000).await,
            Err(StoreError::PushKeyCapacityExceeded)
        ));
        assert!(store.get("h-1").await.unwrap().is_some());
        assert!(store.get("h-2").await.unwrap().is_some());

        // After TTL passes with no webhook activity, expired rows are reclaimed cleanly.
        let r3 = store.register_or_get(&c3, limits, 12_001).await.unwrap();
        assert_eq!(r3, RegisterOutcome::Created("h-3".to_owned()));
        assert!(store.get("h-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sqlite_replay_persists_across_restart_and_refuses_when_full() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relay.sqlite");
        let path_str = db_path.to_str().unwrap();

        let n1 = [1u8; 16];
        let n2 = [2u8; 16];
        let n3 = [3u8; 16];

        {
            let store = SqliteStore::open(path_str).await.unwrap();
            let replay = SqliteReplayStore::new(store.pool().clone(), 2)
                .await
                .unwrap();
            assert!(replay.check_and_record(n1, 10_000, 0).await.unwrap());
            assert!(replay.check_and_record(n2, 10_000, 0).await.unwrap());

            // Full: fresh nonce returns CapacityExceeded (503); live nonces still return false (409).
            assert!(matches!(
                replay.check_and_record(n3, 10_000, 100).await,
                Err(ReplayError::CapacityExceeded)
            ));
            assert!(!replay.check_and_record(n1, 10_000, 100).await.unwrap());

            // Forward-and-back wall clock jump cannot expire live nonces in-process.
            assert_eq!(
                replay
                    .prune_expired(10_000 + NONCE_TTL_MS + 60_000, 5_000)
                    .await
                    .unwrap(),
                0
            );
            assert!(!replay.check_and_record(n1, 12_000, 6_000).await.unwrap());
        }

        // Simulate process restart by reopening the same SQLite database file.
        let reopened = SqliteStore::open(path_str).await.unwrap();
        let replay2 = SqliteReplayStore::new(reopened.pool().clone(), 2)
            .await
            .unwrap();
        assert!(!replay2.check_and_record(n1, 20_000, 0).await.unwrap());
        assert!(!replay2.check_and_record(n2, 20_000, 0).await.unwrap());

        // After 10-minute wall TTL passes across restart, nonces expire cleanly.
        assert!(
            replay2
                .check_and_record(n3, 10_000 + NONCE_TTL_MS, 0)
                .await
                .unwrap()
        );
    }
}
