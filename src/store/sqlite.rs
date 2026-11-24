//! SQLite implementations of [`RegistrationStore`] and durable [`ReplayStore`].

use std::fmt;
use std::path::Path;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use ring::digest::{SHA256, digest};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};

use super::{
    ApnsEnv, BoxFuture, Platform, RegisterOutcome, Registration, RegistrationLimits,
    RegistrationStore, StoreError,
};
use crate::replay::{
    DEFAULT_MAX_NONCES_PER_HANDLE, NONCE_TTL_MS, ReplayError, ReplayStore, handle_replay_hash,
};

struct SqlMigration {
    version: i64,
    description: &'static str,
    sql: &'static str,
}

const SQLITE_MIGRATIONS: &[SqlMigration] = &[
    SqlMigration {
        version: 1,
        description: "initial",
        sql: include_str!("../../migrations/sqlite/0001_initial.sql"),
    },
    SqlMigration {
        version: 2,
        description: "replay_handle_hash",
        sql: include_str!("../../migrations/sqlite/0002_replay_handle_hash.sql"),
    },
];

const SCHEMA_MIGRATIONS_TABLE_SQL: &str = r"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version       INTEGER PRIMARY KEY NOT NULL,
    description   TEXT NOT NULL,
    checksum      TEXT NOT NULL,
    applied_at_ms INTEGER NOT NULL
) STRICT;
";

fn migration_checksum_hex(sql: &str) -> String {
    let sum = digest(&SHA256, sql.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in sum.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn current_epoch_ms_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

fn apply_sqlite_migrations(conn: &mut Connection) -> Result<(), String> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| format!("failed to begin migration transaction: {e}"))?;

    tx.execute_batch(SCHEMA_MIGRATIONS_TABLE_SQL)
        .map_err(|e| format!("failed to create schema_migrations table: {e}"))?;

    for migration in SQLITE_MIGRATIONS {
        let expected_checksum = migration_checksum_hex(migration.sql);
        let existing: Option<String> = tx
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = ?1",
                params![migration.version],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to query schema_migrations: {e}"))?;

        if let Some(found) = existing {
            if found != expected_checksum {
                return Err(format!(
                    "SQLite migration {} ({}) checksum mismatch: database has {found}, binary expects {expected_checksum}",
                    migration.version, migration.description
                ));
            }
            continue;
        }

        tx.execute_batch(migration.sql).map_err(|e| {
            format!(
                "failed to apply SQLite migration {} ({}): {e}",
                migration.version, migration.description
            )
        })?;
        tx.execute(
            "INSERT INTO schema_migrations (version, description, checksum, applied_at_ms) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                migration.version,
                migration.description,
                expected_checksum,
                current_epoch_ms_i64()
            ],
        )
        .map_err(|e| {
            format!(
                "failed to record SQLite migration {}: {e}",
                migration.version
            )
        })?;
    }

    tx.commit()
        .map_err(|e| format!("failed to commit SQLite migrations: {e}"))?;
    Ok(())
}

/// Shared thread-safe SQLite connection handle used by [`SqliteStore`] and [`SqliteReplayStore`].
#[derive(Clone)]
pub struct SqliteHandle {
    conn: Arc<Mutex<Connection>>,
}

impl fmt::Debug for SqliteHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteHandle").finish_non_exhaustive()
    }
}

impl SqliteHandle {
    async fn run<T, E, F>(&self, op: F) -> Result<T, E>
    where
        T: Send + 'static,
        E: Send + 'static + From<String>,
        F: FnOnce(&mut Connection) -> Result<T, E> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock();
            op(&mut guard)
        })
        .await
        .map_err(|e| E::from(format!("sqlite task join error: {e}")))?
    }
}

/// SQLite-backed [`RegistrationStore`].
#[derive(Clone, Debug)]
pub struct SqliteStore {
    handle: SqliteHandle,
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
        let target = path_or_url.to_owned();
        let conn = tokio::task::spawn_blocking(move || open_connection(&target))
            .await
            .map_err(|e| StoreError::Backend(format!("sqlite open task failed: {e}")))??;

        let handle = SqliteHandle {
            conn: Arc::new(Mutex::new(conn)),
        };

        handle
            .run(|conn| apply_sqlite_migrations(conn).map_err(StoreError::Backend))
            .await?;

        Ok(Self { handle })
    }

    /// Creates an ephemeral in-memory SQLite store for tests and local experiments.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] if initialization fails.
    pub async fn in_memory() -> Result<Self, StoreError> {
        Self::open(":memory:").await
    }

    /// Returns a reference to the shared [`SqliteHandle`] so [`SqliteReplayStore`] can
    /// persist nonces in the same SQLite database file.
    #[must_use]
    pub fn pool(&self) -> &SqliteHandle {
        &self.handle
    }
}

fn open_connection(path_or_url: &str) -> Result<Connection, StoreError> {
    let is_memory = path_or_url == ":memory:" || path_or_url == "sqlite::memory:";

    let conn = if is_memory {
        Connection::open_in_memory().map_err(|e| StoreError::Backend(e.to_string()))?
    } else {
        let stripped = path_or_url
            .strip_prefix("sqlite://")
            .or_else(|| path_or_url.strip_prefix("sqlite:"))
            .unwrap_or(path_or_url);
        let file_path = stripped.split('?').next().unwrap_or(stripped);
        if let Some(parent) = Path::new(file_path).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| StoreError::Backend(format!("failed to create db dir: {e}")))?;
        }
        Connection::open(file_path).map_err(|e| StoreError::Backend(e.to_string()))?
    };

    conn.busy_timeout(Duration::from_secs(5))
        .map_err(|e| StoreError::Backend(e.to_string()))?;

    if !is_memory {
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")
            .map_err(|e| StoreError::Backend(e.to_string()))?;
    }

    Ok(conn)
}

fn decode_row(row: &rusqlite::Row<'_>) -> Result<Registration, StoreError> {
    let handle: String = row
        .get(0)
        .map_err(|e| StoreError::CorruptData(e.to_string()))?;
    let platform_str: String = row
        .get(1)
        .map_err(|e| StoreError::CorruptData(e.to_string()))?;
    let platform = Platform::from_str(&platform_str)?;
    let device_token: String = row
        .get(2)
        .map_err(|e| StoreError::CorruptData(e.to_string()))?;
    let key_vec: Vec<u8> = row
        .get(3)
        .map_err(|e| StoreError::CorruptData(e.to_string()))?;
    let push_key: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| StoreError::CorruptData("push_key is not 32 bytes".to_owned()))?;
    let apns_env_str: Option<String> = row
        .get(4)
        .map_err(|e| StoreError::CorruptData(e.to_string()))?;
    let apns_env = apns_env_str.as_deref().map(ApnsEnv::from_str).transpose()?;
    let created_i64: i64 = row
        .get(5)
        .map_err(|e| StoreError::CorruptData(e.to_string()))?;
    let created_at_ms = u64::try_from(created_i64)
        .map_err(|_| StoreError::CorruptData("negative created_at_ms".to_owned()))?;
    let last_active_i64: i64 = row
        .get(6)
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

fn is_unique_violation(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.extended_code == 1555 || inner.extended_code == 2067
    )
}

impl From<String> for StoreError {
    fn from(msg: String) -> Self {
        Self::Backend(msg)
    }
}

impl From<String> for ReplayError {
    fn from(msg: String) -> Self {
        Self::Backend(msg)
    }
}

impl RegistrationStore for SqliteStore {
    fn register_or_get<'a>(
        &'a self,
        candidate: &'a Registration,
        limits: RegistrationLimits,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<RegisterOutcome, StoreError>> {
        let candidate = candidate.clone();
        Box::pin(async move {
            let now_i64 = i64::try_from(now_ms)
                .map_err(|_| StoreError::CorruptData("now_ms overflows i64".to_owned()))?;
            let cutoff_i64 = i64::try_from(now_ms.saturating_sub(limits.ttl_ms)).unwrap_or(0);

            self.handle
                .run(move |conn| {
                    let apns_env = candidate.apns_env.map(ApnsEnv::as_str);
                    let tx = conn
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .map_err(|e| StoreError::Backend(e.to_string()))?;

                    // 1. Idempotent re-registration: return existing active handle for the same
                    //    (platform, device_token, push_key, apns_env).
                    let existing: Option<String> = tx
                        .query_row(
                            "SELECT handle FROM registrations \
                             WHERE platform = ?1 AND device_token = ?2 AND push_key = ?3 \
                               AND apns_env IS ?4 AND last_active_at_ms > ?5 \
                             LIMIT 1",
                            params![
                                candidate.platform.as_str(),
                                &candidate.device_token,
                                candidate.push_key.as_slice(),
                                apns_env,
                                cutoff_i64
                            ],
                            |r| r.get(0),
                        )
                        .optional()
                        .map_err(|e| StoreError::Backend(e.to_string()))?;

                    if let Some(handle) = existing {
                        tx.execute(
                            "UPDATE registrations \
                             SET last_active_at_ms = MAX(last_active_at_ms, ?1) \
                             WHERE handle = ?2",
                            params![now_i64, &handle],
                        )
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                        tx.commit()
                            .map_err(|e| StoreError::Backend(e.to_string()))?;
                        return Ok(RegisterOutcome::Existing(handle));
                    }

                    // 2. Reclaim expired registrations so stale entries never block active ones.
                    tx.execute(
                        "DELETE FROM registrations WHERE last_active_at_ms <= ?1",
                        params![cutoff_i64],
                    )
                    .map_err(|e| StoreError::Backend(e.to_string()))?;

                    // 3. Enforce per-push-key active handle cap (never evicts existing handles).
                    let key_count: i64 = tx
                        .query_row(
                            "SELECT COUNT(*) FROM registrations WHERE push_key = ?1",
                            params![candidate.push_key.as_slice()],
                            |r| r.get(0),
                        )
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    if u64::try_from(key_count).unwrap_or(u64::MAX)
                        >= u64::from(limits.max_handles_per_push_key)
                    {
                        return Err(StoreError::PushKeyCapacityExceeded);
                    }

                    // 4. Enforce global registration capacity cap.
                    let total_count: i64 = tx
                        .query_row("SELECT COUNT(*) FROM registrations", [], |r| r.get(0))
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    if u64::try_from(total_count).unwrap_or(u64::MAX) >= limits.max_registrations {
                        return Err(StoreError::CapacityExceeded);
                    }

                    // 5. Insert fresh handle.
                    let res = tx.execute(
                        "INSERT INTO registrations \
                         (handle, platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            &candidate.handle,
                            candidate.platform.as_str(),
                            &candidate.device_token,
                            candidate.push_key.as_slice(),
                            apns_env,
                            now_i64,
                            now_i64
                        ],
                    );

                    match res {
                        Ok(_) => {
                            tx.commit()
                                .map_err(|e| StoreError::Backend(e.to_string()))?;
                            Ok(RegisterOutcome::Created(candidate.handle))
                        }
                        Err(err) if is_unique_violation(&err) => Err(StoreError::DuplicateHandle),
                        Err(err) => Err(StoreError::Backend(err.to_string())),
                    }
                })
                .await
        })
    }

    fn insert<'a>(
        &'a self,
        registration: &'a Registration,
        max_registrations: Option<u64>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let registration = registration.clone();
        Box::pin(async move {
            let created_at_ms = i64::try_from(registration.created_at_ms)
                .map_err(|_| StoreError::CorruptData("created_at_ms overflows i64".to_owned()))?;
            let last_active_at_ms =
                i64::try_from(registration.last_active_at_ms).map_err(|_| {
                    StoreError::CorruptData("last_active_at_ms overflows i64".to_owned())
                })?;

            self.handle
                .run(move |conn| {
                    let apns_env = registration.apns_env.map(ApnsEnv::as_str);
                    let result = if let Some(cap) = max_registrations {
                        let cap_i64 = i64::try_from(cap).unwrap_or(i64::MAX);
                        conn.execute(
                            "INSERT INTO registrations \
                             (handle, platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms) \
                             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 \
                             WHERE (SELECT COUNT(*) FROM registrations) < ?8",
                            params![
                                &registration.handle,
                                registration.platform.as_str(),
                                &registration.device_token,
                                registration.push_key.as_slice(),
                                apns_env,
                                created_at_ms,
                                last_active_at_ms,
                                cap_i64
                            ],
                        )
                    } else {
                        conn.execute(
                            "INSERT INTO registrations \
                             (handle, platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                            params![
                                &registration.handle,
                                registration.platform.as_str(),
                                &registration.device_token,
                                registration.push_key.as_slice(),
                                apns_env,
                                created_at_ms,
                                last_active_at_ms
                            ],
                        )
                    };

                    match result {
                        Ok(0) => Err(StoreError::CapacityExceeded),
                        Ok(_) => Ok(()),
                        Err(err) if is_unique_violation(&err) => Err(StoreError::DuplicateHandle),
                        Err(err) => Err(StoreError::Backend(err.to_string())),
                    }
                })
                .await
        })
    }

    fn get<'a>(
        &'a self,
        handle: &'a str,
    ) -> BoxFuture<'a, Result<Option<Registration>, StoreError>> {
        let handle = handle.to_owned();
        Box::pin(async move {
            self.handle
                .run(move |conn| {
                    let mut stmt = conn
                        .prepare(
                            "SELECT handle, platform, device_token, push_key, apns_env, \
                                    created_at_ms, last_active_at_ms \
                             FROM registrations WHERE handle = ?1",
                        )
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    let mut rows = stmt
                        .query(params![&handle])
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    match rows
                        .next()
                        .map_err(|e| StoreError::Backend(e.to_string()))?
                    {
                        Some(row) => decode_row(row).map(Some),
                        None => Ok(None),
                    }
                })
                .await
        })
    }

    fn get_active<'a>(
        &'a self,
        handle: &'a str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> BoxFuture<'a, Result<Option<Registration>, StoreError>> {
        let handle = handle.to_owned();
        let cutoff_i64 = i64::try_from(now_ms.saturating_sub(ttl_ms)).unwrap_or(i64::MAX);
        Box::pin(async move {
            self.handle
                .run(move |conn| {
                    let mut stmt = conn
                        .prepare(
                            "SELECT handle, platform, device_token, push_key, apns_env, \
                                    created_at_ms, last_active_at_ms \
                             FROM registrations WHERE handle = ?1 AND last_active_at_ms > ?2",
                        )
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    let mut rows = stmt
                        .query(params![&handle, cutoff_i64])
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    match rows
                        .next()
                        .map_err(|e| StoreError::Backend(e.to_string()))?
                    {
                        Some(row) => decode_row(row).map(Some),
                        None => Ok(None),
                    }
                })
                .await
        })
    }

    fn touch_last_active<'a>(
        &'a self,
        handle: &'a str,
        now_ms: u64,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let handle = handle.to_owned();
        let now_i64 = i64::try_from(now_ms).unwrap_or(i64::MAX);
        Box::pin(async move {
            self.handle
                .run(move |conn| {
                    conn.execute(
                        "UPDATE registrations \
                         SET last_active_at_ms = MAX(last_active_at_ms, ?1) \
                         WHERE handle = ?2",
                        params![now_i64, &handle],
                    )
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                    Ok(())
                })
                .await
        })
    }

    fn prune_expired<'a>(
        &'a self,
        now_ms: u64,
        ttl_ms: u64,
    ) -> BoxFuture<'a, Result<usize, StoreError>> {
        let cutoff_i64 = i64::try_from(now_ms.saturating_sub(ttl_ms)).unwrap_or(i64::MAX);
        Box::pin(async move {
            self.handle
                .run(move |conn| {
                    let deleted = conn
                        .execute(
                            "DELETE FROM registrations WHERE last_active_at_ms <= ?1",
                            params![cutoff_i64],
                        )
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    Ok(deleted)
                })
                .await
        })
    }

    fn delete<'a>(&'a self, handle: &'a str) -> BoxFuture<'a, Result<bool, StoreError>> {
        let handle = handle.to_owned();
        Box::pin(async move {
            self.handle
                .run(move |conn| {
                    let deleted = conn
                        .execute(
                            "DELETE FROM registrations WHERE handle = ?1",
                            params![&handle],
                        )
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    Ok(deleted > 0)
                })
                .await
        })
    }

    fn delete_if_not_newer_than<'a>(
        &'a self,
        handle: &'a str,
        max_last_active_ms: u64,
    ) -> BoxFuture<'a, Result<bool, StoreError>> {
        let handle = handle.to_owned();
        let max_i64 = i64::try_from(max_last_active_ms).unwrap_or(i64::MAX);
        Box::pin(async move {
            self.handle
                .run(move |conn| {
                    let deleted = conn
                        .execute(
                            "DELETE FROM registrations \
                             WHERE handle = ?1 AND last_active_at_ms <= ?2",
                            params![&handle, max_i64],
                        )
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    Ok(deleted > 0)
                })
                .await
        })
    }

    fn ping(&self) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(async move {
            self.handle
                .run(|conn| {
                    let _: i64 = conn
                        .query_row("SELECT 1", [], |r| r.get(0))
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    Ok(())
                })
                .await
        })
    }
}

/// Durable SQLite-backed [`ReplayStore`] for single-instance deployments.
///
/// Persists nonces in the `webhook_nonces` table so replay protection survives restarts,
/// enforces both per-handle and global live-entry caps without ever evicting live nonces,
/// and guards in-process entries with monotonic time so forward-and-back wall-clock jumps
/// cannot reopen a replay.
#[derive(Clone, Debug)]
pub struct SqliteReplayStore {
    handle: SqliteHandle,
    ttl_ms: u64,
    max_entries: usize,
    max_per_handle: usize,
    boot_id: [u8; 16],
}

impl SqliteReplayStore {
    /// Initializes the durable `webhook_nonces` table on `handle` using the standard
    /// 10-minute [`NONCE_TTL_MS`] window, `max_entries` global cap, and
    /// [`DEFAULT_MAX_NONCES_PER_HANDLE`].
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::Backend`] if schema initialization or RNG fails.
    pub async fn new(handle: SqliteHandle, max_entries: usize) -> Result<Self, ReplayError> {
        Self::with_limits(
            handle,
            NONCE_TTL_MS,
            max_entries,
            DEFAULT_MAX_NONCES_PER_HANDLE,
        )
        .await
    }

    /// Initializes the durable `webhook_nonces` table with a custom TTL and global cap.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::Backend`] if schema initialization or RNG fails.
    pub async fn with_ttl(
        handle: SqliteHandle,
        ttl_ms: u64,
        max_entries: usize,
    ) -> Result<Self, ReplayError> {
        Self::with_limits(handle, ttl_ms, max_entries, DEFAULT_MAX_NONCES_PER_HANDLE).await
    }

    /// Initializes the durable `webhook_nonces` table with explicit TTL, global cap, and
    /// per-handle active-nonce cap.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::Backend`] if schema initialization or RNG fails.
    pub async fn with_limits(
        handle: SqliteHandle,
        ttl_ms: u64,
        max_entries: usize,
        max_per_handle: usize,
    ) -> Result<Self, ReplayError> {
        let mut boot_id = [0u8; 16];
        getrandom::fill(&mut boot_id)
            .map_err(|_| ReplayError::Backend("failed to generate boot_id".to_owned()))?;

        handle
            .run(|conn| apply_sqlite_migrations(conn).map_err(ReplayError::Backend))
            .await?;

        Ok(Self {
            handle,
            ttl_ms,
            max_entries: max_entries.max(1),
            max_per_handle: max_per_handle.max(1),
            boot_id,
        })
    }

    /// Returns the total number of rows currently stored in `webhook_nonces` (read-only).
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::Backend`] if the query fails.
    pub async fn row_count(&self) -> Result<usize, ReplayError> {
        self.handle
            .run(|conn| {
                let count: i64 = conn
                    .query_row("SELECT COUNT(*) FROM webhook_nonces", [], |r| r.get(0))
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;
                Ok(usize::try_from(count).unwrap_or(usize::MAX))
            })
            .await
    }
}

impl ReplayStore for SqliteReplayStore {
    fn contains_live<'a>(
        &'a self,
        nonce: [u8; 16],
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ReplayError>> {
        let boot_id = self.boot_id;
        let wall_i64 = i64::try_from(wall_now_ms).unwrap_or(i64::MAX);
        let mono_i64 = i64::try_from(mono_now_ms).unwrap_or(i64::MAX);
        Box::pin(async move {
            self.handle
                .run(move |conn| {
                    // Row is live iff it exists and is NOT conservatively expired.
                    let found: Option<i64> = conn
                        .query_row(
                            "SELECT 1 FROM webhook_nonces \
                             WHERE nonce = ?1 \
                               AND NOT ( \
                                   (boot_id != ?2 AND expires_at_ms <= ?3) \
                                   OR (boot_id = ?2 AND expires_at_ms <= ?3 AND mono_expires_ms <= ?4) \
                               )",
                            params![nonce.as_slice(), boot_id.as_slice(), wall_i64, mono_i64],
                            |r| r.get(0),
                        )
                        .optional()
                        .map_err(|e| ReplayError::Backend(e.to_string()))?;
                    Ok(found.is_some())
                })
                .await
        })
    }

    fn check_and_record<'a>(
        &'a self,
        handle: &'a str,
        nonce: [u8; 16],
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<bool, ReplayError>> {
        let ttl_ms = self.ttl_ms;
        let max_entries = self.max_entries;
        let max_per_handle = self.max_per_handle;
        let boot_id = self.boot_id;
        let handle_hash = handle_replay_hash(handle);
        Box::pin(async move {
            let wall_i64 = i64::try_from(wall_now_ms)
                .map_err(|_| ReplayError::Backend("wall_now_ms overflows i64".to_owned()))?;
            let mono_i64 = i64::try_from(mono_now_ms)
                .map_err(|_| ReplayError::Backend("mono_now_ms overflows i64".to_owned()))?;
            let wall_exp = i64::try_from(wall_now_ms.saturating_add(ttl_ms)).unwrap_or(i64::MAX);
            let mono_exp = i64::try_from(mono_now_ms.saturating_add(ttl_ms)).unwrap_or(i64::MAX);

            self.handle
                .run(move |conn| {
                    let tx = conn
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .map_err(|e| ReplayError::Backend(e.to_string()))?;

                    // Prune entries that are conservatively expired.
                    tx.execute(
                        "DELETE FROM webhook_nonces \
                         WHERE (boot_id != ?1 AND expires_at_ms <= ?2) \
                            OR (boot_id = ?1 AND expires_at_ms <= ?2 AND mono_expires_ms <= ?3)",
                        params![boot_id.as_slice(), wall_i64, mono_i64],
                    )
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;

                    // If still present after conservative pruning, the nonce is live -> replay (409).
                    let exists: Option<i64> = tx
                        .query_row(
                            "SELECT 1 FROM webhook_nonces WHERE nonce = ?1",
                            params![nonce.as_slice()],
                            |r| r.get(0),
                        )
                        .optional()
                        .map_err(|e| ReplayError::Backend(e.to_string()))?;

                    if exists.is_some() {
                        tx.commit()
                            .map_err(|e| ReplayError::Backend(e.to_string()))?;
                        return Ok(false);
                    }

                    // Enforce per-handle active-nonce cap so one noisy handle cannot exhaust
                    // shared replay capacity.
                    let handle_live: i64 = tx
                        .query_row(
                            "SELECT COUNT(*) FROM webhook_nonces WHERE handle_hash = ?1",
                            params![handle_hash.as_slice()],
                            |r| r.get(0),
                        )
                        .map_err(|e| ReplayError::Backend(e.to_string()))?;
                    if usize::try_from(handle_live).unwrap_or(usize::MAX) >= max_per_handle {
                        tx.commit()
                            .map_err(|e| ReplayError::Backend(e.to_string()))?;
                        return Err(ReplayError::HandleCapacityExceeded);
                    }

                    // Never evict live nonces when full; refuse new webhooks with 503.
                    let live_count: i64 = tx
                        .query_row("SELECT COUNT(*) FROM webhook_nonces", [], |r| r.get(0))
                        .map_err(|e| ReplayError::Backend(e.to_string()))?;
                    if usize::try_from(live_count).unwrap_or(usize::MAX) >= max_entries {
                        tx.commit()
                            .map_err(|e| ReplayError::Backend(e.to_string()))?;
                        return Err(ReplayError::CapacityExceeded);
                    }

                    tx.execute(
                        "INSERT INTO webhook_nonces \
                         (nonce, expires_at_ms, boot_id, mono_expires_ms, handle_hash) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            nonce.as_slice(),
                            wall_exp,
                            boot_id.as_slice(),
                            mono_exp,
                            handle_hash.as_slice()
                        ],
                    )
                    .map_err(|e| ReplayError::Backend(e.to_string()))?;

                    tx.commit()
                        .map_err(|e| ReplayError::Backend(e.to_string()))?;
                    Ok(true)
                })
                .await
        })
    }

    fn prune_expired<'a>(
        &'a self,
        wall_now_ms: u64,
        mono_now_ms: u64,
    ) -> BoxFuture<'a, Result<usize, ReplayError>> {
        let boot_id = self.boot_id;
        let wall_i64 = i64::try_from(wall_now_ms).unwrap_or(i64::MAX);
        let mono_i64 = i64::try_from(mono_now_ms).unwrap_or(i64::MAX);
        Box::pin(async move {
            self.handle
                .run(move |conn| {
                    let deleted = conn
                        .execute(
                            "DELETE FROM webhook_nonces \
                             WHERE (boot_id != ?1 AND expires_at_ms <= ?2) \
                                OR (boot_id = ?1 AND expires_at_ms <= ?2 AND mono_expires_ms <= ?3)",
                            params![boot_id.as_slice(), wall_i64, mono_i64],
                        )
                        .map_err(|e| ReplayError::Backend(e.to_string()))?;
                    Ok(deleted)
                })
                .await
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
            let replay = SqliteReplayStore::with_limits(store.pool().clone(), NONCE_TTL_MS, 2, 2)
                .await
                .unwrap();
            assert!(!replay.contains_live(n1, 10_000, 0).await.unwrap());
            assert!(replay.check_and_record("h1", n1, 10_000, 0).await.unwrap());
            assert!(replay.contains_live(n1, 10_000, 0).await.unwrap());
            assert!(replay.check_and_record("h2", n2, 10_000, 0).await.unwrap());

            // Full: fresh nonce returns CapacityExceeded (503); live nonces still return false (409).
            assert!(matches!(
                replay.check_and_record("h3", n3, 10_000, 100).await,
                Err(ReplayError::CapacityExceeded)
            ));
            assert!(
                !replay
                    .check_and_record("h1", n1, 10_000, 100)
                    .await
                    .unwrap()
            );

            // Forward-and-back wall clock jump cannot expire live nonces in-process.
            assert_eq!(
                replay
                    .prune_expired(10_000 + NONCE_TTL_MS + 60_000, 5_000)
                    .await
                    .unwrap(),
                0
            );
            assert!(replay.contains_live(n1, 12_000, 6_000).await.unwrap());
            assert!(
                !replay
                    .check_and_record("h1", n1, 12_000, 6_000)
                    .await
                    .unwrap()
            );
        }

        // Simulate process restart by reopening the same SQLite database file.
        let reopened = SqliteStore::open(path_str).await.unwrap();
        let replay2 = SqliteReplayStore::with_limits(reopened.pool().clone(), NONCE_TTL_MS, 2, 1)
            .await
            .unwrap();
        assert!(!replay2.check_and_record("h1", n1, 20_000, 0).await.unwrap());
        assert!(!replay2.check_and_record("h2", n2, 20_000, 0).await.unwrap());

        // After 10-minute wall TTL passes across restart, nonces expire cleanly.
        assert!(
            replay2
                .check_and_record("h3", n3, 10_000 + NONCE_TTL_MS, 0)
                .await
                .unwrap()
        );
        // Per-handle cap (1) isolates h3 while allowing h4!
        assert!(matches!(
            replay2
                .check_and_record("h3", [4u8; 16], 10_000 + NONCE_TTL_MS, 0)
                .await,
            Err(ReplayError::HandleCapacityExceeded)
        ));
        assert!(
            replay2
                .check_and_record("h4", [4u8; 16], 10_000 + NONCE_TTL_MS, 0)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn applies_versioned_migrations_idempotently_and_detects_checksum_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("migrated.sqlite");
        let path_str = db_path.to_str().unwrap();

        let store = SqliteStore::open(path_str).await.unwrap();
        let versions: Vec<(i64, String)> = store
            .pool()
            .run(|conn| {
                let mut stmt = conn
                    .prepare("SELECT version, description FROM schema_migrations ORDER BY version")
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                let rows = stmt
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StoreError::Backend(e.to_string()))
            })
            .await
            .unwrap();
        assert_eq!(
            versions,
            vec![
                (1, "initial".to_owned()),
                (2, "replay_handle_hash".to_owned())
            ]
        );

        // Re-opening is idempotent.
        let store2 = SqliteStore::open(path_str).await.unwrap();
        store2.ping().await.unwrap();

        // Checksum tampering causes startup migration verification to fail loudly.
        store2
            .pool()
            .run(|conn| {
                conn.execute(
                    "UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1",
                    [],
                )
                .map_err(|e| StoreError::Backend(e.to_string()))?;
                Ok::<(), StoreError>(())
            })
            .await
            .unwrap();
        let err = SqliteStore::open(path_str).await.unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
    }
}
