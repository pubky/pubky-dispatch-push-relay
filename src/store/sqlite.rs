//! SQLite implementation of [`RegistrationStore`].

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::Row as _;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

use super::{ApnsEnv, BoxFuture, Platform, Registration, RegistrationStore, StoreError};

const SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS registrations (
    handle        TEXT PRIMARY KEY NOT NULL,
    platform      TEXT NOT NULL CHECK (platform IN ('apns', 'fcm')),
    device_token  TEXT NOT NULL,
    push_key      BLOB NOT NULL CHECK (length(push_key) = 32),
    apns_env      TEXT CHECK (apns_env IS NULL OR apns_env IN ('production', 'sandbox')),
    created_at_ms INTEGER NOT NULL
) STRICT;
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

        sqlx::query(SCHEMA_SQL)
            .execute(&pool)
            .await
            .map_err(|e| StoreError::Backend(format!("failed to initialize schema: {e}")))?;

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
}

impl RegistrationStore for SqliteStore {
    fn insert<'a>(
        &'a self,
        registration: &'a Registration,
        max_registrations: Option<u64>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let created_at_ms = i64::try_from(registration.created_at_ms)
                .map_err(|_| StoreError::CorruptData("created_at_ms overflows i64".to_owned()))?;
            let apns_env = registration.apns_env.map(ApnsEnv::as_str);

            let result = if let Some(cap) = max_registrations {
                let cap_i64 = i64::try_from(cap).unwrap_or(i64::MAX);
                sqlx::query(
                    "INSERT INTO registrations \
                     (handle, platform, device_token, push_key, apns_env, created_at_ms) \
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6 \
                     WHERE (SELECT COUNT(*) FROM registrations) < ?7",
                )
                .bind(&registration.handle)
                .bind(registration.platform.as_str())
                .bind(&registration.device_token)
                .bind(registration.push_key.as_slice())
                .bind(apns_env)
                .bind(created_at_ms)
                .bind(cap_i64)
                .execute(&self.pool)
                .await
            } else {
                sqlx::query(
                    "INSERT INTO registrations \
                     (handle, platform, device_token, push_key, apns_env, created_at_ms) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .bind(&registration.handle)
                .bind(registration.platform.as_str())
                .bind(&registration.device_token)
                .bind(registration.push_key.as_slice())
                .bind(apns_env)
                .bind(created_at_ms)
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
                "SELECT handle, platform, device_token, push_key, apns_env, created_at_ms \
                 FROM registrations WHERE handle = ?1",
            )
            .bind(handle)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;

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
            let res = sqlx::query("DELETE FROM registrations WHERE handle = ?1")
                .bind(handle)
                .execute(&self.pool)
                .await
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(res.rows_affected() > 0)
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

        // Same device token under a distinct handle is allowed (fresh handle, no redirection).
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

        // Cap of 0 rejects immediately.
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

        // Deleting a handle frees capacity for a subsequent registration.
        assert!(store.delete("h1").await.unwrap());
        store.insert(&sample("h3"), Some(2)).await.unwrap();
        assert!(store.get("h3").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn persists_across_reopen_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("nested").join("relay.sqlite");
        let path_str = db_path.to_str().unwrap();

        let reg = sample("disk-handle");
        {
            let store = SqliteStore::open(path_str).await.unwrap();
            store.insert(&reg, None).await.unwrap();
        }
        let reopened = SqliteStore::open(path_str).await.unwrap();
        assert_eq!(reopened.get("disk-handle").await.unwrap().unwrap(), reg);
    }
}
