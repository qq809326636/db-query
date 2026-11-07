//! `SqlitePool`: SQLite read-only connection management (no file creation,
//! three classes of open errors, concurrent-read pool).

use super::{
    ACQUIRE_TIMEOUT, BUSY_TIMEOUT_MS, EXTRA_OPTS_KEYS, POOL_MAX_SIZE, QUERY_TIMEOUT_SECS,
    SqliteError,
};
use deadpool::managed::{PoolConfig, Timeouts};
use deadpool_sqlite::{Config as DeadpoolConfig, Pool, Runtime};
use excapp_db_core::config::DatabaseConfig;
use std::path::Path;
use std::time::Duration;

/// SQLite read-only connection pool: wraps the deadpool-sqlite pool plus the
/// database id.
pub struct SqlitePool {
    /// Database name (error identifier, carries config.uid).
    pub(crate) db_name: String,
    /// Database file path (for error messages and the pre-open check).
    pub(crate) path: String,
    /// busy_timeout (milliseconds): bounded wait when concurrent reads hit an
    /// external writer's lock.
    pub(crate) busy_timeout_ms: u64,
    /// The deadpool-sqlite pool (connections open read-only via URI `mode=ro`).
    pub(crate) inner: Pool,
}

impl std::fmt::Debug for SqlitePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlitePool")
            .field("db_name", &self.db_name)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SqlitePool {
    /// Create the read-only pool from config (lazy: no file is opened).
    ///
    /// The `db` field carries the file path (username / password / host / port
    /// are ignored); the `extra_opts` whitelist key `busy_timeout`
    /// (milliseconds) can override the 5-second default.
    ///
    /// Read-only hard constraint: connections open via URI
    /// `file:<path>?mode=ro` — `mode=ro` means "read-only and the file must
    /// already exist", so the connection layer has no write channel and never
    /// creates files.
    pub fn new(config: &DatabaseConfig) -> Result<Self, SqliteError> {
        let busy_timeout_ms = parse_busy_timeout(&config.extra_opts, &config.uid)?;

        let mut deadpool_config = DeadpoolConfig::new(read_only_uri(&config.db));
        deadpool_config.pool = Some(PoolConfig {
            max_size: POOL_MAX_SIZE,
            timeouts: Timeouts {
                wait: Some(ACQUIRE_TIMEOUT),
                ..Timeouts::default()
            },
            ..PoolConfig::default()
        });
        let pool =
            deadpool_config
                .create_pool(Runtime::Tokio1)
                .map_err(|e| SqliteError::Connection {
                    db_name: config.uid.clone(),
                    detail: e.to_string(),
                })?;

        Ok(Self {
            db_name: config.uid.clone(),
            path: config.db.clone(),
            busy_timeout_ms,
            inner: pool,
        })
    }

    /// Three-way pre-open classification: file missing / unreadable (mutually
    /// exclusive, distinguishable).
    ///
    /// The driver reports the same error code (unable to open database file) for
    /// both "missing" and "unreadable", so the first two cannot be told apart;
    /// the pre-open metadata check makes the three classes mutually exclusive.
    pub(crate) fn precheck(&self) -> Result<(), SqliteError> {
        let path = Path::new(&self.path);
        if !path.exists() {
            return Err(SqliteError::FileNotFound {
                db_name: self.db_name.clone(),
                path: self.path.clone(),
            });
        }
        // Metadata is queryable but opening as a regular file fails → unreadable
        // (insufficient permissions or a directory).
        if std::fs::File::open(path).is_err() {
            return Err(SqliteError::FileNotReadable {
                db_name: self.db_name.clone(),
                path: self.path.clone(),
            });
        }
        Ok(())
    }

    /// Acquire a connection (2s bounded wait): pre-open check + pool checkout.
    ///
    /// "Not a database file" is judged by the driver's open error (magic-number
    /// validation failure), mapped to [`SqliteError::NotADatabase`].
    pub(crate) async fn acquire(&self) -> Result<deadpool_sqlite::Object, SqliteError> {
        self.precheck()?;
        match tokio::time::timeout(ACQUIRE_TIMEOUT, self.inner.get()).await {
            Err(_) => Err(SqliteError::Connection {
                db_name: self.db_name.clone(),
                detail: format!(
                    "timed out after {}s waiting for an available connection",
                    ACQUIRE_TIMEOUT.as_secs()
                ),
            }),
            Ok(Err(e)) => Err(self.map_open_error(e.to_string())),
            Ok(Ok(object)) => Ok(object),
        }
    }

    /// Liveness-style acquisition + a lightweight query (for health checks).
    pub(crate) async fn acquire_probe(&self) -> Result<(), SqliteError> {
        let object = self.acquire().await?;
        object
            .interact(|conn| conn.execute_batch("SELECT 1"))
            .await
            .map_err(|e| SqliteError::Connection {
                db_name: self.db_name.clone(),
                detail: e.to_string(),
            })?
            .map_err(|e| self.map_open_error(e.to_string()))
    }

    /// Driver error mapping: open failures branch by semantics into
    /// NotADatabase / Connection.
    pub(crate) fn map_open_error(&self, detail: String) -> SqliteError {
        if detail.contains("file is not a database") {
            SqliteError::NotADatabase {
                db_name: self.db_name.clone(),
                path: self.path.clone(),
                detail,
            }
        } else {
            SqliteError::Connection {
                db_name: self.db_name.clone(),
                detail,
            }
        }
    }

    /// Query timeout ceiling (seconds).
    pub(crate) fn query_timeout(&self) -> Duration {
        Duration::from_secs(QUERY_TIMEOUT_SECS)
    }

    /// busy_timeout (milliseconds).
    pub(crate) fn busy_timeout(&self) -> Duration {
        Duration::from_millis(self.busy_timeout_ms)
    }
}

/// Build the read-only URI: `file:<percent-encoded path>?mode=ro`.
///
/// `mode=ro` makes SQLite open read-only and **requires the file to already
/// exist** (no creation); URI reserved characters in the path are
/// percent-encoded per RFC 3986 so they are not parsed as a query string.
fn read_only_uri(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len() + 16);
    for ch in path.chars() {
        match ch {
            '%' => encoded.push_str("%25"),
            '?' => encoded.push_str("%3F"),
            '#' => encoded.push_str("%23"),
            ' ' => encoded.push_str("%20"),
            _ => encoded.push(ch),
        }
    }
    format!("file:{encoded}?mode=ro")
}

/// Parse `busy_timeout` (milliseconds, the only whitelisted key; default 5000).
fn parse_busy_timeout(extra_opts: &str, uid: &str) -> Result<u64, SqliteError> {
    let mut timeout_ms = BUSY_TIMEOUT_MS;
    for pair in extra_opts.split_whitespace() {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(invalid(uid, pair));
        };
        if !key.eq_ignore_ascii_case("busy_timeout") {
            return Err(invalid(uid, pair));
        }
        timeout_ms = value.parse().map_err(|_| invalid(uid, pair))?;
    }
    Ok(timeout_ms)
}

fn invalid(uid: &str, raw: &str) -> SqliteError {
    SqliteError::InvalidExtraOpts {
        db_name: uid.to_string(),
        supported: EXTRA_OPTS_KEYS,
        raw: raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_path(path: &str) -> DatabaseConfig {
        DatabaseConfig {
            uid: "u".into(),
            name: "testdb".into(),
            description: "d".into(),
            db_type: "sqlite".into(),
            dialect: "sqlite".into(),
            username: String::new(),
            password: String::new(),
            host: String::new(),
            port: 0,
            db: path.into(),
            extra_opts: String::new(),
        }
    }

    #[test]
    fn test_read_only_uri_encodes_reserved_chars() {
        assert_eq!(read_only_uri("/tmp/a.db"), "file:/tmp/a.db?mode=ro");
        assert_eq!(
            read_only_uri("/tmp/a b?c#d%.db"),
            "file:/tmp/a%20b%3Fc%23d%25.db?mode=ro"
        );
    }

    #[tokio::test]
    async fn test_new_pool_is_lazy_no_file_created() {
        // Building the pool never creates a file (lazy + mode=ro requires the
        // file to already exist).
        let path = format!("/tmp/excapp-db-sqlite-lazy-{}.db", std::process::id());
        let _ = std::fs::remove_file(&path);
        let pool = SqlitePool::new(&config_with_path(&path)).unwrap();
        assert!(!Path::new(&path).exists());
        // Liveness triggers the open: missing file → FileNotFound, still no creation.
        let err = pool.acquire_probe().await.unwrap_err();
        assert!(matches!(err, SqliteError::FileNotFound { .. }), "{err}");
        assert!(!Path::new(&path).exists());
    }

    #[tokio::test]
    async fn test_precheck_distinguishes_missing_and_unreadable() {
        let missing = SqlitePool::new(&config_with_path("/nonexistent/x.db")).unwrap();
        assert!(matches!(
            missing.precheck().unwrap_err(),
            SqliteError::FileNotFound { .. }
        ));

        // Unreadable: a regular file without read permission (chmod 000).
        let path = format!("/tmp/excapp-db-sqlite-unreadable-{}.db", std::process::id());
        std::fs::write(&path, b"x").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o000);
        std::fs::set_permissions(&path, perms).unwrap();
        let unreadable = SqlitePool::new(&config_with_path(&path)).unwrap();
        let result = unreadable.precheck();
        let _ = std::fs::remove_file(&path);
        assert!(
            matches!(result.unwrap_err(), SqliteError::FileNotReadable { .. }),
            "expected FileNotReadable"
        );
    }

    #[tokio::test]
    async fn test_not_a_database_is_distinguishable() {
        let path = format!("/tmp/excapp-db-sqlite-garbage-{}.db", std::process::id());
        std::fs::write(&path, b"this is not a sqlite database at all").unwrap();
        let pool = SqlitePool::new(&config_with_path(&path)).unwrap();
        let err = pool.acquire_probe().await.unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(matches!(err, SqliteError::NotADatabase { .. }), "{err}");
    }

    #[test]
    fn test_parse_busy_timeout_overrides_default() {
        assert_eq!(parse_busy_timeout("", "u").unwrap(), 5_000);
        assert_eq!(parse_busy_timeout("busy_timeout=1000", "u").unwrap(), 1_000);
        let err = parse_busy_timeout("busy_timeout=abc", "u").unwrap_err();
        assert!(err.to_string().contains("busy_timeout=abc"), "{err}");
        let err = parse_busy_timeout("journal=WAL", "u").unwrap_err();
        assert!(err.to_string().contains("busy_timeout"), "{err}");
    }
}
