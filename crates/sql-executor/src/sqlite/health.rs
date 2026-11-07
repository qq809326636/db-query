//! `SqliteHealthCheck`: the SQLite implementation of core's HealthCheck trait.

use super::SqlitePool;
use std::sync::Arc;
use std::time::Duration;

/// Liveness timeout ceiling (seconds): covers acquisition (including the first
/// open) plus the query as a whole.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// SQLite file-database health check: lightweight liveness probe (`SELECT 1`),
/// no internal state.
///
/// A full verdict = the file opens + is queryable (existence alone would miss
/// invalid files and corrupted pages); failure messages close the loop with the
/// three open-error classes.
pub struct SqliteHealthCheck {
    pool: Arc<SqlitePool>,
}

impl SqliteHealthCheck {
    /// Create a health check on the shared pool.
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }
}

impl excapp_db_core::watch::HealthCheck for SqliteHealthCheck {
    /// Liveness: acquire a connection (including the pre-open check and the
    /// first open) + `SELECT 1`, wrapped in a 5s timeout.
    ///
    /// Success returns `Ok(())`; failures (missing file / unreadable / invalid
    /// file / query error / timeout) return an English failure message
    /// (carrying the database id). No internal state: every call is judged
    /// independently, and once the file becomes usable the next check succeeds.
    fn check(&mut self) -> Result<(), String> {
        // The HealthCheck trait has a synchronous signature; the async probe runs
        // in a self-owned current-thread runtime (single-shot, short-lived, not
        // coupled to any external runtime).
        let pool = Arc::clone(&self.pool);
        tokio::task::block_in_place(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("building a current-thread tokio runtime cannot fail")
                .block_on(async move {
                    tokio::time::timeout(PROBE_TIMEOUT, async {
                        pool.acquire_probe().await.map_err(|e| e.to_string())
                    })
                    .await
                    .map_err(|_| {
                        format!(
                            "sqlite health check failed for '{}': timed out after {}s",
                            pool.db_name,
                            PROBE_TIMEOUT.as_secs()
                        )
                    })?
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use excapp_db_core::config::DatabaseConfig;
    use rusqlite::Connection;

    fn config_with_path(path: &str) -> DatabaseConfig {
        DatabaseConfig {
            uid: "test".into(),
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

    fn check_with_pool(pool: Arc<SqlitePool>) -> Result<(), String> {
        let mut hc = SqliteHealthCheck::new(pool);
        excapp_db_core::watch::HealthCheck::check(&mut hc)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_healthy_file_returns_ok() {
        let path = format!("/tmp/excapp-db-sqlite-hc-{}.db", std::process::id());
        let _ = std::fs::remove_file(&path);
        // Fixture: a valid SQLite file (the write channel is used only by test
        // fixtures).
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE t (v);")
            .unwrap();
        let pool = Arc::new(SqlitePool::new(&config_with_path(&path)).unwrap());
        assert!(check_with_pool(pool).is_ok());
        // Consecutive calls behave identically.
        let pool = Arc::new(SqlitePool::new(&config_with_path(&path)).unwrap());
        assert!(check_with_pool(pool).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_missing_file_failure_contains_identity() {
        let pool = Arc::new(SqlitePool::new(&config_with_path("/nonexistent/x.db")).unwrap());
        let err = check_with_pool(pool).unwrap_err();
        assert!(err.contains("'test'"), "{err}");
        assert!(err.contains("not found"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_not_a_database_failure() {
        let path = format!("/tmp/excapp-db-sqlite-hc-garbage-{}.db", std::process::id());
        std::fs::write(&path, b"this is not a sqlite database at all").unwrap();
        let pool = Arc::new(SqlitePool::new(&config_with_path(&path)).unwrap());
        let err = check_with_pool(pool).unwrap_err();
        assert!(err.contains("not a database"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_recovery_not_cached() {
        // Structural check for no internal state: the only field is the pool
        // (immutably shared).
        let pool = Arc::new(SqlitePool::new(&config_with_path("/tmp/x.db")).unwrap());
        let hc = SqliteHealthCheck::new(pool);
        let _ = hc;
    }
}
