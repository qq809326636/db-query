//! (`MyExecutor`) and health check (`MyHealthCheck`).
//!
//! Built on mysql_async (per-database native drivers, per the overall design
//! revision #2): the pool connects lazily (max 10); queries go through the
//! text protocol `query_iter` (multi-statement batch, timeout atomically bound
//! via a same-string prefixed SET); values surface as text + null flags; the
//! health check implements core's [`HealthCheck`] trait.

mod connection;
mod execute;
mod health;

pub use connection::MyPool;
pub use execute::MyExecutor;
pub use health::MyHealthCheck;

#[cfg(test)]
use excapp_db_core::config::DatabaseConfig;
use std::time::Duration;

/// mysql implementation-layer errors: structured English, carrying the database
#[derive(Debug, thiserror::Error)]
pub enum MyError {
    /// whitelist, or an invalid value).
    #[error(
        "invalid extra_opts for database '{db_name}': expected space-separated key=value pairs with keys from {supported}, got '{raw}'"
    )]
    InvalidExtraOpts {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// Supported key list (embedded in the error message).
        supported: &'static str,
        /// Raw input.
        raw: String,
    },
    /// Failed to get a connection from the pool (including connect failures:
    #[error("mysql connection failed for database '{db_name}': {detail}")]
    Connection {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// Raw driver error (preserving refused / auth-failure semantics).
        detail: String,
    },
    /// does not exist).
    #[error("query failed for database '{db_name}': {detail}")]
    Query {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// Raw driver error.
        detail: String,
    },
    /// Result row count exceeds the limit (no partial results returned).
    #[error(
        "query result exceeds row limit for database '{db_name}': got {actual} rows, limit is {limit}"
    )]
    RowLimit {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// Actual row count.
        actual: usize,
        /// The limit (100).
        limit: usize,
    },
    /// partial results returned).
    #[error(
        "query result exceeds byte limit for database '{db_name}': got {actual} bytes, limit is {limit}"
    )]
    ByteLimit {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// Actual byte total (sum of cell-text UTF-8 bytes).
        actual: usize,
        /// The limit (10MB).
        limit: usize,
    },
}

/// Row limit for a single query result.
pub(crate) const ROW_LIMIT: usize = 100;

/// Pool size limit (fixed, not configurable).
pub(crate) const POOL_MAX_SIZE: usize = 10;

/// Wait limit for acquiring a connection (bounded wait when the pool is exhausted).
pub(crate) const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum execution time for a single SELECT (milliseconds, server-side cancel).
///
/// MySQL 8.0+'s `max_execution_time` only applies to SELECT (fully covering the
/// read-only scenario); timeout error code is 3024.
pub(crate) const MAX_EXECUTION_TIME_MS: u32 = 30_000;

/// Result-set text byte limit for user queries (sum of cell-text UTF-8 bytes).
///
/// Only `execute` (user queries) is bounded; metadata queries are not.
pub(crate) const RESULT_BYTE_LIMIT: usize = 10 * 1024 * 1024;

/// Supported extra_opts keys (whitelist, embedded in the error message).
pub(crate) const EXTRA_OPTS_KEYS: &str = "[ssl-mode, charset]";

/// Test helper: read the test database config from environment variables
#[cfg(test)]
pub(crate) fn test_config() -> DatabaseConfig {
    DatabaseConfig {
        uid: "test".into(),
        name: "testdb".into(),
        description: "integration test db".into(),
        db_type: "mysql".into(),
        dialect: "mysql".into(),
        username: std::env::var("TEST_MY_USER").unwrap_or_else(|_| "test".into()),
        password: std::env::var("TEST_MY_PASSWORD").unwrap_or_else(|_| "test".into()),
        host: std::env::var("TEST_MY_HOST").unwrap_or_else(|_| "localhost".into()),
        port: std::env::var("TEST_MY_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(13306),
        db: std::env::var("TEST_MY_DB").unwrap_or_else(|_| "testdb".into()),
        extra_opts: String::new(),
    }
}

/// Test helper: probe whether the connection is usable (async).
#[cfg(test)]
pub(crate) async fn connection_available(pool: &MyPool) -> bool {
    tokio::time::timeout(Duration::from_secs(2), pool.acquire_probe())
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}
