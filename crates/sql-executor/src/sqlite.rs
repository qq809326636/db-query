//!
//! Built on rusqlite + deadpool-sqlite (per-database native drivers, per the
//! overall design revision #2): the connection layer enforces a read-only hard
//! constraint (URI `mode=ro`, never creating files); queries advance statement
//! by statement via `Batch` (column names are available at prepare time, and
//! empty result sets keep their column names too); values surface as text +
//! null flags per their stored types; the health check implements core's
//! [`HealthCheck`] trait.

mod connection;
mod health;
mod query;

pub use connection::SqlitePool;
pub use health::SqliteHealthCheck;
pub use query::SqliteExecutor;

use std::time::Duration;

/// sqlite implementation-layer errors: structured English, carrying the database
#[derive(Debug, thiserror::Error)]
pub enum SqliteError {
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
    /// The database file does not exist (pre-open check; no file is created).
    #[error("sqlite database file not found for '{db_name}': {path}")]
    FileNotFound {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// The configured file path.
        path: String,
    },
    /// The database file exists but is unreadable (insufficient permissions or the path is a directory).
    #[error("sqlite database file not readable for '{db_name}': {path}")]
    FileNotReadable {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// The configured file path.
        path: String,
    },
    /// The file is readable but is not a valid SQLite database file (driver open
    #[error("sqlite file is not a database for '{db_name}': {path}: {detail}")]
    NotADatabase {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// The configured file path.
        path: String,
        /// Raw driver semantics.
        detail: String,
    },
    /// Other open / connection-acquisition failures.
    #[error("sqlite connection failed for database '{db_name}': {detail}")]
    Connection {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// Raw driver error.
        detail: String,
    },
    /// Query execution failed (passing through SQLite's raw semantics, e.g. table
    #[error("query failed for database '{db_name}': {detail}")]
    Query {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// Raw driver error.
        detail: String,
    },
    /// callback).
    #[error("query timed out for database '{db_name}': limit is {limit}s")]
    Timeout {
        /// Database unique id (uid, error identifier).
        db_name: String,
        /// The limit (seconds).
        limit: u64,
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

/// Execution timeout ceiling for a single query (seconds): interrupted via the
pub(crate) const QUERY_TIMEOUT_SECS: u64 = 30;

/// Progress-callback check granularity (deadline checked every N VM instructions).
pub(crate) const PROGRESS_HANDLER_OPS: i32 = 1_000;

/// Result-set text byte limit for user queries (sum of cell-text UTF-8 bytes,
/// including the hexadecimal text of BLOBs).
pub(crate) const RESULT_BYTE_LIMIT: usize = 10 * 1024 * 1024;

/// Default busy_timeout (milliseconds): bounded wait when concurrent reads hit
pub(crate) const BUSY_TIMEOUT_MS: u64 = 5_000;

/// Supported extra_opts keys (whitelist, embedded in the error message).
pub(crate) const EXTRA_OPTS_KEYS: &str = "[busy_timeout]";
