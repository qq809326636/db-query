//! execution (PgQuery), and health check (PgHealthCheck).
//!
//! The pool connects lazily (deadpool, max 10); queries go through the
//! simple query protocol (multi-statement batches supported); values are
//! rendered as text + a null flag; the health check implements core's
//! [`HealthCheck`] trait.

mod connection;
mod execute;
mod health;

pub use connection::PgPool;
pub use execute::PgExecutor;
pub use health::PgHealthCheck;

#[cfg(test)]
use excapp_db_core::config::DatabaseConfig;
#[cfg(test)]
use std::time::Duration;

/// pg implementation-layer error: structured English, includes the
#[derive(Debug, thiserror::Error)]
pub enum PgError {
    /// extra_opts failed to parse (not in `key=value` pair form).
    #[error(
        "invalid extra_opts for database '{db_name}': expected space-separated key=value pairs, got '{raw}'"
    )]
    InvalidExtraOpts {
        /// Database name (error identity).
        db_name: String,
        /// Raw input.
        raw: String,
    },
    /// Failed to get a connection from the pool (including connection
    #[error("postgres connection failed for database '{db_name}': {detail}")]
    Connection {
        /// Database name (error identity).
        db_name: String,
        /// Raw driver error (preserving refused / auth-failure semantics).
        detail: String,
    },
    /// a missing table).
    #[error("query failed for database '{db_name}': {detail}")]
    Query {
        /// Database name (error identity).
        db_name: String,
        /// Raw driver error.
        detail: String,
    },
    /// Result row count exceeds the limit (no partial results).
    #[error(
        "query result exceeds row limit for database '{db_name}': got {actual} rows, limit is {limit}"
    )]
    RowLimit {
        /// Database name (error identity).
        db_name: String,
        /// Actual row count.
        actual: usize,
        /// The limit (100).
        limit: usize,
    },
    /// Result set text byte total exceeds the limit (user queries only;
    #[error(
        "query result exceeds byte limit for database '{db_name}': got {actual} bytes, limit is {limit}"
    )]
    ByteLimit {
        /// Database name (error identity).
        db_name: String,
        /// Actual byte total (sum of cell text UTF-8 bytes).
        actual: usize,
        /// The limit (10MB).
        limit: usize,
    },
}

/// Flatten the driver error's source chain to capture the full semantics
/// (tokio-postgres's Display often says just "db error"; the real cause is
/// up the chain, e.g. "password authentication failed").
///
/// Server error messages vary with locale (English / Chinese), so the
pub(crate) fn flatten_error(e: &dyn std::error::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut src = e.source();
    while let Some(s) = src {
        let text = s.to_string();
        // error").
        if !parts.contains(&text) {
            parts.push(text);
        }
        src = s.source();
    }
    let mut joined = parts.join(": ");
    // innermost error.
    if let Some(code) = extract_sqlstate(e).filter(|c| !joined.contains(c)) {
        joined.push_str(&format!(" (SQLSTATE {code})"));
    }
    joined
}

/// Search the source chain for a tokio-postgres DbError's SQLSTATE.
fn extract_sqlstate(e: &dyn std::error::Error) -> Option<String> {
    let dbg = format!("{e:?}");
    let idx = dbg.find("SqlState(")?;
    let rest = &dbg[idx + "SqlState(".len()..];
    let end = rest.find(')')?;
    Some(rest[..end].trim_matches('"').to_string())
}

/// Row limit for a single query result.
pub(crate) const ROW_LIMIT: usize = 100;

/// Pool size limit (fixed, not configurable).
pub(crate) const POOL_MAX_SIZE: usize = 10;

/// Connection-level statement timeout (statement_timeout): prevents long
/// queries like pg_sleep from exhausting the pool.
///
/// Applies to every statement on the connection (including metadata
pub(crate) const STATEMENT_TIMEOUT: &str = "30s";

/// Byte-total limit for user query result set text (sum of cell text
/// UTF-8 bytes).
///
/// Only `execute` (user queries) is bounded; metadata tooling
pub(crate) const RESULT_BYTE_LIMIT: usize = 10 * 1024 * 1024;
/// Test helper: read the test database config from environment variables
/// (defaults to localhost:15432).
#[cfg(test)]
pub(crate) fn test_config() -> DatabaseConfig {
    DatabaseConfig {
        uid: "test".into(),
        name: "testdb".into(),
        description: "integration test db".into(),
        db_type: "postgres".into(),
        dialect: "postgres".into(),
        username: std::env::var("TEST_PG_USER").unwrap_or_else(|_| "test".into()),
        password: std::env::var("TEST_PG_PASSWORD").unwrap_or_else(|_| "test".into()),
        host: std::env::var("TEST_PG_HOST").unwrap_or_else(|_| "localhost".into()),
        port: std::env::var("TEST_PG_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(15432),
        db: std::env::var("TEST_PG_DB").unwrap_or_else(|_| "testdb".into()),
        extra_opts: String::new(),
    }
}

/// Test helper: probe whether a connection is usable (async).
#[cfg(test)]
pub(crate) async fn connection_available(pool: &PgPool) -> bool {
    tokio::time::timeout(Duration::from_secs(2), pool.acquire())
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Test helper: probe whether a connection is usable (sync, for sync
#[cfg(test)]
pub(crate) fn connection_available_sync(pool: &PgPool) -> bool {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map(|rt| {
            rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(2), pool.acquire())
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}
