//! Redis implementation: connection pool (RedisPool), read-only command execution (RedisExecutor), and
//! health check (RedisHealthCheck).
//!
//! Built on redis 1.8 + deadpool-redis 0.23 (per the overall design):
//! the pool connects lazily (max 10, 2s bounded acquire wait); RESP2 responses map to
//! columns + rows (per the per-command mapping table);
//! the health check implements core's [`HealthCheck`] trait.
//!
//! Security contract: the `db` field carries the logical database number (0-15); the entry accepts command tokens **already
//! validated by CommandWhitelist**; this module does not re-run whitelist checks.

mod connection;
mod health;
mod query;

pub use connection::RedisPool;
pub use health::RedisHealthCheck;
pub use query::RedisExecutor;

use std::time::Duration;

/// Redis implementation-layer error: structured English, carries the database id (uid), never credentials.
#[derive(Debug, thiserror::Error)]
pub enum RedisError {
    /// The `db` field or a derivation argument is not an integer in 0-15 (rejected at build time).
    #[error(
        "invalid db value for redis database '{db_name}': field 'db' expects an integer between 0 and 15, got '{raw}'"
    )]
    InvalidDbNumber {
        /// Database unique id (uid, error identity).
        db_name: String,
        /// Raw input.
        raw: String,
    },
    /// Non-empty extra_opts (zero keys in the first release, fail closed).
    #[error(
        "invalid extra_opts for database '{db_name}': redis supports no extra_opts keys, got '{raw}'"
    )]
    InvalidExtraOpts {
        /// Database unique id (uid, error identity).
        db_name: String,
        /// Raw input.
        raw: String,
    },
    /// Failed to get a connection from the pool (including connect failures: refused / auth failed / timeout, ...).
    #[error("redis connection failed for database '{db_name}': {detail}")]
    Connection {
        /// Database unique id (uid, error identity).
        db_name: String,
        /// Original driver error (preserves refused / auth-failed / timeout semantics).
        detail: String,
    },
    /// Server-side command error (RESP error such as WRONGTYPE) or a response shape mismatching the mapping expectation.
    #[error("redis command failed for database '{db_name}': {detail}")]
    Command {
        /// Database unique id (uid, error identity).
        db_name: String,
        /// Server or driver error detail.
        detail: String,
    },
    /// Result row count exceeds the cap (no partial results).
    #[error(
        "query result exceeds row limit for database '{db_name}': got {actual} rows, limit is {limit}"
    )]
    RowLimit {
        /// Database unique id (uid, error identity).
        db_name: String,
        /// Actual row count.
        actual: usize,
        /// Cap (100).
        limit: usize,
    },
    /// Result text byte total exceeds the cap (no partial results).
    #[error(
        "query result exceeds byte limit for database '{db_name}': got {actual} bytes, limit is {limit}"
    )]
    ByteLimit {
        /// Database unique id (uid, error identity).
        db_name: String,
        /// Actual byte total (UTF-8 bytes of cell texts, accumulated).
        actual: usize,
        /// Cap (10MB).
        limit: usize,
    },
    /// Single-command execution timeout (a 30s client-side cap over acquire + execute + read).
    #[error("redis command timed out for database '{db_name}': exceeded {}s", COMMAND_TIMEOUT.as_secs())]
    Timeout {
        /// Database unique id (uid, error identity).
        db_name: String,
    },
    /// SQL execution entry mistakenly used on the Redis variant (fail-closed bidirectional mis-route guard).
    #[error("sql execution is not supported for redis database '{db_name}': use execute_redis")]
    SqlNotSupported {
        /// Database unique id (uid, error identity).
        db_name: String,
    },
    /// Derivation entry carries a schema (Redis has no schema concept).
    #[error("schema is not supported for redis database '{db_name}'")]
    SchemaNotSupported {
        /// Database unique id (uid, error identity).
        db_name: String,
    },
}

/// Upper bound of the logical database number (Redis SELECT semantics: 0-15).
const DB_NUMBER_MAX: u8 = 15;

/// Row cap per command result.
pub(crate) const ROW_LIMIT: usize = 100;

/// Pool cap (fixed, not configurable).
pub(crate) const POOL_MAX_SIZE: usize = 10;

/// Acquire wait cap (bounded wait when the pool is exhausted).
pub(crate) const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);

/// Single-command execution timeout (client-side wrapper: acquire + execute + read, the whole span).
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Result text byte total cap (UTF-8 bytes of cell texts, accumulated).
pub(crate) const RESULT_BYTE_LIMIT: usize = 10 * 1024 * 1024;

/// Parse the logical database number: only pure digit text (0-15) is accepted; whitespace, signed forms,
/// non-digits, and integers outside 0-15 all return None (fail closed).
pub(crate) fn parse_db_number(raw: &str) -> Option<u8> {
    if !raw.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: u32 = raw.parse().ok()?;
    (n <= DB_NUMBER_MAX as u32).then_some(n as u8)
}

/// Test helper: build the test database config from env vars (defaults to localhost:16379, aligned with
/// the pg 15432 / mysql 13306 local-default precedent; container runs pass TEST_REDIS_PORT).
#[cfg(test)]
pub(crate) fn test_config(
    host: &str,
    port: u16,
    db: &str,
) -> excapp_db_core::config::DatabaseConfig {
    excapp_db_core::config::DatabaseConfig {
        uid: "test".into(),
        name: "testdb".into(),
        description: "integration test db".into(),
        db_type: "redis".into(),
        dialect: "redis".into(),
        username: String::new(),
        password: String::new(),
        host: host.into(),
        port,
        db: db.into(),
        extra_opts: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_db_number_bounds() {
        assert_eq!(parse_db_number("0"), Some(0));
        assert_eq!(parse_db_number("15"), Some(15));
        assert_eq!(parse_db_number("16"), None);
        assert_eq!(parse_db_number("-1"), None);
        assert_eq!(parse_db_number("abc"), None);
        assert_eq!(parse_db_number(""), None);
        assert_eq!(parse_db_number(" 1"), None);
        assert_eq!(parse_db_number("+1"), None);
        assert_eq!(parse_db_number("01"), Some(1));
    }
}
