//! RedisPool: the Redis connection pool (lazy connect, max 10, recovery on next acquire after a drop).

use super::{ACQUIRE_TIMEOUT, POOL_MAX_SIZE, RedisError, parse_db_number};
use deadpool_redis::{
    Config as DeadpoolConfig, ConnectionAddr, ConnectionInfo, Pool, PoolConfig, ProtocolVersion,
    RedisConnectionInfo, Runtime, Timeouts,
};
use excapp_db_core::config::DatabaseConfig;

/// Redis connection pool: wraps the deadpool-redis pool, the database id, and the logical database number.
///
/// Connection parameters come from the standard config fields: host / port dial the single instance directly, the `db` field carries
/// the logical database number (0-15), and empty `username` / `password` strings count as not provided;
/// `extra_opts` has zero keys in the first release (non-empty is rejected). The protocol is fixed to RESP2.
pub struct RedisPool {
    /// Database name (error identity; carries config.uid).
    pub(crate) db_name: String,
    /// Logical database number (0-15).
    pub(crate) db_number: u8,
    /// Connection parameter: host (for for_database derivation).
    pub(crate) host: String,
    /// Connection parameter: port.
    pub(crate) port: u16,
    /// Connection parameter: username (empty config counts as not provided).
    pub(crate) username: Option<String>,
    /// Connection parameter: password (empty config counts as not provided).
    pub(crate) password: Option<String>,
    /// The deadpool-redis pool.
    pub(crate) inner: Pool,
}

impl std::fmt::Debug for RedisPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisPool")
            .field("db_name", &self.db_name)
            .field("db_number", &self.db_number)
            .field("pool_stats", &self.inner.status())
            .finish()
    }
}

impl RedisPool {
    /// Create the pool from config (lazy: no connection is established).
    ///
    /// The `db` field carries the logical database number: non-0-15 integers are rejected at build time naming the field;
    /// non-empty `extra_opts` returns [`RedisError::InvalidExtraOpts`] (zero keys in the first release).
    pub fn new(config: &DatabaseConfig) -> Result<Self, RedisError> {
        if !config.extra_opts.trim().is_empty() {
            return Err(RedisError::InvalidExtraOpts {
                db_name: config.uid.clone(),
                raw: config.extra_opts.clone(),
            });
        }
        let db_number = parse_db_number(&config.db).ok_or_else(|| RedisError::InvalidDbNumber {
            db_name: config.uid.clone(),
            raw: config.db.clone(),
        })?;
        let username = optional(&config.username);
        let password = optional(&config.password);
        let pool = build_pool(
            &config.uid,
            &config.host,
            config.port,
            db_number,
            username.as_deref(),
            password.as_deref(),
        )?;
        Ok(Self {
            db_name: config.uid.clone(),
            db_number,
            host: config.host.clone(),
            port: config.port,
            username,
            password,
            inner: pool,
        })
    }

    /// Derive a new pool pointing at the same instance with the given logical database number (cross-database queries).
    ///
    /// When the number matches the current one the clone shares the same pool (reusing the base executor); otherwise
    /// a new pool is built from the same instance parameters with only the number replaced, and the error identity becomes `uid::dbN`.
    pub fn for_database(&self, db_field: &str) -> Result<Self, RedisError> {
        let db_number = parse_db_number(db_field).ok_or_else(|| RedisError::InvalidDbNumber {
            db_name: self.db_name.clone(),
            raw: db_field.to_string(),
        })?;
        if db_number == self.db_number {
            return Ok(Self {
                db_name: self.db_name.clone(),
                db_number,
                host: self.host.clone(),
                port: self.port,
                username: self.username.clone(),
                password: self.password.clone(),
                inner: self.inner.clone(),
            });
        }
        let pool = build_pool(
            &self.db_name,
            &self.host,
            self.port,
            db_number,
            self.username.as_deref(),
            self.password.as_deref(),
        )?;
        Ok(Self {
            db_name: format!("{}::db{db_number}", self.db_name),
            db_number,
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            password: self.password.clone(),
            inner: pool,
        })
    }

    /// Acquire a connection (2s bounded wait); failures map to [`RedisError::Connection`].
    ///
    /// Connect failures (refused / auth failed, ...) surface on first acquire - the lazy-connection
    /// failure semantics live here, and dropped connections are recycled by the pool (recovered on next acquire).
    pub(crate) async fn acquire(&self) -> Result<deadpool_redis::Connection, RedisError> {
        match tokio::time::timeout(ACQUIRE_TIMEOUT, self.inner.get()).await {
            Err(_) => Err(RedisError::Connection {
                db_name: self.db_name.clone(),
                detail: format!(
                    "timed out after {}s waiting for an available connection",
                    ACQUIRE_TIMEOUT.as_secs()
                ),
            }),
            Ok(Err(e)) => Err(RedisError::Connection {
                db_name: self.db_name.clone(),
                detail: flatten_error(&e),
            }),
            Ok(Ok(conn)) => Ok(conn),
        }
    }
}

/// Build the deadpool-redis pool from connection parameters (RESP2, max 10, 2s wait).
fn build_pool(
    db_name: &str,
    host: &str,
    port: u16,
    db_number: u8,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Pool, RedisError> {
    let connection = ConnectionInfo {
        addr: ConnectionAddr::Tcp(host.to_string(), port),
        redis: RedisConnectionInfo {
            db: i64::from(db_number),
            username: username.map(str::to_string),
            password: password.map(str::to_string),
            protocol: ProtocolVersion::RESP2,
        },
    };
    let mut config = DeadpoolConfig::from_connection_info(connection);
    config.pool = Some(PoolConfig {
        max_size: POOL_MAX_SIZE,
        timeouts: Timeouts {
            wait: Some(ACQUIRE_TIMEOUT),
            ..Timeouts::default()
        },
        ..PoolConfig::default()
    });
    config
        .create_pool(Some(Runtime::Tokio1))
        .map_err(|e| RedisError::Connection {
            db_name: db_name.to_string(),
            detail: e.to_string(),
        })
}

/// Normalize an empty string to None (credential-not-provided semantics).
fn optional(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Flatten the driver error's source chain for the full semantics (aligned with pg's flatten_error).
pub(crate) fn flatten_error(e: &dyn std::error::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut src = e.source();
    while let Some(s) = src {
        let text = s.to_string();
        if !parts.contains(&text) {
            parts.push(text);
        }
        src = s.source();
    }
    parts.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(db: &str, extra_opts: &str) -> DatabaseConfig {
        DatabaseConfig {
            uid: "u".into(),
            name: "testdb".into(),
            description: "d".into(),
            db_type: "redis".into(),
            dialect: "redis".into(),
            username: String::new(),
            password: String::new(),
            host: "127.0.0.1".into(),
            port: 16379,
            db: db.into(),
            extra_opts: extra_opts.into(),
        }
    }

    #[test]
    fn test_new_rejects_invalid_db_number() {
        for raw in ["16", "-1", "abc", ""] {
            let err = RedisPool::new(&config(raw, "")).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("invalid db value"), "{msg}");
            assert!(msg.contains("'u'"), "{msg}");
            assert!(msg.contains("field 'db'"), "{msg}");
            assert!(msg.contains(&format!("got '{raw}'")), "{msg}");
        }
        // In-bound values pass (no connection, no I/O).
        assert!(RedisPool::new(&config("0", "")).is_ok());
        assert!(RedisPool::new(&config("15", "")).is_ok());
    }

    #[test]
    fn test_new_rejects_extra_opts() {
        let err = RedisPool::new(&config("0", "ssl-mode=required")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid extra_opts"), "{msg}");
        assert!(msg.contains("no extra_opts keys"), "{msg}");
        // Pure whitespace does not count as non-empty.
        assert!(RedisPool::new(&config("0", "  ")).is_ok());
    }

    #[test]
    fn test_for_database_validates_and_labels() {
        let pool = RedisPool::new(&config("0", "")).unwrap();
        // Invalid number: rejected with the raw value reported.
        let err = pool.for_database("16").unwrap_err();
        assert!(err.to_string().contains("got '16'"), "{err}");
        // Same number: the clone shares the pool (closing the original is visible in the clone).
        let same = pool.for_database("0").unwrap();
        assert_eq!(same.db_number, 0);
        assert_eq!(same.db_name, "u");
        // Different number: a new pool, error identity suffixed with dbN.
        let other = pool.for_database("3").unwrap();
        assert_eq!(other.db_number, 3);
        assert_eq!(other.db_name, "u::db3");
        // Sharing check: closing the original closes the clone too, while the different-number pool is unaffected.
        pool.inner.close();
        assert!(same.inner.is_closed());
        assert!(!other.inner.is_closed());
    }
}
