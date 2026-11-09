//! `MyPool`: the MySQL connection pool (lazy connect, max 10, recovery on next
//! acquisition after a drop).

use super::{ACQUIRE_TIMEOUT, EXTRA_OPTS_KEYS, MAX_EXECUTION_TIME_MS, MyError, POOL_MAX_SIZE};
use excapp_db_core::config::DatabaseConfig;
use mysql_async::prelude::*;
use mysql_async::{OptsBuilder, Pool, PoolConstraints, PoolOpts, SslOpts};

/// MySQL connection pool: wraps the mysql_async pool plus the database id.
pub struct MyPool {
    /// Database name (error identifier, carries config.uid).
    pub(crate) db_name: String,
    /// The mysql_async pool.
    pub(crate) inner: Pool,
    /// Session prefix (the SET statement string atomically bound before every
    /// query).
    ///
    /// The target may be a session-scoped proxy (ProxySQL-like) that can reset a
    /// one-shot SET issued right after connecting; sending it in the same string
    /// as the query (text protocol executes sequentially) is the reliable shape.
    pub(crate) session_prefix: String,
    /// Connection parameters (for for_database derivation).
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) extra_opts: String,
}

impl std::fmt::Debug for MyPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MyPool")
            .field("db_name", &self.db_name)
            .finish_non_exhaustive()
    }
}

impl MyPool {
    /// Create the pool from config (lazy: no connection is established).
    ///
    /// `extra_opts` maps space-separated `key=value` pairs through a whitelist:
    /// `ssl-mode` goes into connect options, `charset` into the session prefix
    /// (`SET NAMES`); other shapes or keys outside the whitelist return
    /// [`MyError::InvalidExtraOpts`].
    /// (fail closed).
    pub fn new(config: &DatabaseConfig) -> Result<Self, MyError> {
        let parsed = parse_extra_opts(&config.extra_opts, &config.uid)?;
        let pool = build_pool(
            &config.host,
            config.port,
            &config.db,
            &config.username,
            &config.password,
            &parsed,
        )?;

        Ok(Self {
            db_name: config.uid.clone(),
            session_prefix: session_prefix(parsed.charset.as_deref()),
            host: config.host.clone(),
            port: config.port,
            username: config.username.clone(),
            password: config.password.clone(),
            extra_opts: config.extra_opts.clone(),
            inner: pool,
        })
    }

    /// Derive a new pool pointing at the same instance and the given database
    /// (for cross-database queries).
    ///
    /// In MySQL schema ≡ database (official synonyms), so deriving is database
    /// selection; names go through character-whitelist validation (alphanumerics
    /// plus `_` and `-`) against injection.
    pub fn for_database_with_schema(
        &self,
        database: &str,
        schema: Option<&str>,
    ) -> Result<Self, MyError> {
        validate_identifier(database, "database", &self.db_name)?;
        // schema and database are synonyms in MySQL: when not None they must
        // agree, otherwise the semantics conflict and it is explicitly rejected.
        if let Some(schema) = schema {
            validate_identifier(schema, "schema", &self.db_name)?;
            if schema != database {
                return Err(MyError::InvalidExtraOpts {
                    db_name: self.db_name.clone(),
                    supported: EXTRA_OPTS_KEYS,
                    raw: format!(
                        "schema '{schema}' differs from database '{database}' (synonyms in mysql)"
                    ),
                });
            }
        }
        let parsed = parse_extra_opts(&self.extra_opts, &self.db_name)?;
        let pool = build_pool(
            &self.host,
            self.port,
            database,
            &self.username,
            &self.password,
            &parsed,
        )?;
        Ok(Self {
            db_name: format!("{}::{database}", self.db_name),
            session_prefix: session_prefix(parsed.charset.as_deref()),
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            password: self.password.clone(),
            extra_opts: self.extra_opts.clone(),
            inner: pool,
        })
    }

    /// Acquire a connection from the pool (2s bounded wait); failures map to
    /// [`MyError::Connection`].
    pub(crate) async fn acquire(&self) -> Result<mysql_async::Conn, MyError> {
        tokio::time::timeout(ACQUIRE_TIMEOUT, self.inner.get_conn())
            .await
            .map_err(|_| MyError::Connection {
                db_name: self.db_name.clone(),
                detail: format!(
                    "timed out after {}s waiting for an available connection",
                    ACQUIRE_TIMEOUT.as_secs()
                ),
            })?
            .map_err(|e| MyError::Connection {
                db_name: self.db_name.clone(),
                detail: e.to_string(),
            })
    }

    /// Liveness-style acquisition: verifies connectivity and returns (for health checks).
    pub(crate) async fn acquire_probe(&self) -> Result<(), MyError> {
        let mut conn = self.acquire().await?;
        conn.query_drop("SELECT 1")
            .await
            .map_err(|e| MyError::Connection {
                db_name: self.db_name.clone(),
                detail: e.to_string(),
            })
    }
}

/// Parsed extra_opts (whitelisted keys).
#[derive(Debug, Default)]
pub(crate) struct ParsedExtraOpts {
    /// ssl-mode value (None means unspecified).
    pub(crate) ssl_mode: Option<String>,
    /// charset value (None means unspecified).
    pub(crate) charset: Option<String>,
}

/// Parse `extra_opts` into whitelisted key-values (keys matched after lowercasing).
fn parse_extra_opts(extra_opts: &str, uid: &str) -> Result<ParsedExtraOpts, MyError> {
    let mut parsed = ParsedExtraOpts::default();
    for pair in extra_opts.split_whitespace() {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(invalid(uid, pair));
        };
        match key.to_ascii_lowercase().as_str() {
            "ssl-mode" => {
                validate_ssl_mode(value, uid, key)?;
                parsed.ssl_mode = Some(value.to_ascii_lowercase());
            }
            "charset" => {
                // The charset value goes into the session prefix (SET NAMES);
                // whitelist characters guard against injection.
                if value.is_empty() || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    return Err(invalid(uid, pair));
                }
                parsed.charset = Some(value.to_string());
            }
            _ => return Err(invalid(uid, pair)),
        }
    }
    Ok(parsed)
}

fn invalid(uid: &str, raw: &str) -> MyError {
    MyError::InvalidExtraOpts {
        db_name: uid.to_string(),
        supported: EXTRA_OPTS_KEYS,
        raw: raw.to_string(),
    }
}

/// Validate the ssl-mode value (aligned with driver TLS semantics).
fn validate_ssl_mode(value: &str, uid: &str, key: &str) -> Result<(), MyError> {
    match value.to_ascii_lowercase().as_str() {
        "disabled" | "preferred" | "required" | "verified" => Ok(()),
        _ => Err(MyError::InvalidExtraOpts {
            db_name: uid.to_string(),
            supported: EXTRA_OPTS_KEYS,
            raw: format!("{key}={value}"),
        }),
    }
}

/// Assemble the connection pool (lazy connect; max 10).
///
/// Drop recovery: the mysql_async pool discards connections that errored while
/// in use when they are returned, and the next acquisition creates a new one —
/// the same "recover on next acquisition" semantics as PG.
fn build_pool(
    host: &str,
    port: u16,
    db: &str,
    username: &str,
    password: &str,
    parsed: &ParsedExtraOpts,
) -> Result<Pool, MyError> {
    let constraints = PoolConstraints::new(0, POOL_MAX_SIZE)
        .expect("pool constraints with max >= min cannot fail");
    let mut builder = OptsBuilder::default()
        .ip_or_hostname(host)
        .tcp_port(port)
        .db_name(Some(db))
        .user(Some(username))
        .pass(Some(password))
        .pool_opts(PoolOpts::new().with_constraints(constraints));

    // ssl-mode: disabled turns TLS off; everything else turns it on (verified
    // validates certificates and hostnames, required / preferred do not —
    // aligned with MySQL client semantics).
    if let Some(mode) = &parsed.ssl_mode
        && mode != "disabled"
    {
        let ssl = SslOpts::default().with_danger_skip_domain_validation(mode != "verified");
        builder = builder.ssl_opts(ssl);
    }

    Ok(Pool::new(builder))
}

/// Build the session prefix (sent in the same string as the query, atomically
/// bound).
///
/// The timeout is always set; a specified charset adds `SET NAMES` (the value
/// is already whitelist-validated).
fn session_prefix(charset: Option<&str>) -> String {
    let timeout = format!("SET SESSION max_execution_time = {MAX_EXECUTION_TIME_MS}; ");
    match charset {
        Some(charset) => format!("SET NAMES {charset}; {timeout}"),
        None => timeout,
    }
}

/// Whitelist validation for database / schema names (alphanumerics plus `_`, `-`).
fn validate_identifier(name: &str, kind: &str, uid: &str) -> Result<(), MyError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(MyError::InvalidExtraOpts {
            db_name: uid.to_string(),
            supported: EXTRA_OPTS_KEYS,
            raw: format!("{kind} name '{name}'"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_extra_opts_accepts_whitelisted_keys() {
        let parsed = parse_extra_opts("ssl-mode=required charset=utf8mb4", "u").unwrap();
        assert_eq!(parsed.ssl_mode.as_deref(), Some("required"));
        assert_eq!(parsed.charset.as_deref(), Some("utf8mb4"));
    }

    #[test]
    fn test_parse_extra_opts_rejects_unknown_key() {
        let err = parse_extra_opts("connect_timeout=5", "u").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ssl-mode"), "{msg}");
        assert!(msg.contains("charset"), "{msg}");
    }

    #[test]
    fn test_parse_extra_opts_rejects_non_pair() {
        let err = parse_extra_opts("sslmode", "u").unwrap_err();
        assert!(matches!(err, MyError::InvalidExtraOpts { .. }));
    }

    #[test]
    fn test_parse_extra_opts_rejects_charset_injection() {
        let err = parse_extra_opts("charset=utf8;DROP", "u").unwrap_err();
        assert!(matches!(err, MyError::InvalidExtraOpts { .. }));
    }

    #[test]
    fn test_validate_ssl_mode_values() {
        assert!(validate_ssl_mode("DISABLED", "u", "ssl-mode").is_ok());
        let err = validate_ssl_mode("auto", "u", "ssl-mode").unwrap_err();
        assert!(err.to_string().contains("ssl-mode=auto"), "{err}");
    }

    #[test]
    fn test_session_prefix_contains_timeout_and_charset() {
        let prefix = session_prefix(Some("utf8mb4"));
        assert!(prefix.contains("max_execution_time = 30000"), "{prefix}");
        assert!(prefix.contains("SET NAMES utf8mb4;"), "{prefix}");
        let plain = session_prefix(None);
        assert!(!plain.contains("SET NAMES"), "{plain}");
    }

    #[test]
    fn test_validate_identifier_rejects_injection() {
        assert!(validate_identifier("app_db-1", "database", "u").is_ok());
        let err = validate_identifier("db; DROP", "database", "u").unwrap_err();
        assert!(err.to_string().contains("database name"), "{err}");
    }

    #[tokio::test]
    async fn test_new_pool_is_lazy() {
        // Building the pool establishes no connection: an unreachable address
        // still succeeds (the error surfaces at acquisition time).
        // The password takes a distinct value: sharing the uid's value would
        // false-positive the "no password" assertion.
        let mut config = crate::mysql::test_config();
        config.port = 59999;
        config.password = "unique-secret-pw".into();
        let pool = MyPool::new(&config).unwrap();
        let err = pool.acquire().await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mysql connection failed"), "{msg}");
        assert!(msg.contains("'test'"), "{msg}");
        assert!(!msg.contains("unique-secret-pw"), "{msg}");
    }
}
