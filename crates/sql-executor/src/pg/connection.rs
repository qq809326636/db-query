//! recovers from drops on next acquire).

use super::{POOL_MAX_SIZE, PgError, STATEMENT_TIMEOUT};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use excapp_db_core::config::DatabaseConfig;
use tokio_postgres::Config;

/// PostgreSQL connection pool: wraps a deadpool pool plus the database
pub struct PgPool {
    /// Database name (for error identity).
    pub(crate) db_name: String,
    /// The deadpool pool.
    pub(crate) inner: Pool,
    /// The target may be a transaction-level pooler proxy (pgbouncer
    /// style): it strips startup packet options and resets session-level
    /// GUCs when recycling backend connections — so the timeout and
    /// search_path cannot rely on startup parameters or a one-shot SET
    /// after connect; they must be sent in the same string as the query
    /// (simple query protocol executes sequentially, atomically bound).
    pub(crate) session_prefix: String,
    /// Connection parameters (for for_database derivation).
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) extra_opts: String,
}

impl std::fmt::Debug for PgPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgPool")
            .field("db_name", &self.db_name)
            .field("pool_stats", &self.inner.status())
            .finish()
    }
}

impl PgPool {
    ///
    /// When `extra_opts` is non-empty, space-separated `key=value` pairs
    /// are passed through to the connection config; anything not in
    /// `key=value` form returns [`PgError::InvalidExtraOpts`].
    pub fn new(config: &DatabaseConfig) -> Result<Self, PgError> {
        let mut pg_config = Config::new();
        pg_config
            .host(&config.host)
            .port(config.port)
            .dbname(&config.db)
            .user(&config.username)
            .password(&config.password);

        append_extra_opts(&mut pg_config, &config.extra_opts, &config.uid)?;

        let manager = Manager::from_config(
            pg_config,
            tokio_postgres::NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(POOL_MAX_SIZE)
            .build()
            .expect("deadpool builder with valid config cannot fail");

        Ok(Self {
            db_name: config.uid.clone(),
            session_prefix: timeout_prefix(),
            host: config.host.clone(),
            port: config.port,
            username: config.username.clone(),
            password: config.password.clone(),
            extra_opts: config.extra_opts.clone(),
            inner: pool,
        })
    }

    /// Derive a new pool pointing at the same instance and a given
    /// database (for cross-database queries).
    ///
    /// Reuses this pool's connection config (host/port/credentials/
    pub fn for_database(&self, database: &str) -> Result<Self, PgError> {
        self.for_database_with_schema(database, None)
    }
    /// (via search_path).
    ///
    /// The schema name is validated against the same character whitelist
    /// as the database name.
    pub fn for_database_with_schema(
        &self,
        database: &str,
        schema: Option<&str>,
    ) -> Result<Self, PgError> {
        if database.is_empty()
            || !database
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(PgError::InvalidExtraOpts {
                db_name: self.db_name.clone(),
                raw: format!("database name '{database}'"),
            });
        }
        if let Some(schema) = schema
            && (schema.is_empty()
                || !schema
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        {
            return Err(PgError::InvalidExtraOpts {
                db_name: self.db_name.clone(),
                raw: format!("schema name '{schema}'"),
            });
        }
        let mut pg_config = Config::new();
        pg_config
            .host(&self.host)
            .port(self.port)
            .dbname(database)
            .user(&self.username)
            .password(&self.password);
        append_extra_opts(&mut pg_config, &self.extra_opts, &self.db_name)?;

        // Session prefix: the timeout is always set; when a schema is
        // given, search_path is set as well (both already validated
        let session_prefix = match schema {
            Some(schema) => format!("SET search_path TO {schema}; {}", timeout_prefix()),
            None => timeout_prefix(),
        };

        let manager = Manager::from_config(
            pg_config,
            tokio_postgres::NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(POOL_MAX_SIZE)
            .build()
            .expect("deadpool builder with valid config cannot fail");
        Ok(Self {
            db_name: format!("{}::{database}", self.db_name),
            session_prefix,
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            password: self.password.clone(),
            extra_opts: self.extra_opts.clone(),
            inner: pool,
        })
    }

    /// Acquire a connection from the pool; setup/recycling failures map
    pub(crate) async fn acquire(&self) -> Result<deadpool_postgres::Client, PgError> {
        self.inner.get().await.map_err(|e| PgError::Connection {
            db_name: self.db_name.clone(),
            detail: crate::pg::flatten_error(&e),
        })
    }
}

/// Build the session prefix for the statement timeout (sent in the same
fn timeout_prefix() -> String {
    format!("SET statement_timeout = '{STATEMENT_TIMEOUT}'; ")
}
///
/// Each pair gets a `-c` prefix and the fragments are joined with spaces
/// into a **single** [`Config::options`] call: `options()` is a setter
/// (repeated calls overwrite each other), and PostgreSQL 18 accepts only
/// `-c config=val` forms in startup parameters. Parameter keys are
/// whitelisted against injection.
fn append_extra_opts(
    pg_config: &mut Config,
    extra_opts: &str,
    db_name: &str,
) -> Result<(), PgError> {
    let mut fragments: Vec<String> = Vec::new();
    for pair in extra_opts.split_whitespace() {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(PgError::InvalidExtraOpts {
                db_name: db_name.to_string(),
                raw: pair.to_string(),
            });
        };
        // Whitelist parameter keys: accept only legal identifier
        // forms of PG connection parameters, preventing arbitrary
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(PgError::InvalidExtraOpts {
                db_name: db_name.to_string(),
                raw: pair.to_string(),
            });
        }
        fragments.push(format!("-c {key}={value}"));
    }
    if !fragments.is_empty() {
        pg_config.options(fragments.join(" "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pool_rejects_invalid_extra_opts() {
        let mut config = crate::pg::test_config();
        config.extra_opts = "sslmode".into(); // no =value
        let err = PgPool::new(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid extra_opts"), "{msg}");
        assert!(msg.contains("'test'"), "{msg}");

        config.extra_opts = "bad key=value".into(); // bad has no =
        assert!(PgPool::new(&config).is_err());

        config.extra_opts = "ssl;mode=require".into(); // illegal character
        assert!(PgPool::new(&config).is_err());
    }

    #[test]
    fn test_new_pool_accepts_valid_extra_opts() {
        let mut config = crate::pg::test_config();
        config.extra_opts = "application_name=db-query".into();
        assert!(PgPool::new(&config).is_ok());
    }

    #[test]
    fn test_pool_is_lazy() {
        // Lazy connect: building a pool pointing at a nonexistent port
        let mut config = crate::pg::test_config();
        config.port = 59999;
        assert!(PgPool::new(&config).is_ok());
    }

    #[tokio::test]
    async fn test_connection_error_contains_identity_not_password() {
        let mut config = crate::pg::test_config();
        config.port = 59999; // unreachable port
        let pool = PgPool::new(&config).unwrap();
        let err = pool.acquire().await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("'test'"), "{msg}");
        assert!(msg.contains("connection failed"), "{msg}");
        assert!(
            !msg.contains("test/test") && !msg.contains("password"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn test_connect_ok_when_database_available() {
        let pool = PgPool::new(&crate::pg::test_config()).unwrap();
        if !crate::pg::connection_available(&pool).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        assert!(pool.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn test_connection_sets_statement_timeout_via_session() {
        // BUG-04 regression: the timeout is bound atomically via the
        // pre-query SET prefix (startup options are stripped by proxies,
        // and a one-shot SET after connect is reset by them; the same-
        let executor = crate::pg::PgExecutor::new(&crate::pg::test_config()).unwrap();
        if !crate::pg::connection_available(&executor.shared_pool()).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        let result = executor
            .execute_metadata("SHOW statement_timeout")
            .await
            .unwrap();
        assert_eq!(
            result.rows[0][0].text, "30s",
            "statement_timeout must be bound to every execution path"
        );
    }

    #[tokio::test]
    async fn test_auth_failure_distinguishable_from_refused() {
        let mut config = crate::pg::test_config();
        config.password = "wrong-password".into();
        let pool = PgPool::new(&config).unwrap();
        let err = pool.acquire().await.unwrap_err();
        let msg = err.to_string();
        // Auth failure: the server message for SQLSTATE 28P01 varies with
        // locale (English "password authentication failed" / Chinese
        // equivalent), so assert the code first and keep the English text
        assert!(
            msg.contains("28P01") || msg.contains("password authentication"),
            "{msg}"
        );

        let mut config = crate::pg::test_config();
        config.port = 59999;
        let pool = PgPool::new(&config).unwrap();
        let err = pool.acquire().await.unwrap_err();
        let msg = err.to_string();
        // silently-dropping firewall are both legitimate network paths
        // for this failure class.
        assert!(
            msg.contains("refused")
                || msg.contains("connect")
                || msg.contains("timed out")
                || msg.contains("timeout"),
            "{msg}"
        );
    }
}
