//! SQL execution library: run queries that passed read-only validation per config and return structured results.
//!
//! # Security contract
//!
//! **The caller must validate SQL through sql-validator first**; this library does not re-check statement classes;
//! the caller bears the consequences of passing write statements directly.
//!
//! The multi-database entry [`DatabaseExecutor`] (enum dispatch) routes by the configured `db_type` to the
//! postgres / mysql / sqlite implementations; other types return an unsupported error (fail closed).
//! The three databases share one unified entry (see the overall design).

pub mod mysql;
pub mod pg;
pub mod redis;
pub mod sqlite;

use excapp_db_core::config::DatabaseConfig;

/// Cell value: text form + null marker (NULL is distinguishable from empty string, `0`, `f`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellValue {
    /// Text rendering of the value (integers as decimal, booleans as `t`/`f`, times per-database text forms).
    pub text: String,
    /// Whether the value is SQL NULL.
    pub is_null: bool,
}

impl CellValue {
    /// Construct a non-null text value.
    pub fn text(value: impl Into<String>) -> Self {
        Self {
            text: value.into(),
            is_null: false,
        }
    }

    /// Construct a NULL value.
    pub fn null() -> Self {
        Self {
            text: String::new(),
            is_null: true,
        }
    }
}

/// Query result: a column-name array + a two-dimensional row-value array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    /// Column names, in SQL return order; empty result sets keep the column names.
    pub columns: Vec<String>,
    /// Row values; an empty array for empty result sets.
    pub rows: Vec<Vec<CellValue>>,
    /// SCAN-family cursor (Redis only): the opaque server cursor as decimal
    /// text, `"0"` meaning iteration complete; always `None` on SQL paths.
    pub cursor: Option<String>,
}

/// Execution error: the unified exit (the error surface of enum dispatch), English messages, no credentials.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// Database type not supported (entry-layer fail-closed dispatch).
    #[error(
        "unsupported database type '{db_type}' for database '{db_name}'; supported: postgres, mysql, sqlite, redis"
    )]
    UnsupportedDbType {
        /// Database type from the config.
        db_type: String,
        /// Database unique id (uid) from the config.
        db_name: String,
    },
    /// Wraps the pg implementation-layer error.
    #[error("{0}")]
    Pg(#[from] pg::PgError),
    /// Wraps the mysql implementation-layer error.
    #[error("{0}")]
    MySql(#[from] mysql::MyError),
    /// Wraps the sqlite implementation-layer error.
    #[error("{0}")]
    Sqlite(#[from] sqlite::SqliteError),
    /// Wraps the redis implementation-layer error.
    #[error("{0}")]
    Redis(#[from] redis::RedisError),
    /// execute_redis mistakenly used on a non-redis variant (fail-closed bidirectional mis-route guard).
    #[error("execute_redis is not applicable to database '{db_name}' of type '{db_type}'")]
    NotRedis {
        /// Database type from the config.
        db_type: String,
        /// Database unique id (uid) from the config.
        db_name: String,
    },
}

/// Multi-database unified execution entry (enum dispatch): each variant carries its implementation executor.
///
/// The operation surface covers the caller's (sql-mcp) current calls: [`execute`] (user queries,
/// triple-protected), [`execute_metadata`](DatabaseExecutor::execute_metadata)
/// (server-fixed metadata SQL, skipping the row / byte caps),
/// [`for_database_with_schema`](DatabaseExecutor::for_database_with_schema)
/// (cross-database / schema-scoped derivation).
#[derive(Debug)]
pub enum DatabaseExecutor {
    /// PostgreSQL implementation.
    Pg(pg::PgExecutor),
    /// MySQL implementation.
    MySql(mysql::MyExecutor),
    /// SQLite implementation.
    Sqlite(sqlite::SqliteExecutor),
    /// Redis implementation (read-only command execution; the entry is
    /// [`execute_redis`](DatabaseExecutor::execute_redis)).
    Redis(redis::RedisExecutor),
}

impl DatabaseExecutor {
    /// Execute a user query (triple protection: rows / bytes / statement timeout).
    ///
    /// The result is the columns + rows of the last statement group with a result set; the SQL is assumed to be
    /// validated by the caller through sql-validator.
    pub async fn execute(&self, sql: &str) -> Result<QueryResult, ExecutorError> {
        match self {
            DatabaseExecutor::Pg(e) => Ok(e.execute(sql).await?),
            DatabaseExecutor::MySql(e) => Ok(e.execute(sql).await?),
            DatabaseExecutor::Sqlite(e) => Ok(e.execute(sql).await?),
            // The SQL entry fails closed on the Redis variant (bidirectional mis-route guard).
            DatabaseExecutor::Redis(e) => {
                Err(ExecutorError::Redis(redis::RedisError::SqlNotSupported {
                    db_name: e.db_name().to_string(),
                }))
            }
        }
    }

    /// Execute server-fixed metadata SQL (skips the row / byte caps; the timeout still applies).
    ///
    /// # Security boundary
    ///
    /// Only for metadata queries hard-assembled in caller code; **never** for user-input
    /// SQL (which must go through [`execute`]).
    pub async fn execute_metadata(&self, sql: &str) -> Result<QueryResult, ExecutorError> {
        match self {
            DatabaseExecutor::Pg(e) => Ok(e.execute_metadata(sql).await?),
            DatabaseExecutor::MySql(e) => Ok(e.execute_metadata(sql).await?),
            DatabaseExecutor::Sqlite(e) => Ok(e.execute_metadata(sql).await?),
            // The SQL entry fails closed on the Redis variant (bidirectional mis-route guard).
            DatabaseExecutor::Redis(e) => {
                Err(ExecutorError::Redis(redis::RedisError::SqlNotSupported {
                    db_name: e.db_name().to_string(),
                }))
            }
        }
    }

    /// Execute a validated read-only Redis command (triple protection: rows / bytes / timeout).
    ///
    /// tokens are the flat vector of a CommandWhitelist-allowed command (command name, subcommand
    /// and arguments); commands are assumed to be validated by sql-validator already. Non-Redis variants
    /// returns [`ExecutorError::NotRedis`].
    pub async fn execute_redis(&self, tokens: &[String]) -> Result<QueryResult, ExecutorError> {
        match self {
            DatabaseExecutor::Redis(e) => Ok(e.execute(tokens).await?),
            other => Err(ExecutorError::NotRedis {
                db_type: variant_type(other).to_string(),
                db_name: variant_name(other),
            }),
        }
    }

    /// Execute fixed Redis metadata commands (skips the row / byte caps; the timeout still applies).
    ///
    /// # Security boundary
    ///
    /// Only for whitelisted command sequences hard-assembled in caller code; **never** for
    /// user-input commands (which must go through [`execute_redis`](Self::execute_redis)).
    pub async fn execute_redis_metadata(
        &self,
        tokens: &[String],
    ) -> Result<QueryResult, ExecutorError> {
        match self {
            DatabaseExecutor::Redis(e) => Ok(e.execute_metadata(tokens).await?),
            other => Err(ExecutorError::NotRedis {
                db_type: variant_type(other).to_string(),
                db_name: variant_name(other),
            }),
        }
    }

    /// Derive an executor: cross-database (in MySQL, database is the schema choice) plus optional
    /// schema scoping (PG sets search_path; SQLite has no schema concept,
    /// a non-None value returns an unsupported error).
    pub fn for_database_with_schema(
        &self,
        database: &str,
        schema: Option<&str>,
    ) -> Result<DatabaseExecutor, ExecutorError> {
        match self {
            DatabaseExecutor::Pg(e) => Ok(DatabaseExecutor::Pg(
                e.for_database_with_schema(database, schema)?,
            )),
            DatabaseExecutor::MySql(e) => Ok(DatabaseExecutor::MySql(
                e.for_database_with_schema(database, schema)?,
            )),
            DatabaseExecutor::Sqlite(e) => Ok(DatabaseExecutor::Sqlite(
                e.for_database_with_schema(database, schema)?,
            )),
            // database carries the logical database number; schema is meaningless for Redis (rejected by the implementation).
            DatabaseExecutor::Redis(e) => Ok(DatabaseExecutor::Redis(
                e.for_database_with_schema(database, schema)?,
            )),
        }
    }
}

/// The variant's db_type text (for NotRedis error construction).
fn variant_type(e: &DatabaseExecutor) -> &'static str {
    match e {
        DatabaseExecutor::Pg(_) => "postgres",
        DatabaseExecutor::MySql(_) => "mysql",
        DatabaseExecutor::Sqlite(_) => "sqlite",
        DatabaseExecutor::Redis(_) => "redis",
    }
}

/// The variant's database id (for NotRedis error construction; the per-implementation uid).
fn variant_name(e: &DatabaseExecutor) -> String {
    match e {
        DatabaseExecutor::Pg(e) => e.db_name().to_string(),
        DatabaseExecutor::MySql(e) => e.db_name().to_string(),
        DatabaseExecutor::Sqlite(e) => e.db_name().to_string(),
        DatabaseExecutor::Redis(e) => e.db_name().to_string(),
    }
}

/// Build an executor from the database config (unified entry, dispatched by `db_type`).
///
/// Returned errors carry the database id (uid); unsupported types are rejected here.
pub fn build_executor(config: &DatabaseConfig) -> Result<DatabaseExecutor, ExecutorError> {
    match config.db_type.as_str() {
        "postgres" => Ok(DatabaseExecutor::Pg(pg::PgExecutor::new(config)?)),
        "mysql" => Ok(DatabaseExecutor::MySql(mysql::MyExecutor::new(config)?)),
        "sqlite" => Ok(DatabaseExecutor::Sqlite(sqlite::SqliteExecutor::new(
            config,
        )?)),
        "redis" => Ok(DatabaseExecutor::Redis(redis::RedisExecutor::new(config)?)),
        other => Err(ExecutorError::UnsupportedDbType {
            db_type: other.to_string(),
            db_name: config.name.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg_config() -> DatabaseConfig {
        DatabaseConfig {
            uid: "u".into(),
            name: "testdb".into(),
            description: "d".into(),
            db_type: "postgres".into(),
            dialect: "postgres".into(),
            username: "test".into(),
            password: "test".into(),
            host: "localhost".into(),
            port: 15432,
            db: "testdb".into(),
            extra_opts: String::new(),
        }
    }

    #[tokio::test]
    async fn test_build_executor_dispatches_postgres() {
        assert!(matches!(
            build_executor(&pg_config()).unwrap(),
            DatabaseExecutor::Pg(_)
        ));
    }

    #[tokio::test]
    async fn test_build_executor_dispatches_mysql_and_sqlite() {
        let mut config = pg_config();
        config.db_type = "mysql".into();
        assert!(matches!(
            build_executor(&config).unwrap(),
            DatabaseExecutor::MySql(_)
        ));
        let mut sqlite_config = pg_config();
        sqlite_config.db_type = "sqlite".into();
        sqlite_config.db = "/nonexistent/path/db.sqlite3".into();
        assert!(matches!(
            build_executor(&sqlite_config).unwrap(),
            DatabaseExecutor::Sqlite(_)
        ));
    }

    #[test]
    fn test_build_executor_rejects_unsupported_type() {
        let mut config = pg_config();
        config.db_type = "mongodb".into();
        let err = build_executor(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported database type 'mongodb'"), "{msg}");
        assert!(msg.contains("testdb"), "{msg}");
        assert!(
            msg.contains("supported: postgres, mysql, sqlite, redis"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn test_redis_variant_routings() {
        let mut config = pg_config();
        config.db_type = "redis".into();
        config.db = "0".into();
        let executor = build_executor(&config).unwrap();
        assert!(matches!(executor, DatabaseExecutor::Redis(_)));
        // The SQL entry fails closed on the Redis variant.
        let err = executor.execute("SELECT 1").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("sql execution is not supported for redis"),
            "{msg}"
        );
        assert!(msg.contains("'u'"), "{msg}");
        // execute_redis mistakenly used on an SQL variant fails closed.
        let pg = build_executor(&pg_config()).unwrap();
        let err = pg
            .execute_redis(&["GET".to_string(), "k".to_string()])
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("execute_redis is not applicable"), "{msg}");
        assert!(msg.contains("'postgres'"), "{msg}");
        assert!(msg.contains("'u'"), "{msg}");
    }
}
