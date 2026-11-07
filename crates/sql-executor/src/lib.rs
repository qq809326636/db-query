//! SQL execution library: executes queries that passed read-only validation per
//! config and returns structured results.
//!
//! # Security contract
//!
//! **The caller must validate SQL through sql-validator first**; this library
//! does not re-check statement kinds, and the consequences of passing write
//! statements directly rest with the caller.
//!
//! The multi-database entry [`DatabaseExecutor`] (enum dispatch) routes per the
//! configured `db_type` to the postgres / mysql / sqlite implementations;
//! anything else returns an unsupported error (fail closed).
//! All three databases use their native drivers (per the overall design).

pub mod mysql;
pub mod pg;
pub mod sqlite;

use excapp_db_core::config::DatabaseConfig;

/// Cell value: textual shape + null flag (NULL stays distinguishable from empty
/// string, `0`, `f`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellValue {
    /// Textual rendering of the value (integers in decimal, booleans as `t`/`f`,
    /// temporals in each database's textual shape).
    pub text: String,
    /// Whether the value is SQL NULL.
    pub is_null: bool,
}

impl CellValue {
    /// Build a non-null text value.
    pub fn text(value: impl Into<String>) -> Self {
        Self {
            text: value.into(),
            is_null: false,
        }
    }

    /// Build a NULL value.
    pub fn null() -> Self {
        Self {
            text: String::new(),
            is_null: true,
        }
    }
}

/// Query result: column-name array + two-dimensional row-value array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    /// Column names, in the order SQL returns them; empty result sets keep the
    /// column names.
    pub columns: Vec<String>,
    /// Row values; an empty array for empty result sets.
    pub rows: Vec<Vec<CellValue>>,
}

/// Execution errors: the unified exit (the error surface of enum dispatch),
/// English messages, no connection credentials.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// Database type not supported (entry-layer fail-closed dispatch).
    #[error(
        "unsupported database type '{db_type}' for database '{db_name}'; supported: postgres, mysql, sqlite"
    )]
    UnsupportedDbType {
        /// The database type from config.
        db_type: String,
        /// The database unique id (uid) from config.
        db_name: String,
    },
    /// Wraps the pg implementation layer's errors.
    #[error("{0}")]
    Pg(#[from] pg::PgError),
    /// Wraps the mysql implementation layer's errors.
    #[error("{0}")]
    MySql(#[from] mysql::MyError),
    /// Wraps the sqlite implementation layer's errors.
    #[error("{0}")]
    Sqlite(#[from] sqlite::SqliteError),
}

/// Unified multi-database execution entry (enum dispatch): variants carry the
/// corresponding implementation executor.
///
/// The common surface covers the caller's (sql-mcp's) current calls:
/// [`execute`] (user queries, with triple protection),
/// [`execute_metadata`](DatabaseExecutor::execute_metadata) (server-side fixed
/// metadata SQL, skipping row / byte limits), and
/// [`for_database_with_schema`](DatabaseExecutor::for_database_with_schema)
/// (cross-database / schema scoped derivation).
#[derive(Debug)]
pub enum DatabaseExecutor {
    /// PostgreSQL implementation.
    Pg(pg::PgExecutor),
    /// MySQL implementation.
    MySql(mysql::MyExecutor),
    /// SQLite implementation.
    Sqlite(sqlite::SqliteExecutor),
}

impl DatabaseExecutor {
    /// Execute a user query (triple protection: rows / bytes / statement
    /// timeout).
    ///
    /// The result is the column names + row values of the last statement group
    /// with a result set; the SQL is assumed to be already validated by the
    /// caller via sql-validator.
    pub async fn execute(&self, sql: &str) -> Result<QueryResult, ExecutorError> {
        match self {
            DatabaseExecutor::Pg(e) => Ok(e.execute(sql).await?),
            DatabaseExecutor::MySql(e) => Ok(e.execute(sql).await?),
            DatabaseExecutor::Sqlite(e) => Ok(e.execute(sql).await?),
        }
    }

    /// Execute server-side fixed metadata SQL (skipping row / byte limits; the
    /// timeout still applies).
    ///
    /// # Security boundary
    ///
    /// Only for metadata queries assembled statically inside caller code;
    /// **never** for user-supplied SQL (which must go through [`execute`]).
    pub async fn execute_metadata(&self, sql: &str) -> Result<QueryResult, ExecutorError> {
        match self {
            DatabaseExecutor::Pg(e) => Ok(e.execute_metadata(sql).await?),
            DatabaseExecutor::MySql(e) => Ok(e.execute_metadata(sql).await?),
            DatabaseExecutor::Sqlite(e) => Ok(e.execute_metadata(sql).await?),
        }
    }

    /// Derive an executor: cross-database (in MySQL the database is the schema
    /// selection) plus optional schema scoping (PG sets search_path; SQLite has
    /// no schema concept, so non-None returns an unsupported error).
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
        }
    }
}

/// Build an executor from the database config (unified entry, dispatched by
/// `db_type`).
///
/// Returned errors already carry the database id (uid); unsupported types are
/// rejected right here.
pub fn build_executor(config: &DatabaseConfig) -> Result<DatabaseExecutor, ExecutorError> {
    match config.db_type.as_str() {
        "postgres" => Ok(DatabaseExecutor::Pg(pg::PgExecutor::new(config)?)),
        "mysql" => Ok(DatabaseExecutor::MySql(mysql::MyExecutor::new(config)?)),
        "sqlite" => Ok(DatabaseExecutor::Sqlite(sqlite::SqliteExecutor::new(
            config,
        )?)),
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
        config.db_type = "redis".into();
        let err = build_executor(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported database type 'redis'"), "{msg}");
        assert!(msg.contains("testdb"), "{msg}");
        assert!(msg.contains("supported: postgres, mysql, sqlite"), "{msg}");
    }
}
