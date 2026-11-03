//! SQL execution library: execute queries that passed read-only
//! validation per the config and return structured results.
//!
//! # Safety contract
//!
//! **The caller must validate SQL through sql-validator first**; this
//! library does not re-check statement categories; the consequences of
//! passing a write statement directly are borne by the caller.
//!
//! The multi-database entry point dispatches by the configured `db_type`;
//! PostgreSQL is implemented first (the `pg` module), and other types
//! return an unsupported error (fail closed).

pub mod pg;

use excapp_db_core::config::DatabaseConfig;

/// A cell value: text form + a null flag (NULL stays distinguishable from
/// the empty string, `0`, `f`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellValue {
    /// Text rendering of the value (integers in decimal, booleans as
    /// `t`/`f`, timestamps in PG's default format).
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

/// Query result: a column-name array + a 2D array of row values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    /// Column names, in the order returned by the SQL; kept even for an
    /// empty result set.
    pub columns: Vec<String>,
    /// Row values; an empty array for an empty result set.
    pub rows: Vec<Vec<CellValue>>,
}

/// Execution error: structured English message, no connection
/// credentials.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    /// Database type not supported (fail-closed dispatch at the entry
    /// layer).
    #[error("unsupported database type '{db_type}' for database '{db_name}'; supported: postgres")]
    UnsupportedDbType {
        /// Database type from the config.
        db_type: String,
        /// Database name from the config (error identity).
        db_name: String,
    },
    /// Wraps errors from the pg implementation layer.
    #[error("{0}")]
    Pg(#[from] pg::PgError),
}

/// Build an executor from the database config (unified entry point,
/// dispatching by `db_type`).
///
/// Returned errors already include the database identity; unsupported
/// types are rejected right here.
pub fn build_executor(config: &DatabaseConfig) -> Result<pg::PgExecutor, ExecutorError> {
    match config.db_type.as_str() {
        "postgres" => Ok(pg::PgExecutor::new(config)?),
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

    #[test]
    fn test_build_executor_dispatches_postgres() {
        assert!(build_executor(&pg_config()).is_ok());
    }

    #[test]
    fn test_build_executor_rejects_unsupported_type() {
        let mut config = pg_config();
        config.db_type = "mysql".into();
        let err = build_executor(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported database type 'mysql'"), "{msg}");
        assert!(msg.contains("testdb"), "{msg}");
        assert!(msg.contains("supported: postgres"), "{msg}");
    }
}
