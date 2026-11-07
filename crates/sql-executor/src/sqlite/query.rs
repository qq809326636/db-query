//! `SqliteExecutor`: query execution (Batch per-statement, dynamic-type
//! stringification, triple protection).

use super::{PROGRESS_HANDLER_OPS, QUERY_TIMEOUT_SECS, RESULT_BYTE_LIMIT, ROW_LIMIT, SqliteError};
use crate::{CellValue, QueryResult};
use fallible_iterator::FallibleIterator;
use rusqlite::Batch;
use rusqlite::types::ValueRef;
use std::time::{Duration, Instant};

/// SQLite query executor: holds the read-only connection pool and implements the
/// unified execution entry.
pub struct SqliteExecutor {
    /// Shared connection pool (shared with the health check).
    pool: std::sync::Arc<super::SqlitePool>,
}

impl std::fmt::Debug for SqliteExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteExecutor")
            .field("pool", &self.pool)
            .finish()
    }
}

impl SqliteExecutor {
    /// Create the executor from config (builds the pool; invalid `extra_opts`
    /// errors at pool-build time).
    pub fn new(config: &excapp_db_core::config::DatabaseConfig) -> Result<Self, SqliteError> {
        Ok(Self {
            pool: std::sync::Arc::new(super::SqlitePool::new(config)?),
        })
    }

    /// Execute a query (semicolon-separated multi-statement batches supported).
    ///
    /// - The result is the column names + row values of the last statement that
    ///   has a result set (stringified per stored type; BLOBs as lowercase
    ///   hexadecimal);
    /// - Over 100 rows or over 10MB of total text bytes fails the whole batch,
    ///   never returning partial results;
    /// - A statement running past 30 seconds is interrupted via the progress
    ///   callback and surfaces a timeout error;
    /// - Out-of-bounds write statements are denied by the read-only connection,
    ///   passing through the database's raw error;
    /// - The SQL is assumed to be already validated by the caller via
    ///   sql-validator.
    pub async fn execute(&self, sql: &str) -> Result<QueryResult, SqliteError> {
        self.run(sql, true).await
    }

    /// Execute server-side fixed metadata SQL: same execution path as
    /// [`execute`], only skipping the row and byte limits (the timeout still
    /// applies).
    ///
    /// # Security boundary
    ///
    /// Only for metadata queries assembled statically inside caller code;
    /// **never** for user-supplied SQL (which must go through [`execute`]).
    pub async fn execute_metadata(&self, sql: &str) -> Result<QueryResult, SqliteError> {
        self.run(sql, false).await
    }

    /// Execution backbone: acquire a connection → advance statement by statement
    /// inside the blocking closure (with timeout interruption).
    async fn run(&self, sql: &str, enforce_limits: bool) -> Result<QueryResult, SqliteError> {
        let object = self.pool.acquire().await?;
        let db_name = self.pool.db_name.clone();
        let busy = self.pool.busy_timeout();
        let timeout = self.pool.query_timeout();
        let sql_owned = sql.to_string();
        let name_for_interact = db_name.clone();

        object
            .interact(move |conn| {
                execute_sync(
                    conn,
                    &sql_owned,
                    enforce_limits,
                    busy,
                    timeout,
                    &name_for_interact,
                )
            })
            .await
            .map_err(|e| SqliteError::Connection {
                db_name,
                detail: e.to_string(),
            })?
    }

    /// Expose the shared pool handle (the health check reuses the same pool).
    pub fn shared_pool(&self) -> std::sync::Arc<super::SqlitePool> {
        std::sync::Arc::clone(&self.pool)
    }

    /// Derive an executor: SQLite has no schema concept, so the database must
    /// equal the main database path (sharing the same pool when equal,
    /// rejected otherwise).
    pub fn for_database_with_schema(
        &self,
        database: &str,
        schema: Option<&str>,
    ) -> Result<Self, SqliteError> {
        // schema not None: SQLite has no equivalent, so it is explicitly rejected
        // (fail closed).
        if let Some(schema) = schema {
            return Err(SqliteError::InvalidExtraOpts {
                db_name: self.pool.db_name.clone(),
                supported: super::EXTRA_OPTS_KEYS,
                raw: format!("schema '{schema}' is not supported for sqlite"),
            });
        }
        if database != self.pool.path {
            return Err(SqliteError::InvalidExtraOpts {
                db_name: self.pool.db_name.clone(),
                supported: super::EXTRA_OPTS_KEYS,
                raw: format!(
                    "cross-database '{database}' is not supported for sqlite (single file database)"
                ),
            });
        }
        Ok(Self {
            pool: std::sync::Arc::clone(&self.pool),
        })
    }
}

/// Execution inside the blocking closure: busy_timeout + deadline progress
/// callback + per-statement collection.
///
/// Timeout mechanism: SQLite has no server-side timeout, and `interact`'s
/// blocking closure cannot be cancelled from the async side (dropping the
/// future does not stop the blocking thread; the connection would be left in a
/// locked state). Hence interruption is implemented as a **progress callback +
/// absolute deadline**: the callback checks once every
/// [`PROGRESS_HANDLER_OPS`] VM instructions and returns false past the deadline,
/// making SQLite abort the current execution (`OperationInterrupted`) while the
/// connection stays clean and reclaimable.
fn execute_sync(
    conn: &mut rusqlite::Connection,
    sql: &str,
    enforce_limits: bool,
    busy: Duration,
    timeout: Duration,
    db_name: &str,
) -> Result<QueryResult, SqliteError> {
    conn.busy_timeout(busy)
        .map_err(|e| query_error(db_name, &e))?;

    let deadline = Instant::now() + timeout;
    // Mind the polarity: rusqlite's progress callback returning `true` means
    // **interrupt** the execution.
    conn.progress_handler(
        PROGRESS_HANDLER_OPS,
        Some(move || Instant::now() >= deadline),
    )
    .map_err(|e| query_error(db_name, &e))?;

    let result = collect(conn, sql, enforce_limits, db_name);

    // Clear the progress callback: a connection returned to the pool must not
    // keep this query's deadline.
    let _ = conn.progress_handler(0, None::<fn() -> bool>);

    result.map_err(|e| map_interrupted(e, db_name))
}

/// Advance statement by statement and collect results (taking the last statement
/// group that has a result set).
///
/// Column names are available at prepare time (`column_names`), so **empty
/// result sets keep their column names too**; `Batch` splits statements with
/// SQLite's own tokenizer, so semicolons inside strings and comments are never
/// mis-split.
fn collect(
    conn: &rusqlite::Connection,
    sql: &str,
    enforce_limits: bool,
    db_name: &str,
) -> Result<QueryResult, SqliteError> {
    let mut batch = Batch::new(conn, sql);
    let mut columns: Vec<String> = Vec::new();
    let mut result_rows: Vec<Vec<CellValue>> = Vec::new();
    let mut row_count: usize = 0;
    let mut byte_total: usize = 0;

    loop {
        let mut stmt = match batch.next() {
            Ok(Some(stmt)) => stmt,
            Ok(None) => break,
            Err(e) => return Err(query_error(db_name, &e)),
        };

        // Column names are available at prepare time (empty result sets keep them too).
        let stmt_columns: Vec<String> = stmt
            .column_names()
            .iter()
            .map(|name| (*name).to_string())
            .collect();

        let mut stmt_rows: Vec<Vec<CellValue>> = Vec::new();
        let column_count = stmt_columns.len();
        let mut raw_query = stmt.raw_query();
        loop {
            match raw_query.next() {
                Ok(Some(row)) => {
                    let mut cells = Vec::with_capacity(column_count);
                    for i in 0..column_count {
                        let value = row.get_ref(i).map_err(|e| query_error(db_name, &e))?;
                        let cell = cell_value(value);
                        if !cell.is_null {
                            byte_total += cell.text.len();
                        }
                        cells.push(cell);
                    }
                    row_count += 1;
                    stmt_rows.push(cells);
                    if enforce_limits && row_count > ROW_LIMIT {
                        return Err(SqliteError::RowLimit {
                            db_name: db_name.to_string(),
                            actual: row_count,
                            limit: ROW_LIMIT,
                        });
                    }
                    if enforce_limits && byte_total > RESULT_BYTE_LIMIT {
                        return Err(SqliteError::ByteLimit {
                            db_name: db_name.to_string(),
                            actual: byte_total,
                            limit: RESULT_BYTE_LIMIT,
                        });
                    }
                }
                Ok(None) => break,
                Err(e) => return Err(query_error(db_name, &e)),
            }
        }

        // Statements with column definitions (including empty result sets)
        // override the final result; statements without definitions (e.g. PRAGMA
        // with no output) do not participate.
        if !stmt_columns.is_empty() {
            columns = stmt_columns;
            result_rows = stmt_rows;
        }
    }

    Ok(QueryResult {
        columns,
        rows: result_rows,
    })
}

/// Value stringification: rendered per the **actual stored type** (dynamic-type
/// semantics).
fn cell_value(value: ValueRef<'_>) -> CellValue {
    match value {
        ValueRef::Null => CellValue::null(),
        ValueRef::Integer(i) => CellValue::text(i.to_string()),
        ValueRef::Real(f) => CellValue::text(f.to_string()),
        ValueRef::Text(t) => CellValue::text(String::from_utf8_lossy(t)),
        // BLOB: lowercase hexadecimal (lossless, distinguishable from NULL / TEXT).
        ValueRef::Blob(b) => CellValue::text(to_hex(b)),
    }
}

/// Lowercase hexadecimal text of a byte sequence.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Build a query error (passing through the driver's raw semantics).
fn query_error(db_name: &str, e: &rusqlite::Error) -> SqliteError {
    SqliteError::Query {
        db_name: db_name.to_string(),
        detail: e.to_string(),
    }
}

/// Map a progress-callback interruption (OperationInterrupted) to a timeout error.
fn map_interrupted(e: SqliteError, db_name: &str) -> SqliteError {
    match &e {
        SqliteError::Query { detail, .. } if detail.contains("interrupted") => {
            SqliteError::Timeout {
                db_name: db_name.to_string(),
                limit: QUERY_TIMEOUT_SECS,
            }
        }
        _ => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use excapp_db_core::config::DatabaseConfig;
    use rusqlite::Connection;

    /// Fixture path generation: unique per call (parallel tests never share files).
    fn unique_db_path(tag: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        format!("/tmp/excapp-db-sqlite-{tag}-{}-{n}.db", std::process::id())
    }

    /// Create the database via the write channel and load sample data (test
    /// fixtures only).
    fn write_fixture(path: &str, ddl: &str) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(ddl).unwrap();
    }

    fn config_with_path(path: &str) -> DatabaseConfig {
        DatabaseConfig {
            uid: "test".into(),
            name: "testdb".into(),
            description: "d".into(),
            db_type: "sqlite".into(),
            dialect: "sqlite".into(),
            username: String::new(),
            password: String::new(),
            host: String::new(),
            port: 0,
            db: path.into(),
            extra_opts: String::new(),
        }
    }

    #[test]
    fn test_cell_value_by_storage_class() {
        assert!(cell_value(ValueRef::Null).is_null);
        assert_eq!(cell_value(ValueRef::Integer(42)).text, "42");
        assert_eq!(cell_value(ValueRef::Real(1.5)).text, "1.5");
        assert_eq!(cell_value(ValueRef::Text(b"abc")).text, "abc");
        assert_eq!(
            cell_value(ValueRef::Blob(&[0xde, 0xad, 0xbe, 0xef])).text,
            "deadbeef"
        );
    }

    #[tokio::test]
    async fn test_execute_types_text_blob_null() -> anyhow::Result<()> {
        let path = unique_db_path("types");
        write_fixture(
            &path,
            "CREATE TABLE t (id INTEGER, name TEXT, ratio REAL, data BLOB);
             INSERT INTO t VALUES (1, 'a', 1.5, x'deadbeef');
             INSERT INTO t VALUES (2, NULL, 2.5, NULL);",
        );
        let exec = SqliteExecutor::new(&config_with_path(&path))?;
        let result = exec
            .execute("SELECT id, name, ratio, data FROM t ORDER BY id")
            .await?;
        assert_eq!(
            result.columns,
            vec!["id", "name", "ratio", "data"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.rows[0][0].text, "1");
        assert_eq!(result.rows[0][2].text, "1.5");
        assert_eq!(result.rows[0][3].text, "deadbeef");
        // NULL flag (distinguishable from empty string and 0).
        assert!(result.rows[1][1].is_null);
        assert!(result.rows[1][3].is_null);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn test_execute_empty_result_keeps_columns() -> anyhow::Result<()> {
        let path = unique_db_path("empty");
        write_fixture(&path, "CREATE TABLE t (v INTEGER);");
        let exec = SqliteExecutor::new(&config_with_path(&path))?;
        // Empty result sets still keep column names (available at prepare time).
        let result = exec.execute("SELECT v AS n FROM t WHERE 0").await?;
        assert_eq!(result.columns, vec!["n".to_string()]);
        assert!(result.rows.is_empty());
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn test_execute_dynamic_type_numeric_affinity() -> anyhow::Result<()> {
        let path = unique_db_path("affinity");
        // A NUMERIC-affinity column storing the text '123' → rendered per its
        // INTEGER storage.
        write_fixture(
            &path,
            "CREATE TABLE num (v NUMERIC); INSERT INTO num VALUES ('123');",
        );
        let exec = SqliteExecutor::new(&config_with_path(&path))?;
        let result = exec.execute("SELECT v FROM num").await?;
        assert_eq!(result.rows[0][0].text, "123");
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn test_execute_rejects_write_on_readonly_connection() -> anyhow::Result<()> {
        let path = unique_db_path("readonly");
        write_fixture(&path, "CREATE TABLE t (v INTEGER);");
        let exec = SqliteExecutor::new(&config_with_path(&path))?;
        // Out-of-bounds write statement (reaching here without validation):
        // denied by the read-only connection, error passed through.
        let err = exec.execute("INSERT INTO t VALUES (3)").await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("readonly"), "{msg}");
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn test_execute_row_limit_rejects_whole_batch() -> anyhow::Result<()> {
        let path = unique_db_path("rowlimit");
        write_fixture(&path, "CREATE TABLE t (v INTEGER);");
        let exec = SqliteExecutor::new(&config_with_path(&path))?;
        let err = exec
            .execute("WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 200) SELECT n FROM seq")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("row limit"), "{msg}");
        assert!(msg.contains("limit is 100"), "{msg}");
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn test_execute_batch_takes_last_result_group() -> anyhow::Result<()> {
        let path = unique_db_path("batch");
        write_fixture(
            &path,
            "CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (1), (2);",
        );
        let exec = SqliteExecutor::new(&config_with_path(&path))?;
        let result = exec
            .execute("SELECT 1 AS a; SELECT count(*) AS c FROM t")
            .await?;
        assert_eq!(result.columns, vec!["c".to_string()]);
        assert_eq!(result.rows[0][0].text, "2");
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn test_for_database_with_schema_rejects_schema() -> anyhow::Result<()> {
        let path = unique_db_path("derive");
        write_fixture(&path, "CREATE TABLE t (v INTEGER);");
        let exec = SqliteExecutor::new(&config_with_path(&path))?;
        let err = exec
            .for_database_with_schema(&path, Some("main"))
            .unwrap_err();
        assert!(
            err.to_string().contains("not supported for sqlite"),
            "{err}"
        );
        // Same database without schema: derivation succeeds (shared pool).
        assert!(exec.for_database_with_schema(&path, None).is_ok());
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}
