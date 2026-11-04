//! PgQuery: query execution (simple query protocol, text-rendered values,
//! row-limit protection).

use super::{PgError, RESULT_BYTE_LIMIT, ROW_LIMIT};
use crate::{CellValue, QueryResult};

/// PostgreSQL query executor: holds the connection pool and implements
/// the unified execution entry point.
pub struct PgExecutor {
    /// Shared connection pool (shared with the health check).
    pool: std::sync::Arc<super::PgPool>,
}

impl std::fmt::Debug for PgExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgExecutor")
            .field("pool", &self.pool)
            .finish()
    }
}

impl PgExecutor {
    /// Create an executor from the config (builds the pool; illegal
    /// `extra_opts` errors at pool-build time).
    pub fn new(config: &excapp_db_core::config::DatabaseConfig) -> Result<Self, PgError> {
        Ok(Self {
            pool: std::sync::Arc::new(super::PgPool::new(config)?),
        })
    }

    /// Execute a query (simple query protocol, supports semicolon-
    /// separated multi-statement batches).
    ///
    /// - The result is the columns + row values (text + null flag) of the
    ///   last statement that produced a result set;
    /// - More than 100 rows rejects the whole batch, no partial results;
    /// - The SQL is assumed to have been validated by the caller through
    ///   sql-validator.
    pub async fn execute(&self, sql: &str) -> Result<QueryResult, PgError> {
        let rows = self.simple_query(sql).await?;

        // Count before assembly: abort once over the limit (the
        // simple_query result is already in memory, but deciding before
        // assembly guarantees no partial results).
        let row_count = rows
            .iter()
            .filter(|r| matches!(r, tokio_postgres::SimpleQueryMessage::Row(_)))
            .count();
        if row_count > ROW_LIMIT {
            return Err(PgError::RowLimit {
                db_name: self.pool.db_name.clone(),
                actual: row_count,
                limit: ROW_LIMIT,
            });
        }

        // Byte-total limit (user queries only): sum of cell text UTF-8
        // bytes; deciding before assembly returns no partial results.
        let byte_total: usize = rows
            .iter()
            .filter_map(|m| match m {
                tokio_postgres::SimpleQueryMessage::Row(row) => Some(
                    (0..row.columns().len())
                        .filter_map(|i| row.get(i))
                        .map(str::len)
                        .sum::<usize>(),
                ),
                _ => None,
            })
            .sum();
        if byte_total > RESULT_BYTE_LIMIT {
            return Err(PgError::ByteLimit {
                db_name: self.pool.db_name.clone(),
                actual: byte_total,
                limit: RESULT_BYTE_LIMIT,
            });
        }

        Ok(assemble_result(rows))
    }

    /// Execute fixed server-side metadata SQL: same execution path as
    /// [`execute`], only skipping the row limit.
    ///
    /// # Safety boundary
    ///
    /// For metadata queries hard-coded in caller code (information_schema
    /// / pg_catalog, etc.) only — the row count of such queries is decided
    /// by the target database's catalog size, and truncation would break
    /// listing completeness. It must **not** be used to execute
    /// user-supplied SQL: user SQL must go through [`execute`]
    /// (protected by the row limit).
    pub async fn execute_metadata(&self, sql: &str) -> Result<QueryResult, PgError> {
        let rows = self.simple_query(sql).await?;
        Ok(assemble_result(rows))
    }

    /// Execute via the simple query protocol and return raw messages
    /// (error mapping includes the SQLSTATE enhancement).
    ///
    /// Every execution atomically binds the session prefix before the
    /// query (statement timeout; derived connections also include
    /// search_path): the target may be a transaction-level pooler proxy
    /// that strips startup parameters and resets session GUCs when
    /// recycling backend connections, so the same-string prefix is the
    /// only reliable form.
    async fn simple_query(
        &self,
        sql: &str,
    ) -> Result<Vec<tokio_postgres::SimpleQueryMessage>, PgError> {
        let client = self.pool.acquire().await?;
        let prefixed = format!("{}{sql}", self.pool.session_prefix);
        client
            .simple_query(&prefixed)
            .await
            .map_err(|e| PgError::Query {
                db_name: self.pool.db_name.clone(),
                detail: crate::pg::flatten_error(&e),
            })
    }

    /// Expose the shared pool handle (the health check reuses the same
    /// pool).
    pub fn shared_pool(&self) -> std::sync::Arc<super::PgPool> {
        std::sync::Arc::clone(&self.pool)
    }

    /// Derive an executor pointing at the same instance and a given
    /// database (for cross-database queries).
    ///
    /// Only dbname is replaced; connection parameters (host/port/
    /// credentials) are inherited from this executor.
    pub fn for_database(&self, database: &str) -> Result<Self, super::PgError> {
        self.pool.for_database(database).map(|pool| Self {
            pool: std::sync::Arc::new(pool),
        })
    }

    /// Same as [`for_database`], additionally setting a default schema
    /// (search_path).
    pub fn for_database_with_schema(
        &self,
        database: &str,
        schema: Option<&str>,
    ) -> Result<Self, super::PgError> {
        self.pool
            .for_database_with_schema(database, schema)
            .map(|pool| Self {
                pool: std::sync::Arc::new(pool),
            })
    }
}

/// Group the simple query message stream by statement and take the result
/// of the last statement that produced a result set.
///
/// A RowDescription opens a result set group and a CommandComplete closes
/// it; for multi-statement batches the last group with a RowDescription
/// wins (later groups overwrite earlier ones); an empty result set still
/// yields column names from its RowDescription.
fn assemble_result(rows: Vec<tokio_postgres::SimpleQueryMessage>) -> QueryResult {
    let mut columns: Vec<String> = Vec::new();
    let mut result_rows: Vec<Vec<CellValue>> = Vec::new();
    let mut current_columns: Vec<String> = Vec::new();
    let mut current_rows: Vec<Vec<CellValue>> = Vec::new();

    for message in rows {
        match message {
            tokio_postgres::SimpleQueryMessage::RowDescription(desc) => {
                // A new statement's result set begins: reset the
                // accumulating group.
                current_columns = desc.iter().map(|c| c.name().to_string()).collect();
                current_rows = Vec::new();
            }
            tokio_postgres::SimpleQueryMessage::Row(row) => {
                let mut values = Vec::with_capacity(row.len());
                for i in 0..row.len() {
                    match row.get(i) {
                        Some(text) => values.push(CellValue::text(text)),
                        None => values.push(CellValue::null()),
                    }
                }
                current_rows.push(values);
            }
            tokio_postgres::SimpleQueryMessage::CommandComplete(_)
                if !current_columns.is_empty() =>
            {
                // This statement ends: the group had a RowDescription,
                // so it overwrites the final result as the latest
                // statement with a result set.
                columns = std::mem::take(&mut current_columns);
                result_rows = std::mem::take(&mut current_rows);
            }
            _ => {}
        }
    }

    QueryResult {
        columns,
        rows: result_rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn executor() -> PgExecutor {
        PgExecutor::new(&crate::pg::test_config()).unwrap()
    }

    async fn ensure_available(exe: &PgExecutor) -> bool {
        crate::pg::connection_available(&exe.shared_pool()).await
    }

    #[tokio::test]
    async fn test_simple_select_returns_columns_and_rows() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        let result = exe.execute("SELECT 1 AS n").await.unwrap();
        assert_eq!(result.columns, vec!["n".to_string()]);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][0].text, "1");
        assert!(!result.rows[0][0].is_null);
    }

    #[tokio::test]
    async fn test_multi_column_multi_row_order_preserved() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        let result = exe
            .execute("SELECT * FROM (VALUES (2,'b'),(1,'a')) AS t(n, s) ORDER BY n")
            .await
            .unwrap();
        assert_eq!(result.columns, vec!["n".to_string(), "s".to_string()]);
        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.rows[0][0].text, "1");
        assert_eq!(result.rows[0][1].text, "a");
        assert_eq!(result.rows[1][0].text, "2");
    }

    #[tokio::test]
    async fn test_type_text_rendering() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        let result = exe
            .execute("SELECT 42::int, 3.5::float8, true::bool, false::bool, 'txt'::text, NULL::text, ''::text, '2026-11-02'::date")
            .await
            .unwrap();
        let row = &result.rows[0];
        assert_eq!(row[0].text, "42");
        assert_eq!(row[1].text, "3.5");
        assert_eq!(row[2].text, "t");
        assert_eq!(row[3].text, "f");
        assert_eq!(row[4].text, "txt");
        assert!(row[5].is_null, "NULL must be marked");
        assert!(
            !row[6].is_null && row[6].text.is_empty(),
            "empty string distinct from NULL"
        );
        assert_eq!(row[7].text, "2026-11-02");
    }

    #[tokio::test]
    async fn test_empty_result_set_keeps_columns() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        let result = exe.execute("SELECT 1 AS x WHERE false").await.unwrap();
        assert_eq!(result.columns, vec!["x".to_string()]);
        assert!(result.rows.is_empty());
    }

    #[tokio::test]
    async fn test_query_error_passes_pg_semantics() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        let err = exe
            .execute("SELECT * FROM no_such_table_xyz")
            .await
            .unwrap_err();
        let msg = err.to_string();
        // Server errors vary with locale (English "does not exist" /
        // Chinese "不存在"); assert the error classification + database
        // identity + SQLSTATE 42P01 (undefined_table).
        assert!(msg.contains("query failed"), "{msg}");
        assert!(msg.contains("'test'"), "{msg}");
        assert!(
            msg.contains("42P01") || msg.contains("does not exist") || msg.contains("不存在"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn test_row_limit_exceeded_fails_whole_batch() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        let err = exe
            .execute("SELECT g FROM generate_series(1, 101) AS g")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("row limit"), "{msg}");
        assert!(msg.contains("101"), "{msg}");
        assert!(msg.contains("100"), "{msg}");
    }

    #[tokio::test]
    async fn test_row_limit_boundary_100_ok() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        let result = exe
            .execute("SELECT g FROM generate_series(1, 100) AS g")
            .await
            .unwrap();
        assert_eq!(result.rows.len(), 100);
    }

    #[tokio::test]
    async fn test_byte_limit_exceeded_fails_whole_batch() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        // A single 11MB row: exceeds the 10MB byte-total limit.
        let err = exe
            .execute("SELECT repeat('A', 11 * 1024 * 1024)")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("byte limit"), "{msg}");
        assert!(msg.contains("test"), "{msg}");
    }

    #[tokio::test]
    async fn test_byte_limit_boundary_1mb_ok() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        // A single 1MB row: far below the limit, returns normally.
        let result = exe
            .execute("SELECT length(repeat('A', 1024 * 1024)) AS len")
            .await
            .unwrap();
        assert_eq!(result.rows[0][0].text, "1048576");
    }

    #[tokio::test]
    async fn test_metadata_entry_skips_row_limit() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        // The metadata entry point has no row limit (catalog size is
        // decided by the target database).
        let result = exe
            .execute_metadata("SELECT g FROM generate_series(1, 101) AS g")
            .await
            .unwrap();
        assert_eq!(result.rows.len(), 101);
        assert_eq!(result.columns, vec!["g".to_string()]);
    }

    #[tokio::test]
    async fn test_multi_statement_batch() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        // Multi-statement: the last statement with a result set wins
        // (whitelist already validated by the caller).
        let result = exe.execute("SELECT 1 AS a; SELECT 2 AS b").await.unwrap();
        assert_eq!(result.columns, vec!["b".to_string()]);
        assert_eq!(result.rows[0][0].text, "2");
    }

    #[tokio::test]
    async fn test_special_characters_preserved() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        let result = exe
            .execute("SELECT 'quote''d \"dq\" \n newline 中文 🚀' AS s")
            .await
            .unwrap();
        assert_eq!(result.rows[0][0].text, "quote'd \"dq\" \n newline 中文 🚀");
    }

    #[tokio::test]
    async fn test_duplicate_column_names_kept() {
        let exe = executor().await;
        if !ensure_available(&exe).await {
            eprintln!("skipping: test postgres not available");
            return;
        }
        let result = exe.execute("SELECT 1 AS a, 2 AS a").await.unwrap();
        assert_eq!(result.columns, vec!["a".to_string(), "a".to_string()]);
    }
}
