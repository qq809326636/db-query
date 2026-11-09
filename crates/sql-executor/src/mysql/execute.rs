//! byte limit protection).

use super::{MyError, RESULT_BYTE_LIMIT, ROW_LIMIT};
use crate::{CellValue, QueryResult};
use futures_util::StreamExt;

use mysql_async::prelude::*;
use mysql_async::{Column, Row, Value};
/// MySQL query executor: holds the connection pool and implements the unified
/// execution entry.
pub struct MyExecutor {
    /// Shared connection pool (shared with the health check).
    pool: std::sync::Arc<super::MyPool>,
}

impl std::fmt::Debug for MyExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MyExecutor")
            .field("pool", &self.pool)
            .finish()
    }
}

impl MyExecutor {
    /// Create the executor from config (builds the pool; invalid `extra_opts`
    pub fn new(config: &excapp_db_core::config::DatabaseConfig) -> Result<Self, MyError> {
        Ok(Self {
            pool: std::sync::Arc::new(super::MyPool::new(config)?),
        })
    }

    /// Execute a query (text protocol; semicolon-separated multi-statement
    /// batches supported).
    ///
    /// - The result is the column names + row values (text + null flags) of the
    ///   last statement that has a result set;
    pub async fn execute(&self, sql: &str) -> Result<QueryResult, MyError> {
        self.run(sql, true).await
    }

    /// Execute server-side fixed metadata SQL: same execution path as
    /// [`execute`], only skipping the row and byte limits.
    ///
    /// # Security boundary
    ///
    /// Only for metadata queries assembled statically inside caller code
    /// (information_schema etc.); **never** for user-supplied SQL (which must go
    pub async fn execute_metadata(&self, sql: &str) -> Result<QueryResult, MyError> {
        self.run(sql, false).await
    }
    /// consumption.
    ///
    /// Every execution atomically binds the session prefix (the timeout SET; a
    /// configured charset adds SET NAMES) before the query: the target may be a
    /// session-scoped proxy that can reset a one-shot SET issued right after
    /// connecting, so the same-string prefix is the reliable shape.
    async fn run(&self, sql: &str, enforce_limits: bool) -> Result<QueryResult, MyError> {
        let mut conn = self.pool.acquire().await?;
        let prefixed = format!("{}{sql}", self.pool.session_prefix);

        let mut result = conn
            .query_iter(prefixed.as_str())
            .await
            .map_err(|e| MyError::Query {
                db_name: self.pool.db_name.clone(),
                detail: e.to_string(),
            })?;

        let mut columns: Vec<String> = Vec::new();
        let mut result_rows: Vec<Vec<CellValue>> = Vec::new();
        let mut row_count: usize = 0;
        let mut byte_total: usize = 0;
        // set each call (None means no more); column names are available as soon
        // as the result set is established — **empty result sets keep their
        // column names too** (the text protocol sends column definitions before
        // row data).
        loop {
            let Some(mut stream) = result.stream::<Row>().await.map_err(|e| MyError::Query {
                db_name: self.pool.db_name.clone(),
                detail: e.to_string(),
            })?
            else {
                break;
            };

            let set_columns: Vec<String> = stream
                .columns_ref()
                .iter()
                .map(|c| c.name_str().to_string())
                .collect();
            // Binary column flag (the BLOB family renders as hexadecimal).
            let binary: Vec<bool> = stream.columns_ref().iter().map(is_binary_column).collect();

            let mut set_rows: Vec<Vec<CellValue>> = Vec::new();
            while let Some(item) = stream.next().await {
                let row = item.map_err(|e| MyError::Query {
                    db_name: self.pool.db_name.clone(),
                    detail: e.to_string(),
                })?;
                let mut values = Vec::with_capacity(row.len());
                for (i, value) in row.unwrap_raw().into_iter().enumerate() {
                    let cell = cell_value(value, binary.get(i).copied().unwrap_or(false));
                    if !cell.is_null {
                        byte_total += cell.text.len();
                    }
                    values.push(cell);
                }
                row_count += 1;
                set_rows.push(values);
                if enforce_limits && row_count > ROW_LIMIT {
                    return Err(MyError::RowLimit {
                        db_name: self.pool.db_name.clone(),
                        actual: row_count,
                        limit: ROW_LIMIT,
                    });
                }
                if enforce_limits && byte_total > RESULT_BYTE_LIMIT {
                    return Err(MyError::ByteLimit {
                        db_name: self.pool.db_name.clone(),
                        actual: byte_total,
                        limit: RESULT_BYTE_LIMIT,
                    });
                }
            }

            // Result sets with column definitions (including empty ones) override
            // the final result; statements producing only OK packets (e.g. SET)
            if !set_columns.is_empty() {
                columns = set_columns;
                result_rows = set_rows;
            }
        }

        Ok(QueryResult {
            columns,
            rows: result_rows,
            cursor: None,
        })
    }

    /// Expose the shared pool handle (the health check reuses the same pool).
    pub fn shared_pool(&self) -> std::sync::Arc<super::MyPool> {
        std::sync::Arc::clone(&self.pool)
    }

    /// Database id (for the enum-layer NotRedis error).
    pub(crate) fn db_name(&self) -> &str {
        &self.pool.db_name
    }
    /// Derive an executor pointing at the same instance and the given database
    /// (for cross-database queries).
    pub fn for_database(&self, database: &str) -> Result<Self, MyError> {
        self.pool
            .for_database_with_schema(database, None)
            .map(|pool| Self {
                pool: std::sync::Arc::new(pool),
            })
    }

    /// Same as [`for_database`], with an optional schema (synonymous with
    /// database in MySQL; rejected when they disagree).
    pub fn for_database_with_schema(
        &self,
        database: &str,
        schema: Option<&str>,
    ) -> Result<Self, MyError> {
        self.pool
            .for_database_with_schema(database, schema)
            .map(|pool| Self {
                pool: std::sync::Arc::new(pool),
            })
    }
}

/// Whether the column belongs to the binary family (BLOB / BINARY / VARBINARY).
///
/// Judged by column type and charset, **not** by `BINARY_FLAG` — that flag is
/// set for every non-text column in the MySQL protocol (including numeric /
/// temporal); numeric / temporal columns also have charset 63 (binary). Hence:
/// the BLOB family is judged by column type; BINARY / VARBINARY have string
/// column types with charset 63 (numeric columns are excluded by their types).
/// Judging by the flag would wrongly hex-encode the integer `1` (byte `0x31`)
fn is_binary_column(column: &Column) -> bool {
    use mysql_async::consts::ColumnType;

    match column.column_type() {
        ColumnType::MYSQL_TYPE_BLOB
        | ColumnType::MYSQL_TYPE_TINY_BLOB
        | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
        | ColumnType::MYSQL_TYPE_LONG_BLOB => true,
        // String family: only the binary charset (63) means BINARY / VARBINARY.
        ColumnType::MYSQL_TYPE_STRING | ColumnType::MYSQL_TYPE_VAR_STRING => {
            column.character_set() == 63
        }
        // Numeric / temporal / others: rendered as text (charset 63 does not imply binary data).
        _ => false,
    }
}
/// through lowercase hexadecimal, everything else as text.
///
/// Under the text protocol the server already provides the textual shape per
/// column type (decimal integers, dates `YYYY-MM-DD`, timestamps
/// `YYYY-MM-DD HH:MM:SS`, etc.), so decoding directly suffices; other variants
/// (the binary-protocol path) render as equivalent text.
fn cell_value(value: Option<Value>, binary: bool) -> CellValue {
    let Some(value) = value else {
        return CellValue::null();
    };
    match value {
        Value::NULL => CellValue::null(),
        Value::Bytes(bytes) => {
            if binary {
                CellValue::text(to_hex(&bytes))
            } else {
                CellValue::text(String::from_utf8_lossy(&bytes))
            }
        }
        Value::Int(i) => CellValue::text(i.to_string()),
        Value::UInt(u) => CellValue::text(u.to_string()),
        Value::Float(f) => CellValue::text(f.to_string()),
        Value::Double(d) => CellValue::text(d.to_string()),
        Value::Date(year, month, day, hour, minute, second, micros) => {
            if hour == 0 && minute == 0 && second == 0 && micros == 0 {
                CellValue::text(format!("{year:04}-{month:02}-{day:02}"))
            } else {
                CellValue::text(format_datetime(
                    year, month, day, hour, minute, second, micros,
                ))
            }
        }
        Value::Time(negative, days, hours, minutes, seconds, micros) => {
            let total_hours = days * 24 + u32::from(hours);
            let sign = if negative { "-" } else { "" };
            if micros == 0 {
                CellValue::text(format!("{sign}{total_hours:02}:{minutes:02}:{seconds:02}"))
            } else {
                CellValue::text(format!(
                    "{sign}{total_hours:02}:{minutes:02}:{seconds:02}.{micros:06}"
                ))
            }
        }
    }
}

/// Datetime textual shape (`YYYY-MM-DD HH:MM:SS[.ffffff]`).
fn format_datetime(
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    micros: u32,
) -> String {
    if micros == 0 {
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
    } else {
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{micros:06}")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn executor() -> MyExecutor {
        MyExecutor::new(&crate::mysql::test_config()).unwrap()
    }

    #[test]
    fn test_cell_value_null_and_text() {
        assert!(cell_value(None, false).is_null);
        assert!(cell_value(Some(Value::NULL), false).is_null);
        let cell = cell_value(Some(Value::Bytes(b"abc".to_vec())), false);
        assert_eq!(cell.text, "abc");
        assert!(!cell.is_null);
    }

    #[test]
    fn test_cell_value_binary_is_lowercase_hex() {
        let cell = cell_value(Some(Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef])), true);
        assert_eq!(cell.text, "deadbeef");
    }

    #[test]
    fn test_cell_value_numbers_and_datetime() {
        assert_eq!(cell_value(Some(Value::Int(-7)), false).text, "-7");
        assert_eq!(cell_value(Some(Value::UInt(7)), false).text, "7");
        let date = cell_value(Some(Value::Date(2026, 11, 5, 0, 0, 0, 0)), false);
        assert_eq!(date.text, "2026-11-05");
        let ts = cell_value(Some(Value::Date(2026, 11, 5, 10, 20, 30, 0)), false);
        assert_eq!(ts.text, "2026-11-05 10:20:30");
        let time = cell_value(Some(Value::Time(false, 1, 2, 3, 4, 0)), false);
        assert_eq!(time.text, "26:03:04");
    }

    #[tokio::test]
    async fn test_execute_simple_query() -> anyhow::Result<()> {
        let exec = executor();
        if !crate::mysql::connection_available(&exec.shared_pool()).await {
            eprintln!("skipping: test mysql not available");
            return Ok(());
        }
        let result = exec.execute("SELECT 1 AS n").await?;
        assert_eq!(result.columns, vec!["n".to_string()]);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][0].text, "1");
        Ok(())
    }

    #[tokio::test]
    async fn test_execute_types_blob_hex_and_text_intact() -> anyhow::Result<()> {
        let exec = executor();
        if !crate::mysql::connection_available(&exec.shared_pool()).await {
            eprintln!("skipping: test mysql not available");
            return Ok(());
        }
        // INT / CHAR columns stay text (regression anchor: numerics were once
        // misjudged as binary and hex-encoded).
        let result = exec
            .execute(concat!(
                "SELECT CAST(x'deadbeef' AS BINARY(4)) AS b, ",
                "CAST(31 AS SIGNED) AS i, ",
                "CAST('31' AS CHAR(2)) AS c, ",
                "x'deadbeef' AS blob_col"
            ))
            .await?;
        assert_eq!(
            result.columns,
            vec!["b", "i", "c", "blob_col"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(result.rows.len(), 1);
        // BINARY(4): string family + binary charset → hexadecimal.
        assert_eq!(result.rows[0][0].text, "deadbeef");
        // SIGNED numerics: charset 63 but a numeric column type → text rendering.
        assert_eq!(result.rows[0][1].text, "31");
        // CHAR text columns: text as-is.
        assert_eq!(result.rows[0][2].text, "31");
        // BLOB literal columns: BLOB family → hexadecimal.
        assert_eq!(result.rows[0][3].text, "deadbeef");
        Ok(())
    }

    #[tokio::test]
    async fn test_execute_empty_result_keeps_columns() -> anyhow::Result<()> {
        let exec = executor();
        if !crate::mysql::connection_available(&exec.shared_pool()).await {
            eprintln!("skipping: test mysql not available");
            return Ok(());
        }
        // Empty result sets still keep column names (text protocol sends column
        let result = exec.execute("SELECT 1 AS n WHERE false").await?;
        assert_eq!(result.columns, vec!["n".to_string()]);
        assert!(result.rows.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_execute_batch_takes_last_result_group() -> anyhow::Result<()> {
        let exec = executor();
        if !crate::mysql::connection_available(&exec.shared_pool()).await {
            eprintln!("skipping: test mysql not available");
            return Ok(());
        }
        let result = exec
            .execute("SELECT 1 AS a; SELECT 2 AS b WHERE false; SELECT 3 AS c")
            .await?;
        assert_eq!(result.columns, vec!["c".to_string()]);
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][0].text, "3");
        Ok(())
    }

    #[tokio::test]
    async fn test_execute_row_limit_rejects_whole_batch() -> anyhow::Result<()> {
        let exec = executor();
        if !crate::mysql::connection_available(&exec.shared_pool()).await {
            eprintln!("skipping: test mysql not available");
            return Ok(());
        }
        let err = exec
            .execute(
                "WITH RECURSIVE seq AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM seq WHERE n < 101) SELECT n FROM seq",
            )
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("row limit"), "{msg}");
        assert!(msg.contains("limit is 100"), "{msg}");
        Ok(())
    }

    #[tokio::test]
    async fn test_execute_error_contains_identity_and_semantics() -> anyhow::Result<()> {
        let exec = executor();
        if !crate::mysql::connection_available(&exec.shared_pool()).await {
            eprintln!("skipping: test mysql not available");
            return Ok(());
        }
        let err = exec
            .execute("SELECT * FROM no_such_table_xyz")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("query failed"), "{msg}");
        assert!(msg.contains("'test'"), "{msg}");
        assert!(
            msg.to_lowercase().contains("no_such_table_xyz")
                || msg.to_lowercase().contains("doesn't exist"),
            "{msg}"
        );
        Ok(())
    }
}
