//! RedisExecutor: read-only command execution and RESP2 response mapping.
//!
//! Per-command column-structure mapping implementation:
//! the five RESP shapes map to columns + rows (text + null marker, binaries rendered as lowercase
//! hexadecimal); SCAN-family cursors go into `QueryResult.cursor`; the row / byte /
//! row/byte/timeout protections align with the existing three databases.

use super::connection::flatten_error;
use super::{COMMAND_TIMEOUT, RESULT_BYTE_LIMIT, ROW_LIMIT, RedisError, RedisPool};
use crate::{CellValue, QueryResult};
use std::sync::Arc;

/// Redis command executor: holds the shared connection pool and implements execution and mapping.
pub struct RedisExecutor {
    /// Shared connection pool (shared with the health check).
    pool: Arc<RedisPool>,
}

impl std::fmt::Debug for RedisExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisExecutor")
            .field("pool", &self.pool)
            .finish()
    }
}

impl RedisExecutor {
    /// Create the executor from config (pool built lazily, no connection; db validation happens at pool build).
    pub fn new(config: &excapp_db_core::config::DatabaseConfig) -> Result<Self, RedisError> {
        Ok(Self {
            pool: Arc::new(RedisPool::new(config)?),
        })
    }

    /// Execute a validated command (triple protection: rows / bytes / timeout).
    ///
    /// # Security contract
    ///
    /// tokens must come from a CommandWhitelist-allowed normalized command (command name,
    /// subcommand and arguments flattened); this executor neither re-runs whitelist checks nor relaxes anything.
    pub async fn execute(&self, tokens: &[String]) -> Result<QueryResult, RedisError> {
        let result = self.run(tokens).await?;
        if result.rows.len() > ROW_LIMIT {
            return Err(RedisError::RowLimit {
                db_name: self.pool.db_name.clone(),
                actual: result.rows.len(),
                limit: ROW_LIMIT,
            });
        }
        // Byte total: UTF-8 bytes of cell texts (nulls count 0; the cursor is excluded).
        let byte_total: usize = result
            .rows
            .iter()
            .flatten()
            .map(|c| if c.is_null { 0 } else { c.text.len() })
            .sum();
        if byte_total > RESULT_BYTE_LIMIT {
            return Err(RedisError::ByteLimit {
                db_name: self.pool.db_name.clone(),
                actual: byte_total,
                limit: RESULT_BYTE_LIMIT,
            });
        }
        Ok(result)
    }

    /// Execute fixed metadata commands: skips the row / byte caps (the timeout still applies).
    ///
    /// # Security boundary
    ///
    /// Only for whitelisted command sequences hard-assembled in caller code; **never** for
    /// user-input commands (which must go through [`execute`](Self::execute)).
    pub async fn execute_metadata(&self, tokens: &[String]) -> Result<QueryResult, RedisError> {
        self.run(tokens).await
    }

    /// Execution backbone: a 30s client-side timeout wraps "acquire + command send + response read"
    /// (multiplexed connections give each request an independent response channel, so a timeout drop breaks no consistency),
    /// then produces the QueryResult per the per-command mapping table.
    async fn run(&self, tokens: &[String]) -> Result<QueryResult, RedisError> {
        if tokens.is_empty() {
            return Err(RedisError::Command {
                db_name: self.pool.db_name.clone(),
                detail: "empty command".to_string(),
            });
        }
        let db_name = self.pool.db_name.clone();
        let send = async {
            let mut conn = self.pool.acquire().await?;
            redis::cmd(&tokens[0])
                .arg(&tokens[1..])
                .query_async::<redis::Value>(&mut conn)
                .await
                .map_err(|e| RedisError::Command {
                    db_name: db_name.clone(),
                    detail: flatten_error(&e),
                })
        };
        let value = tokio::time::timeout(COMMAND_TIMEOUT, send)
            .await
            .map_err(|_| RedisError::Timeout {
                db_name: db_name.clone(),
            })??;
        map_response(&db_name, tokens, value)
    }

    /// Expose the shared pool handle (the health check reuses the same pool).
    pub fn shared_pool(&self) -> Arc<RedisPool> {
        Arc::clone(&self.pool)
    }

    /// Derive an executor (cross-logical-database queries): same number clones the shared pool, a different number builds a new one;
    /// schema is meaningless for Redis and is explicitly rejected when not None (aligned with the sqlite precedent).
    pub fn for_database_with_schema(
        &self,
        db_field: &str,
        schema: Option<&str>,
    ) -> Result<Self, RedisError> {
        if let Some(schema) = schema {
            let _ = schema;
            return Err(RedisError::SchemaNotSupported {
                db_name: self.pool.db_name.clone(),
            });
        }
        let pool = self.pool.for_database(db_field)?;
        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    /// Database id (for enum-layer error construction).
    pub(crate) fn db_name(&self) -> &str {
        &self.pool.db_name
    }
}

// -- Mapping layer (pure functions, the per-command column mapping table) --

/// One RESP value -> one cell: Nil -> null; a valid-UTF-8 BulkString -> the original text,
/// otherwise lowercase hexadecimal; Int -> decimal text; SimpleString -> the original text;
/// Okay -> `OK`; array-shaped values in a scalar position -> Err (shape mismatch).
fn cell_of(v: &redis::Value) -> Result<CellValue, ()> {
    Ok(match v {
        redis::Value::Nil => CellValue::null(),
        redis::Value::Int(i) => CellValue::text(i.to_string()),
        redis::Value::BulkString(b) => CellValue::text(bulk_text(b)),
        redis::Value::SimpleString(s) => CellValue::text(s.clone()),
        redis::Value::Okay => CellValue::text("OK"),
        _ => return Err(()),
    })
}

/// Render a bulk string: valid UTF-8 as-is, otherwise lowercase hexadecimal (no prefix).
fn bulk_text(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

/// Take array contents (non-array -> Err).
fn array_of(v: &redis::Value) -> Result<&[redis::Value], ()> {
    match v {
        redis::Value::Array(items) => Ok(items),
        _ => Err(()),
    }
}

/// Scalar single-value commands: one column, one row; a top-level Nil -> an empty result set (columns kept).
fn single(
    col: &'static str,
    value: &redis::Value,
) -> Result<(Vec<&'static str>, Vec<Vec<CellValue>>), ()> {
    if matches!(value, redis::Value::Nil) {
        return Ok((vec![col], Vec::new()));
    }
    Ok((vec![col], vec![vec![cell_of(value)?]]))
}

/// Pair a flat alternating array into rows (odd length -> Err, defensively).
fn pair_rows(
    cols: [&'static str; 2],
    items: &[redis::Value],
) -> Result<(Vec<&'static str>, Vec<Vec<CellValue>>), ()> {
    if !items.len().is_multiple_of(2) {
        return Err(());
    }
    let mut rows = Vec::with_capacity(items.len() / 2);
    for pair in items.chunks_exact(2) {
        rows.push(vec![cell_of(&pair[0])?, cell_of(&pair[1])?]);
    }
    Ok((cols.into(), rows))
}

/// One single-column row per array element.
fn element_rows(
    col: &'static str,
    items: &[redis::Value],
) -> Result<(Vec<&'static str>, Vec<Vec<CellValue>>), ()> {
    Ok((
        vec![col],
        items
            .iter()
            .map(|e| Ok(vec![cell_of(e)?]))
            .collect::<Result<_, ()>>()?,
    ))
}

/// RESP response -> QueryResult (per-command column mapping table).
///
/// Column structures and option branches (WITHSCORES / WITHCOORD / COUNT, ...) are decided by the input tokens;
/// the same command with the same input shape yields a stable column structure. Unknown command names (the caller bypassing
/// the whitelist) are rejected as shape mismatches (fail closed, no panic).
pub(crate) fn map_response(
    db_name: &str,
    tokens: &[String],
    value: redis::Value,
) -> Result<QueryResult, RedisError> {
    use redis::Value;
    let name = tokens[0].to_uppercase();
    let has_opt = |opt: &str| tokens.iter().any(|t| t.eq_ignore_ascii_case(opt));
    let mismatch = || RedisError::Command {
        db_name: db_name.to_string(),
        detail: format!("unexpected response shape for command '{name}'"),
    };
    let shape = || -> Result<&[Value], RedisError> { array_of(&value).map_err(|_| mismatch()) };

    // -- G. SCAN family: the cursor goes into the cursor field --
    if matches!(name.as_str(), "SCAN" | "SSCAN" | "HSCAN" | "ZSCAN") {
        let parts = shape()?;
        if parts.len() != 2 {
            return Err(mismatch());
        }
        let cursor = match &parts[0] {
            Value::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
            _ => return Err(mismatch()),
        };
        let elements = array_of(&parts[1]).map_err(|_| mismatch())?;
        let (columns, rows) = match name.as_str() {
            "SCAN" => element_rows("key", elements).map_err(|_| mismatch())?,
            "SSCAN" => element_rows("member", elements).map_err(|_| mismatch())?,
            "HSCAN" => pair_rows(["field", "value"], elements).map_err(|_| mismatch())?,
            _ => pair_rows(["member", "score"], elements).map_err(|_| mismatch())?,
        };
        return Ok(QueryResult {
            columns: columns.into_iter().map(str::to_string).collect(),
            rows,
            cursor: Some(cursor),
        });
    }

    let (columns, rows): (Vec<&str>, Vec<Vec<CellValue>>) = match name.as_str() {
        // -- A. Scalar single values (top-level Nil -> 0 rows) --
        "GET" | "GETRANGE" | "SUBSTR" | "HGET" | "LINDEX" => {
            single("value", &value).map_err(|_| mismatch())?
        }
        "STRLEN" => single("length", &value).map_err(|_| mismatch())?,
        "TTL" => single("ttl_seconds", &value).map_err(|_| mismatch())?,
        "PTTL" => single("ttl_milliseconds", &value).map_err(|_| mismatch())?,
        "TYPE" => single("type", &value).map_err(|_| mismatch())?,
        "RANDOMKEY" => single("key", &value).map_err(|_| mismatch())?,
        "EXISTS" | "DBSIZE" | "LLEN" | "SCARD" | "ZCARD" | "XLEN" | "PFCOUNT" | "ZCOUNT"
        | "ZLEXCOUNT" | "BITCOUNT" => single("count", &value).map_err(|_| mismatch())?,
        "PING" => single("reply", &value).map_err(|_| mismatch())?,
        "ECHO" => single("message", &value).map_err(|_| mismatch())?,
        "LASTSAVE" => single("unix_seconds", &value).map_err(|_| mismatch())?,
        "HEXISTS" => single("exists", &value).map_err(|_| mismatch())?,
        "SISMEMBER" => single("is_member", &value).map_err(|_| mismatch())?,
        "ZSCORE" => single("score", &value).map_err(|_| mismatch())?,
        "ZRANK" | "ZREVRANK" => single("rank", &value).map_err(|_| mismatch())?,
        "GETBIT" => single("bit", &value).map_err(|_| mismatch())?,
        "BITPOS" => single("position", &value).map_err(|_| mismatch())?,
        "GEODIST" => single("distance", &value).map_err(|_| mismatch())?,
        "INFO" => single("info", &value).map_err(|_| mismatch())?,
        // -- A. Subcommand granularity --
        "OBJECT" => {
            let col = match tokens.get(1).map(|s| s.to_uppercase()).as_deref() {
                Some("ENCODING") => "encoding",
                Some("REFCOUNT") => "refcount",
                Some("IDLETIME") => "idle_time_seconds",
                Some("FREQ") => "frequency",
                _ => return Err(mismatch()),
            };
            single(col, &value).map_err(|_| mismatch())?
        }
        "MEMORY" => {
            let sub = tokens.get(1).map(|s| s.to_uppercase());
            if sub.as_deref() != Some("USAGE") {
                return Err(mismatch());
            }
            single("bytes", &value).map_err(|_| mismatch())?
        }
        // -- A. TIME: two-element array -> two columns, one row --
        "TIME" => {
            let parts = shape()?;
            if parts.len() != 2 {
                return Err(mismatch());
            }
            (
                vec!["unix_seconds", "unix_microseconds"],
                vec![vec![
                    cell_of(&parts[0]).map_err(|_| mismatch())?,
                    cell_of(&parts[1]).map_err(|_| mismatch())?,
                ]],
            )
        }
        // -- B. Input alignment --
        "MGET" => {
            let keys = &tokens[1..];
            let items = shape()?;
            if items.len() != keys.len() {
                return Err(mismatch());
            }
            (
                vec!["key", "value"],
                keys.iter()
                    .zip(items)
                    .map(|(k, v)| {
                        Ok(vec![
                            CellValue::text(k.clone()),
                            cell_of(v).map_err(|_| mismatch())?,
                        ])
                    })
                    .collect::<Result<_, RedisError>>()?,
            )
        }
        "HMGET" => input_paired("field", "value", &tokens[2..], &value).map_err(|_| mismatch())?,
        "SMISMEMBER" => {
            input_paired("member", "is_member", &tokens[2..], &value).map_err(|_| mismatch())?
        }
        "ZMSCORE" => {
            input_paired("member", "score", &tokens[2..], &value).map_err(|_| mismatch())?
        }
        // -- C. Key / element collections --
        "HGETALL" => pair_rows(["field", "value"], shape()?).map_err(|_| mismatch())?,
        "HKEYS" => element_rows("field", shape()?).map_err(|_| mismatch())?,
        "HVALS" => element_rows("value", shape()?).map_err(|_| mismatch())?,
        "SMEMBERS" => element_rows("member", shape()?).map_err(|_| mismatch())?,
        "SRANDMEMBER" => match &value {
            // No count: a single value; with count: an array; empty / missing key: Nil -> 0 rows.
            Value::Nil => (vec!["member"], Vec::new()),
            Value::Array(_) => element_rows("member", shape()?).map_err(|_| mismatch())?,
            other => (
                vec!["member"],
                vec![vec![cell_of(other).map_err(|_| mismatch())?]],
            ),
        },
        "LRANGE" => element_rows("element", shape()?).map_err(|_| mismatch())?,
        "LPOS" => match &value {
            Value::Nil => (vec!["position"], Vec::new()),
            Value::Array(_) => element_rows("position", shape()?).map_err(|_| mismatch())?,
            other => (
                vec!["position"],
                vec![vec![cell_of(other).map_err(|_| mismatch())?]],
            ),
        },
        "BITFIELD_RO" => {
            let items = shape()?;
            (
                vec!["value"],
                items
                    .iter()
                    .map(|e| Ok(vec![cell_of(e).map_err(|_| mismatch())?]))
                    .collect::<Result<_, RedisError>>()?,
            )
        }
        // -- D. Sorted-set ranges: the WITHSCORES branch --
        "ZRANGE" | "ZREVRANGE" | "ZRANGEBYSCORE" | "ZREVRANGEBYSCORE" | "ZRANGEBYLEX"
        | "ZREVRANGEBYLEX" => {
            let items = shape()?;
            if has_opt("WITHSCORES") {
                pair_rows(["member", "score"], items).map_err(|_| mismatch())?
            } else {
                element_rows("member", items).map_err(|_| mismatch())?
            }
        }
        // -- E. Geo --
        "GEOPOS" => {
            let members = &tokens[2..];
            let items = shape()?;
            if items.len() != members.len() {
                return Err(mismatch());
            }
            (
                vec!["member", "longitude", "latitude"],
                members
                    .iter()
                    .zip(items)
                    .map(|(m, coord)| {
                        let (lon, lat) = match coord {
                            Value::Nil => (CellValue::null(), CellValue::null()),
                            Value::Array(c) if c.len() == 2 => (
                                cell_of(&c[0]).map_err(|_| mismatch())?,
                                cell_of(&c[1]).map_err(|_| mismatch())?,
                            ),
                            _ => return Err(mismatch()),
                        };
                        Ok(vec![CellValue::text(m.clone()), lon, lat])
                    })
                    .collect::<Result<_, RedisError>>()?,
            )
        }
        "GEOHASH" => {
            let members = &tokens[2..];
            let items = shape()?;
            if items.len() != members.len() {
                return Err(mismatch());
            }
            (
                vec!["member", "geohash"],
                members
                    .iter()
                    .zip(items)
                    .map(|(m, h)| {
                        Ok(vec![
                            CellValue::text(m.clone()),
                            cell_of(h).map_err(|_| mismatch())?,
                        ])
                    })
                    .collect::<Result<_, RedisError>>()?,
            )
        }
        "GEOSEARCH" => {
            let with_dist = has_opt("WITHDIST");
            let with_hash = has_opt("WITHHASH");
            let with_coord = has_opt("WITHCOORD");
            let mut columns = vec!["member"];
            if with_dist {
                columns.push("distance");
            }
            if with_hash {
                columns.push("hash");
            }
            if with_coord {
                columns.push("longitude");
                columns.push("latitude");
            }
            let items = shape()?;
            let mut rows = Vec::with_capacity(items.len());
            for entry in items {
                // Layout: [member, (dist), (hash), ([lon, lat])], trimmed by the request flags.
                let fields = array_of(entry).map_err(|_| mismatch())?;
                let mut idx = 0usize;
                let mut row = Vec::with_capacity(columns.len());
                let member = fields
                    .get(idx)
                    .map(cell_of)
                    .transpose()
                    .map_err(|_| mismatch())?;
                idx += 1;
                let Some(member) = member else {
                    return Err(mismatch());
                };
                row.push(member);
                if with_dist {
                    row.push(
                        cell_of(fields.get(idx).ok_or_else(mismatch)?).map_err(|_| mismatch())?,
                    );
                    idx += 1;
                }
                if with_hash {
                    row.push(
                        cell_of(fields.get(idx).ok_or_else(mismatch)?).map_err(|_| mismatch())?,
                    );
                    idx += 1;
                }
                if with_coord {
                    let coord =
                        array_of(fields.get(idx).ok_or_else(mismatch)?).map_err(|_| mismatch())?;
                    if coord.len() != 2 {
                        return Err(mismatch());
                    }
                    row.push(cell_of(&coord[0]).map_err(|_| mismatch())?);
                    row.push(cell_of(&coord[1]).map_err(|_| mismatch())?);
                }
                rows.push(row);
            }
            (columns, rows)
        }
        // -- F. Streams --
        "XRANGE" | "XREVRANGE" => {
            let entries = shape()?;
            let mut rows = Vec::new();
            for entry in entries {
                let pair = array_of(entry).map_err(|_| mismatch())?;
                if pair.len() != 2 {
                    return Err(mismatch());
                }
                let id = cell_of(&pair[0]).map_err(|_| mismatch())?;
                let fields = array_of(&pair[1]).map_err(|_| mismatch())?;
                if fields.is_empty() {
                    // Field-less entries: existence kept (field / value null).
                    rows.push(vec![id, CellValue::null(), CellValue::null()]);
                } else {
                    for field_pair in fields.chunks_exact(2) {
                        rows.push(vec![
                            id.clone(),
                            cell_of(&field_pair[0]).map_err(|_| mismatch())?,
                            cell_of(&field_pair[1]).map_err(|_| mismatch())?,
                        ]);
                    }
                }
            }
            (vec!["id", "field", "value"], rows)
        }
        "XREAD" => {
            let mut rows = Vec::new();
            if let Value::Array(groups) = &value {
                for group in groups {
                    // One group per stream: [key, [entries...]].
                    let pair = array_of(group).map_err(|_| mismatch())?;
                    if pair.len() != 2 {
                        return Err(mismatch());
                    }
                    let key = cell_of(&pair[0]).map_err(|_| mismatch())?;
                    let entries = array_of(&pair[1]).map_err(|_| mismatch())?;
                    for entry in entries {
                        let entry_pair = array_of(entry).map_err(|_| mismatch())?;
                        if entry_pair.len() != 2 {
                            return Err(mismatch());
                        }
                        let id = cell_of(&entry_pair[0]).map_err(|_| mismatch())?;
                        let fields = array_of(&entry_pair[1]).map_err(|_| mismatch())?;
                        if fields.is_empty() {
                            rows.push(vec![key.clone(), id, CellValue::null(), CellValue::null()]);
                        } else {
                            for field_pair in fields.chunks_exact(2) {
                                rows.push(vec![
                                    key.clone(),
                                    id.clone(),
                                    cell_of(&field_pair[0]).map_err(|_| mismatch())?,
                                    cell_of(&field_pair[1]).map_err(|_| mismatch())?,
                                ]);
                            }
                        }
                    }
                }
            } else if !matches!(value, Value::Nil) {
                return Err(mismatch());
            }
            (vec!["key", "id", "field", "value"], rows)
        }
        // Unknown command bypassing the whitelist (defensive, fail closed).
        _ => return Err(mismatch()),
    };

    Ok(QueryResult {
        columns: columns.into_iter().map(str::to_string).collect(),
        rows,
        cursor: None,
    })
}

/// Input-aligned commands (HMGET / SMISMEMBER / ZMSCORE): inputs and the reply array
/// pair one-to-one into rows, columns being [input_col, reply_col] (decided by command semantics).
fn input_paired(
    input_col: &'static str,
    reply_col: &'static str,
    inputs: &[String],
    value: &redis::Value,
) -> Result<(Vec<&'static str>, Vec<Vec<CellValue>>), ()> {
    let items = array_of(value)?;
    if items.len() != inputs.len() {
        return Err(());
    }
    let mut rows = Vec::with_capacity(inputs.len());
    for (input, v) in inputs.iter().zip(items) {
        rows.push(vec![CellValue::text(input.clone()), cell_of(v)?]);
    }
    Ok((vec![input_col, reply_col], rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::Value;

    fn tokens(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn map(name: &str, args: &[&str], value: Value) -> Result<QueryResult, RedisError> {
        let mut all = vec![name];
        all.extend_from_slice(args);
        map_response("u", &tokens(&all), value)
    }

    fn bulk(s: &str) -> Value {
        Value::BulkString(s.as_bytes().to_vec())
    }

    // -- A. Five scalar shapes --

    #[test]
    fn test_scalar_shapes() {
        // Top-level Nil -> an empty result set (columns kept).
        let r = map("GET", &["k"], Value::Nil).unwrap();
        assert_eq!(r.columns, vec!["value"]);
        assert!(r.rows.is_empty());
        assert!(r.cursor.is_none());
        // Int -> decimal text.
        let r = map("TTL", &["k"], Value::Int(-2)).unwrap();
        assert_eq!(r.columns, vec!["ttl_seconds"]);
        assert_eq!(r.rows[0][0].text, "-2");
        assert!(!r.rows[0][0].is_null);
        // SimpleString -> the original text.
        let r = map("TYPE", &["k"], Value::SimpleString("list".into())).unwrap();
        assert_eq!(r.columns, vec!["type"]);
        assert_eq!(r.rows[0][0].text, "list");
        // Okay -> OK.
        let r = map("PING", &[], Value::Okay).unwrap();
        assert_eq!(r.rows[0][0].text, "OK");
        // BulkString -> the original text.
        let r = map("GET", &["k"], bulk("hello")).unwrap();
        assert_eq!(r.rows[0][0].text, "hello");
    }

    #[test]
    fn test_binary_bulk_as_lowercase_hex() {
        let r = map(
            "GET",
            &["k"],
            Value::BulkString(vec![0xde, 0xad, 0xbe, 0xef]),
        )
        .unwrap();
        assert_eq!(r.rows[0][0].text, "deadbeef");
        // Empty string and null are distinguishable.
        let r = map("GET", &["k"], Value::BulkString(Vec::new())).unwrap();
        assert_eq!(r.rows[0][0].text, "");
        assert!(!r.rows[0][0].is_null);
        let r = map("GET", &["k"], Value::Nil).unwrap();
        assert!(r.rows.is_empty());
    }

    #[test]
    fn test_time_two_columns() {
        let r = map(
            "TIME",
            &[],
            Value::Array(vec![Value::Int(1), Value::Int(2)]),
        )
        .unwrap();
        assert_eq!(r.columns, vec!["unix_seconds", "unix_microseconds"]);
        assert_eq!(r.rows.len(), 1);
    }

    #[test]
    fn test_object_and_memory_subcommand_columns() {
        let r = map("OBJECT", &["ENCODING", "k"], bulk("int")).unwrap();
        assert_eq!(r.columns, vec!["encoding"]);
        let r = map("MEMORY", &["USAGE", "k"], Value::Int(56)).unwrap();
        assert_eq!(r.columns, vec!["bytes"]);
        // Out-of-whitelist subcommand (defensively rejected).
        assert!(map("OBJECT", &["HELP"], bulk("x")).is_err());
    }

    // -- B. Input alignment --

    #[test]
    fn test_mget_input_paired_with_null() {
        let r = map(
            "MGET",
            &["k1", "k2"],
            Value::Array(vec![bulk("v1"), Value::Nil]),
        )
        .unwrap();
        assert_eq!(r.columns, vec!["key", "value"]);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[0][0].text, "k1");
        assert_eq!(r.rows[0][1].text, "v1");
        assert!(r.rows[1][1].is_null);
        // Length mismatch -> shape mismatch.
        assert!(map("MGET", &["k1", "k2"], Value::Array(vec![bulk("v")])).is_err());
    }

    // -- C. Collections and pairing --

    #[test]
    fn test_hgetall_pairs_and_odd_length_rejected() {
        let r = map(
            "HGETALL",
            &["k"],
            Value::Array(vec![bulk("f1"), bulk("v1"), bulk("f2"), bulk("v2")]),
        )
        .unwrap();
        assert_eq!(r.columns, vec!["field", "value"]);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[1][0].text, "f2");
        // Odd length -> a Command error (defensive, no partial results).
        let err = map(
            "HGETALL",
            &["k"],
            Value::Array(vec![bulk("f1"), bulk("v1"), bulk("f2")]),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("unexpected response shape"),
            "{err}"
        );
        assert!(err.to_string().contains("'HGETALL'"), "{err}");
    }

    #[test]
    fn test_zrange_withscores_branch() {
        let flat = Value::Array(vec![bulk("m1"), bulk("1.5"), bulk("m2"), bulk("2.5")]);
        // No WITHSCORES: a single member column (a plain member array).
        let r = map(
            "ZRANGE",
            &["z", "0", "-1"],
            Value::Array(vec![bulk("m1"), bulk("m2")]),
        )
        .unwrap();
        assert_eq!(r.columns, vec!["member"]);
        assert_eq!(r.rows.len(), 2);
        // With WITHSCORES (case-insensitive): the flat alternating array pairs up.
        let r = map("ZRANGE", &["z", "0", "-1", "withscores"], flat).unwrap();
        assert_eq!(r.columns, vec!["member", "score"]);
        assert_eq!(r.rows[0][1].text, "1.5");
    }

    // -- E. Geo --

    #[test]
    fn test_geosearch_option_columns() {
        let entry = |extra: Vec<Value>| {
            let mut v = vec![bulk("Palermo")];
            v.extend(extra);
            Value::Array(v)
        };
        // Member only (the server response is an array of entry arrays).
        let r = map(
            "GEOSEARCH",
            &["g", "FROMMEMBER", "x"],
            Value::Array(vec![entry(vec![])]),
        )
        .unwrap();
        assert_eq!(r.columns, vec!["member"]);
        assert_eq!(r.rows.len(), 1);
        // WITHDIST + WITHCOORD: column order member, distance, longitude, latitude.
        let r = map(
            "GEOSEARCH",
            &["g", "FROMMEMBER", "x", "WITHDIST", "WITHCOORD"],
            Value::Array(vec![entry(vec![
                bulk("190.4424"),
                Value::Array(vec![bulk("13.3613"), bulk("38.1155")]),
            ])]),
        )
        .unwrap();
        assert_eq!(
            r.columns,
            vec!["member", "distance", "longitude", "latitude"]
        );
        assert_eq!(r.rows[0][1].text, "190.4424");
        assert_eq!(r.rows[0][2].text, "13.3613");
        // All options: member, distance, hash, longitude, latitude.
        let r = map(
            "GEOSEARCH",
            &["g", "x", "WITHDIST", "WITHHASH", "WITHCOORD"],
            Value::Array(vec![entry(vec![
                bulk("1.0"),
                Value::Int(3479099956),
                Value::Array(vec![bulk("1.0"), bulk("2.0")]),
            ])]),
        )
        .unwrap();
        assert_eq!(
            r.columns,
            vec!["member", "distance", "hash", "longitude", "latitude"]
        );
        assert_eq!(r.rows[0][2].text, "3479099956");
    }

    #[test]
    fn test_geopos_missing_member_null_cells() {
        let r = map(
            "GEOPOS",
            &["g", "m1"],
            Value::Array(vec![Value::Array(vec![bulk("13.3"), bulk("38.1")])]),
        )
        .unwrap();
        assert_eq!(r.columns, vec!["member", "longitude", "latitude"]);
        assert_eq!(r.rows[0][1].text, "13.3");
        // Missing member -> null longitude/latitude cells.
        let r = map("GEOPOS", &["g", "m2"], Value::Array(vec![Value::Nil])).unwrap();
        assert!(r.rows[0][1].is_null && r.rows[0][2].is_null);
    }

    // -- F. Streams --

    #[test]
    fn test_xrange_rows_and_no_field_entry() {
        let r = map(
            "XRANGE",
            &["s", "-", "+"],
            Value::Array(vec![Value::Array(vec![
                bulk("1-1"),
                Value::Array(vec![bulk("f1"), bulk("v1"), bulk("f2"), bulk("v2")]),
            ])]),
        )
        .unwrap();
        assert_eq!(r.columns, vec!["id", "field", "value"]);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[0][0].text, "1-1");
        assert_eq!(r.rows[1][1].text, "f2");
        // Field-less entries: existence kept as one row (field / value null).
        let r = map(
            "XRANGE",
            &["s", "-", "+"],
            Value::Array(vec![Value::Array(vec![bulk("2-2"), Value::Array(vec![])])]),
        )
        .unwrap();
        assert_eq!(r.rows.len(), 1);
        assert!(r.rows[0][1].is_null && r.rows[0][2].is_null);
    }

    #[test]
    fn test_xread_nil_and_multi_stream() {
        // No new entries -> 0 rows (columns kept).
        let r = map("XREAD", &["STREAMS", "s", "0"], Value::Nil).unwrap();
        assert_eq!(r.columns, vec!["key", "id", "field", "value"]);
        assert!(r.rows.is_empty());
        // Multiple streams unfold into the same column structure.
        let r = map(
            "XREAD",
            &["STREAMS", "s1", "s2", "0", "0"],
            Value::Array(vec![
                Value::Array(vec![
                    bulk("s1"),
                    Value::Array(vec![Value::Array(vec![
                        bulk("1-1"),
                        Value::Array(vec![bulk("f"), bulk("v")]),
                    ])]),
                ]),
                Value::Array(vec![
                    bulk("s2"),
                    Value::Array(vec![Value::Array(vec![bulk("2-2"), Value::Array(vec![])])]),
                ]),
            ]),
        )
        .unwrap();
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[0][0].text, "s1");
        assert!(r.rows[1][2].is_null);
    }

    // -- G. SCAN family --

    #[test]
    fn test_scan_family_cursor_and_columns() {
        let scan = Value::Array(vec![bulk("42"), Value::Array(vec![bulk("k1"), bulk("k2")])]);
        let r = map("SCAN", &["0"], scan.clone()).unwrap();
        assert_eq!(r.columns, vec!["key"]);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.cursor.as_deref(), Some("42"));
        // Completion check: cursor 0.
        let done = Value::Array(vec![bulk("0"), Value::Array(vec![])]);
        let r = map("SCAN", &["42"], done).unwrap();
        assert_eq!(r.cursor.as_deref(), Some("0"));
        assert!(r.rows.is_empty());
        // HSCAN / ZSCAN paired columns.
        let pair = Value::Array(vec![bulk("0"), Value::Array(vec![bulk("f"), bulk("v")])]);
        let r = map("HSCAN", &["k", "0"], pair.clone()).unwrap();
        assert_eq!(r.columns, vec!["field", "value"]);
        let r = map("ZSCAN", &["k", "0"], pair).unwrap();
        assert_eq!(r.columns, vec!["member", "score"]);
    }

    // -- Defensive --

    #[test]
    fn test_unknown_command_and_wrong_shape_rejected() {
        // Unknown command (caller bypassing the whitelist): fail closed, no panic.
        let err = map("SET", &["k", "v"], Value::Okay).unwrap_err();
        assert!(err.to_string().contains("'SET'"), "{err}");
        // Shape mismatch (GET returning an array).
        assert!(map("GET", &["k"], Value::Array(vec![])).is_err());
        // SRANDMEMBER single-value / array branches.
        let r = map("SRANDMEMBER", &["k"], bulk("m")).unwrap();
        assert_eq!(r.rows.len(), 1);
        let r = map(
            "SRANDMEMBER",
            &["k", "2"],
            Value::Array(vec![bulk("m1"), bulk("m2")]),
        )
        .unwrap();
        assert_eq!(r.rows.len(), 2);
    }

    #[test]
    fn test_timeout_error_message() {
        let e = RedisError::Timeout {
            db_name: "u".into(),
        };
        assert_eq!(
            e.to_string(),
            "redis command timed out for database 'u': exceeded 30s"
        );
    }

    // -- Integration tests (dbq-redis8; skipped when unreachable, aligned with the pg precedent) --

    fn redis_port() -> u16 {
        std::env::var("TEST_REDIS_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(16379)
    }

    fn integration_config() -> excapp_db_core::config::DatabaseConfig {
        crate::redis::test_config("127.0.0.1", redis_port(), "0")
    }

    /// Direct fixture client (test code bypasses the whitelist).
    async fn fixture_conn() -> Option<redis::aio::MultiplexedConnection> {
        let client = redis::Client::open(format!("redis://127.0.0.1:{}/", redis_port())).ok()?;
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.get_multiplexed_async_connection(),
        )
        .await
        .ok()?
        .ok()
    }

    const PREFIX: &str = "dbq_re_it:";

    /// Wrapper for one binary argument (redis expands Vec<u8>/&[u8] into per-element arguments,
    /// so a single binary value cannot be passed directly; fixture-write only).
    struct RawArg(Vec<u8>);

    impl redis::ToRedisArgs for RawArg {
        fn write_redis_args<W: ?Sized + redis::RedisWrite>(&self, out: &mut W) {
            out.write_arg(&self.0);
        }
    }

    #[tokio::test]
    async fn test_execute_column_shapes_on_live_server() {
        let Some(mut fix) = fixture_conn().await else {
            eprintln!("skipping: test redis not available");
            return;
        };
        let _: () = redis::cmd("SET")
            .arg(format!("{PREFIX}str"))
            .arg("hello")
            .query_async(&mut fix)
            .await
            .unwrap();
        let _: () = redis::cmd("SET")
            .arg(format!("{PREFIX}bin"))
            .arg(RawArg(vec![0xde, 0xad, 0xbe, 0xef]))
            .query_async(&mut fix)
            .await
            .unwrap();
        let _: () = redis::cmd("HSET")
            .arg(format!("{PREFIX}hash"))
            .arg("f1")
            .arg("v1")
            .arg("f2")
            .arg("v2")
            .query_async(&mut fix)
            .await
            .unwrap();
        let _: () = redis::cmd("ZADD")
            .arg(format!("{PREFIX}zset"))
            .arg("1.5")
            .arg("m1")
            .arg("2.5")
            .arg("m2")
            .query_async(&mut fix)
            .await
            .unwrap();

        let exec = RedisExecutor::new(&integration_config()).unwrap();
        // GET: one column, one row; binary -> hexadecimal.
        let r = exec
            .execute(&tokens(&["GET", &format!("{PREFIX}str")]))
            .await
            .unwrap();
        assert_eq!(r.columns, vec!["value"]);
        assert_eq!(r.rows[0][0].text, "hello");
        let r = exec
            .execute(&tokens(&["GET", &format!("{PREFIX}bin")]))
            .await
            .unwrap();
        assert_eq!(r.rows[0][0].text, "deadbeef");
        // Missing key -> an empty result set with columns kept.
        let r = exec
            .execute(&tokens(&["GET", &format!("{PREFIX}missing")]))
            .await
            .unwrap();
        assert_eq!(r.columns, vec!["value"]);
        assert!(r.rows.is_empty());
        // HGETALL: two paired columns.
        let r = exec
            .execute(&tokens(&["HGETALL", &format!("{PREFIX}hash")]))
            .await
            .unwrap();
        assert_eq!(r.columns, vec!["field", "value"]);
        assert_eq!(r.rows.len(), 2);
        // ZRANGE WITHSCORES.
        let r = exec
            .execute(&tokens(&[
                "ZRANGE",
                &format!("{PREFIX}zset"),
                "0",
                "-1",
                "WITHSCORES",
            ]))
            .await
            .unwrap();
        assert_eq!(r.columns, vec!["member", "score"]);
        assert_eq!(r.rows.len(), 2);
        // MGET: missing -> null cells.
        let r = exec
            .execute(&tokens(&[
                "MGET",
                &format!("{PREFIX}str"),
                &format!("{PREFIX}missing"),
            ]))
            .await
            .unwrap();
        assert_eq!(r.columns, vec!["key", "value"]);
        assert!(r.rows[1][1].is_null);
    }

    #[tokio::test]
    async fn test_scan_cursor_iteration_on_live_server() {
        let Some(mut fix) = fixture_conn().await else {
            eprintln!("skipping: test redis not available");
            return;
        };
        let _: () = redis::cmd("SET")
            .arg(format!("{PREFIX}scan1"))
            .arg("v")
            .query_async(&mut fix)
            .await
            .unwrap();
        let exec = RedisExecutor::new(&integration_config()).unwrap();
        let r = exec.execute(&tokens(&["SCAN", "0"])).await.unwrap();
        assert_eq!(r.columns, vec!["key"]);
        assert!(r.cursor.is_some());
        // Iterate until the cursor is 0 (complete).
        let mut cursor = r.cursor.clone().unwrap();
        let mut guard = 0;
        while cursor != "0" {
            guard += 1;
            assert!(guard < 100, "scan iteration did not terminate");
            let r = exec.execute(&tokens(&["SCAN", &cursor])).await.unwrap();
            cursor = r.cursor.unwrap();
        }
    }

    #[tokio::test]
    async fn test_row_limit_and_metadata_skip_on_live_server() {
        let Some(mut fix) = fixture_conn().await else {
            eprintln!("skipping: test redis not available");
            return;
        };
        // A 101-element list: LRANGE 0 99 passes, 0 -1 fails the whole batch.
        let mut elements = Vec::new();
        for i in 0..101 {
            elements.push(format!("e{i}"));
        }
        let mut cmd = redis::cmd("RPUSH");
        cmd.arg(format!("{PREFIX}list"));
        for e in &elements {
            cmd.arg(e);
        }
        let _: i64 = cmd.query_async(&mut fix).await.unwrap();

        let exec = RedisExecutor::new(&integration_config()).unwrap();
        let r = exec
            .execute(&tokens(&["LRANGE", &format!("{PREFIX}list"), "0", "99"]))
            .await
            .unwrap();
        assert_eq!(r.rows.len(), 100);
        let err = exec
            .execute(&tokens(&["LRANGE", &format!("{PREFIX}list"), "0", "-1"]))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("row limit"), "{msg}");
        assert!(msg.contains("got 101 rows"), "{msg}");
        // Metadata entry: skips the row cap.
        let r = exec
            .execute_metadata(&tokens(&["LRANGE", &format!("{PREFIX}list"), "0", "-1"]))
            .await
            .unwrap();
        assert_eq!(r.rows.len(), 101);
        // Cleanup.
        let _: () = redis::cmd("DEL")
            .arg(format!("{PREFIX}list"))
            .query_async(&mut fix)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_byte_limit_on_live_server() {
        let Some(mut fix) = fixture_conn().await else {
            eprintln!("skipping: test redis not available");
            return;
        };
        // Over-cap value: 10MB + 1 byte.
        let big = vec![b'x'; RESULT_BYTE_LIMIT + 1];
        let _: () = redis::cmd("SET")
            .arg(format!("{PREFIX}big"))
            .arg(RawArg(big))
            .query_async(&mut fix)
            .await
            .unwrap();
        let exec = RedisExecutor::new(&integration_config()).unwrap();
        let err = exec
            .execute(&tokens(&["GET", &format!("{PREFIX}big")]))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("byte limit"), "{msg}");
        // Cleanup.
        let _: () = redis::cmd("DEL")
            .arg(format!("{PREFIX}big"))
            .query_async(&mut fix)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_server_error_wrapped_on_live_server() {
        let Some(mut fix) = fixture_conn().await else {
            eprintln!("skipping: test redis not available");
            return;
        };
        let _: () = redis::cmd("SET")
            .arg(format!("{PREFIX}str"))
            .arg("hello")
            .query_async(&mut fix)
            .await
            .unwrap();
        let exec = RedisExecutor::new(&integration_config()).unwrap();
        // WRONGTYPE: HGETALL on a string key -> the server error passes through in English, uid included.
        let err = exec
            .execute(&tokens(&["HGETALL", &format!("{PREFIX}str")]))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("WRONGTYPE"), "{msg}");
        assert!(msg.contains("'test'"), "{msg}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_for_database_schema_rejected_and_health_ok() {
        let Some(_fix) = fixture_conn().await else {
            eprintln!("skipping: test redis not available");
            return;
        };
        let exec = RedisExecutor::new(&integration_config()).unwrap();
        // Schema rejected.
        let err = exec
            .for_database_with_schema("0", Some("public"))
            .unwrap_err();
        assert!(err.to_string().contains("schema is not supported"), "{err}");
        // Same-number derivation: a clone sharing the pool.
        let same = exec.for_database_with_schema("0", None).unwrap();
        let _ = same.execute(&tokens(&["PING"])).await.unwrap();
        // Health check reachable path.
        let mut hc = super::super::RedisHealthCheck::new(exec.shared_pool());
        assert!(excapp_db_core::watch::HealthCheck::check(&mut hc).is_ok());
    }
}
