//! MCP tool layer: seven tools (uid-addressed), shared by both transports.
//! MCP tool layer: six tools (uid addressing), shared by both transports.
//!
//! - list-connection: reads connection metadata locally (no database round trip)
//! - list-database / list-schema / list-table / describe-table: fixed metadata
//!   queries
//! - execute-sql: mandatory sql-validator validation → sql-executor execution

use crate::state::SharedState;
use excapp_db_sql_executor::{CellValue, QueryResult};
use rmcp::handler::server::prompt::PromptContext;
use rmcp::handler::server::router::prompt::PromptRouter;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

/// MCP server: six tools + seven prompts + shared state.
#[derive(Clone)]
pub struct DbQueryServer {
    /// Executor set (uid addressing, atomic swap on hot reload).
    pub state: SharedState,
    pub(crate) tool_router: ToolRouter<Self>,
    /// Prompt router (guide + six tool-matching prompts; static content).
    pub(crate) prompt_router: PromptRouter<Self>,
}

impl DbQueryServer {
    /// Build the server on a shared state.
    pub fn new(state: SharedState) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
            prompt_router: crate::prompts::build_prompt_router(),
        }
    }

    /// Uniform JSON text for tool output.
    fn json_output(value: serde_json::Value) -> CallToolResult {
        CallToolResult::success(vec![rmcp::model::ContentBlock::text(value.to_string())])
    }

    /// Uniform JSON for tool errors (isError).
    fn error_output(value: serde_json::Value) -> CallToolResult {
        CallToolResult::error(vec![rmcp::model::ContentBlock::text(value.to_string())])
    }

    /// Unknown-uid error (with the available uid list).
    fn uid_not_found(uid: &str, available: &[String]) -> CallToolResult {
        Self::error_output(json!({
            "error": format!("connection '{uid}' not found"),
            "available": available,
        }))
    }

    /// Literal-safe quoting for schema / table inputs (single quotes doubled).
    fn quote_literal(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    /// Validation denial details (passing through sql-validator's denials).
    fn validation_denied(denials: &[excapp_db_sql_validator::Denial]) -> CallToolResult {
        let items: Vec<serde_json::Value> = denials
            .iter()
            .map(|d| {
                json!({
                    "index": d.index,
                    "category": format!("{:?}", d.category),
                    "message": d.message,
                })
            })
            .collect();
        Self::error_output(json!({
            "error": "SQL validation failed",
            "denials": items,
        }))
    }

    /// Execution errors passed through.
    fn executor_error(err: excapp_db_sql_executor::ExecutorError) -> CallToolResult {
        Self::error_output(json!({ "error": err.to_string() }))
    }

    /// Redis command validation denial details (passing through CommandWhitelist's denials;
    /// structurally isomorphic to the SQL validation_denied).
    fn redis_denied(denials: &[excapp_db_sql_validator::RedisDenial]) -> CallToolResult {
        let items: Vec<serde_json::Value> = denials
            .iter()
            .map(|d| {
                json!({
                    "index": d.index,
                    "category": format!("{:?}", d.category),
                    "message": d.message,
                })
            })
            .collect();
        Self::error_output(json!({
            "error": "Redis command validation failed",
            "denials": items,
        }))
    }

    /// QueryResult -> output JSON (the SCAN family carries a cursor field).
    ///
    /// The base structure (columns + rows) is isomorphic to query_result; the cursor is appended only when
    /// it is a SCAN family result (QueryResult.cursor is not None).
    fn query_result_with_cursor(result: QueryResult) -> CallToolResult {
        let cursor = result.cursor.clone();
        let CallToolResult { content, .. } = Self::query_result(result);
        let mut base = content
            .first()
            .and_then(|b| match b {
                rmcp::model::ContentBlock::Text(t) => {
                    serde_json::from_str::<serde_json::Value>(&t.text).ok()
                }
                _ => None,
            })
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(cursor) = cursor {
            base["cursor"] = json!(cursor);
        }
        Self::json_output(base)
    }

    /// Metadata command entry for redis connections: the uid is already validated by the caller to exist and be
    /// of the redis type; derivation happens when database differs from the configured default logical database.
    async fn execute_redis_metadata_by_uid(
        &self,
        uid: &str,
        tokens: &[String],
    ) -> Result<QueryResult, CallToolResult> {
        let executor = self
            .state
            .executor(uid)
            .ok_or_else(|| Self::uid_not_found(uid, &self.state.uids()))?;
        let derived = match &*executor {
            excapp_db_sql_executor::DatabaseExecutor::Redis(e) => e
                .for_database_with_schema(
                    self.state.database_of(uid).as_deref().unwrap_or("0"),
                    None,
                )
                .map(excapp_db_sql_executor::DatabaseExecutor::Redis)
                .map_err(|e| {
                    Self::executor_error(excapp_db_sql_executor::ExecutorError::Redis(e))
                })?,
            _ => unreachable!("redis branch validated by caller"),
        };
        let derived = std::sync::Arc::new(derived);
        derived
            .execute_redis_metadata(tokens)
            .await
            .map_err(Self::executor_error)
    }

    /// Redis branch: list-table maps to a paginated key list via SCAN.
    async fn redis_list_table(
        &self,
        uid: &str,
        database: &str,
        schema: &str,
        cursor: Option<&str>,
    ) -> rmcp::model::CallToolResult {
        if schema != "public" {
            return Self::error_output(json!({
                "error": "schema is not supported for redis connections (parameter schema must be omitted or 'public')",
            }));
        }
        // Derive when database differs from the configured default logical database (the redis shape of the resolve semantics).
        let executor = match self.resolve_redis(uid, database) {
            Ok(e) => e,
            Err(out) => return out,
        };
        let cursor = cursor.unwrap_or("0");
        let tokens = vec![
            "SCAN".to_string(),
            cursor.to_string(),
            "COUNT".to_string(),
            "100".to_string(),
        ];
        match executor.execute_redis_metadata(&tokens).await {
            Ok(result) => {
                let tables: Vec<serde_json::Value> = result
                    .rows
                    .iter()
                    .map(|r| json!({ "name": r[0].text }))
                    .collect();
                let cursor = result.cursor.clone().unwrap_or_else(|| "0".to_string());
                Self::json_output(json!({ "tables": tables, "cursor": cursor }))
            }
            Err(e) => Self::executor_error(e),
        }
    }

    /// Redis branch: describe-table maps to key inspection (seven commands in sequence).
    async fn redis_describe_table(
        &self,
        uid: &str,
        database: &str,
        schema: &str,
        key: &str,
    ) -> rmcp::model::CallToolResult {
        if schema != "public" {
            return Self::error_output(json!({
                "error": "schema is not supported for redis connections (parameter schema must be omitted or 'public')",
            }));
        }
        let executor = match self.resolve_redis(uid, database) {
            Ok(e) => e,
            Err(out) => return out,
        };
        // Seven commands in sequence: TYPE / TTL / PTTL / OBJECT x3 / MEMORY USAGE.
        let commands: Vec<Vec<String>> = vec![
            vec!["TYPE".into(), key.into()],
            vec!["TTL".into(), key.into()],
            vec!["PTTL".into(), key.into()],
            vec!["OBJECT".into(), "ENCODING".into(), key.into()],
            vec!["OBJECT".into(), "REFCOUNT".into(), key.into()],
            vec!["OBJECT".into(), "IDLETIME".into(), key.into()],
            vec!["MEMORY".into(), "USAGE".into(), key.into()],
        ];
        let mut outputs: Vec<Option<String>> = Vec::with_capacity(commands.len());
        for tokens in &commands {
            let value = match executor.execute_redis_metadata(tokens).await {
                Ok(r) => r.rows.first().map(|row| row[0].clone()),
                // Server errors such as the key being deleted mid-way: the field degrades to null without blocking the rest.
                Err(_) => None,
            };
            outputs.push(value.map(|c| c.text));
        }
        let [ty, ttl, pttl, encoding, refcount, idle, memory] = &outputs[..] else {
            unreachable!("seven commands collected");
        };
        let ty = ty.clone().unwrap_or_else(|| "none".to_string());
        let exists = ty != "none";
        Self::json_output(json!({
            "key": key,
            "exists": exists,
            "type": ty,
            "ttl_seconds": ttl.clone(),
            "ttl_milliseconds": pttl.clone(),
            "encoding": encoding.clone(),
            "refcount": refcount.clone(),
            "idle_time_seconds": idle.clone(),
            "memory_bytes": memory.clone(),
        }))
    }

    /// database derivation for redis connections: reuses the base
    /// executor when it matches the configured default; otherwise derives via for_database (same number clones the shared pool).
    fn resolve_redis(
        &self,
        uid: &str,
        database: &str,
    ) -> Result<std::sync::Arc<excapp_db_sql_executor::DatabaseExecutor>, CallToolResult> {
        let executor = self
            .state
            .executor(uid)
            .ok_or_else(|| Self::uid_not_found(uid, &self.state.uids()))?;
        let config_db = self.state.database_of(uid);
        if database == config_db.as_deref().unwrap_or("") {
            return Ok(executor);
        }
        let derived = match &*executor {
            excapp_db_sql_executor::DatabaseExecutor::Redis(e) => e
                .for_database_with_schema(database, None)
                .map(excapp_db_sql_executor::DatabaseExecutor::Redis)
                .map_err(|e| {
                    Self::executor_error(excapp_db_sql_executor::ExecutorError::Redis(e))
                })?,
            _ => unreachable!("redis branch validated by caller"),
        };
        Ok(std::sync::Arc::new(derived))
    }

    /// QueryResult → output JSON.
    fn query_result(result: QueryResult) -> CallToolResult {
        let columns: Vec<&str> = result.columns.iter().map(String::as_str).collect();
        let rows: Vec<Vec<serde_json::Value>> = result
            .rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|c: &CellValue| {
                        if c.is_null {
                            json!({ "text": c.text, "is_null": true })
                        } else {
                            json!({ "text": c.text, "is_null": false })
                        }
                    })
                    .collect()
            })
            .collect();
        Self::json_output(json!({ "columns": columns, "rows": rows }))
    }

    /// Run a fixed metadata query on the given connection and take the first
    async fn metadata_column(
        &self,
        uid: &str,
        database: Option<&str>,
        sql: &str,
    ) -> Result<Vec<String>, excapp_db_sql_executor::ExecutorError> {
        // database (None = the configured default) and take the first column.
        let executor = match self.resolve(uid, database, None) {
            Ok(e) => e,
            Err(_) => unreachable!("uid validated by caller"),
        };
        let result = executor.execute_metadata(sql).await?;
        Ok(result.rows.iter().map(|r| r[0].text.clone()).collect())
    }

    /// uid validation: returns the executor or a not-found output.
    fn resolve(
        &self,
        uid: &str,
        database: Option<&str>,
        schema: Option<&str>,
    ) -> Result<std::sync::Arc<excapp_db_sql_executor::DatabaseExecutor>, CallToolResult> {
        let executor = self
            .state
            .executor(uid)
            .ok_or_else(|| Self::uid_not_found(uid, &self.state.uids()))?;
        // database None: the configured default database; when it matches the
        // configured one and schema is the default (None or public), the base
        // executor is reused (public is the first entry of PG's default
        let config_db = self.state.database_of(uid);
        let same_db = match database {
            None => true,
            Some(db) => config_db.as_deref() == Some(db),
        };
        let default_public = schema.is_none() || schema == Some("public");
        if same_db && default_public {
            return Ok(executor);
        }
        // Remaining cases (cross-database or explicit schema) derive: cross
        let target_db = database.unwrap_or_else(|| config_db.as_deref().unwrap_or("postgres"));
        match executor.for_database_with_schema(target_db, schema) {
            Ok(derived) => Ok(std::sync::Arc::new(derived)),
            Err(e) => Err(Self::executor_error(e)),
        }
    }
}

// ---- Tool parameters (JSON schema generated from the serde definitions) ----

/// List databases under a connection.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct UidParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
}

/// List schemas in a database.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct UidDbParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Target database name.
    pub(crate) database: String,
}

/// List tables in a schema.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct ListTableParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Target database name.
    pub(crate) database: String,
    /// PG schema (defaults to public; Postgres only).
    #[serde(default = "default_schema")]
    pub(crate) schema: String,
    /// SCAN cursor (redis connection pagination; ignored on the SQL path; defaults to the start).
    #[serde(default)]
    pub(crate) cursor: Option<String>,
}

fn default_schema() -> String {
    "public".to_string()
}

/// Describe a table's DDL and columns.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct DescribeTableParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Target database name.
    pub(crate) database: String,
    /// PG schema (defaults to public; Postgres only).
    #[serde(default = "default_schema")]
    pub(crate) schema: String,
    /// Table name.
    pub(crate) table: String,
}

/// Execute read-only SQL.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct SqlParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Target database name.
    pub(crate) database: String,
    /// PG schema (defaults to public; Postgres only).
    #[serde(default = "default_schema")]
    pub(crate) schema: String,
    /// The SQL to validate and execute.
    pub(crate) sql: String,
}

/// Execute a read-only Redis command.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct RedisParam {
    /// Configured connection uid.
    pub(crate) uid: String,
    /// Redis command text to validate and execute (single command; out-of-whitelist is rejected).
    pub(crate) command: String,
}

#[tool_router]
impl DbQueryServer {
    /// List configured database connections (uid, name, description, default db, db type).
    #[tool(
        name = "list-connection",
        title = "List Connections",
        description = "List configured database connections with uid, name, description, default database (db) and database type (type)."
    )]
    async fn list_connection(&self) -> rmcp::model::CallToolResult {
        let connections: Vec<serde_json::Value> = self
            .state
            .connections()
            .iter()
            .map(|c| {
                json!({
                    "uid": c.uid,
                    "name": c.name,
                    "description": c.description,
                    "db": c.db,
                    "type": c.db_type,
                })
            })
            .collect();
        Self::json_output(json!({ "connections": connections }))
    }

    /// List visible databases under a connection.
    #[tool(
        name = "list-database",
        title = "List Databases",
        description = "List all visible databases under the connection identified by uid."
    )]
    async fn list_database(
        &self,
        Parameters(param): Parameters<UidParam>,
    ) -> rmcp::model::CallToolResult {
        let executor = match self.state.executor(&param.uid) {
            Some(e) => e,
            None => return Self::uid_not_found(&param.uid, &self.state.uids()),
        };
        // Redis connection: INFO keyspace maps to the logical database list.
        if let excapp_db_sql_executor::DatabaseExecutor::Redis(_) = *executor {
            return self.redis_list_database(&param.uid).await;
        }
        // Instance-level query (pg_catalog is visible across databases); the
        // configured connection's base executor suffices.
        let sql = "SELECT datname FROM pg_database WHERE datallowconn \
                   AND datname NOT IN ('template0', 'template1') ORDER BY datname";
        match self.metadata_column(&param.uid, None, sql).await {
            Ok(dbs) => Self::json_output(json!({ "databases": dbs })),
            Err(e) => Self::executor_error(e),
        }
    }

    /// List schemas of the connection's database (Postgres only).
    async fn redis_list_database(&self, uid: &str) -> rmcp::model::CallToolResult {
        let tokens = vec!["INFO".to_string(), "keyspace".to_string()];
        let result = match self.execute_redis_metadata_by_uid(uid, &tokens).await {
            Ok(r) => r,
            Err(out) => return out,
        };
        // INFO single column, single row: the raw text (0 rows when there are no keys).
        let info_text = result
            .rows
            .first()
            .map(|r| r[0].text.as_str())
            .unwrap_or("");
        let current_db = format!("db{}", self.state.database_of(uid).unwrap_or_default());
        let databases: Vec<serde_json::Value> = parse_info_keyspace(info_text)
            .into_iter()
            .map(|entry| {
                json!({
                    "name": entry.name,
                    "keys": entry.keys,
                    "expires": entry.expires,
                    "current": entry.name == current_db,
                })
            })
            .collect();
        Self::json_output(json!({ "databases": databases }))
    }

    /// List schemas of the connection's database (Postgres only).
    #[tool(
        name = "list-schema",
        title = "List Schemas",
        description = "List all schemas in the given database (Postgres only), excluding system schemas."
    )]
    async fn list_schema(
        &self,
        Parameters(param): Parameters<UidDbParam>,
    ) -> rmcp::model::CallToolResult {
        let executor = match self.state.executor(&param.uid) {
            Some(e) => e,
            None => return Self::uid_not_found(&param.uid, &self.state.uids()),
        };
        // Redis connection: no schema concept, explicit rejection.
        if let excapp_db_sql_executor::DatabaseExecutor::Redis(_) = *executor {
            return Self::error_output(json!({
                "error": "list-schema is not supported for redis connections: redis has no schema concept (use list-database for logical databases)",
            }));
        }
        let sql = "SELECT schema_name FROM information_schema.schemata \
                   WHERE schema_name NOT LIKE 'pg\\_%' ESCAPE '\\' \
                   AND schema_name <> 'information_schema' ORDER BY schema_name";
        match self
            .metadata_column(&param.uid, Some(&param.database), sql)
            .await
        {
            Ok(schemas) => Self::json_output(json!({ "schemas": schemas })),
            Err(e) => Self::executor_error(e),
        }
    }

    /// List tables of a schema (default public).
    #[tool(
        name = "list-table",
        title = "List Tables",
        description = "List tables and views in the given database and schema (default public, Postgres only). Partition child tables are not listed separately; partitioned parents are marked as PARTITIONED TABLE. For redis connections this lists keys via SCAN pagination (cursor parameter for continuation, \"0\" means complete)."
    )]
    async fn list_table(
        &self,
        Parameters(param): Parameters<ListTableParam>,
    ) -> rmcp::model::CallToolResult {
        let base = match self.state.executor(&param.uid) {
            Some(e) => e,
            None => return Self::uid_not_found(&param.uid, &self.state.uids()),
        };
        // Redis connection: a paginated key list via SCAN.
        if let excapp_db_sql_executor::DatabaseExecutor::Redis(_) = *base {
            return self
                .redis_list_table(
                    &param.uid,
                    &param.database,
                    &param.schema,
                    param.cursor.as_deref(),
                )
                .await;
        }
        let executor = match self.resolve(
            &param.uid,
            Some(&param.database),
            Some(param.schema.as_str()),
        ) {
            Ok(e) => e,
            Err(out) => return out,
        };
        // project as BASE TABLE). Here the partition parent's inherited children
        // are excluded and the parent is labeled PARTITIONED TABLE; traditional
        // inheritance children stay listed.
        let sql = format!(
            "SELECT c.relname, \
             CASE c.relkind WHEN 'r' THEN 'BASE TABLE' WHEN 'p' THEN 'PARTITIONED TABLE' \
             WHEN 'v' THEN 'VIEW' WHEN 'f' THEN 'FOREIGN TABLE' END AS table_type \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = {} AND c.relkind IN ('r', 'p', 'v', 'f') \
             AND NOT EXISTS (SELECT 1 FROM pg_inherits i JOIN pg_class parent ON parent.oid = i.inhparent \
             WHERE i.inhrelid = c.oid AND parent.relkind = 'p') \
             ORDER BY c.relname",
            Self::quote_literal(&param.schema)
        );
        match executor.execute_metadata(&sql).await {
            Ok(result) => {
                let tables: Vec<serde_json::Value> = result
                    .rows
                    .iter()
                    .map(|r| json!({ "name": r[0].text, "type": r[1].text }))
                    .collect();
                Self::json_output(json!({ "tables": tables }))
            }
            Err(e) => Self::executor_error(e),
        }
    }

    /// Show a table's CREATE DDL and column metadata.
    #[tool(
        name = "describe-table",
        title = "Describe Table",
        description = "Show the CREATE TABLE DDL and column metadata (name, type, nullable, comment) of the given table in the given database and schema (default public). Table comment is included when present. For redis connections the table parameter is the key name and key metadata (type, ttl, encoding, memory) is returned."
    )]
    async fn describe_table(
        &self,
        Parameters(param): Parameters<DescribeTableParam>,
    ) -> rmcp::model::CallToolResult {
        let base = match self.state.executor(&param.uid) {
            Some(e) => e,
            None => return Self::uid_not_found(&param.uid, &self.state.uids()),
        };
        // Redis connection: key inspection.
        if let excapp_db_sql_executor::DatabaseExecutor::Redis(_) = *base {
            return self
                .redis_describe_table(&param.uid, &param.database, &param.schema, &param.table)
                .await;
        }
        let executor = match self.resolve(
            &param.uid,
            Some(&param.database),
            Some(param.schema.as_str()),
        ) {
            Ok(e) => e,
            Err(out) => return out,
        };
        // Column metadata + column comments (via pg_attribute: comments are only
        // available through the catalog path; types render in full form via
        // format_type, e.g. character varying(32)).
        let columns_sql = format!(
            "SELECT a.attname, format_type(a.atttypid, a.atttypmod), \
             CASE WHEN a.attnotnull THEN 'NO' ELSE 'YES' END, \
             col_description(a.attrelid, a.attnum) \
             FROM pg_attribute a \
             JOIN pg_class c ON c.oid = a.attrelid \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = {} AND c.relname = {} \
             AND a.attnum > 0 AND NOT a.attisdropped \
             ORDER BY a.attnum",
            Self::quote_literal(&param.schema),
            Self::quote_literal(&param.table)
        );
        let columns_result = match executor.execute_metadata(&columns_sql).await {
            Ok(r) => r,
            Err(e) => return Self::executor_error(e),
        };
        if columns_result.rows.is_empty() {
            return Self::error_output(json!({
                "error": format!("table '{}' not found in schema '{}'", param.table, param.schema),
            }));
        }
        let columns: Vec<serde_json::Value> = columns_result
            .rows
            .iter()
            .map(|r| {
                json!({
                    "name": r[0].text,
                    "data_type": r[1].text,
                    "nullable": r[2].text == "YES",
                    "comment": if r[3].is_null { serde_json::Value::Null } else { json!(r[3].text) },
                })
            })
            .collect();

        // Table comment (obj_description; null when absent).
        let table_comment_sql = format!(
            "SELECT obj_description(c.oid, 'pg_class') \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = {} AND c.relname = {}",
            Self::quote_literal(&param.schema),
            Self::quote_literal(&param.table)
        );
        let table_comment = match executor.execute_metadata(&table_comment_sql).await {
            Ok(r) if !r.rows.is_empty() && !r.rows[0][0].is_null => Some(r.rows[0][0].text.clone()),
            _ => None,
        };
        // DDL: catalog assembly (column definitions + defaults + not-null +
        // primary keys). Default expressions render via pg_get_expr —
        // pg_attrdef.adsrc was removed in PG 12.
        let ddl_sql = format!(
            "SELECT 'CREATE TABLE ' || n.nspname || '.' || c.relname || ' (' || \
             string_agg(\
               quote_ident(a.attname) || ' ' || format_type(a.atttypid, a.atttypmod) || \
               CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END || \
               CASE WHEN d.oid IS NOT NULL THEN ' DEFAULT ' || pg_get_expr(d.adbin, d.adrelid) ELSE '' END, \
               ', ' ORDER BY a.attnum\
             ) || \
             (SELECT ', PRIMARY KEY (' || string_agg(quote_ident(k.attname), ', ' ORDER BY k.attnum) || ')' \
              FROM pg_index i JOIN pg_attribute k ON k.attrelid = i.indrelid AND k.attnum = ANY(i.indkey) \
              WHERE i.indrelid = c.oid AND i.indisprimary) || \
             ');' \
             FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped \
             LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum \
             WHERE n.nspname = {} AND c.relname = {} \
             GROUP BY n.nspname, c.relname, c.oid",
            Self::quote_literal(&param.schema),
            Self::quote_literal(&param.table)
        );
        // A DDL assembly failure does not block column metadata (degradable),
        let (ddl, ddl_error) = match executor.execute_metadata(&ddl_sql).await {
            Ok(r) if !r.rows.is_empty() => (r.rows[0][0].text.clone(), None),
            Ok(_) => (String::new(), None),
            Err(e) => (String::new(), Some(e.to_string())),
        };
        // executable/readable; they are already provided structurally via
        // columns[].comment).
        let ddl = match &table_comment {
            Some(c) => format!("-- {c}\n{ddl}"),
            None => ddl,
        };

        let mut output = json!({
            "ddl": ddl,
            "table_comment": table_comment,
            "columns": columns,
        });
        if let Some(err) = ddl_error {
            output["ddl_error"] = json!(err);
        }
        Self::json_output(output)
    }

    /// Execute SQL after mandatory read-only validation.
    #[tool(
        name = "execute-sql",
        title = "Execute SQL",
        description = "Execute SQL on the given database (schema optional, default public). The SQL is validated first: only read-only queries (SELECT/EXPLAIN/SHOW/metadata) are allowed; rejections return structured details. Results are capped at 100 rows; exceeding fails the whole batch with no partial results — narrow the result set with LIMIT."
    )]
    async fn execute_sql(
        &self,
        Parameters(param): Parameters<SqlParam>,
    ) -> rmcp::model::CallToolResult {
        let base = match self.state.executor(&param.uid) {
            Some(e) => e,
            None => return Self::uid_not_found(&param.uid, &self.state.uids()),
        };
        // Redis connections do not support SQL: mis-route guard (pointing to the right tool).
        if let excapp_db_sql_executor::DatabaseExecutor::Redis(_) = *base {
            return Self::error_output(json!({
                "error": format!(
                    "redis connection '{}' does not support SQL queries; use execute-redis",
                    param.uid
                ),
            }));
        }
        let executor = match self.resolve(
            &param.uid,
            Some(&param.database),
            Some(param.schema.as_str()),
        ) {
            Ok(e) => e,
            Err(out) => return out,
        };
        let dialect = match self.state.dialect_of(&param.uid) {
            Some(d) => d,
            None => return Self::uid_not_found(&param.uid, &self.state.uids()),
        };

        // Mandatory validation: denials never reach execution.
        let verdict = excapp_db_sql_validator::validate_with_policy(
            &dialect,
            &param.sql,
            &self.state.policy(),
        );
        if !verdict.allowed {
            return Self::validation_denied(&verdict.denials);
        }

        match executor.execute(&param.sql).await {
            Ok(result) => Self::query_result(result),
            Err(e) => Self::executor_error(e),
        }
    }

    /// Execute a read-only Redis command after whitelist validation.
    #[tool(
        name = "execute-redis",
        title = "Execute Redis Command",
        description = "Execute a Redis command on the connection identified by uid. The command is validated first: only read-only whitelist commands are allowed; rejections return structured details. Results are capped at 100 rows / 10MB with a 30s timeout. SCAN-family results include a cursor field (\"0\" means iteration complete)."
    )]
    async fn execute_redis(
        &self,
        Parameters(param): Parameters<RedisParam>,
    ) -> rmcp::model::CallToolResult {
        let executor = match self.state.executor(&param.uid) {
            Some(e) => e,
            None => return Self::uid_not_found(&param.uid, &self.state.uids()),
        };
        // Non-redis connection: mis-route guard (actual type included).
        let db_type = match &*executor {
            excapp_db_sql_executor::DatabaseExecutor::Redis(_) => "redis",
            excapp_db_sql_executor::DatabaseExecutor::Pg(_) => "postgres",
            excapp_db_sql_executor::DatabaseExecutor::MySql(_) => "mysql",
            excapp_db_sql_executor::DatabaseExecutor::Sqlite(_) => "sqlite",
        };
        if db_type != "redis" {
            return Self::error_output(json!({
                "error": format!(
                    "connection '{}' is of type '{}'; execute-redis requires a redis connection",
                    param.uid, db_type
                ),
            }));
        }

        // Mandatory validation: rejections never reach execution.
        let verdict = excapp_db_sql_validator::validate_redis(&param.command);
        if !verdict.allowed {
            return Self::redis_denied(&verdict.denials);
        }
        // Flatten the token vector: name + subcommand + args.
        let command = verdict.command().expect("allowed carries command");
        let mut tokens = vec![command.name.clone()];
        if let Some(sub) = &command.subcommand {
            tokens.push(sub.clone());
        }
        tokens.extend(command.args.iter().cloned());

        match executor.execute_redis(&tokens).await {
            Ok(result) => Self::query_result_with_cursor(result),
            Err(e) => Self::executor_error(e),
        }
    }
}

/// One INFO keyspace entry (the parse product).
struct KeyspaceEntry {
    name: String,
    keys: String,
    expires: String,
}

/// Parse the INFO keyspace text: only `db<N>:keys=<K>,expires=<E>` lines are recognized
/// (logical databases without keys do not appear in INFO; unparseable lines are ignored - fail soft,
/// the presentation layer does not fail the whole batch on format changes).
fn parse_info_keyspace(info_text: &str) -> Vec<KeyspaceEntry> {
    info_text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (name, rest) = line.split_once(':')?;
            if !name.starts_with("db") {
                return None;
            }
            let mut keys = String::new();
            let mut expires = String::new();
            for pair in rest.split(',') {
                if let Some((k, v)) = pair.split_once('=') {
                    match k.trim() {
                        "keys" => keys = v.trim().to_string(),
                        "expires" => expires = v.trim().to_string(),
                        _ => {}
                    }
                }
            }
            if keys.is_empty() {
                return None;
            }
            Some(KeyspaceEntry {
                name: name.to_string(),
                keys,
                expires,
            })
        })
        .collect()
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for DbQueryServer {
    fn get_info(&self) -> rmcp::model::ServerConfig {
        rmcp::model::ServerConfig::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .build(),
        )
        .with_instructions("db-query read-only SQL MCP server")
    }

    // The prompt_handler macro would regenerate the whole ServerHandler impl
    // (conflicting with tool_handler), so prompts are routed manually here in
    fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<rmcp::model::GetPromptResponse, rmcp::ErrorData>>
    + rmcp::service::MaybeSendFuture
    + '_ {
        let prompt_context = PromptContext::new(self, request.name, request.arguments, context);
        self.prompt_router.get_prompt(prompt_context)
    }

    fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<rmcp::model::ListPromptsResult, rmcp::ErrorData>>
    + rmcp::service::MaybeSendFuture
    + '_ {
        let prompts = self.prompt_router.list_all();
        std::future::ready(Ok(rmcp::model::ListPromptsResult {
            prompts,
            ..Default::default()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ExecutorSet, SharedState};

    fn redis_config_text(port: u16, db: &str) -> String {
        format!(
            "[[databases]]\nuid = \"r1\"\nname = \"Redis One\"\ndescription = \"d\"\n\
             type = \"redis\"\ndialect = \"redis\"\nusername = \"\"\npassword = \"\"\n\
             host = \"127.0.0.1\"\nport = {port}\ndb = \"{db}\"\n"
        )
    }

    fn sqlite_config_text() -> String {
        "[[databases]]\nuid = \"s1\"\nname = \"SQLite\"\ndescription = \"d\"\n\
         type = \"sqlite\"\ndialect = \"sqlite\"\nusername = \"\"\npassword = \"\"\n\
         host = \"\"\nport = 0\ndb = \"/nonexistent/path/db.sqlite3\"\n"
            .to_string()
    }

    fn server_with(text: &str) -> DbQueryServer {
        let config = excapp_db_core::config::AppConfig::parse(text).unwrap();
        DbQueryServer::new(SharedState::with_policy(
            ExecutorSet::build(&config).unwrap(),
            ExecutorSet::build_policy(&config).unwrap(),
        ))
    }

    fn redis_port() -> u16 {
        std::env::var("TEST_REDIS_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(16379)
    }

    fn redis_server() -> DbQueryServer {
        server_with(&redis_config_text(redis_port(), "0"))
    }

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

    fn text_of(result: &CallToolResult) -> String {
        match result.content.first() {
            Some(rmcp::model::ContentBlock::Text(t)) => t.text.clone(),
            _ => String::new(),
        }
    }

    fn json_of(result: &CallToolResult) -> serde_json::Value {
        serde_json::from_str(&text_of(result)).unwrap_or(serde_json::Value::Null)
    }

    // -- Registry enumeration (seven tools / eight prompts; both transports share one registry) --

    #[test]
    fn test_tool_registry_lists_seven_tools_with_execute_redis() {
        let server = redis_server();
        let tools = server.tool_router.list_all();
        let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
        assert_eq!(
            names.len(),
            7,
            "tools/list must expose seven tools: {names:?}"
        );
        assert!(names.iter().any(|n| n == "execute-redis"), "{names:?}");
        for expected in [
            "list-connection",
            "list-database",
            "list-schema",
            "list-table",
            "describe-table",
            "execute-sql",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing {expected}: {names:?}"
            );
        }
    }

    #[test]
    fn test_prompt_registry_lists_eight_with_execute_redis() {
        let server = redis_server();
        let prompts = server.prompt_router.list_all();
        let names: Vec<String> = prompts.iter().map(|p| p.name.to_string()).collect();
        assert_eq!(names.len(), 8, "guide + seven tool prompts: {names:?}");
        assert!(names.iter().any(|n| n == "execute-redis"), "{names:?}");
        assert!(names.iter().any(|n| n == "guide"), "{names:?}");
    }

    // -- INFO keyspace parse pure function --

    #[test]
    fn test_parse_info_keyspace_shapes() {
        let entries = parse_info_keyspace(
            "# Keyspace\n\ndb0:keys=3,expires=1,avg_ttl=0\ndb5:keys=10,expires=0,avg_ttl=0\n",
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "db0");
        assert_eq!(entries[0].keys, "3");
        assert_eq!(entries[0].expires, "1");
        assert_eq!(entries[1].name, "db5");
        // Key-less databases / empty text / non-db lines / missing keys field: ignored.
        assert!(parse_info_keyspace("").is_empty());
        assert!(parse_info_keyspace("# Keyspace\n\n").is_empty());
        assert!(parse_info_keyspace("garbage\n").is_empty());
        assert!(parse_info_keyspace("db1:expires=2\n").is_empty());
    }

    // -- Mis-route guards and uid (no-network paths) --

    #[tokio::test]
    async fn test_execute_redis_rejects_unknown_uid_and_wrong_type() {
        let server = redis_server();
        // Unknown uid: the available list.
        let out = server
            .execute_redis(Parameters(RedisParam {
                uid: "nope".into(),
                command: "GET k".into(),
            }))
            .await;
        let v = json_of(&out);
        assert_eq!(v["error"], "connection 'nope' not found");
        assert!(v["available"].as_array().unwrap().iter().any(|u| u == "r1"));
        // Non-redis connection: the error names the actual type.
        let sqlite = server_with(&sqlite_config_text());
        let out = sqlite
            .execute_redis(Parameters(RedisParam {
                uid: "s1".into(),
                command: "GET k".into(),
            }))
            .await;
        let v = json_of(&out);
        assert_eq!(
            v["error"],
            "connection 's1' is of type 'sqlite'; execute-redis requires a redis connection"
        );
    }

    #[tokio::test]
    async fn test_execute_sql_rejects_redis_connection() {
        let server = redis_server();
        let out = server
            .execute_sql(Parameters(SqlParam {
                uid: "r1".into(),
                database: "0".into(),
                schema: "public".into(),
                sql: "SELECT 1".into(),
            }))
            .await;
        let v = json_of(&out);
        assert_eq!(
            v["error"],
            "redis connection 'r1' does not support SQL queries; use execute-redis"
        );
    }

    #[tokio::test]
    async fn test_list_schema_rejects_redis_connection() {
        let server = redis_server();
        let out = server
            .list_schema(Parameters(UidDbParam {
                uid: "r1".into(),
                database: "0".into(),
            }))
            .await;
        let v = json_of(&out);
        assert!(
            v["error"].as_str().unwrap().contains("no schema concept"),
            "{v}"
        );
    }

    // -- Integration (dbq-redis8; skipped when unreachable) --

    const PREFIX: &str = "dbq_mrt_it:";

    #[tokio::test]
    async fn test_execute_redis_chain_on_live_server() {
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
        let server = redis_server();
        // Allowed: columns + rows isomorphic.
        let out = server
            .execute_redis(Parameters(RedisParam {
                uid: "r1".into(),
                command: format!("GET {PREFIX}str"),
            }))
            .await;
        let v = json_of(&out);
        assert_eq!(v["columns"][0], "value");
        assert_eq!(v["rows"][0][0]["text"], "hello");
        assert!(v.get("cursor").is_none(), "non-SCAN must omit cursor");
        // Denied: denials isomorphic (category + full original text).
        let out = server
            .execute_redis(Parameters(RedisParam {
                uid: "r1".into(),
                command: format!("SET {PREFIX}str world"),
            }))
            .await;
        let v = json_of(&out);
        assert_eq!(v["error"], "Redis command validation failed");
        assert_eq!(v["denials"][0]["category"], "NotReadOnly");
        assert!(v["denials"][0]["message"].as_str().unwrap().contains("SET"));
        // Empty input: a batch-level error.
        let out = server
            .execute_redis(Parameters(RedisParam {
                uid: "r1".into(),
                command: "   ".into(),
            }))
            .await;
        let v = json_of(&out);
        assert_eq!(v["denials"][0]["category"], "EmptyInput");
        // SCAN: the cursor field appears (the MATCH option passes through with the command).
        let out = server
            .execute_redis(Parameters(RedisParam {
                uid: "r1".into(),
                command: format!("SCAN 0 MATCH {PREFIX}*"),
            }))
            .await;
        let v = json_of(&out);
        assert_eq!(v["columns"][0], "key");
        assert!(v["cursor"].is_string());
    }

    #[tokio::test]
    async fn test_metadata_tools_on_live_server() {
        let Some(mut fix) = fixture_conn().await else {
            eprintln!("skipping: test redis not available");
            return;
        };
        let _: () = redis::cmd("SET")
            .arg(format!("{PREFIX}meta"))
            .arg("v")
            .query_async(&mut fix)
            .await
            .unwrap();
        let server = redis_server();
        // list-database: INFO parsing + the current marker.
        let out = server
            .list_database(Parameters(UidParam { uid: "r1".into() }))
            .await;
        let v = json_of(&out);
        let dbs = v["databases"].as_array().unwrap();
        assert!(!dbs.is_empty());
        let db0 = dbs
            .iter()
            .find(|d| d["name"] == "db0")
            .expect("db0 present");
        assert_eq!(db0["current"], true);
        // list-table: the SCAN paginated output carries the cursor.
        let out = server
            .list_table(Parameters(ListTableParam {
                uid: "r1".into(),
                database: "0".into(),
                schema: "public".into(),
                cursor: None,
            }))
            .await;
        let v = json_of(&out);
        assert!(v["cursor"].is_string());
        assert!(
            v["tables"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| { t["name"].as_str().unwrap().starts_with(PREFIX) })
        );
        // list-table: non-public schema rejected.
        let out = server
            .list_table(Parameters(ListTableParam {
                uid: "r1".into(),
                database: "0".into(),
                schema: "other".into(),
                cursor: None,
            }))
            .await;
        let v = json_of(&out);
        assert!(
            v["error"].as_str().unwrap().contains("not supported"),
            "{v}"
        );
        // describe-table: full key metadata fields.
        let out = server
            .describe_table(Parameters(DescribeTableParam {
                uid: "r1".into(),
                database: "0".into(),
                schema: "public".into(),
                table: format!("{PREFIX}meta"),
            }))
            .await;
        let v = json_of(&out);
        assert_eq!(v["exists"], true);
        assert_eq!(v["type"], "string");
        assert_eq!(v["ttl_seconds"], "-1");
        assert!(v["encoding"].is_string());
        assert!(v["memory_bytes"].is_string());
        // describe-table: a missing key yields exists=false.
        let out = server
            .describe_table(Parameters(DescribeTableParam {
                uid: "r1".into(),
                database: "0".into(),
                schema: "public".into(),
                table: format!("{PREFIX}missing"),
            }))
            .await;
        let v = json_of(&out);
        assert_eq!(v["exists"], false);
        assert_eq!(v["type"], "none");
        assert_eq!(v["ttl_seconds"], "-2");
        assert!(v["encoding"].is_null());
    }

    #[tokio::test]
    async fn test_list_table_cursor_round_trip_on_live_server() {
        let Some(mut fix) = fixture_conn().await else {
            eprintln!("skipping: test redis not available");
            return;
        };
        let _: () = redis::cmd("SET")
            .arg(format!("{PREFIX}page"))
            .arg("v")
            .query_async(&mut fix)
            .await
            .unwrap();
        let server = redis_server();
        // Cursor round-trip: the first page omits cursor (defaulting to "0"), later pages pass the previous response value until "0".
        let mut cursor = String::new();
        let mut seen = std::collections::HashSet::new();
        let mut guard = 0;
        loop {
            let out = server
                .list_table(Parameters(ListTableParam {
                    uid: "r1".into(),
                    database: "0".into(),
                    schema: "public".into(),
                    cursor: if cursor.is_empty() {
                        None
                    } else {
                        Some(cursor.clone())
                    },
                }))
                .await;
            let v = json_of(&out);
            for t in v["tables"].as_array().unwrap() {
                seen.insert(t["name"].as_str().unwrap().to_string());
            }
            cursor = v["cursor"].as_str().unwrap().to_string();
            guard += 1;
            assert!(guard < 200, "cursor iteration did not terminate");
            if cursor == "0" {
                break;
            }
        }
        assert!(seen.iter().any(|k| k.starts_with(PREFIX)), "{seen:?}");
    }

    #[tokio::test]
    async fn test_hot_reload_reflects_redis_availability() {
        // Start with a sqlite set, replace with a redis set, and availability flips immediately (shared state).
        let server = server_with(&sqlite_config_text());
        let out = server
            .execute_redis(Parameters(RedisParam {
                uid: "s1".into(),
                command: "PING".into(),
            }))
            .await;
        assert!(json_of(&out)["error"].as_str().unwrap().contains("sqlite"));
        let redis_config =
            excapp_db_core::config::AppConfig::parse(&redis_config_text(redis_port(), "0"))
                .unwrap();
        server
            .state
            .replace(ExecutorSet::build(&redis_config).unwrap());
        // The same server instance sees the new set through the shared state (execute-redis availability changes).
        assert!(server.state.executor("r1").is_some());
        assert!(server.state.executor("s1").is_none());
    }
}
