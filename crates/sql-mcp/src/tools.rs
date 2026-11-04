//! MCP tool layer: six tools (uid addressing), shared by both transports.
//!
//! - list-conf: reads connection metadata locally (no database access)
//! - list-database / list-schema / list-table / describe-table: fixed
//!   metadata queries
//! - execute-sql: mandatory sql-validator validation -> sql-executor
//!   execution

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
    /// Executor set (uid addressing, atomic hot-reload replacement).
    pub state: SharedState,
    pub(crate) tool_router: ToolRouter<Self>,
    /// Prompt router (guide + one prompt per tool; static content).
    pub(crate) prompt_router: PromptRouter<Self>,
}

impl DbQueryServer {
    /// Build the server with shared state.
    pub fn new(state: SharedState) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
            prompt_router: crate::prompts::build_prompt_router(),
        }
    }

    /// Unified JSON text output for tools.
    fn json_output(value: serde_json::Value) -> CallToolResult {
        CallToolResult::success(vec![rmcp::model::ContentBlock::text(value.to_string())])
    }

    /// Unified JSON error for tools (isError).
    fn error_output(value: serde_json::Value) -> CallToolResult {
        CallToolResult::error(vec![rmcp::model::ContentBlock::text(value.to_string())])
    }

    /// Unknown-uid error (including the available uid list).
    fn uid_not_found(uid: &str, available: &[String]) -> CallToolResult {
        Self::error_output(json!({
            "error": format!("connection '{uid}' not found"),
            "available": available,
        }))
    }

    /// Literal-safe quoting for schema / table inputs (single quotes
    /// doubled).
    fn quote_literal(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    /// Validation denial details (passing through sql-validator's
    /// denials).
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

    /// Execution error pass-through.
    fn executor_error(err: excapp_db_sql_executor::pg::PgError) -> CallToolResult {
        Self::error_output(json!({ "error": err.to_string() }))
    }

    /// QueryResult -> output JSON.
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

    /// Execute a fixed metadata query on the given connection and take
    /// the first column's text.
    async fn metadata_column(
        &self,
        uid: &str,
        database: Option<&str>,
        sql: &str,
    ) -> Result<Vec<String>, excapp_db_sql_executor::pg::PgError> {
        // uid existence was validated upstream; resolve the executor by
        // database (None = configured default) and take the first column.
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
    ) -> Result<std::sync::Arc<excapp_db_sql_executor::pg::PgExecutor>, CallToolResult> {
        let executor = self
            .state
            .executor(uid)
            .ok_or_else(|| Self::uid_not_found(uid, &self.state.uids()))?;
        // database None means the configured default database; when it
        // matches the configured database and the schema is the default
        // (None or public), reuse the base executor (public is first in
        // PG's default search_path, no derivation needed).
        let config_db = self.state.database_of(uid);
        let same_db = match database {
            None => true,
            Some(db) => config_db.as_deref() == Some(db),
        };
        let default_public = schema.is_none() || schema == Some("public");
        if same_db && default_public {
            return Ok(executor);
        }
        // Other cases (cross-database or explicit schema) derive:
        // cross-database + optional search_path.
        let target_db = database.unwrap_or_else(|| config_db.as_deref().unwrap_or("postgres"));
        match executor.for_database_with_schema(target_db, schema) {
            Ok(derived) => Ok(std::sync::Arc::new(derived)),
            Err(e) => Err(Self::executor_error(e)),
        }
    }
}

// ---- Tool parameters (JSON Schema generated from serde definitions) ----

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
pub(crate) struct SchemaParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Target database name.
    pub(crate) database: String,
    /// PG schema (defaults to public, Postgres only).
    #[serde(default = "default_schema")]
    pub(crate) schema: String,
}

fn default_schema() -> String {
    "public".to_string()
}

/// Describe a table's DDL and columns.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct TableParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Target database name.
    pub(crate) database: String,
    /// PG schema (defaults to public, Postgres only).
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
    /// PG schema (defaults to public, Postgres only).
    #[serde(default = "default_schema")]
    pub(crate) schema: String,
    /// SQL to validate and execute.
    pub(crate) sql: String,
}

#[tool_router]
impl DbQueryServer {
    /// List configured database connections (uid, name, description, default db, db type).
    #[tool(
        name = "list-conf",
        title = "List Connections",
        description = "List configured database connections with uid, name, description, default database (db) and database type (type)."
    )]
    async fn list_conf(&self) -> rmcp::model::CallToolResult {
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
        // Instance-level query (pg_catalog is visible across databases);
        // the connection's base executor suffices.
        if self.state.executor(&param.uid).is_none() {
            return Self::uid_not_found(&param.uid, &self.state.uids());
        }
        let sql = "SELECT datname FROM pg_database WHERE datallowconn \
                   AND datname NOT IN ('template0', 'template1') ORDER BY datname";
        match self.metadata_column(&param.uid, None, sql).await {
            Ok(dbs) => Self::json_output(json!({ "databases": dbs })),
            Err(e) => Self::executor_error(e),
        }
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
        if self.state.executor(&param.uid).is_none() {
            return Self::uid_not_found(&param.uid, &self.state.uids());
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
        description = "List tables and views in the given database and schema (default public, Postgres only). Partition child tables are not listed separately; partitioned parents are marked as PARTITIONED TABLE."
    )]
    async fn list_table(
        &self,
        Parameters(param): Parameters<SchemaParam>,
    ) -> rmcp::model::CallToolResult {
        let executor = match self.resolve(
            &param.uid,
            Some(&param.database),
            Some(param.schema.as_str()),
        ) {
            Ok(e) => e,
            Err(out) => return out,
        };
        // pg_catalog query: information_schema is partition-unaware in PG
        // (partition children are indistinguishable, and partitioned
        // parents also project as BASE TABLE). Here we exclude the
        // inherited children of partitioned parents and mark the parents
        // PARTITIONED TABLE; traditional inheritance children stay
        // listed.
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
        description = "Show the CREATE TABLE DDL and column metadata (name, type, nullable, comment) of the given table in the given database and schema (default public). Table comment is included when present."
    )]
    async fn describe_table(
        &self,
        Parameters(param): Parameters<TableParam>,
    ) -> rmcp::model::CallToolResult {
        let executor = match self.resolve(
            &param.uid,
            Some(&param.database),
            Some(param.schema.as_str()),
        ) {
            Ok(e) => e,
            Err(out) => return out,
        };

        // Column metadata + column comments (via pg_attribute: comments
        // are only obtainable through catalog paths; types are rendered in
        // full form via format_type, e.g. character varying(32)).
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

        // DDL: catalog-assembled (column definitions + defaults + NOT
        // NULL + primary key). Default expressions are rendered via
        // pg_get_expr — pg_attrdef.adsrc was removed in PG 12.
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
        // DDL assembly failure does not block column metadata
        // (degradable), but the error is carried explicitly.
        let (ddl, ddl_error) = match executor.execute_metadata(&ddl_sql).await {
            Ok(r) if !r.rows.is_empty() => (r.rows[0][0].text.clone(), None),
            Ok(_) => (String::new(), None),
            Err(e) => (String::new(), Some(e.to_string())),
        };
        // When a table comment exists, inline it as a comment line atop
        // the DDL (column comments are not inlined, preserving the CREATE
        // statement's executability/readability; they are already
        // provided structurally via columns[].comment).
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
        let verdict = excapp_db_sql_validator::validate(&dialect, &param.sql);
        if !verdict.allowed {
            return Self::validation_denied(&verdict.denials);
        }

        match executor.execute(&param.sql).await {
            Ok(result) => Self::query_result(result),
            Err(e) => Self::executor_error(e),
        }
    }
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

    // The prompt_handler macro would regenerate the whole ServerHandler
    // impl (conflicting with tool_handler), so prompts are routed
    // manually here in a form equivalent to the macro expansion.
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
