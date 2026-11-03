//! MCP prompt layer: the guide prompt + six per-tool prompts mirroring
//! tool parameters.
//!
//! - Pure in-memory text rendering: no database access, no validation,
//!   no SharedState access
//! - The lang parameter (an ISO 639-1 subset, zh / en, defaulting to zh)
//!   selects the returned language, single message

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{PromptMessage, Role};
use rmcp::{prompt, prompt_router};
use schemars::JsonSchema;
use serde::Deserialize;

/// Guide language (an ISO 639-1 subset): defaults to zh; unknown values
/// are rejected at deserialization.
#[derive(Debug, Default, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Lang {
    /// Chinese.
    #[default]
    Zh,
    /// English.
    En,
}

// ---- Prompt parameter structs (tool params + lang; does not intrude on
// tools.rs structs) ----

/// guide / list-conf: lang only.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct LangParam {
    /// Guide language (zh / en, defaults to zh).
    #[serde(default)]
    pub(crate) lang: Lang,
}

/// list-database: uid + lang.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct UidLangParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Guide language (zh / en, defaults to zh).
    #[serde(default)]
    pub(crate) lang: Lang,
}

/// list-schema: uid + database + lang.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct UidDbLangParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Target database name.
    pub(crate) database: String,
    /// Guide language (zh / en, defaults to zh).
    #[serde(default)]
    pub(crate) lang: Lang,
}

/// list-table: uid + database + schema + lang.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct SchemaLangParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Target database name.
    pub(crate) database: String,
    /// PG schema (defaults to public, Postgres only).
    #[serde(default = "default_schema")]
    pub(crate) schema: String,
    /// Guide language (zh / en, defaults to zh).
    #[serde(default)]
    pub(crate) lang: Lang,
}

fn default_schema() -> String {
    "public".to_string()
}

/// describe-table: uid + database + schema + table + lang.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct TableLangParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Target database name.
    pub(crate) database: String,
    /// PG schema (defaults to public, Postgres only).
    #[serde(default = "default_schema")]
    pub(crate) schema: String,
    /// Table name.
    pub(crate) table: String,
    /// Guide language (zh / en, defaults to zh).
    #[serde(default)]
    pub(crate) lang: Lang,
}

/// execute-sql: uid + database + schema + sql + lang.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct SqlLangParam {
    /// uid of the configured connection.
    pub(crate) uid: String,
    /// Target database name.
    pub(crate) database: String,
    /// PG schema (defaults to public, Postgres only).
    #[serde(default = "default_schema")]
    pub(crate) schema: String,
    /// SQL to validate and execute.
    pub(crate) sql: String,
    /// Guide language (zh / en, defaults to zh).
    #[serde(default)]
    pub(crate) lang: Lang,
}

/// Select the monolingual body by lang, returning a single user message.
fn localized(lang: Lang, zh: String, en: String) -> Vec<PromptMessage> {
    let text = match lang {
        Lang::Zh => zh,
        Lang::En => en,
    };
    vec![PromptMessage::new_text(Role::User, text)]
}

/// Parameter value embedded as "field name = value".
fn field(name: &str, value: &str) -> String {
    format!("{name} = {value}")
}

#[prompt_router]
impl crate::tools::DbQueryServer {
    /// Overview guide for the six tools (lang selects the language,
    /// defaulting to zh).
    #[prompt(
        name = "guide",
        description = "db-query six-tool usage overview: purpose, params, combined flows, errors and limits (lang selects the language)"
    )]
    async fn prompt_guide(&self, Parameters(p): Parameters<LangParam>) -> Vec<PromptMessage> {
        let zh = "\
db-query 只读查询 MCP 使用指引
================================

工具链（建议顺序）：
1. list-conf：列出配置的全部连接（uid / name / description）——入口，不连数据库。
2. list-database：列出连接可见的数据库（入参 uid）。
3. list-schema：列出库内 schema，排除系统 schema（入参 uid + database）。
4. list-table：列出 schema 内表与视图（入参 uid + database + schema，schema 缺省 public）。
5. describe-table：表结构（入参 uid + database + schema + table）。
6. execute-sql：校验并执行只读 SQL（入参 uid + database + schema + sql）。

组合流程：list-conf 找 uid → list-database 选库 → list-schema 定位 schema →
list-table 找表 → describe-table 看结构与注释 → execute-sql 查询数据。

异常与限制：
- uid 不存在：返回错误并列出可用 uid 清单（available）。
- 行数上限：execute-sql 的用户查询最多 100 行，超出整批报错（不返回部分结果）；
  元数据工具（list-table 等）不受此限制。
- 只读白名单：execute-sql 仅允许 SELECT / EXPLAIN / SHOW / 元数据查询；
  DML / DDL / 事务 / COPY / 锁子句一律拒绝，返回 denials 结构（逐条列出拒绝原因）。
- 分区表语义：list-table 中分区父表标注 PARTITIONED TABLE，分区子表不单列。
- 注释：describe-table 输出 table_comment（表注释）与 columns[].comment（列注释），
  DDL 顶部以「-- 表注释」内联；无注释时对应字段为 null。
- ddl_error：describe-table 的 DDL 拼装失败时列元数据仍返回，错误置于 ddl_error 字段。

连接敏感信息（密码、主机、端口）不会出现在任何输出中。";
        let en = "\
db-query read-only SQL MCP Usage Guide
======================================

Tool chain (recommended order):
1. list-conf: list configured connections (uid / name / description) - entry point, no database access.
2. list-database: list databases visible to the connection (params: uid).
3. list-schema: list schemas in a database, system schemas excluded (params: uid + database).
4. list-table: list tables and views in a schema (params: uid + database + schema; schema defaults to public).
5. describe-table: table structure (params: uid + database + schema + table).
6. execute-sql: validate then execute read-only SQL (params: uid + database + schema + sql).

Typical flow: list-conf to find uid -> list-database to pick a database ->
list-schema -> list-table -> describe-table for structure and comments -> execute-sql for data.

Exceptions and limits:
- Unknown uid: the error response includes the available uid list.
- Row limit: execute-sql user queries are capped at 100 rows; exceeding fails the whole
  batch (no partial results). Metadata tools (list-table, etc.) are not affected.
- Read-only whitelist: execute-sql allows SELECT / EXPLAIN / SHOW / metadata queries only;
  DML / DDL / transactions / COPY / locking clauses are rejected with a denials structure.
- Partition semantics: partitioned parents are marked PARTITIONED TABLE in list-table;
  partition children are not listed separately.
- Comments: describe-table returns table_comment and columns[].comment; the DDL is
  prefixed with '-- <table comment>' when present; null when absent.
- ddl_error: if DDL assembly fails in describe-table, column metadata is still returned
  and the error is exposed via the ddl_error field.

Connection secrets (password, host, port) never appear in any output.";
        localized(p.lang, zh.to_string(), en.to_string())
    }

    /// Prompt for list-conf (lang selects the language).
    #[prompt(
        name = "list-conf",
        description = "Usage guide: list configured database connections (lang selects the language)"
    )]
    async fn prompt_list_conf(&self, Parameters(p): Parameters<LangParam>) -> Vec<PromptMessage> {
        let zh = "\
工具 list-conf 使用指引
========================
用途：列出配置文件中的全部数据库连接，是发现可用 uid 的入口；不连接数据库。

输出结构：connections 数组，每项含 uid / name / description。

异常：本工具不访问数据库，几乎不会失败；若返回空列表说明配置未定义任何连接。

衔接建议：拿到 uid 后调用 list-database 查看该连接可用的数据库。";
        let en = "\
Prompt for tool list-conf
=========================
Purpose: list all database connections from configuration; it is the entry point to
discover available uids. No database access.

Output: a connections array where each item has uid / name / description.

Errors: this tool does not touch the database; an empty array simply means no
connection is configured.

Next step: once you have a uid, call list-database to see available databases.";
        localized(p.lang, zh.to_string(), en.to_string())
    }

    /// Prompt for list-database (uid).
    #[prompt(
        name = "list-database",
        description = "Usage guide: list databases visible to the connection (lang selects the language)"
    )]
    async fn prompt_list_database(
        &self,
        Parameters(p): Parameters<UidLangParam>,
    ) -> Vec<PromptMessage> {
        let zh = format!(
            "\
工具 list-database 使用指引
============================
用途：列出指定连接实例上可见、可连接的数据库（基于 pg_database，排除模板库）。

参数：
- {uid}

输出结构：databases 数组（数据库名列表）。

常见异常：
- uid 不存在：错误响应携带 available 清单，请改用清单中的 uid。
- 连接不可达：返回英文错误信息（含连接标识，不含密码）。

衔接建议：选定 database 后调用 list-schema 查看 schema 清单。",
            uid = field("目标连接 uid", &p.uid)
        );
        let en = format!(
            "\
Prompt for tool list-database
=============================
Purpose: list visible and connectable databases on the connection's instance
(based on pg_database, template databases excluded).

Params:
- {uid}

Output: a databases array (database names).

Common errors:
- Unknown uid: the error includes an available list; retry with one of them.
- Unreachable connection: an English error message (connection identity included,
  never the password).

Next step: pick a database, then call list-schema.",
            uid = field("target connection uid", &p.uid)
        );
        localized(p.lang, zh, en)
    }

    /// Prompt for list-schema (uid + database).
    #[prompt(
        name = "list-schema",
        description = "Usage guide: list schemas in a database (lang selects the language)"
    )]
    async fn prompt_list_schema(
        &self,
        Parameters(p): Parameters<UidDbLangParam>,
    ) -> Vec<PromptMessage> {
        let zh = format!(
            "\
工具 list-schema 使用指引
==========================
用途：列出目标库中的全部 schema（排除 pg_* 系统 schema 与 information_schema）。

参数：
- {uid}
- {db}

输出结构：schemas 数组（schema 名列表）。

常见异常：
- uid 不存在：错误响应携带 available 清单。
- database 不存在或无权限：英文错误（含库名，不含密码）。

衔接建议：通常业务表在 public；选定 schema 后调用 list-table。",
            uid = field("目标连接 uid", &p.uid),
            db = field("目标数据库名", &p.database)
        );
        let en = format!(
            "\
Prompt for tool list-schema
===========================
Purpose: list all schemas in the target database (pg_* system schemas and
information_schema excluded).

Params:
- {uid}
- {db}

Output: a schemas array (schema names).

Common errors:
- Unknown uid: the error includes an available list.
- Missing database or insufficient privilege: an English error (database name
  included, never the password).

Next step: business tables usually live in public; call list-table with the schema.",
            uid = field("target connection uid", &p.uid),
            db = field("target database", &p.database)
        );
        localized(p.lang, zh, en)
    }

    /// Prompt for list-table (uid + database + optional schema).
    #[prompt(
        name = "list-table",
        description = "Usage guide: list tables and views in a schema, including partition semantics (lang selects the language)"
    )]
    async fn prompt_list_table(
        &self,
        Parameters(p): Parameters<SchemaLangParam>,
    ) -> Vec<PromptMessage> {
        let zh = format!(
            "\
工具 list-table 使用指引
========================
用途：列出目标 schema 中的表与视图。

参数：
- {uid}
- {db}
- {schema}（可选，缺省 public；仅限 Postgres）

输出结构：tables 数组，每项含 name 与 type；type 取值 BASE TABLE /
PARTITIONED TABLE / VIEW / FOREIGN TABLE。

分区语义：分区父表标注 PARTITIONED TABLE；分区子表（如 *_p20260101、
*_default）不单独列出——它们是父表的数据分片，请对父表查询。

常见异常：
- uid 不存在：错误响应携带 available 清单。
- database/schema 不存在或无权限：英文错误（不含密码）。

衔接建议：找到目标表后调用 describe-table 查看结构与注释。",
            uid = field("目标连接 uid", &p.uid),
            db = field("目标数据库名", &p.database),
            schema = field("PG schema", &p.schema)
        );
        let en = format!(
            "\
Prompt for tool list-table
==========================
Purpose: list tables and views in the target schema.

Params:
- {uid}
- {db}
- {schema} (optional, defaults to public; Postgres only)

Output: a tables array where each item has name and type; type is one of
BASE TABLE / PARTITIONED TABLE / VIEW / FOREIGN TABLE.

Partition semantics: partitioned parents are marked PARTITIONED TABLE; partition
children (e.g. *_p20260101, *_default) are NOT listed separately - they are data
shards of the parent, query the parent instead.

Common errors:
- Unknown uid: the error includes an available list.
- Missing database/schema or insufficient privilege: an English error (no password).

Next step: call describe-table on the target table for structure and comments.",
            uid = field("target connection uid", &p.uid),
            db = field("target database", &p.database),
            schema = field("PG schema", &p.schema)
        );
        localized(p.lang, zh, en)
    }

    /// Prompt for describe-table (uid + database + optional schema +
    /// table).
    #[prompt(
        name = "describe-table",
        description = "Usage guide: table structure, DDL and comments (lang selects the language)"
    )]
    async fn prompt_describe_table(
        &self,
        Parameters(p): Parameters<TableLangParam>,
    ) -> Vec<PromptMessage> {
        let zh = format!(
            "\
工具 describe-table 使用指引
============================
用途：查看目标表的 CREATE TABLE DDL 与列元数据（含注释）。

参数：
- {uid}
- {db}
- {schema}（可选，缺省 public）
- {table}

输出契约：
- ddl：目录拼装的 CREATE TABLE 语句（列定义 + 缺省 + 非空 + 主键）；存在表注释时
  顶部以「-- 表注释」内联一行。
- table_comment：表注释（string 或 null）。
- columns：数组，每项含 name / data_type（完整类型，如 character varying(32)）/
  nullable / comment（string 或 null）。
- ddl_error：仅当 DDL 拼装失败时出现；此时列元数据仍正常返回。

常见异常：
- 表不存在：错误信息指明 schema 与表名。
- 分区父表：DDL 为父表定义，不含 PARTITION BY 子句（按既有契约）。

衔接建议：确认结构与注释后调用 execute-sql 查询数据。",
            uid = field("目标连接 uid", &p.uid),
            db = field("目标数据库名", &p.database),
            schema = field("PG schema", &p.schema),
            table = field("表名", &p.table)
        );
        let en = format!(
            "\
Prompt for tool describe-table
==============================
Purpose: inspect the target table's CREATE TABLE DDL and column metadata
(including comments).

Params:
- {uid}
- {db}
- {schema} (optional, defaults to public)
- {table}

Output contract:
- ddl: a catalog-assembled CREATE TABLE statement (columns + defaults + NOT NULL +
  primary key); prefixed with '-- <table comment>' when a table comment exists.
- table_comment: the table comment (string or null).
- columns: an array of name / data_type (full type such as character varying(32)) /
  nullable / comment (string or null).
- ddl_error: present only when DDL assembly fails; column metadata is still returned.

Common errors:
- Table not found: the error names the schema and table.
- Partitioned parent: the DDL is the parent definition without a PARTITION BY
  clause (per the existing contract).

Next step: call execute-sql once the structure and comments are confirmed.",
            uid = field("target connection uid", &p.uid),
            db = field("target database", &p.database),
            schema = field("PG schema", &p.schema),
            table = field("table", &p.table)
        );
        localized(p.lang, zh, en)
    }

    /// Prompt for execute-sql (uid + database + optional schema + sql).
    #[prompt(
        name = "execute-sql",
        description = "Usage guide: read-only SQL validation and execution, whitelist and row limits (lang selects the language)"
    )]
    async fn prompt_execute_sql(
        &self,
        Parameters(p): Parameters<SqlLangParam>,
    ) -> Vec<PromptMessage> {
        let zh = format!(
            "\
工具 execute-sql 使用指引
=========================
用途：先经只读白名单校验，再执行 SQL 并返回结果（文本化单元格）。

参数：
- {uid}
- {db}
- {schema}（可选，缺省 public；作为 search_path）
- {sql}

只读白名单：仅允许 SELECT / EXPLAIN / SHOW / 元数据查询；DML（INSERT/UPDATE/
DELETE）/ DDL / 事务（BEGIN/COMMIT 等）/ COPY / 锁子句（FOR UPDATE 等）一律拒绝。
拒绝响应为 denials 数组：逐条给出语句序号、违规类别与原因，SQL 不会执行。

行数上限：结果最多 100 行；超出时整批报错（如 got 101, limit is 100），
不返回部分结果。请用 LIMIT / 聚合缩小结果集。

输出结构：columns（列名）+ rows（单元格为 {{text, is_null}} 文本渲染）。

常见异常：
- uid 不存在：错误响应携带 available 清单。
- 校验拒绝：见 denials。
- 行数超限：见上；多语句批以最后一个含结果集的语句为准。

衔接建议：先用 describe-table 确认列名与类型，再写 SQL；宽表请显式选择列。",
            uid = field("目标连接 uid", &p.uid),
            db = field("目标数据库名", &p.database),
            schema = field("PG schema", &p.schema),
            sql = field("待执行 SQL", &p.sql)
        );
        let en = format!(
            "\
Prompt for tool execute-sql
===========================
Purpose: validate SQL against the read-only whitelist first, then execute and
return text-rendered results.

Params:
- {uid}
- {db}
- {schema} (optional, defaults to public; used as search_path)
- {sql}

Read-only whitelist: only SELECT / EXPLAIN / SHOW / metadata queries are allowed;
DML (INSERT/UPDATE/DELETE), DDL, transactions (BEGIN/COMMIT, ...), COPY and locking
clauses (FOR UPDATE, ...) are always rejected. The rejection response is a denials
array listing statement index, violation category and reason; the SQL is not executed.

Row limit: at most 100 rows; exceeding fails the whole batch (e.g. got 101,
limit is 100) with no partial results. Narrow the result set with LIMIT or
aggregations.

Output: columns (names) + rows (cells as {{text, is_null}} text rendering).

Common errors:
- Unknown uid: the error includes an available list.
- Validation denial: see denials.
- Row limit exceeded: see above; for multi-statement batches the last statement
  with a result set wins.

Next step: confirm column names and types with describe-table before writing SQL;
select columns explicitly on wide tables.",
            uid = field("target connection uid", &p.uid),
            db = field("target database", &p.database),
            schema = field("PG schema", &p.schema),
            sql = field("SQL to execute", &p.sql)
        );
        localized(p.lang, zh, en)
    }
}

/// Build the prompt router (assembled by DbQueryServer::new; the
/// macro-generated prompt_router function is module-private, forwarded
/// here as pub(crate)).
pub(crate) fn build_prompt_router() -> rmcp::handler::server::router::prompt::PromptRouter<
    crate::tools::DbQueryServer,
> {
    <crate::tools::DbQueryServer>::prompt_router()
}
