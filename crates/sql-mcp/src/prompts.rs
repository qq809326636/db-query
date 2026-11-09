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
pub(crate) enum Lang {
    /// Chinese.
    #[default]
    Zh,
    /// English.
    En,
}
// ---- Prompt parameter structs (tool params + lang; does not intrude on
// tools.rs structs) ----

/// guide / list-connection: lang only.
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
    /// Guide language (zh / en, defaulting to zh).
    #[serde(default)]
    pub(crate) lang: Lang,
}

/// execute-redis: uid + command + lang.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct RedisLangParam {
    /// Configured connection uid.
    pub(crate) uid: String,
    /// Redis command to execute.
    pub(crate) command: String,
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
    /// Overview guide for the seven tools (lang selects the language,
    /// defaulting to zh).
    #[prompt(
        name = "guide",
        description = "db-query seven-tool usage overview: purpose, params, combined flows, errors and limits (lang selects the language)"
    )]
    async fn prompt_guide(&self, Parameters(p): Parameters<LangParam>) -> Vec<PromptMessage> {
        let zh = "\
db-query 只读查询 MCP 使用指引
================================

工具链（建议顺序）：
1. list-connection：列出配置的全部连接（uid / name / description / type）——入口，不连数据库。
2. list-database：列出连接可见的数据库（入参 uid；redis 连接返回逻辑库清单）。
3. list-schema：列出库内 schema，排除系统 schema（入参 uid + database；redis 不支持）。
4. list-table：列出 schema 内表与视图（入参 uid + database + schema，schema 缺省 public；
   redis 连接映射为 SCAN 分页键清单，cursor 参数往返）。
5. describe-table：表结构（入参 uid + database + schema + table；redis 连接映射为键探查，
   table 承载键名）。
6. execute-sql：校验并执行只读 SQL（入参 uid + database + schema + sql；redis 连接不可用，
   请改用 execute-redis）。
7. execute-redis：校验并执行只读 Redis 命令（入参 uid + command；仅限 redis 连接）。

组合流程（SQL 库）：list-connection 找 uid → list-database 选库 → list-schema 定位 schema →
list-table 找表 → describe-table 看结构与注释 → execute-sql 查询数据。

组合流程（Redis）：list-connection 找 redis 连接 uid → list-database 看逻辑库 →
list-table 分页浏览键（cursor 往返）→ describe-table 探查键元数据 → execute-redis 查询数据。

异常与限制：
- uid 不存在：返回错误并列出可用 uid 清单（available）。
- 行数上限：execute-sql / execute-redis 的用户查询最多 100 行，超出整批报错
  （不返回部分结果）；元数据工具不受此限制。
- 只读白名单（SQL）：execute-sql 仅允许 SELECT / EXPLAIN / SHOW / 元数据查询；
  DML / DDL / 事务 / COPY / 锁子句一律拒绝，返回 denials 结构。
- 只读白名单（Redis）：execute-redis 仅允许白名单内只读命令（键 / 字符串 / 哈希 /
  列表 / 集合 / 有序集合 / 位图 / 地理 / 流 / SCAN / INFO 等）；写 / 过期 / 删除 /
  事务 / 脚本 / 发布订阅 / 管理命令一律拒绝，返回同构 denials 结构。
- SCAN 游标：execute-redis 的 SCAN 族结果含 cursor 字段（\"0\" 表示迭代完结）；
  list-table 的 redis 分页经 cursor 参数往返。
- 分区表语义：list-table 中分区父表标注 PARTITIONED TABLE，分区子表不单列。
- 注释：describe-table 输出 table_comment 与 columns[].comment；redis 连接输出键元数据
  （type / ttl / encoding / memory 等，不存在键 exists=false）。
- ddl_error：describe-table 的 DDL 拼装失败时列元数据仍返回，错误置于 ddl_error 字段。

连接敏感信息（密码、主机、端口）不会出现在任何输出中。";
        let en = "\
db-query read-only SQL MCP Usage Guide
======================================

Tool chain (recommended order):
1. list-connection: list configured connections (uid / name / description / type) - entry point, no database access.
2. list-database: list databases visible to the connection (params: uid; redis connections return logical databases).
3. list-schema: list schemas in a database, system schemas excluded (params: uid + database; not supported for redis).
4. list-table: list tables and views in a schema (params: uid + database + schema, schema defaults to public;
   redis connections map to a paginated key list via SCAN with a round-trip cursor parameter).
5. describe-table: table structure (params: uid + database + schema + table; redis connections map to key
   inspection with the table parameter carrying the key name).
6. execute-sql: validate then execute read-only SQL (params: uid + database + schema + sql; not applicable to
   redis connections - use execute-redis instead).
7. execute-redis: validate then execute a read-only Redis command (params: uid + command; redis connections only).

Typical flow (SQL databases): list-connection to find uid -> list-database to pick a database ->
list-schema -> list-table -> describe-table for structure and comments -> execute-sql for data.

Typical flow (Redis): list-connection to find a redis uid -> list-database for logical databases ->
list-table to browse keys page by page (cursor round-trip) -> describe-table for key metadata ->
execute-redis for data.

Exceptions and limits:
- Unknown uid: the error response includes the available uid list.
- Row limit: execute-sql / execute-redis user queries are capped at 100 rows; exceeding fails the
  whole batch (no partial results). Metadata tools are not affected.
- Read-only whitelist (SQL): execute-sql allows SELECT / EXPLAIN / SHOW / metadata queries only;
  DML / DDL / transactions / COPY / locking clauses are rejected with a denials structure.
- Read-only whitelist (Redis): execute-redis allows whitelisted read-only commands only
  (keys / strings / hashes / lists / sets / sorted sets / bitmaps / geo / streams / SCAN / INFO, ...);
  writes / expiry / deletion / transactions / scripts / pub-sub / admin commands are rejected with
  an isomorphic denials structure.
- SCAN cursor: SCAN-family results of execute-redis include a cursor field (\"0\" means iteration
  complete); list-table pagination for redis round-trips via the cursor parameter.
- Partition semantics: partitioned parents are marked PARTITIONED TABLE in list-table;
  partition children are not listed separately.
- Comments: describe-table returns table_comment and columns[].comment; redis connections return
  key metadata (type / ttl / encoding / memory, ...) with exists=false for missing keys.
- ddl_error: if DDL assembly fails in describe-table, column metadata is still returned
  and the error is exposed via the ddl_error field.

Connection secrets (password, host, port) never appear in any output.";
        localized(p.lang, zh.to_string(), en.to_string())
    }

    /// Prompt for list-connection (lang selects the language).
    #[prompt(
        name = "list-connection",
        description = "Usage guide: list configured database connections (lang selects the language)"
    )]
    async fn prompt_list_connection(
        &self,
        Parameters(p): Parameters<LangParam>,
    ) -> Vec<PromptMessage> {
        let zh = "\
工具 list-connection 使用指引
========================
用途：列出配置文件中的全部数据库连接，是发现可用 uid 的入口；不连接数据库。

输出结构：connections 数组，每项含 uid / name / description。

异常：本工具不访问数据库，几乎不会失败；若返回空列表说明配置未定义任何连接。

衔接建议：拿到 uid 后调用 list-database 查看该连接可用的数据库。";
        let en = "\
Prompt for tool list-connection
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

Redis 连接：返回逻辑库清单（基于 INFO keyspace）——每项含 name（dbN 形态）/
keys / expires / current（是否配置默认逻辑库）；仅列出有键的逻辑库。

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

Redis connections: returns the logical database list (based on INFO keyspace) -
each item has name (dbN form) / keys / expires / current (whether it is the
configured default logical database); only logical databases with keys appear.

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

Redis 连接：不支持——返回明确错误（Redis 无 schema 概念，请改用 list-database
查看逻辑库）。

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

Redis connections: not supported - an explicit error is returned (redis has no
schema concept; use list-database for logical databases).

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

Redis 连接：映射为 SCAN 分页键清单——tables 数组每项含 name（键名）；
输出含 cursor 字段（服务端游标文本，\"0\" 表示迭代完结），下一页将其作为
cursor 参数传入；schema 参数仅接受缺省 public。

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

Redis connections: mapped to a paginated key list via SCAN - each tables item has
name (the key); the output includes a cursor field (server cursor text, \"0\" means
iteration complete); pass it back as the cursor parameter for the next page; the
schema parameter only accepts the default public.

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

Redis 连接：映射为键探查（table 承载键名）——输出 key / exists / type /
ttl_seconds / ttl_milliseconds / encoding / refcount / idle_time_seconds /
memory_bytes；不存在键 exists=false 且 type=none、TTL 为 -2、其余字段 null；
schema 参数仅接受缺省 public。

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

Redis connections: mapped to key inspection (the table parameter carries the key
name) - output is key / exists / type / ttl_seconds / ttl_milliseconds / encoding /
refcount / idle_time_seconds / memory_bytes; a missing key yields exists=false with
type=none, TTL -2 and null for the remaining fields; the schema parameter only
accepts the default public.

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

    /// Prompt for execute-redis (uid + command).
    #[prompt(
        name = "execute-redis",
        description = "Usage guide: read-only Redis command validation and execution, whitelist and cursor (lang selects the language)"
    )]
    async fn prompt_execute_redis(
        &self,
        Parameters(p): Parameters<RedisLangParam>,
    ) -> Vec<PromptMessage> {
        let zh = format!(
            "\
工具 execute-redis 使用指引
===========================
用途：先经只读白名单校验，再在 Redis 连接上执行命令并返回结构化结果
（文本化单元格，与 execute-sql 输出同构）。

参数：
- {uid}
- {command}

只读白名单：仅允许白名单内只读命令——键（TYPE / TTL / EXISTS / ...）、字符串
（GET / STRLEN / MGET / ...）、哈希（HGET / HGETALL / HSCAN / ...）、列表、集合、
有序集合、位图、地理、流、SCAN 族、OBJECT / MEMORY、INFO / DBSIZE / PING 等；
写（SET / DEL / ...）、过期、事务、脚本（EVAL）、发布订阅、管理命令一律拒绝。
拒绝响应为 denials 数组：逐条给出序号、违规类别与原因（含完整命令原文），
命令不会执行。

单命令：一次一条命令（多命令 / 分号 / 换行整体拒绝）；引号可包裹含空格参数。

保护：结果最多 100 行 / 10MB，超出整批报错；单命令 30 秒超时。

输出结构：columns（列名）+ rows（单元格为 {{text, is_null}}）；SCAN 族另含
cursor 字段（服务端游标文本，\"0\" 表示迭代完结，非 0 时继续迭代）。

常见异常：
- uid 不存在：错误响应携带 available 清单。
- 连接非 redis 类型：错误指明实际类型。
- 校验拒绝：见 denials。
- 服务端错误（如 WRONGTYPE）：英文透传（含连接标识，不含凭据）。

衔接建议：先用 list-table 分页浏览键、describe-table 探查键元数据，再取值；
大集合用 SCAN / HSCAN 分页（COUNT 已受白名单约束）。",
            uid = field("目标连接 uid", &p.uid),
            command = field("待执行 Redis 命令", &p.command)
        );
        let en = format!(
            "\
Prompt for tool execute-redis
=============================
Purpose: validate the command against the read-only whitelist first, then execute
it on the Redis connection and return structured results (text-rendered cells,
isomorphic with execute-sql output).

Params:
- {uid}
- {command}

Read-only whitelist: only whitelisted read-only commands are allowed - keys
(TYPE / TTL / EXISTS, ...), strings (GET / STRLEN / MGET, ...), hashes
(HGET / HGETALL / HSCAN, ...), lists, sets, sorted sets, bitmaps, geo, streams,
the SCAN family, OBJECT / MEMORY, INFO / DBSIZE / PING, ...; writes (SET / DEL, ...),
expiry, transactions, scripts (EVAL), pub-sub and admin commands are always
rejected. The rejection response is a denials array listing index, violation
category and reason (with the full original command); the command is not executed.

Single command: one command per call (multi-command input, semicolons and newlines
are rejected as a whole); quotes may wrap arguments containing spaces.

Limits: at most 100 rows / 10MB; exceeding fails the whole batch; 30s timeout
per command.

Output: columns (names) + rows (cells as {{text, is_null}}); the SCAN family
additionally includes a cursor field (server cursor text, \"0\" means iteration
complete, keep iterating while non-zero).

Common errors:
- Unknown uid: the error includes an available list.
- Non-redis connection: the error names the actual type.
- Validation denial: see denials.
- Server errors (e.g. WRONGTYPE): passed through in English (connection identity
  included, never credentials).

Next step: browse keys with list-table and inspect key metadata with
describe-table before fetching values; page large collections with SCAN / HSCAN
(COUNT is already constrained by the whitelist).",
            uid = field("target connection uid", &p.uid),
            command = field("Redis command to execute", &p.command)
        );
        localized(p.lang, zh, en)
    }
}

/// Build the prompt router (assembled by DbQueryServer::new; the
/// macro-generated prompt_router function is module-private, forwarded
/// here as pub(crate)).
pub(crate) fn build_prompt_router()
-> rmcp::handler::server::router::prompt::PromptRouter<crate::tools::DbQueryServer> {
    <crate::tools::DbQueryServer>::prompt_router()
}
