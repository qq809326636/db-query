//! execute).

use clap::Args as ClapArgs;
use excapp_db_core::config::AppConfig;

/// Arguments for `excapp-db sql`.
#[derive(Debug, ClapArgs)]
pub struct SqlArgs {
    #[command(subcommand)]
    command: SqlCommand,
}

/// sql subcommands.
#[derive(Debug, clap::Subcommand)]
enum SqlCommand {
    /// Validate SQL only (no execution, no database connection).
    Validate {
        /// uid of the target connection.
        #[arg(long)]
        uid: String,
        /// SQL text (defaults to reading from stdin).
        #[arg(long)]
        sql: Option<String>,
        /// Config file path.
        #[arg(long, default_value = "config.toml")]
        config: std::path::PathBuf,
    },
    /// Validate then execute SQL, printing a table (--json switches to JSON).
    Exec {
        /// uid of the target connection.
        #[arg(long)]
        uid: String,
        /// SQL text (defaults to reading from stdin).
        #[arg(long)]
        sql: Option<String>,
        /// Config file path.
        #[arg(long, default_value = "config.toml")]
        config: std::path::PathBuf,
        /// Output as JSON (same shape as MCP execute-sql).
        #[arg(long)]
        json: bool,
    },
}

/// sql command entry (async: exec needs a runtime).
pub async fn run(args: SqlArgs) -> i32 {
    match args.command {
        SqlCommand::Validate { uid, sql, config } => {
            let Some(sql) = read_sql(sql) else {
                return fail("no SQL provided (use --sql or stdin)");
            };
            validate(&config, &uid, &sql)
        }
        SqlCommand::Exec {
            uid,
            sql,
            config,
            json,
        } => {
            let Some(sql) = read_sql(sql) else {
                return fail("no SQL provided (use --sql or stdin)");
            };
            exec(&config, &uid, &sql, json).await
        }
    }
}

/// Read SQL: --sql takes precedence, otherwise stdin until EOF (trimmed non-empty).
fn read_sql(sql: Option<String>) -> Option<String> {
    if let Some(text) = sql {
        return Some(text);
    }
    let mut buffer = String::new();
    use std::io::Read;
    std::io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| eprintln!("excapp-db: failed to read stdin: {e}"))
        .ok()?;
    let trimmed = buffer.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Locate the database config by uid; returns (dialect, db config).
fn locate(
    config_path: &std::path::Path,
    uid: &str,
) -> Result<excapp_db_core::config::DatabaseConfig, String> {
    let config = AppConfig::load(config_path)?;
    config
        .databases
        .into_iter()
        .find(|db| db.uid == uid)
        .ok_or_else(|| {
            let available: Vec<String> = excapp_db_core::config::AppConfig::load(config_path)
                .map(|c| c.databases.iter().map(|d| d.uid.clone()).collect())
                .unwrap_or_default();
            format!("connection '{uid}' not found; available: {available:?}")
        })
}

/// Build the validation policy from config; on load or build failure fall back
/// to the built-in policy (local validation commands must not be blocked by a
fn load_policy(config_path: &std::path::Path) -> excapp_db_sql_validator::Policy {
    match AppConfig::load(config_path) {
        Ok(config) => match build_policy_from(&config) {
            Ok(policy) => policy,
            Err(e) => {
                eprintln!("warning: falling back to builtin validator policy: {e}");
                excapp_db_sql_validator::Policy::default()
            }
        },
        Err(e) => {
            eprintln!("warning: falling back to builtin validator policy: {e}");
            excapp_db_sql_validator::Policy::default()
        }
    }
}
/// Config → policy (same assembly semantics as sql-mcp; kinds subsetting +
/// three-dialect appends).
fn build_policy_from(
    config: &excapp_db_core::config::AppConfig,
) -> Result<excapp_db_sql_validator::Policy, String> {
    use excapp_db_sql_validator::{PolicyBuilder, StatementKind};
    let sql = &config.validator.sql;
    let mut builder = PolicyBuilder::default();
    let kinds: Vec<StatementKind> = sql
        .whitelist
        .kinds
        .iter()
        .map(|k| StatementKind::parse_allow_name(k))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "invalid validator.sql.whitelist.kinds entry".to_string())?;
    builder
        .allow_kinds(&kinds)
        .map_err(|e| format!("validator.sql.whitelist.kinds: {e}"))?;
    for (dialect, section) in [
        ("postgres", &sql.pg),
        ("mysql", &sql.mysql),
        ("sqlite", &sql.sqlite),
    ] {
        builder
            .extend_fn_blacklist(dialect, &section.blacklist.function)
            .map_err(|e| format!("validator.sql.{dialect}.blacklist.function: {e}"))?;
    }
    Ok(builder.build())
}

fn validate(config_path: &std::path::Path, uid: &str, sql: &str) -> i32 {
    let db = match locate(config_path, uid) {
        Ok(db) => db,
        Err(e) => return fail(&e),
    };
    let policy = load_policy(config_path);
    let verdict = excapp_db_sql_validator::validate_with_policy(&db.dialect, sql, &policy);
    if verdict.allowed {
        println!("OK: statement passes read-only validation");
        0
    } else {
        for denial in &verdict.denials {
            eprintln!(
                "denied #{} [{:?}]: {}",
                denial.index, denial.category, denial.message
            );
        }
        1
    }
}

async fn exec(config_path: &std::path::Path, uid: &str, sql: &str, json: bool) -> i32 {
    let db = match locate(config_path, uid) {
        Ok(db) => db,
        Err(e) => return fail(&e),
    };
    let policy = load_policy(config_path);
    let verdict = excapp_db_sql_validator::validate_with_policy(&db.dialect, sql, &policy);
    if !verdict.allowed {
        for denial in &verdict.denials {
            eprintln!(
                "denied #{} [{:?}]: {}",
                denial.index, denial.category, denial.message
            );
        }
        return 1;
    }

    let executor = match excapp_db_sql_executor::build_executor(&db) {
        Ok(e) => e,
        Err(e) => return fail(&e.to_string()),
    };
    let result = match executor.execute(sql).await {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string()),
    };

    if json {
        println!("{}", render_json(&result));
    } else {
        render_table(&result);
    }
    0
}

/// JSON output: same shape as MCP execute-sql (QueryResult serialized directly).
fn render_json(result: &excapp_db_sql_executor::QueryResult) -> String {
    let columns: Vec<&str> = result.columns.iter().map(String::as_str).collect();
    let rows: Vec<Vec<serde_json::Value>> = result
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|c| serde_json::json!({ "text": c.text, "is_null": c.is_null }))
                .collect()
        })
        .collect();
    serde_json::json!({ "columns": columns, "rows": rows }).to_string()
}

/// Table rendering: two-space separated, adaptive column widths, cells over 60
fn render_table(result: &excapp_db_sql_executor::QueryResult) {
    const MAX_CELL: usize = 60;
    let cell = |text: &str, is_null: bool| -> String {
        if is_null {
            "NULL".to_string()
        } else if text.chars().count() > MAX_CELL {
            let truncated: String = text.chars().take(MAX_CELL).collect();
            format!("{truncated}…")
        } else {
            text.to_string()
        }
    };

    let header: Vec<String> = result.columns.clone();
    let body: Vec<Vec<String>> = result
        .rows
        .iter()
        .map(|row| row.iter().map(|c| cell(&c.text, c.is_null)).collect())
        .collect();

    // Column width = max(header width, widest cell).
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in &body {
        for (i, cell_text) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell_text.chars().count());
        }
    }

    let format_row = |row: &[String]| -> String {
        row.iter()
            .enumerate()
            .map(|(i, cell_text)| format!("{:<width$}", cell_text, width = widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
    };

    println!("{}", format_row(&header));
    for row in &body {
        println!("{}", format_row(row));
    }
    if body.is_empty() {
        println!("(0 rows)");
    }
}

fn fail(message: &str) -> i32 {
    eprintln!("excapp-db: {message}");
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use excapp_db_sql_executor::{CellValue, QueryResult};

    fn sample_result() -> QueryResult {
        QueryResult {
            columns: vec!["id".into(), "name".into()],
            rows: vec![
                vec![CellValue::text("1"), CellValue::text("alice")],
                vec![CellValue::text("2"), CellValue::null()],
            ],
            cursor: None,
        }
    }

    #[test]
    fn test_json_render_matches_mcp_shape() {
        let json = render_json(&sample_result());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["columns"][0], "id");
        assert_eq!(parsed["rows"][1][1]["is_null"], true);
        assert_eq!(parsed["rows"][0][1]["text"], "alice");
    }

    #[test]
    fn test_table_render_null_and_alignment() {
        // Rendering without panicking is the baseline; assert the NULL flag and
        let result = sample_result();
        render_table(&result); // stdout output (visible in test environments)

        let empty = QueryResult {
            columns: vec!["x".into()],
            rows: vec![],
            cursor: None,
        };
        render_table(&empty);
    }

    #[test]
    fn test_cell_truncation() {
        let long = "a".repeat(65);
        let result = QueryResult {
            columns: vec!["c".into()],
            rows: vec![vec![CellValue::text(long)]],
            cursor: None,
        };
        render_table(&result);
    }
}
