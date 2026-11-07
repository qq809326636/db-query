//! SQLite dialect implementation: PRAGMA read/write verdicts, dialect-specific
//! variant classification and name normalization.
//!
//! PRAGMA verdicts combine `(value, is_eq)` into three forms (overall design
//! revision #1): no-argument forms go through the read-only allowlist;
//! assignment forms (`=`) are denied outright; parenthesized forms are matched
//! against the parameterized allowlist. Entries not covered by the allowlist
//! are conservatively denied as writes (fail closed). The executor additionally
//! enforces a connection-level read-only hard constraint (mode=ro); the
//! validation baseline stays independent and is not lowered (defense in depth).

use crate::common::{DialectRule, StatementKind};
use sqlparser::ast::Statement;
use sqlparser::dialect::{Dialect, SQLiteDialect};

/// Static SQLite parse dialect instance.
static SQLITE_DIALECT: SQLiteDialect = SQLiteDialect {};

/// SQLite function blacklist: the extension-loading channel (arbitrary code execution).
const FUNCTION_BLACKLIST: &[&str] = &["load_extension", "enable_load_extension"];

/// Read-only PRAGMA allowlist (no-argument query form).
///
/// Read/write annotations follow the Pragma index in the official SQLite docs;
/// session / persistent parameters in query form (journal_mode, etc.) are
/// allowed, while any parameterized assignment is denied. PRAGMAs not in the
/// allowlist (including writable_schema / query_only) are denied in every form
/// (conservative fallback).
const PRAGMA_NO_ARG_READONLY: &[&str] = &[
    "database_list",
    "table_list",
    "pragma_list",
    "module_list",
    "compile_options",
    "encoding",
    "page_size",
    "page_count",
    "max_page_count",
    "journal_mode",
    "foreign_keys",
    "integrity_check",
    "quick_check",
    "freelist_count",
    "data_version",
    "user_version",
    "application_id",
    "locking_mode",
    "synchronous",
    "cache_size",
    "temp_store",
    "mmap_size",
];

/// Read-only PRAGMA allowlist (parenthesized parameterized query form).
///
/// Parameterized assignment semantics like `journal_mode(WAL)` are not in the
/// allowlist (denied); metadata queries such as `table_info(t)` /
/// `index_list(t)` are in the allowlist (allowed).
const PRAGMA_PAREN_READONLY: &[&str] = &[
    "table_info",
    "table_xinfo",
    "index_list",
    "index_info",
    "index_xinfo",
    "foreign_key_list",
    "integrity_check",
    "quick_check",
];

/// SQLite dialect rule (stateless static instance).
pub(crate) struct SqliteRule;

impl DialectRule for SqliteRule {
    fn id(&self) -> &'static str {
        "sqlite"
    }

    fn parser(&self) -> &'static dyn Dialect {
        &SQLITE_DIALECT
    }

    fn function_blacklist(&self) -> &'static [&'static str] {
        FUNCTION_BLACKLIST
    }

    fn normalize_function_name(&self, raw: &str) -> String {
        // Ident.value is already unquoted (double quotes / brackets); no escape
        // form exists, so lowercase normalization applies.
        raw.to_lowercase()
    }

    fn classify(&self, statement: &Statement) -> Option<StatementKind> {
        match statement {
            // PRAGMA combines into three forms: read-only → Describe (metadata
            // viewing, allow side), write / uncovered → Pragma (deny side,
            // "pragma statement").
            Statement::Pragma {
                name, value, is_eq, ..
            } => {
                let bare = pragma_bare_name(name);
                match value {
                    // No-argument form: match against the allowlist.
                    None => {
                        if PRAGMA_NO_ARG_READONLY.contains(&bare.as_str()) {
                            Some(StatementKind::Describe)
                        } else {
                            Some(StatementKind::Pragma)
                        }
                    }
                    // Assignment form (`PRAGMA name = v`): denied outright.
                    Some(_) if *is_eq => Some(StatementKind::Pragma),
                    // Parenthesized form (`PRAGMA name(v)`): matched against the parameterized allowlist.
                    Some(_) => {
                        if PRAGMA_PAREN_READONLY.contains(&bare.as_str()) {
                            Some(StatementKind::Describe)
                        } else {
                            Some(StatementKind::Pragma)
                        }
                    }
                }
            }
            // ATTACH: mounting arbitrary files bypasses the config boundary.
            // (DETACH has no standalone AST variant; parsing fails with a
            // ParseError — fail closed.)
            Statement::AttachDatabase { .. } => Some(StatementKind::Attach),
            // VACUUM (including the VACUUM REINDEX prefix form): rewrites the database file.
            Statement::Vacuum { .. } => Some(StatementKind::Vacuum),
            // ANALYZE: produces persistent statistics tables (same class as maintenance statements).
            Statement::Analyze { .. } => Some(StatementKind::Vacuum),
            _ => None,
        }
    }
}

/// Take the last segment of the PRAGMA name and lowercase it (`main.table_info` → `table_info`).
fn pragma_bare_name(name: &sqlparser::ast::ObjectName) -> String {
    name.0
        .last()
        .and_then(|p| p.as_ident())
        .map(|ident| ident.value.to_lowercase())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use crate::common::{Policy, judge_statements, parse_statements, resolve_rule};
    use crate::error::Denial;

    /// Verdict helper (sqlite path, default policy).
    fn judge_sql(sql: &str) -> Vec<Denial> {
        let rule = resolve_rule("sqlite").unwrap();
        match parse_statements(rule.parser(), sql) {
            Ok(statements) => judge_statements(&statements, rule, &Policy::default()),
            Err(e) => vec![e.into_denial()],
        }
    }

    #[test]
    fn test_allows_sqlite_select_and_explain_query_plan() {
        assert!(judge_sql("SELECT id, `name` FROM t WHERE id > 1").is_empty());
        assert!(judge_sql("SELECT 1 UNION SELECT 2").is_empty());
        // EXPLAIN / EXPLAIN QUERY PLAN: recursive generic verdict on the inner statement.
        assert!(judge_sql("EXPLAIN SELECT 1").is_empty());
        assert!(judge_sql("EXPLAIN QUERY PLAN SELECT * FROM t").is_empty());
    }

    #[test]
    fn test_allows_readonly_pragmas() {
        // Parenthesized form with quoted argument (parse_pragma_value only
        // accepts strings / numbers / placeholders; bare identifier arguments
        // fail with a ParseError).
        assert!(judge_sql("PRAGMA table_info('t')").is_empty());
        assert!(judge_sql("PRAGMA table_xinfo('t')").is_empty());
        assert!(judge_sql("PRAGMA index_list('t')").is_empty());
        assert!(judge_sql("PRAGMA foreign_key_list('t')").is_empty());
        // Table-valued functions: the recommended metadata query form (generic Query allow).
        assert!(judge_sql("SELECT * FROM pragma_table_info('t')").is_empty());
        // No-argument query form.
        assert!(judge_sql("PRAGMA database_list").is_empty());
        assert!(judge_sql("PRAGMA table_list").is_empty());
        assert!(judge_sql("PRAGMA journal_mode").is_empty());
        assert!(judge_sql("PRAGMA page_count").is_empty());
        assert!(judge_sql("PRAGMA integrity_check").is_empty());
        // Qualified names (main.table_info): match on the last segment.
        assert!(judge_sql("PRAGMA main.table_info('t')").is_empty());
    }

    #[test]
    fn test_rejects_write_pragmas() {
        // Number / string assignment form (parseable): any name is denied outright.
        for sql in [
            "PRAGMA writable_schema = 1",
            "PRAGMA user_version = 2",
            "PRAGMA application_id = 'x'",
        ] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "{sql}");
            assert_eq!(
                denials[0].category,
                crate::RejectCategory::NonReadOnly,
                "{sql}"
            );
            assert!(denials[0].message.contains("pragma statement"), "{sql}");
        }
        // Keyword values (` = WAL`) and bare-argument forms: parsing fails with
        // a ParseError (fail closed holds; category is ParseError).
        for sql in ["PRAGMA journal_mode = WAL", "PRAGMA foreign_keys = ON"] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "{sql}");
            assert_eq!(
                denials[0].category,
                crate::RejectCategory::ParseError,
                "{sql}"
            );
        }
        assert_eq!(
            judge_sql("PRAGMA table_info(t)").len(),
            1,
            "bare identifier arg fails to parse"
        );
        // Names outside the allowlist (conservative fallback; parseable no-argument forms are denied outright).
        assert_eq!(judge_sql("PRAGMA secure_delete").len(), 1);
        assert_eq!(judge_sql("PRAGMA trusted_schema").len(), 1);
        // writable_schema / query_only are denied in every form.
        assert_eq!(judge_sql("PRAGMA writable_schema").len(), 1);
        assert_eq!(judge_sql("PRAGMA query_only").len(), 1);
    }

    #[test]
    fn test_rejects_attach_vacuum_analyze() {
        // ATTACH: mounting channel (dedicated message).
        let denials = judge_sql("ATTACH DATABASE '/tmp/x.db' AS extra");
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].category, crate::RejectCategory::NonReadOnly);
        assert!(denials[0].message.contains("attach statement"));

        // VACUUM / VACUUM REINDEX / ANALYZE: maintenance statements (dedicated message).
        for sql in ["VACUUM", "VACUUM REINDEX", "ANALYZE"] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "{sql}");
            assert!(denials[0].message.contains("vacuum statement"), "{sql}");
        }

        // Standalone REINDEX statement: sqlparser 0.63 has no dedicated parse
        // path, so it fails with a ParseError (fail closed holds; category is
        // ParseError rather than Vacuum).
        let denials = judge_sql("REINDEX t");
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].category, crate::RejectCategory::ParseError);
    }

    #[test]
    fn test_rejects_load_extension_with_identifier_variants() {
        for sql in [
            "SELECT load_extension('/tmp/evil.so')",
            "SELECT LOAD_EXTENSION('/tmp/evil.so')",
            "SELECT \"load_extension\"('/tmp/evil.so')",
        ] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "{sql}");
            assert_eq!(
                denials[0].category,
                crate::RejectCategory::ForbiddenFunction,
                "{sql}"
            );
        }
    }

    #[test]
    fn test_rejects_dml_ddl_and_generic_baseline() {
        for sql in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a = 1",
            "CREATE TABLE t (id INTEGER)",
            "DROP TABLE t",
            "SELECT * FROM t FOR UPDATE",
        ] {
            assert_eq!(judge_sql(sql).len(), 1, "failed for {sql}");
        }
        // Data-modifying CTE (common skeleton).
        let denials = judge_sql("WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d");
        assert_eq!(denials[0].category, crate::RejectCategory::DataModifyingCte);
    }
}
