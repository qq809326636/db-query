//! Whitelist judging: AST-level read-only judgment over parsed statements.
//!
//! Allowed items are explicitly enumerated (pure queries / conditionally
//! allowed EXPLAIN / SHOW and DESC metadata viewing); everything else
//! falls into the catch-all rejection (fail closed), so new variants
//! introduced by sqlparser upgrades are rejected by default.

use crate::error::{
    Denial, render_data_modifying_cte, render_forbidden_function, render_locking_clause,
    render_non_read_only,
};
use core::ops::ControlFlow;
use sqlparser::ast::{Expr, Query, SetExpr, Statement, Visit, Visitor};

/// Expression-level blacklisted functions: session-level advisory locks
/// (left over on pooled connections across requests, enabling DoS against
/// business lock mechanisms), server administration functions
/// (terminate/cancel backends, reload config, change session parameters),
/// sequence position modification (persistent state corruption), and
/// large-object read/write channels.
///
/// Allowed: `pg_advisory_xact_lock` (transaction-scoped, released when
/// the statement ends), `pg_advisory_unlock` (unlock cleanup),
/// `pg_sleep` (bounded by statement_timeout), and `currval` (read-only
/// position query, no consumption).
const FUNCTION_BLACKLIST: &[&str] = &[
    // Session-level advisory locks
    "pg_advisory_lock",
    "pg_try_advisory_lock",
    "pg_advisory_unlock_all",
    // Server administration
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_reload_conf",
    "set_config",
    // Sequence position modification (persistent state)
    "setval",
    "nextval",
    "set_masked",
    // Large-object read/write channels (the whole family)
    "lo_create",
    "lo_import",
    "lo_export",
    "lo_unlink",
    "lo_open",
    "loread",
    "lowrite",
    "lo_close",
    "lo_truncate",
    "lo_lseek",
    "lo_tell",
];

/// Decode Unicode escapes inside delimited identifiers (PG U&"..."
/// semantics).
///
/// - `\XXXX` (4 hex digits) and `\+XXXXXX` (6 digits) are decoded and
///   replaced as a char;
/// - `\\` decodes to a literal `\`;
/// - Illegal escape sequences are kept as-is (conservative: they simply
///   miss the blacklist comparison, matching the PG server behavior of
///   rejecting illegal escapes outright).
///
/// sqlparser does not support U& delimited identifiers, so `Ident.value`
/// keeps the raw `\005F` escape text; decoding must happen before the
/// blacklist comparison, otherwise escaped forms can bypass it.
fn decode_unicode_escapes(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(value[i..].chars().next().unwrap_or('\\'));
            let ch_len = value[i..].chars().next().map_or(1, char::len_utf8);
            i += ch_len;
            continue;
        }
        // Backslash escapes
        let rest = &value[i + 1..];
        if let Some(stripped) = rest.strip_prefix('+') {
            if let Some(decoded) = try_hex_char(stripped, 6) {
                out.push(decoded);
                i += 1 + 1 + 6;
                continue;
            }
        } else if let Some(decoded) = try_hex_char(rest, 4) {
            out.push(decoded);
            i += 1 + 4;
            continue;
        } else if rest.starts_with('\\') {
            out.push('\\');
            i += 2;
            continue;
        }
        // Illegal escape: keep the backslash and the following character
        // as-is.
        out.push('\\');
        i += 1;
    }
    out
}

/// Try to take `n` hex digits starting at `s` and decode them into a char.
fn try_hex_char(s: &str, n: usize) -> Option<char> {
    let hex = s.get(..n)?;
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let code = u32::from_str_radix(hex, 16).ok()?;
    char::from_u32(code)
}

/// Expression-level function blacklist scanner: recursively visits every
/// `Expr` in the statement and Breaks on a hit; it also rejects SELECTs
/// with an INTO clause (the SELECT-shaped DDL write channel).
struct ForbiddenFunctionScanner {
    hit: Option<String>,
}

impl Visitor for ForbiddenFunctionScanner {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::Function(func) = expr {
            // The function name takes the last segment
            // (pg_catalog.pg_advisory_lock equals the bare name).
            // Extracted via Ident.value: the inner value of a delimited
            // identifier ("pg_advisory_lock", "PG_ADVISORY_LOCK") has no
            // quotes; then U& Unicode escapes (\005F form) are decoded
            // and lowercased — quoting, casing, and escaping cannot
            // bypass the blacklist.
            let name = func
                .name
                .0
                .last()
                .and_then(|p| p.as_ident())
                .map(|ident| decode_unicode_escapes(&ident.value).to_lowercase())
                .unwrap_or_default();
            if FUNCTION_BLACKLIST.contains(&name.as_str()) {
                self.hit = Some(name);
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, select: &sqlparser::ast::Select) -> ControlFlow<Self::Break> {
        // SELECT ... INTO (including INTO TEMP) is a Query-shaped DDL
        // write channel.
        if select.into.is_some() {
            self.hit = Some("<select-into>".to_string());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Scan the statement's expression level for blacklisted functions and
/// INTO clauses; a hit returns an identifier (the blacklisted function
/// name or `<select-into>`).
fn scan_forbidden_function(statement: &Statement) -> Option<String> {
    let mut scanner = ForbiddenFunctionScanner { hit: None };
    if statement.visit(&mut scanner).is_break() {
        scanner.hit
    } else {
        None
    }
}

/// Render a scan hit into a denial report (functions go through
/// ForbiddenFunction; INTO goes through the NonReadOnly SELECT INTO
/// channel message).
fn render_scan_hit(index: usize, hit: &str, statement: &str) -> Denial {
    if hit == "<select-into>" {
        render_non_read_only(index, "SELECT INTO", statement)
    } else {
        render_forbidden_function(index, hit, statement)
    }
}

/// Judge a statement list one by one, returning reports for all rejected
/// statements; an empty list means the whole batch is allowed.
///
/// Numbering starts at 1; statements that pass do not enter the return
/// value.
pub(crate) fn judge_statements(statements: &[Statement]) -> Vec<Denial> {
    statements
        .iter()
        .enumerate()
        .filter_map(|(i, statement)| judge_one(i + 1, statement))
        .collect()
}

/// Judge a single statement; `None` means allowed, `Some(denial)` is a
/// rejection report.
fn judge_one(index: usize, statement: &Statement) -> Option<Denial> {
    match statement {
        // Pure query: including CTEs / set operations / VALUES /
        // subqueries; locking clauses, data-modifying CTEs (DML variants
        // in the CTE body or the body itself), and expression-level
        // blacklisted functions are rejected separately.
        Statement::Query(query) => {
            if let Some(hit) = scan_forbidden_function(statement) {
                return Some(render_scan_hit(index, &hit, &statement.to_string()));
            }
            judge_query(index, query, None, &statement.to_string())
        }
        // EXPLAIN / EXPLAIN ANALYZE: the same judgment is recursively
        // applied to the inner statement.
        Statement::Explain {
            statement: inner, ..
        } => {
            if let Some(hit) = scan_forbidden_function(statement) {
                return Some(render_scan_hit(index, &hit, &statement.to_string()));
            }
            judge_one(index, inner)
        }
        // DESC / DESCRIBE table-structure metadata viewing.
        Statement::ExplainTable { .. } => None,
        // SHOW-style metadata viewing (variables / columns / definitions /
        // database and table listings, etc.).
        Statement::ShowFunctions { .. }
        | Statement::ShowVariable { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowCatalogs { .. }
        | Statement::ShowDatabases { .. }
        | Statement::ShowProcessList { .. }
        | Statement::ShowSchemas { .. }
        | Statement::ShowTables { .. }
        | Statement::ShowViews { .. }
        | Statement::ShowCollation { .. } => None,
        // Everything else (DML / DDL / transactions / privilege & session /
        // COPY / unrecognized) falls into the catch-all rejection.
        other => Some(render_non_read_only(
            index,
            statement_kind(other),
            &other.to_string(),
        )),
    }
}

/// Judge a query statement: locking clauses, CTE bodies (recursive,
/// covering nesting), and DML variants of the body.
///
/// A data-modifying CTE (`WITH ins AS (INSERT ... RETURNING *) SELECT
/// ...`) is still a Query in sqlparser: the CTE body hangs off
/// `with.cte_tables`, and the body may also directly be a
/// `SetExpr::Insert/Update/Delete/Merge` — both must be rejected.
///
/// `cte_label` is the name of the CTE that triggered this judgment
/// (`None` for the top-level query; the CTE's alias when recursing into
/// its body); `root` is the full statement text (referenced by rejection
/// reports so the user sees the complete WITH form).
fn judge_query(index: usize, query: &Query, cte_label: Option<&str>, root: &str) -> Option<Denial> {
    if !query.locks.is_empty() {
        return Some(render_locking_clause(index, root));
    }
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            // A CTE body is a full Query: recursively apply the same
            // judgment (including its own with and body, naturally
            // covering nested data-modifying CTEs), passing the CTE name
            // down.
            if let Some(denial) =
                judge_query(index, &cte.query, Some(cte.alias.name.value.as_str()), root)
            {
                return Some(denial);
            }
        }
    }
    match query.body.as_ref() {
        SetExpr::Insert(stmt)
        | SetExpr::Update(stmt)
        | SetExpr::Delete(stmt)
        | SetExpr::Merge(stmt) => Some(render_data_modifying_cte(
            index,
            cte_label.unwrap_or(""),
            statement_kind(stmt),
            root,
        )),
        // Select / Query / SetOperation / Values / Table: read-only forms
        // are allowed (deeper nodes of subqueries and set operations are
        // covered for non-read-only forms by the statement-level
        // catch-all rejection).
        _ => None,
    }
}

/// Categorize a rejected statement into an English kind description for
/// error messages.
fn statement_kind(statement: &Statement) -> &'static str {
    match statement {
        Statement::Insert { .. } => "DML",
        Statement::Update { .. } => "DML",
        Statement::Delete { .. } => "DML",
        Statement::Merge { .. } => "DML",
        Statement::CreateTable { .. }
        | Statement::CreateIndex { .. }
        | Statement::CreateView { .. }
        | Statement::CreateSchema { .. }
        | Statement::CreateFunction { .. }
        | Statement::CreateProcedure { .. } => "DDL",
        Statement::AlterTable { .. } => "DDL",
        Statement::Drop { .. } => "DDL",
        Statement::Truncate { .. } => "DDL",
        Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. } => "transaction control",
        Statement::Grant { .. } | Statement::Revoke { .. } => "privilege statement",
        Statement::Set { .. } => "session statement",
        Statement::Use { .. } => "session statement",
        Statement::Call { .. } => "procedure call",
        Statement::Copy { .. } => "COPY",
        _ => "non-read-only statement",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialect::{parse_statements, resolve_dialect};

    /// Judging helper: on parse failure, return as a ParseError Denial
    /// (matching the public entry point's behavior).
    fn judge_sql(sql: &str) -> Vec<Denial> {
        let dialect = resolve_dialect("postgres").unwrap();
        match parse_statements(&dialect, sql) {
            Ok(statements) => judge_statements(&statements),
            // unwrap is used only for error construction inside tests
            // (this function cannot fail), a sanctioned exception.
            Err(e) => vec![e.into_denial()],
        }
    }

    #[test]
    fn test_allows_plain_select_with_common_clauses() {
        assert!(
            judge_sql(
                "SELECT o.id, c.name FROM orders o JOIN customers c ON o.customer_id = c.id \
             WHERE o.created_at >= '2026-01-01' GROUP BY c.name ORDER BY o.id LIMIT 10"
            )
            .is_empty()
        );
    }

    #[test]
    fn test_allows_cte_setops_and_values() {
        assert!(
            judge_sql("WITH recent AS (SELECT * FROM orders) SELECT count(*) FROM recent")
                .is_empty()
        );
        assert!(judge_sql("SELECT 1 UNION SELECT 2 EXCEPT SELECT 3").is_empty());
        assert!(judge_sql("SELECT * FROM (VALUES (1),(2)) t").is_empty());
    }

    #[test]
    fn test_rejects_forbidden_functions_in_any_expression_position() {
        // Blacklisted functions: projections / WHERE / inside function
        // arguments / subqueries / CTE bodies / EXPLAIN.
        for sql in [
            "SELECT pg_advisory_lock(1)",
            "SELECT pg_try_advisory_lock(1, 2)",
            "SELECT 1 FROM t WHERE pg_advisory_lock(1) IS NOT NULL",
            "SELECT length(pg_terminate_backend(pg_backend_pid()))",
            "SELECT * FROM (SELECT pg_cancel_backend(123) AS x) sub",
            "WITH c AS (SELECT pg_reload_conf() AS r) SELECT * FROM c",
            "EXPLAIN SELECT set_config('search_path', 'evil', false)",
            "SELECT pg_catalog.pg_advisory_lock(7)",
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
    fn test_allows_safe_function_regressions() {
        // Transaction-scoped locks (released with the statement), unlock
        // cleanup, sleep (bounded by the timeout), and normal functions
        // are allowed.
        assert!(judge_sql("SELECT pg_advisory_xact_lock(1)").is_empty());
        assert!(judge_sql("SELECT pg_advisory_unlock(1)").is_empty());
        assert!(judge_sql("SELECT pg_sleep(2)").is_empty());
        assert!(judge_sql("SELECT avg(x), count(*) FROM t GROUP BY 1").is_empty());
        assert!(judge_sql("SELECT repeat('A', 10)").is_empty());
        assert!(judge_sql("SELECT * FROM pg_advisory_locks WHERE lockid = 1").is_empty());
    }

    #[test]
    fn test_rejects_quoted_function_name_bypass() {
        // Delimited identifier forms (quoted / uppercase / mixed) hit
        // the blacklist the same as bare names.
        for sql in [
            r#"SELECT "pg_advisory_lock"(990101)"#,
            r#"SELECT "PG_ADVISORY_LOCK"(1)"#,
            r#"SELECT "Set_Config"('a', 'b', false)"#,
            r#"SELECT "setval"('s', 1)"#,
        ] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "{sql}");
            assert_eq!(
                denials[0].category,
                crate::RejectCategory::ForbiddenFunction,
                "{sql}"
            );
        }
        // Quoted legal functions are unaffected.
        assert!(judge_sql(r#"SELECT "length"('abc')"#).is_empty());
    }

    #[test]
    fn test_rejects_select_into_ddl_channel() {
        // SELECT ... INTO (new table / TEMP / subquery) is a DDL write
        // channel.
        for sql in [
            "SELECT 1 AS c INTO zz_escape_test",
            "SELECT 1 INTO TEMP zz_t",
            "SELECT c INTO zz FROM (SELECT 1 AS c) t",
        ] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "{sql}");
            assert_eq!(
                denials[0].category,
                crate::RejectCategory::NonReadOnly,
                "{sql}"
            );
            assert!(denials[0].message.contains("SELECT INTO"), "{sql}");
        }
        // Plain SELECTs are unaffected.
        assert!(judge_sql("SELECT 1 AS c").is_empty());
    }

    #[test]
    fn test_rejects_sequence_and_large_object_functions() {
        for sql in [
            "SELECT setval('migrations_id_seq', 999999)",
            "SELECT nextval('s')",
            "SELECT set_masked('s', true)",
            "SELECT lo_import('/etc/passwd')",
            "SELECT lo_unlink(1)",
            "SELECT lo_create(1)",
            "SELECT lo_export(1, '/tmp/x')",
            "SELECT lowrite(0, 'x')",
            "SELECT loread(0, 10)",
        ] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "{sql}");
            assert_eq!(
                denials[0].category,
                crate::RejectCategory::ForbiddenFunction,
                "{sql}"
            );
        }
        // currval (read-only position) and sequence catalog queries are
        // allowed.
        assert!(judge_sql("SELECT currval('s')").is_empty());
        assert!(judge_sql("SELECT last_value FROM migrations_id_seq").is_empty());
    }

    #[test]
    fn test_rejects_unicode_escape_identifier_bypass() {
        // U& delimited identifier \XXXX / \+XXXXXX escapes hit the
        // blacklist like bare names after decoding.
        for sql in [
            r#"SELECT U&"pg_advisory\005Flock"(990110)"#,
            r#"SELECT u&"set\0076al"('s', 1)"#,
            r#"SELECT U&"pg_terminate\005Fbackend"(pg_backend_pid())"#,
            // 6-digit form: \+00005F = '_'
            r#"SELECT U&"pg_advisory\+00005Flock"(1)"#,
        ] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "{sql}");
            assert_eq!(
                denials[0].category,
                crate::RejectCategory::ForbiddenFunction,
                "{sql}"
            );
        }
        // Escaped non-blacklisted functions are allowed after decoding
        // (decoding semantics correctness).
        assert!(judge_sql(r#"SELECT U&"pg\005Fsleep"(1)"#).is_empty());
    }

    #[test]
    fn test_rejects_pg_advisory_unlock_all() {
        let denials = judge_sql("SELECT pg_advisory_unlock_all()");
        assert_eq!(denials.len(), 1);
        assert_eq!(
            denials[0].category,
            crate::RejectCategory::ForbiddenFunction
        );
        // Single-key unlock (leftover cleanup) stays allowed.
        assert!(judge_sql("SELECT pg_advisory_unlock(1)").is_empty());
    }

    #[test]
    fn test_rejects_data_modifying_cte_all_dml_kinds() {
        // BUG-01 reproduction form: a CTE wrapping DML + RETURNING, with
        // an outer SELECT.
        for sql in [
            "WITH ins AS (INSERT INTO auth_user (uid, name) VALUES ('bypass', 'x') RETURNING *) SELECT * FROM ins",
            "WITH upd AS (UPDATE auth_user SET name = 'x' WHERE uid = 'y' RETURNING *) SELECT * FROM upd",
            "WITH del AS (DELETE FROM auth_user WHERE uid = 'y' RETURNING *) SELECT * FROM del",
        ] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "{sql}");
            assert_eq!(
                denials[0].category,
                crate::RejectCategory::DataModifyingCte,
                "{sql}"
            );
            assert!(denials[0].message.contains("data-modifying CTE"), "{sql}");
        }
    }

    #[test]
    fn test_rejects_nested_and_recursive_data_modifying_cte() {
        let nested = "WITH c AS (WITH d AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM d) SELECT * FROM c";
        let denials = judge_sql(nested);
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].category, crate::RejectCategory::DataModifyingCte);

        let recursive =
            "WITH RECURSIVE r AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM r";
        assert_eq!(
            judge_sql(recursive)[0].category,
            crate::RejectCategory::DataModifyingCte
        );
    }

    #[test]
    fn test_rejects_explain_wrapping_data_modifying_cte() {
        let sql = "EXPLAIN WITH ins AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM ins";
        let denials = judge_sql(sql);
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].category, crate::RejectCategory::DataModifyingCte);
    }

    #[test]
    fn test_allows_readonly_cte_regressions() {
        // Plain / multiple / nested read-only CTEs and mixed read-only
        // forms stay allowed (regression).
        assert!(judge_sql("WITH sel AS (SELECT 1) SELECT * FROM sel").is_empty());
        assert!(
            judge_sql(
                "WITH a AS (SELECT 1), b AS (SELECT 2) SELECT * FROM a UNION ALL SELECT * FROM b"
            )
            .is_empty()
        );
        assert!(
            judge_sql("WITH c AS (WITH d AS (VALUES (1)) SELECT * FROM d) SELECT * FROM c")
                .is_empty()
        );
        assert!(
            judge_sql("WITH RECURSIVE t(n) AS (VALUES (1) UNION ALL SELECT n+1 FROM t WHERE n < 5) SELECT sum(n) FROM t")
                .is_empty()
        );
        assert!(judge_sql("SELECT * FROM (WITH x AS (VALUES (1)) SELECT * FROM x) sub").is_empty());
    }

    #[test]
    fn test_allows_explain_show_and_describe() {
        assert!(judge_sql("EXPLAIN SELECT 1").is_empty());
        assert!(judge_sql("EXPLAIN ANALYZE SELECT 1").is_empty());
        assert!(judge_sql("DESCRIBE orders").is_empty());
        assert!(judge_sql("SHOW ALL").is_empty());
    }

    #[test]
    fn test_rejects_explain_over_non_read_only() {
        let denials = judge_sql("EXPLAIN DELETE FROM orders");
        assert_eq!(denials.len(), 1);
        assert_eq!(
            denials[0].category,
            crate::error::RejectCategory::NonReadOnly
        );
    }

    #[test]
    fn test_rejects_locking_clauses() {
        // sqlparser 0.63's LockType only covers FOR UPDATE / FOR SHARE;
        // both parse as locking clauses and are rejected under the
        // LockingClause category.
        for sql in ["SELECT * FROM t FOR UPDATE", "SELECT * FROM t FOR SHARE"] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "failed for {sql}");
            assert_eq!(
                denials[0].category,
                crate::error::RejectCategory::LockingClause
            );
        }
        // FOR NO KEY UPDATE / FOR KEY SHARE cannot be parsed by 0.63 and
        // fall into ParseError rejection (fail closed: never allowed
        // either way).
        for sql in [
            "SELECT * FROM t FOR NO KEY UPDATE",
            "SELECT * FROM t FOR KEY SHARE",
        ] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "failed for {sql}");
            assert_eq!(
                denials[0].category,
                crate::error::RejectCategory::ParseError
            );
        }
    }

    #[test]
    fn test_rejects_dml_ddl_transaction_privilege_copy() {
        for sql in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a = 1",
            "DELETE FROM t",
            "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = 1",
            "CREATE TABLE t (id INT)",
            "ALTER TABLE t ADD COLUMN c INT",
            "DROP TABLE t",
            "TRUNCATE TABLE t",
            "BEGIN",
            "COMMIT",
            "SAVEPOINT sp1",
            "GRANT SELECT ON t TO u",
            "REVOKE SELECT ON t FROM u",
            "SET search_path TO public",
            "CALL proc()",
        ] {
            assert_eq!(judge_sql(sql).len(), 1, "failed for {sql}");
        }
    }

    #[test]
    fn test_rejects_copy_both_directions() {
        assert_eq!(judge_sql("COPY t FROM '/tmp/data'").len(), 1);
        assert_eq!(judge_sql("COPY t TO STDOUT").len(), 1);
    }

    #[test]
    fn test_keyword_case_and_comments_do_not_affect_verdict() {
        assert!(judge_sql("select * from t").is_empty());
        assert!(judge_sql("-- comment\nSELECT 1").is_empty());
    }

    #[test]
    fn test_string_literal_keyword_not_misjudged() {
        assert!(judge_sql("SELECT 'DROP TABLE t'").is_empty());
    }

    #[test]
    fn test_multi_statement_batch_reports_all_denials() {
        let denials = judge_sql("SELECT 1; DROP TABLE t; UPDATE t SET a = 1; SELECT 2");
        assert_eq!(denials.len(), 2);
        assert_eq!(denials[0].index, 2);
        assert_eq!(denials[1].index, 3);
        for d in &denials {
            assert!(d.message.contains("Statement #"));
            assert!(d.message.contains("Statement: "));
        }
    }
}
