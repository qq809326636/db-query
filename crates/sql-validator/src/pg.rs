//! PostgreSQL dialect implementation: blacklist entries, U& escape
//! normalization and PG-specific variant classification.
//!
//! Verdict outcomes accumulated over four rounds of security hardening
//! (advisory-lock family / large-object channels / administrative and
//! sequence functions / U& escape decoding) live in this module; entries are
//! append-only (config can only add).

use crate::common::{DialectRule, StatementKind};
use sqlparser::ast::Statement;
use sqlparser::dialect::{Dialect, PostgreSqlDialect};

/// Static PG parse dialect instance.
static PG_DIALECT: PostgreSqlDialect = PostgreSqlDialect {};

/// PG function blacklist: session-level advisory locks (persist across requests
/// on pooled connections, enabling DoS against business lock mechanisms),
/// server-side administrative functions (terminate/cancel backends, reload
/// config, change session parameters), sequence position modification
/// (persistent state corruption), and large-object read/write channels.
///
/// Allowed: `pg_advisory_xact_lock` (transaction-scoped, released when the
/// statement ends), `pg_advisory_unlock` (lock cleanup), `pg_sleep`
/// (statement_timeout as the session-level fallback), and `currval` (read-only
/// position query, no consumption).
const FUNCTION_BLACKLIST: &[&str] = &[
    // Session-level advisory locks
    "pg_advisory_lock",
    "pg_try_advisory_lock",
    "pg_advisory_unlock_all",
    // Server-side administration
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_reload_conf",
    "set_config",
    // Sequence position modification (persistent state)
    "setval",
    "nextval",
    "set_masked",
    // Large-object read/write channels (full family)
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

/// PostgreSQL dialect rule (stateless static instance).
pub(crate) struct PgRule;

impl DialectRule for PgRule {
    fn id(&self) -> &'static str {
        "postgres"
    }

    fn parser(&self) -> &'static dyn Dialect {
        &PG_DIALECT
    }

    fn function_blacklist(&self) -> &'static [&'static str] {
        FUNCTION_BLACKLIST
    }

    fn normalize_function_name(&self, raw: &str) -> String {
        decode_unicode_escapes(raw).to_lowercase()
    }

    fn classify(&self, _statement: &Statement) -> Option<StatementKind> {
        // PG has no dialect-specific variants to map: PRAGMA / ATTACH / VACUUM
        // (forms parseable under the postgres dialect) and unrecognized variants
        // all fall into the catch-all Other ("non-read-only statement"),
        // consistent with existing behavior.
        None
    }
}

/// Decode Unicode escapes inside a quoted identifier (PG U&"..." semantics).
///
/// - `\XXXX` (4 hex digits) and `\+XXXXXX` (6 digits) are decoded and
///   replaced as chars;
/// - `\\` decodes to a literal `\`;
/// - Invalid escape sequences are kept as-is (conservative: they naturally
///   miss the blacklist, matching the PG server behavior of rejecting invalid
///   escapes outright).
///
/// sqlparser does not support U& quoted identifiers, so `Ident.value` keeps the
/// raw `\005F` escape text; it must be decoded before blacklist comparison,
/// otherwise escaped forms could bypass.
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
        // Backslash escape
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
        // Invalid escape: keep the backslash and the following characters as-is.
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

// ---- Zero-regression tests for the PG path (suite migrated from the former
// ---- validator modules) ----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{Policy, judge_statements, parse_statements, resolve_rule};
    use crate::error::Denial;

    /// Verdict helper: parse failures return as a ParseError Denial (matching
    /// the public entry point); the policy is the default (built-in) one.
    fn judge_sql(sql: &str) -> Vec<Denial> {
        let rule = resolve_rule("postgres").unwrap();
        match parse_statements(rule.parser(), sql) {
            Ok(statements) => judge_statements(&statements, rule, &Policy::default()),
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
        // Blacklisted functions: projections / WHERE / inside function arguments /
        // subqueries / CTE bodies / EXPLAIN.
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
        // Transaction-scoped locks (released with the statement), unlock cleanup,
        // the timeout-fallback sleep, and ordinary functions are allowed.
        assert!(judge_sql("SELECT pg_advisory_xact_lock(1)").is_empty());
        assert!(judge_sql("SELECT pg_advisory_unlock(1)").is_empty());
        assert!(judge_sql("SELECT pg_sleep(2)").is_empty());
        assert!(judge_sql("SELECT avg(x), count(*) FROM t GROUP BY 1").is_empty());
        assert!(judge_sql("SELECT repeat('A', 10)").is_empty());
        assert!(judge_sql("SELECT * FROM pg_advisory_locks WHERE lockid = 1").is_empty());
    }

    #[test]
    fn test_rejects_quoted_function_name_bypass() {
        // Quoted identifier forms (quoted / uppercase / mixed) hit the blacklist the same as bare names.
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
        // Quoted legitimate functions are unaffected.
        assert!(judge_sql(r#"SELECT "length"('abc')"#).is_empty());
    }

    #[test]
    fn test_rejects_select_into_ddl_channel() {
        // SELECT ... INTO (new table / TEMP / subquery) is a DDL write channel.
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
        // Ordinary SELECTs are unaffected.
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
        // currval (read-only position) and sequence catalog queries are allowed.
        assert!(judge_sql("SELECT currval('s')").is_empty());
        assert!(judge_sql("SELECT last_value FROM migrations_id_seq").is_empty());
    }

    #[test]
    fn test_rejects_unicode_escape_identifier_bypass() {
        // U& quoted-identifier escapes (\XXXX / \+XXXXXX) hit the same as bare names after decoding.
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
        // Escaped non-blacklisted functions are allowed after decoding (decoding semantics correctness).
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
        // Single-key unlock (residue cleanup) stays allowed.
        assert!(judge_sql("SELECT pg_advisory_unlock(1)").is_empty());
    }

    #[test]
    fn test_rejects_data_modifying_cte_all_dml_kinds() {
        // BUG-01 reproduction shape: CTE wrapping DML + RETURNING with an outer SELECT.
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
        // Ordinary / multiple / nested read-only CTEs and mixed read-only shapes
        // remain allowed (regression).
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
        // sqlparser 0.63's LockType only covers FOR UPDATE / FOR SHARE; both
        // parse as locking clauses and are denied under the LockingClause category.
        for sql in ["SELECT * FROM t FOR UPDATE", "SELECT * FROM t FOR SHARE"] {
            let denials = judge_sql(sql);
            assert_eq!(denials.len(), 1, "failed for {sql}");
            assert_eq!(
                denials[0].category,
                crate::error::RejectCategory::LockingClause
            );
        }
        // FOR NO KEY UPDATE / FOR KEY SHARE cannot be parsed by 0.63 and fall
        // into a ParseError denial (fail closed: never allowed either way).
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

    #[test]
    fn test_error_messages_keep_exact_legacy_texts() {
        // Denial message text is zero-regression (category wording and full statement text).
        let denials = judge_sql("DROP TABLE t");
        assert_eq!(
            denials[0].message,
            "Statement #1 is not read-only (DDL); only SELECT/EXPLAIN/SHOW/metadata queries are allowed. Statement: DROP TABLE t"
        );
        let denials = judge_sql("SELECT * FROM t FOR UPDATE");
        assert!(
            denials[0]
                .message
                .contains("uses a locking clause (FOR UPDATE/FOR SHARE), which is not allowed")
        );
    }

    #[test]
    fn test_pg_classify_falls_back_to_other() {
        // PRAGMA / ATTACH / VACUUM forms parseable under the postgres dialect
        // fall into the catch-all Other via pg.classify (None) — consistent with
        // existing behavior.
        let rule = crate::common::resolve_rule("postgres").unwrap();
        let stmts = parse_statements(rule.parser(), "PRAGMA foo").unwrap();
        // PRAGMA parses under the postgres dialect (no gating) and falls into the catch-all denial.
        assert_eq!(stmts.len(), 1);
        let denials = judge_statements(&stmts, rule, &Policy::default());
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].category, crate::RejectCategory::NonReadOnly);
        assert!(denials[0].message.contains("non-read-only statement"));
    }

    #[test]
    fn test_decode_unicode_escapes_units() {
        assert_eq!(decode_unicode_escapes("plain"), "plain");
        assert_eq!(decode_unicode_escapes("pg\\005Flock"), "pg_lock");
        assert_eq!(decode_unicode_escapes("pg\\+00005Flock"), "pg_lock");
        assert_eq!(decode_unicode_escapes("a\\\\b"), "a\\b");
        // Invalid escapes are kept as-is.
        assert_eq!(decode_unicode_escapes("bad\\zz"), "bad\\zz");
    }
}
