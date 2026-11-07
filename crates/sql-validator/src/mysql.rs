//! MySQL dialect implementation: blacklist entries, dialect-specific variant
//! classification and name normalization.
//!
//! The security baseline aligns with the four rounds of PG hardening: session
//! locks, administrative and resource-consuming functions, and write-channel
//! statements are all denied, while metadata viewing is allowed; verdicts reuse
//! the common skeleton (locking clauses / SELECT INTO / data-modifying CTEs are
//! handled generically by the skeleton).

use crate::common::{DialectRule, StatementKind};
use sqlparser::ast::Statement;
use sqlparser::dialect::{Dialect, MySqlDialect};

/// Static MySQL parse dialect instance.
static MY_DIALECT: MySqlDialect = MySqlDialect {};

/// MySQL function blacklist: session locks (the GET_LOCK family persists across
/// statements on pooled connections), resource consumption (SLEEP has no
/// function-level timeout fallback — max_execution_time only constrains the
/// execution phase of SELECT; BENCHMARK burns CPU), and the file read channel
/// (LOAD_FILE).
const FUNCTION_BLACKLIST: &[&str] = &[
    // Session locks (mirrors the PG advisory-lock baseline)
    "get_lock",
    "release_lock",
    "release_all_locks",
    "is_free_lock",
    "is_used_lock",
    // Administrative and resource consumption (mirrors the PG admin-function baseline)
    "sleep",
    "benchmark",
    // File read channel
    "load_file",
];

/// MySQL dialect rule (stateless static instance).
pub(crate) struct MyRule;

impl DialectRule for MyRule {
    fn id(&self) -> &'static str {
        "mysql"
    }

    fn parser(&self) -> &'static dyn Dialect {
        &MY_DIALECT
    }

    fn function_blacklist(&self) -> &'static [&'static str] {
        FUNCTION_BLACKLIST
    }

    fn normalize_function_name(&self, raw: &str) -> String {
        // After sqlparser parses, Ident.value is already unquoted (backticks /
        // double quotes); MySQL has no U& escape form, so only lowercase
        // normalization applies.
        raw.to_lowercase()
    }

    fn classify(&self, statement: &Statement) -> Option<StatementKind> {
        match statement {
            // LOAD DATA / LOAD XML: file-import write channels, reusing the COPY channel category.
            Statement::LoadData { .. } => Some(StatementKind::Copy),
            // LOCK / UNLOCK TABLES: table-level lock statements (parsed by the MySQL dialect extension).
            Statement::LockTables { .. } => Some(StatementKind::Other),
            // SHOW CHARACTER SET / SHOW CHARSET: MySQL-specific Show variants.
            Statement::ShowCharset { .. } => Some(StatementKind::Show),
            // Remaining variants (KILL / FLUSH / SET PASSWORD, etc.) fall into
            // the catch-all Other category, matching how PG treats unlisted
            // variants (fail closed).
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{Policy, judge_statements, parse_statements, resolve_rule};
    use crate::error::Denial;

    /// Verdict helper (mysql path, default policy).
    fn judge_sql(sql: &str) -> Vec<Denial> {
        let rule = resolve_rule("mysql").unwrap();
        match parse_statements(rule.parser(), sql) {
            Ok(statements) => judge_statements(&statements, rule, &Policy::default()),
            Err(e) => vec![e.into_denial()],
        }
    }

    #[test]
    fn test_allows_mysql_select_with_backtick_identifiers() {
        assert!(judge_sql("SELECT `id`, `name` FROM `orders` WHERE `id` > 10").is_empty());
        assert!(judge_sql("SELECT 1 UNION SELECT 2").is_empty());
        assert!(judge_sql("WITH c AS (SELECT 1) SELECT * FROM c").is_empty());
    }

    #[test]
    fn test_mysql_accepts_pg_cast_syntax() {
        // MySqlDialect accepts `::` casts (verified): routed to the generic Query
        // verdict, dialect-agnostic.
        assert!(judge_sql("SELECT 1::text").is_empty());
    }

    #[test]
    fn test_rejects_session_lock_functions() {
        for sql in [
            "SELECT GET_LOCK('k', 10)",
            "SELECT RELEASE_LOCK('k')",
            "SELECT RELEASE_ALL_LOCKS()",
            "SELECT IS_FREE_LOCK('k')",
            "SELECT IS_USED_LOCK('k')",
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
    fn test_rejects_dangerous_functions_with_identifier_variants() {
        // Backquoted and mixed-case names hit the same as bare names (double
        // quotes are string literals in MySQL, parsed as constants rather than
        // functions — not a bypass surface).
        for sql in [
            "SELECT SLEEP(5)",
            "SELECT sleep(5)",
            "SELECT `SLEEP`(5)",
            "SELECT `benchmark`(1000000, MD5('x'))",
            "SELECT Load_File('/etc/passwd')",
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
    fn test_load_data_fails_to_parse() {
        // LOAD DATA: sqlparser 0.63 does not enable supports_load_data for
        // MySqlDialect, so parsing fails with a ParseError (fail closed).
        let denials = judge_sql("LOAD DATA INFILE '/tmp/data' INTO TABLE t");
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].category, crate::RejectCategory::ParseError);

        // LOCK / UNLOCK TABLES: reachable via the MySQL dialect extension; denied.
        assert_eq!(judge_sql("LOCK TABLES t READ").len(), 1);
        assert_eq!(judge_sql("UNLOCK TABLES").len(), 1);
    }

    #[test]
    fn test_allows_show_desc_and_explain() {
        // SHOW family (MySQL forms) is allowed.
        assert!(judge_sql("SHOW DATABASES").is_empty());
        assert!(judge_sql("SHOW TABLES").is_empty());
        assert!(judge_sql("SHOW FULL COLUMNS FROM t").is_empty());
        assert!(judge_sql("SHOW VARIABLES LIKE 'max%'").is_empty());
        assert!(judge_sql("SHOW CHARACTER SET").is_empty());
        // DESC / DESCRIBE: same semantics as EXPLAIN — allowed when followed by a table name.
        assert!(judge_sql("DESC t").is_empty());
        assert!(judge_sql("DESCRIBE t").is_empty());
        // EXPLAIN: recursive generic verdict on the inner statement.
        assert!(judge_sql("EXPLAIN SELECT 1").is_empty());
    }

    #[test]
    fn test_desc_following_query_recurses_like_explain() {
        // DESC followed by a query: same treatment as EXPLAIN (requirement revision #1).
        assert!(judge_sql("DESC SELECT 1").is_empty());
        let denials = judge_sql("DESC DELETE FROM t");
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].category, crate::RejectCategory::NonReadOnly);
    }

    #[test]
    fn test_rejects_locking_clause_and_data_modifying_cte() {
        // Baselines carried by the common skeleton apply equally on the mysql path.
        let denials = judge_sql("SELECT * FROM t FOR UPDATE");
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].category, crate::RejectCategory::LockingClause);

        let denials = judge_sql("WITH ins AS (INSERT INTO t VALUES (1)) SELECT * FROM ins");
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].category, crate::RejectCategory::DataModifyingCte);
    }

    #[test]
    fn test_rejects_dml_ddl_session() {
        for sql in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a = 1",
            "DELETE FROM t",
            "CREATE TABLE t (id INT)",
            "DROP TABLE t",
            "TRUNCATE TABLE t",
            "START TRANSACTION",
            "SET @x = 1",
            "CALL proc()",
        ] {
            assert_eq!(judge_sql(sql).len(), 1, "failed for {sql}");
        }
    }
}
