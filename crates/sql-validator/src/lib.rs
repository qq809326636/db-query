//! SQL syntax validation library: only read-only SELECT / EXPLAIN / SHOW /
//! metadata-viewing statements are allowed.
//!
//! As db-query's read-only security layer, any SQL must pass [`validate`] before
//! reaching database execution. Validation is based on sqlparser parsing
//! (AST-level verdicts), not keyword matching:
//!
//! - Allowed: pure queries (including CTEs / set operations / VALUES /
//!   subqueries), EXPLAIN whose inner statement is whitelisted (including
//!   ANALYZE), SHOW and DESC-style metadata viewing (sqlite includes read-only
//!   PRAGMAs);
//! - Denied: all DML / DDL / transaction-control / privilege-and-session
//!   statements, COPY (including `TO STDOUT` and MySQL's `LOAD DATA`), queries
//!   with locking clauses (`FOR UPDATE` / `FOR SHARE`, etc.), sqlite's
//!   write-shaped PRAGMAs / ATTACH / the VACUUM family, and anything that fails
//!   to parse or is unrecognized;
//! - Multi-statement batches (semicolon-separated) are judged as a whole: any
//!   denied statement denies the whole batch, reporting every denied statement
//!   (indices starting at 1).
//!
//! Multi-dialect: postgres / mysql / sqlite go through a unified skeleton, with
//! dialect differences (function blacklists, dialect-specific statement
//! handling) carried by the dialect implementations; unknown dialects fail
//! closed.
//!
//! Policy: [`Policy`] supports allow-kind subsetting (kinds, tighten only) and
//! function-blacklist appends (append only), defaulting to the built-in policy;
//! injected via [`validate_with_policy`].
//!
//! The library is purely functional: it executes no SQL, opens no database
//! connections, and has no I/O side effects.
//!
//! # Examples
//!
//! ```
//! use excapp_db_sql_validator::{validate, RejectCategory};
//!
//! // A pure query is allowed
//! assert!(validate("postgres", "SELECT count(*) FROM orders").allowed);
//!
//! // A write statement is denied, with a programmatically usable category
//! let result = validate("postgres", "UPDATE orders SET status = 'paid'");
//! assert!(!result.allowed);
//! assert_eq!(result.denials[0].category, RejectCategory::NonReadOnly);
//!
//! // An unsupported dialect is denied (fail closed)
//! assert!(!validate("oracle", "SELECT 1").allowed);
//! ```

mod common;
mod error;
mod mysql;
mod pg;
mod sqlite;

pub use common::{Policy, PolicyBuilder, StatementKind};
pub use error::{Denial, RejectCategory, ValidationResult};

use error::BatchError;
use sqlparser::ast::Statement;

/// Validate SQL: parse and judge per the `dialect` identifier (see the
/// `dialect` field in db-query's config).
///
/// Equivalent to calling [`validate_with_policy`] with the built-in policy
/// ([`Policy::default`]).
///
/// - `dialect` is case-insensitive with surrounding whitespace ignored;
///   `postgres` / `mysql` / `sqlite` are supported.
/// - The return value is always a structured [`ValidationResult`]: denial is a
///   normal business outcome, not an exception; each denial carries a
///   machine-readable category and an English explanation (full statement
///   text, never truncated).
pub fn validate(dialect: &str, sql: &str) -> ValidationResult {
    validate_with_policy(dialect, sql, &Policy::default())
}

/// Validate SQL (policy entry): tightens allow kinds / appends function
/// blacklists per `policy`.
///
/// The assembly layers (sql-mcp / cli) build a [`Policy`] from config and
/// inject it here; the default policy ([`Policy::default`]) behaves exactly
/// like [`validate`].
pub fn validate_with_policy(dialect: &str, sql: &str, policy: &Policy) -> ValidationResult {
    let result = (|| -> Result<(Vec<Statement>, &'static dyn common::DialectRule), BatchError> {
        let rule = common::resolve_rule(dialect)?;
        let statements = common::parse_statements(rule.parser(), sql)?;
        Ok((statements, rule))
    })();

    match result {
        Err(batch_error) => ValidationResult::denied(vec![batch_error.into_denial()]),
        Ok((statements, rule)) => {
            let denials = common::judge_statements(&statements, rule, policy);
            ValidationResult::denied(denials)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_end_to_end_allow() {
        let result = validate("postgres", "SELECT 1");
        assert!(result.allowed);
        assert!(result.denials.is_empty());
    }

    #[test]
    fn test_validate_end_to_end_deny_with_category() {
        let result = validate("postgres", "DROP TABLE t");
        assert!(!result.allowed);
        assert_eq!(result.denials.len(), 1);
        assert_eq!(result.denials[0].category, RejectCategory::NonReadOnly);
        assert_eq!(result.denials[0].index, 1);
    }

    #[test]
    fn test_validate_unsupported_dialect() {
        let result = validate("oracle", "SELECT 1");
        assert!(!result.allowed);
        assert_eq!(
            result.denials[0].category,
            RejectCategory::UnsupportedDialect
        );
        assert!(
            result.denials[0]
                .message
                .contains("Supported dialects: postgres, mysql, sqlite")
        );
    }

    #[test]
    fn test_validate_empty_input_and_parse_error() {
        let result = validate("postgres", "   ");
        assert!(!result.allowed);
        assert_eq!(result.denials[0].category, RejectCategory::EmptyInput);

        let result = validate("postgres", "SELCT 1 FROM");
        assert!(!result.allowed);
        assert_eq!(result.denials[0].category, RejectCategory::ParseError);
    }

    #[test]
    fn test_validate_mysql_and_sqlite_end_to_end() {
        // mysql: backquoted queries allowed, session locks denied.
        assert!(validate("mysql", "SELECT `id` FROM `t`").allowed);
        let result = validate("mysql", "SELECT GET_LOCK('k', 1)");
        assert_eq!(
            result.denials[0].category,
            RejectCategory::ForbiddenFunction
        );

        // sqlite: read-only PRAGMAs allowed, write-shaped ones denied.
        assert!(validate("sqlite", "PRAGMA table_info('t')").allowed);
        // The keyword-value form (= WAL) lands in ParseError; the numeric
        // assignment form is denied under the Pragma category.
        assert_eq!(
            validate("sqlite", "PRAGMA journal_mode = WAL").denials[0].category,
            RejectCategory::ParseError
        );
        let result = validate("sqlite", "PRAGMA user_version = 2");
        assert_eq!(result.denials[0].category, RejectCategory::NonReadOnly);
        assert!(result.denials[0].message.contains("pragma statement"));
    }

    #[test]
    fn test_validate_with_policy_restricts_kinds() {
        // After tightening EXPLAIN: EXPLAIN is denied (PolicyRestricted), SELECT
        // is unaffected.
        let policy = Policy::builder()
            .allow_kinds(&[
                StatementKind::Query,
                StatementKind::Show,
                StatementKind::Describe,
            ])
            .unwrap()
            .build();
        let result = validate_with_policy("postgres", "EXPLAIN SELECT 1", &policy);
        assert!(!result.allowed);
        assert_eq!(result.denials[0].category, RejectCategory::PolicyRestricted);
        assert!(result.denials[0].message.contains("EXPLAIN"));

        assert!(validate_with_policy("postgres", "SELECT 1", &policy).allowed);

        // The default policy = the built-in full set (EXPLAIN allowed).
        assert!(validate("postgres", "EXPLAIN SELECT 1").allowed);
    }

    #[test]
    fn test_validate_with_policy_appends_function_blacklist() {
        // Appended entries apply per dialect: after pg appends my_func it hits;
        // the sqlite path is unaffected.
        let policy = Policy::builder()
            .extend_fn_blacklist("postgres", ["my_func"])
            .unwrap()
            .build();
        let result = validate_with_policy("postgres", "SELECT my_func(1)", &policy);
        assert_eq!(
            result.denials[0].category,
            RejectCategory::ForbiddenFunction
        );
        assert!(validate_with_policy("sqlite", "SELECT my_func(1)", &policy).allowed);

        // Built-in entries cannot be removed by policy (no removal API; still
        // denied by default).
        assert!(!validate("postgres", "SELECT pg_advisory_lock(1)").allowed);
    }
}
