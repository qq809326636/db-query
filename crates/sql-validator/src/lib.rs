//! SQL syntax validation library: only read-only SELECT / EXPLAIN / SHOW /
//! metadata-viewing statements are allowed.
//!
//! As the read-only safety layer of db-query, any SQL must pass
//! [`validate`] before entering database execution. Validation is based
//! on sqlparser syntax parsing (AST-level judging) rather than keyword
//! matching:
//!
//! - Allowed: pure queries (including CTEs / set operations / VALUES /
//!   subqueries), EXPLAIN (including ANALYZE) whose inner statement is
//!   whitelisted, and SHOW / DESC-style metadata viewing;
//! - Rejected: all DML / DDL / transaction control / privilege and session
//!   statements, COPY (including `TO STDOUT`), queries with locking
//!   clauses (`FOR UPDATE` / `FOR SHARE`, etc.), and statements that fail
//!   to parse or are unrecognized;
//! - Multi-statement batches (semicolon-separated) are judged as a whole:
//!   any rejected statement rejects the entire batch, reporting every
//!   rejected statement individually (numbered from 1).
//!
//! The library is pure-function behavior: it executes no SQL, opens no
//! database connections, and has no I/O side effects.
//!
//! # Examples
//!
//! ```
//! use excapp_db_sql_validator::{validate, RejectCategory};
//!
//! // A pure query is allowed
//! assert!(validate("postgres", "SELECT count(*) FROM orders").allowed);
//!
//! // A write statement is rejected; the category is programmatically
//! // checkable
//! let result = validate("postgres", "UPDATE orders SET status = 'paid'");
//! assert!(!result.allowed);
//! assert_eq!(result.denials[0].category, RejectCategory::NonReadOnly);
//!
//! // An unsupported dialect is rejected (fail closed)
//! assert!(!validate("oracle", "SELECT 1").allowed);
//! ```

mod dialect;
mod error;
mod whitelist;

pub use error::{Denial, RejectCategory, ValidationResult};

use error::BatchError;

/// Validate SQL: parse and judge by the `dialect` identifier (see the
/// `dialect` field in the db-query config).
///
/// - `dialect` is case-insensitive with surrounding whitespace ignored;
///   the first supported dialect is `postgres`.
/// - The return value is always a structured [`ValidationResult`]:
///   rejection is a normal business outcome rather than an exception, and
///   each denial carries a machine-readable category and an English
///   message (full statement text, never truncated).
pub fn validate(dialect: &str, sql: &str) -> ValidationResult {
    let result = (|| -> Result<Vec<sqlparser::ast::Statement>, BatchError> {
        let resolved = dialect::resolve_dialect(dialect)?;
        let statements = dialect::parse_statements(&resolved, sql)?;
        Ok(statements)
    })();

    match result {
        Err(batch_error) => ValidationResult::denied(vec![batch_error.into_denial()]),
        Ok(statements) => {
            let denials = whitelist::judge_statements(&statements);
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
        let result = validate("mysql", "SELECT 1");
        assert!(!result.allowed);
        assert_eq!(
            result.denials[0].category,
            RejectCategory::UnsupportedDialect
        );
        assert!(
            result.denials[0]
                .message
                .contains("Supported dialects: postgres")
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
}
