//! Dialect resolution: normalize and map the dialect identifier and run
//! SQL parsing.
//!
//! The sqlparser dialect is selected by the `dialect` string configured in
//! db-query; empty / unknown identifiers and parse failures are all
//! rejected via [`BatchError`], never panicking.

use crate::error::BatchError;
use sqlparser::ast::Statement;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// Resolve the dialect identifier into a sqlparser dialect instance.
///
/// - The identifier is case-insensitive with surrounding whitespace
///   ignored (`Postgres` / ` postgres ` both work).
/// - An empty identifier returns [`BatchError::EmptyDialect`]; an unknown
///   identifier returns [`BatchError::UnsupportedDialect`] (the English
///   message includes the supported list).
pub(crate) fn resolve_dialect(identifier: &str) -> Result<PostgreSqlDialect, BatchError> {
    let normalized = identifier.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "postgres" => Ok(PostgreSqlDialect {}),
        "" => Err(BatchError::EmptyDialect),
        other => Err(BatchError::UnsupportedDialect(other.to_string())),
    }
}

/// Parse SQL text into a list of statements using the dialect.
///
/// - Parse failure: the parser error (with line/column position) is
///   passed through as [`BatchError::Parse`].
/// - Parsing succeeds but the statement list is empty (empty string /
///   semicolons only / comments only): [`BatchError::EmptyInput`].
pub(crate) fn parse_statements(
    dialect: &PostgreSqlDialect,
    sql: &str,
) -> Result<Vec<Statement>, BatchError> {
    let statements =
        Parser::parse_sql(dialect, sql).map_err(|e| BatchError::Parse(e.to_string()))?;
    if statements.is_empty() {
        return Err(BatchError::EmptyInput);
    }
    Ok(statements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_dialect_postgres_case_insensitive() {
        for id in ["postgres", "Postgres", "POSTGRES", "  postgres  "] {
            assert!(resolve_dialect(id).is_ok(), "failed for {id:?}");
        }
    }

    #[test]
    fn test_resolve_dialect_rejects_empty() {
        let err = resolve_dialect("").unwrap_err();
        assert!(matches!(err, BatchError::EmptyDialect));
        assert!(err.to_string().contains("Supported dialects"));
    }

    #[test]
    fn test_resolve_dialect_rejects_unknown() {
        let err = resolve_dialect("oracle").unwrap_err();
        match err {
            BatchError::UnsupportedDialect(ref raw) => assert_eq!(raw, "oracle"),
            other => panic!("unexpected: {other:?}"),
        }
        assert!(err.to_string().contains("Supported dialects: postgres"));
    }

    #[test]
    fn test_parse_statements_parses_postgres_cast_syntax() {
        let dialect = resolve_dialect("postgres").unwrap();
        let stmts = parse_statements(&dialect, "SELECT 1::text").unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn test_parse_statements_rejects_syntax_error() {
        let dialect = resolve_dialect("postgres").unwrap();
        let err = parse_statements(&dialect, "SELCT 1 FROM").unwrap_err();
        assert!(matches!(err, BatchError::Parse(_)));
        assert!(err.to_string().contains("Failed to parse SQL"));
    }

    #[test]
    fn test_parse_statements_rejects_empty_input() {
        let dialect = resolve_dialect("postgres").unwrap();
        for sql in ["", "   ", ";", "-- just a comment\n"] {
            let err = parse_statements(&dialect, sql).unwrap_err();
            assert!(matches!(err, BatchError::EmptyInput), "failed for {sql:?}");
        }
    }
}
