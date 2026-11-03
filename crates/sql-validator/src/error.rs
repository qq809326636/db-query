//! Validation result contract: public allow/deny result types and English
//! error message rendering.
//!
//! Rejection is a normal business outcome (not an exception): the public
//! API returns [`ValidationResult`], where each denial carries a
//! machine-readable category ([`RejectCategory`]) and a stable English
//! message. Message templates live in this module; the judging module is
//! unaware of English wording.

use std::fmt;

/// Machine-readable category of a validation rejection.
///
/// Adding or removing variants is a breaking change, reflected in the
/// crate version number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectCategory {
    /// The dialect identifier is empty or not in the supported list.
    UnsupportedDialect,
    /// SQL syntax parsing failed.
    ParseError,
    /// The input is empty or contains no statements (empty string /
    /// semicolons only / comments only).
    EmptyInput,
    /// The statement is not on the read-only whitelist (DML / DDL /
    /// transaction control / privilege & session / COPY / unrecognized).
    NonReadOnly,
    /// The query carries a locking clause (FOR UPDATE / FOR SHARE).
    LockingClause,
    /// The query contains a data-modifying CTE (INSERT/UPDATE/DELETE/MERGE
    /// inside WITH).
    DataModifyingCte,
    /// An expression calls a blacklisted function (session-level advisory
    /// locks / server administration functions).
    ForbiddenFunction,
}

impl RejectCategory {
    /// Short English name of the category, for logging and debugging.
    pub fn as_str(self) -> &'static str {
        match self {
            RejectCategory::UnsupportedDialect => "unsupported dialect",
            RejectCategory::ParseError => "parse error",
            RejectCategory::EmptyInput => "empty input",
            RejectCategory::NonReadOnly => "not read-only",
            RejectCategory::LockingClause => "locking clause",
            RejectCategory::DataModifyingCte => "data-modifying CTE",
            RejectCategory::ForbiddenFunction => "forbidden function",
        }
    }
}

impl fmt::Display for RejectCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Report of a single rejected statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// Statement number, 1-based within a multi-statement batch;
    /// batch-level errors (dialect / parsing / empty input) use 1.
    pub index: usize,
    /// Rejection category.
    pub category: RejectCategory,
    /// Stable English message, including the full rejected statement
    /// text (never truncated).
    pub message: String,
}

/// Validation result: `allowed` is always equivalent to `denials` being
/// empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    /// True when every statement is on the whitelist.
    pub allowed: bool,
    /// Per-statement denial reports; statements that pass do not appear.
    pub denials: Vec<Denial>,
}

impl ValidationResult {
    /// Construct an allowed result (no denials).
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            denials: Vec::new(),
        }
    }

    /// Construct a denied result; `allowed` is derived from whether
    /// `denials` is empty, so the two can never contradict.
    pub fn denied(denials: Vec<Denial>) -> Self {
        Self {
            allowed: denials.is_empty(),
            denials,
        }
    }
}

/// Internal error type for batch-level failures (dialect / parsing /
/// empty input), ultimately rendered into [`ValidationResult`].
///
/// `Display` always goes through [`BatchError::render`], the stable
/// English wording facing callers.
#[derive(Debug, thiserror::Error)]
#[error("{}", self.render())]
pub(crate) enum BatchError {
    /// The dialect identifier is empty.
    EmptyDialect,
    /// The dialect identifier is not in the supported list; `0` is the
    /// raw identifier.
    UnsupportedDialect(String),
    /// SQL parsing failed; `0` is the parser error message (with
    /// position).
    Parse(String),
    /// The input contains no statements.
    EmptyInput,
}

impl BatchError {
    fn category(&self) -> RejectCategory {
        match self {
            BatchError::EmptyDialect | BatchError::UnsupportedDialect(_) => {
                RejectCategory::UnsupportedDialect
            }
            BatchError::Parse(_) => RejectCategory::ParseError,
            BatchError::EmptyInput => RejectCategory::EmptyInput,
        }
    }

    /// Render into the public English message (stable wording, no
    /// nondeterministic content such as timestamps).
    ///
    /// The `Display` impl of this type (thiserror-derived) is only for
    /// internal logs; the wording facing callers is defined by this
    /// method.
    fn render(&self) -> String {
        match self {
            BatchError::EmptyDialect => {
                "Dialect identifier is empty. Supported dialects: postgres.".to_string()
            }
            BatchError::UnsupportedDialect(raw) => {
                format!("Unsupported dialect '{raw}'. Supported dialects: postgres.")
            }
            BatchError::Parse(detail) => {
                format!("Failed to parse SQL: {detail}.")
            }
            BatchError::EmptyInput => "SQL input is empty or contains no statements.".to_string(),
        }
    }

    /// Convert into a public denial report (batch-level errors use index 1).
    pub(crate) fn into_denial(self) -> Denial {
        Denial {
            index: 1,
            category: self.category(),
            message: self.render(),
        }
    }
}

/// Render the English message for a single not-read-only rejection.
pub(crate) fn render_non_read_only(index: usize, kind: &str, statement: &str) -> Denial {
    Denial {
        index,
        category: RejectCategory::NonReadOnly,
        message: format!(
            "Statement #{index} is not read-only ({kind}); only SELECT/EXPLAIN/SHOW/metadata queries are allowed. Statement: {statement}"
        ),
    }
}

/// Render the English message for a single locking-clause rejection.
pub(crate) fn render_locking_clause(index: usize, statement: &str) -> Denial {
    Denial {
        index,
        category: RejectCategory::LockingClause,
        message: format!(
            "Statement #{index} uses a locking clause (FOR UPDATE/FOR SHARE), which is not allowed. Statement: {statement}"
        ),
    }
}

/// Render the English message for a single data-modifying CTE rejection.
///
/// `cte` is the CTE name (alias), `kind` is the statement category inside
/// it (e.g. DML), and `statement` is the full rejected statement text.
pub(crate) fn render_data_modifying_cte(
    index: usize,
    cte: &str,
    kind: &str,
    statement: &str,
) -> Denial {
    Denial {
        index,
        category: RejectCategory::DataModifyingCte,
        message: format!(
            "Statement #{index} contains a data-modifying CTE '{cte}' ({kind}); CTEs that modify data (INSERT/UPDATE/DELETE/MERGE) are not allowed. Statement: {statement}"
        ),
    }
}

/// Render the English message for a single forbidden-function rejection.
///
/// `function` is the matched function name (normalized to lowercase),
/// and `statement` is the full rejected statement text.
pub(crate) fn render_forbidden_function(index: usize, function: &str, statement: &str) -> Denial {
    Denial {
        index,
        category: RejectCategory::ForbiddenFunction,
        message: format!(
            "Statement #{index} calls forbidden function '{function}' (session-level advisory locks and server administration functions are not allowed in queries). Statement: {statement}"
        ),
    }
}
