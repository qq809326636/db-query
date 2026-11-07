//! Validation result contract: the public allow/deny result types and the
//! English error message rendering.
//! Denial is a normal business outcome (not an exception): the public API
//! returns [`ValidationResult`], where each denial carries a machine-readable
//! category ([`RejectCategory`]) and a stable English explanation.
//! Message templates are centralized in this module; the verdict modules know
//! nothing about English wording.

use std::fmt;

/// Machine-readable categories of validation denials.
/// Adding or removing variants is a breaking change, reflected in the crate
/// version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectCategory {
    /// The dialect identifier is empty or not in the supported list.
    UnsupportedDialect,
    /// The SQL failed to parse.
    ParseError,
    /// The input is empty or contains no statements (empty string / bare
    /// semicolons / comments only).
    EmptyInput,
    /// The statement is outside the read-only whitelist (DML / DDL / transaction
    /// control / privilege-session / COPY / unrecognized).
    NonReadOnly,
    /// The query carries a locking clause (FOR UPDATE / FOR SHARE).
    LockingClause,
    /// The query contains a data-modifying CTE (INSERT/UPDATE/DELETE/MERGE inside
    /// WITH).
    DataModifyingCte,
    /// An expression calls a blacklisted function (session-level advisory locks
    /// / server-side administrative functions).
    ForbiddenFunction,
    /// The statement kind was tightened out by policy (not in the allowed set
    /// after kinds subsetting).
    PolicyRestricted,
}

impl RejectCategory {
    /// Short English name of the category, for logs and debugging.
    pub fn as_str(self) -> &'static str {
        match self {
            RejectCategory::UnsupportedDialect => "unsupported dialect",
            RejectCategory::ParseError => "parse error",
            RejectCategory::EmptyInput => "empty input",
            RejectCategory::NonReadOnly => "not read-only",
            RejectCategory::LockingClause => "locking clause",
            RejectCategory::DataModifyingCte => "data-modifying CTE",
            RejectCategory::ForbiddenFunction => "forbidden function",
            RejectCategory::PolicyRestricted => "policy restricted",
        }
    }
}

impl fmt::Display for RejectCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Report of a single denied statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// Statement index, starting at 1 in a multi-statement batch; batch-level
    /// errors (dialect / parse / empty input) take 1.
    pub index: usize,
    /// The denial category.
    pub category: RejectCategory,
    /// Stable English explanation, including the full denied statement text
    /// (never truncated).
    pub message: String,
}

/// Validation result: `allowed` is always equivalent to `denials` being empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    /// True when every statement is whitelisted.
    pub allowed: bool,
    /// Per-statement denial reports; statements that pass never appear.
    pub denials: Vec<Denial>,
}

impl ValidationResult {
    /// Build an allowed result (no denials).
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            denials: Vec::new(),
        }
    }

    /// Build a denied result; `allowed` is derived from whether `denials` is
    /// empty, so the two can never disagree.
    pub fn denied(denials: Vec<Denial>) -> Self {
        Self {
            allowed: denials.is_empty(),
            denials,
        }
    }
}

/// Internal error type for batch-level failures (dialect / parse / empty
/// input), ultimately rendered into [`ValidationResult`].
/// `Display` uniformly goes through [`BatchError::render`], the stable
/// caller-facing English wording.
#[derive(Debug, thiserror::Error)]
#[error("{}", self.render())]
pub(crate) enum BatchError {
    /// The dialect identifier is empty.
    EmptyDialect,
    /// The dialect identifier is not in the supported list; `0` is the raw
    /// identifier.
    UnsupportedDialect(String),
    /// The SQL failed to parse; `0` is the parser error message (with position).
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

    /// Render into the public English explanation (stable wording, nothing
    /// nondeterministic like timestamps).
    ///
    /// The `Display` impl on this type (thiserror-derived) is for internal logs
    /// only; the caller-facing wording is this method.
    fn render(&self) -> String {
        match self {
            BatchError::EmptyDialect => {
                "Dialect identifier is empty. Supported dialects: postgres, mysql, sqlite."
                    .to_string()
            }
            BatchError::UnsupportedDialect(raw) => {
                format!("Unsupported dialect '{raw}'. Supported dialects: postgres, mysql, sqlite.")
            }
            BatchError::Parse(detail) => {
                format!("Failed to parse SQL: {detail}.")
            }
            BatchError::EmptyInput => "SQL input is empty or contains no statements.".to_string(),
        }
    }

    /// Convert into the public denial report (batch-level errors take index 1).
    pub(crate) fn into_denial(self) -> Denial {
        Denial {
            index: 1,
            category: self.category(),
            message: self.render(),
        }
    }
}

/// Render the English explanation for a non-read-only denial.
pub(crate) fn render_non_read_only(index: usize, kind: &str, statement: &str) -> Denial {
    Denial {
        index,
        category: RejectCategory::NonReadOnly,
        message: format!(
            "Statement #{index} is not read-only ({kind}); only SELECT/EXPLAIN/SHOW/metadata queries are allowed. Statement: {statement}"
        ),
    }
}

/// Render the English explanation for a locking-clause denial.
pub(crate) fn render_locking_clause(index: usize, statement: &str) -> Denial {
    Denial {
        index,
        category: RejectCategory::LockingClause,
        message: format!(
            "Statement #{index} uses a locking clause (FOR UPDATE/FOR SHARE), which is not allowed. Statement: {statement}"
        ),
    }
}

/// Render the English explanation for a data-modifying-CTE denial.
///
/// `cte` is the CTE name (alias), `kind` the statement kind inside it (e.g.
/// DML), and `statement` the full denied statement text.
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

/// Render the English explanation for a blacklisted-function denial.
///
/// `function` is the hit function name (normalized to lowercase), `statement`
/// the full denied statement text.
pub(crate) fn render_forbidden_function(index: usize, function: &str, statement: &str) -> Denial {
    Denial {
        index,
        category: RejectCategory::ForbiddenFunction,
        message: format!(
            "Statement #{index} calls forbidden function '{function}' (session-level advisory locks and server administration functions are not allowed in queries). Statement: {statement}"
        ),
    }
}

/// Render the English explanation for a policy-tightened denial.
///
/// `kind_name` is the tightened statement kind's name (e.g. `EXPLAIN`),
/// `statement` the full denied statement text.
pub(crate) fn render_policy_restricted(index: usize, kind_name: &str, statement: &str) -> Denial {
    Denial {
        index,
        category: RejectCategory::PolicyRestricted,
        message: format!(
            "Statement #{index} uses statement kind '{kind_name}' which is disabled by the validator policy. Statement: {statement}"
        ),
    }
}
