//! Common verdict skeleton: standard-SQL read-only verdicts, statement-kind
//! enumeration, the dialect interface and the policy surface.
//!
//! The skeleton carries dialect-agnostic verdicts (allow set / catch-all
//! denial / data-modifying CTEs / multi-statement batches / function-blacklist
//! scanning); dialect differences are injected via [`DialectRule`]; [`Policy`]
//! is the configurable policy surface (kind subsetting tightens + function
//! blacklist appends), defaulting to the built-in policy.

use crate::error::{
    BatchError, Denial, render_data_modifying_cte, render_forbidden_function, render_non_read_only,
    render_policy_restricted,
};
use core::ops::ControlFlow;
use sqlparser::ast::{Expr, Query, SetExpr, Statement, Visit, Visitor};
use sqlparser::dialect::Dialect;
use std::collections::HashMap;

/// Static registry mapping dialect identifiers to implementations.
static PG_RULE: crate::pg::PgRule = crate::pg::PgRule;
static MY_RULE: crate::mysql::MyRule = crate::mysql::MyRule;
static SQLITE_RULE: crate::sqlite::SqliteRule = crate::sqlite::SqliteRule;

/// Statement kinds: the allow side (Query / Explain / Show / Describe) and the
/// deny side (Dml through Other) are separated; deny-side
/// [`StatementKind::render`] wording matches the existing PG error messages
/// verbatim (zero-regression anchor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatementKind {
    /// Pure query (SELECT / CTE / set operations / VALUES / subqueries).
    Query,
    /// EXPLAIN (recursive verdict on the inner statement).
    Explain,
    /// SHOW-family metadata viewing.
    Show,
    /// DESC / DESCRIBE table-structure viewing.
    Describe,
    /// INSERT / UPDATE / DELETE / MERGE。
    Dml,
    /// CREATE / ALTER / DROP / TRUNCATE family.
    Ddl,
    /// BEGIN / COMMIT / ROLLBACK / SAVEPOINT。
    Transaction,
    /// GRANT / REVOKE。
    Privilege,
    /// SET / USE。
    Session,
    /// CALL。
    ProcedureCall,
    /// COPY (including the LOAD DATA file channel).
    Copy,
    /// PRAGMA (deny forms reachable only on the sqlite path).
    Pragma,
    /// ATTACH (reachable only on the sqlite path).
    Attach,
    /// VACUUM / ANALYZE maintenance statements (reachable only on the sqlite path).
    Vacuum,
    /// Catch-all: variants not explicitly listed (fail closed).
    Other,
}

impl StatementKind {
    /// Config / display name of the kind (UPPER_SNAKE; same source as the config kinds values).
    pub fn as_str(self) -> &'static str {
        match self {
            StatementKind::Query => "QUERY",
            StatementKind::Explain => "EXPLAIN",
            StatementKind::Show => "SHOW",
            StatementKind::Describe => "DESCRIBE",
            StatementKind::Dml => "DML",
            StatementKind::Ddl => "DDL",
            StatementKind::Transaction => "TRANSACTION",
            StatementKind::Privilege => "PRIVILEGE",
            StatementKind::Session => "SESSION",
            StatementKind::ProcedureCall => "PROCEDURE",
            StatementKind::Copy => "COPY",
            StatementKind::Pragma => "PRAGMA",
            StatementKind::Attach => "ATTACH",
            StatementKind::Vacuum => "VACUUM",
            StatementKind::Other => "OTHER",
        }
    }

    /// Deny-side English wording (verbatim match with the existing PG error messages).
    ///
    /// The allow side never produces denial reports, so the wording is
    /// unreachable (returns the kind name as a placeholder).
    pub(crate) fn render(self) -> &'static str {
        match self {
            StatementKind::Dml => "DML",
            StatementKind::Ddl => "DDL",
            StatementKind::Transaction => "transaction control",
            StatementKind::Privilege => "privilege statement",
            StatementKind::Session => "session statement",
            StatementKind::ProcedureCall => "procedure call",
            StatementKind::Copy => "COPY",
            StatementKind::Pragma => "pragma statement",
            StatementKind::Attach => "attach statement",
            StatementKind::Vacuum => "vacuum statement",
            StatementKind::Other => "non-read-only statement",
            StatementKind::Query | StatementKind::Explain | StatementKind::Show => {
                unreachable!("allow-side kinds never render a denial")
            }
            StatementKind::Describe => unreachable!("allow-side kinds never render a denial"),
        }
    }

    /// Whether the kind belongs to the allow side (categories that kinds subsetting can tighten).
    pub fn is_allow_side(self) -> bool {
        matches!(
            self,
            StatementKind::Query
                | StatementKind::Explain
                | StatementKind::Show
                | StatementKind::Describe
        )
    }

    /// Parse a config name into the enum (only the four allow-side kinds;
    /// case-insensitive, surrounding whitespace ignored).
    ///
    /// Deny-side kinds are outside the value domain (structural guarantee of "tighten only").
    pub fn parse_allow_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_uppercase().as_str() {
            "QUERY" => Some(StatementKind::Query),
            "EXPLAIN" => Some(StatementKind::Explain),
            "SHOW" => Some(StatementKind::Show),
            "DESCRIBE" => Some(StatementKind::Describe),
            _ => None,
        }
    }
}

/// Validation policy: allow-kind subsetting (tighten only) + per-dialect
/// function blacklist appends (append only).
///
/// [`Policy::default`] is the built-in policy (full allow side + no appends)
/// and carries PG-path zero regression; policies are built via
/// [`PolicyBuilder`], with invalid values rejected at build time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Enable bits for the four allow-side kinds (false = tightened by policy).
    allow: [bool; 4],
    /// Appended function blacklists per dialect (keyed by dialect id, values are lowercase function names).
    extra_fn_blacklist: HashMap<String, Vec<String>>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow: [true; 4],
            extra_fn_blacklist: HashMap::new(),
        }
    }
}

impl Policy {
    /// Policy builder.
    pub fn builder() -> PolicyBuilder {
        PolicyBuilder::default()
    }

    /// Whether a statement kind is allowed by policy (allow-side kinds check
    /// the enable bits; the deny side is always false).
    pub(crate) fn allows(&self, kind: StatementKind) -> bool {
        match kind {
            StatementKind::Query => self.allow[0],
            StatementKind::Explain => self.allow[1],
            StatementKind::Show => self.allow[2],
            StatementKind::Describe => self.allow[3],
            _ => false,
        }
    }

    /// The appended function blacklist for a dialect (lowercase; empty slice when nothing appended).
    pub(crate) fn extra_blacklist(&self, dialect_id: &str) -> &[String] {
        self.extra_fn_blacklist
            .get(dialect_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Builder for [`Policy`]: value-domain / shape validation of kinds subsetting
/// and function appends happens here (second line of defense; core's startup
/// validation is the first).
#[derive(Debug, Default)]
pub struct PolicyBuilder {
    allow: Option<[bool; 4]>,
    extra_fn_blacklist: HashMap<String, Vec<String>>,
}

impl PolicyBuilder {
    /// Set the allow-kind subset (tighten only).
    ///
    /// - Empty slice = built-in full set (same semantics as the config default);
    /// - Non-empty = the given subset (unlisted allow kinds are tightened);
    /// - Passing a deny-side kind is an `Err` (cannot be allowed via config).
    pub fn allow_kinds(&mut self, kinds: &[StatementKind]) -> Result<&mut Self, String> {
        if kinds.is_empty() {
            self.allow = None;
            return Ok(self);
        }
        let mut allow = [false; 4];
        for kind in kinds {
            match kind {
                StatementKind::Query => allow[0] = true,
                StatementKind::Explain => allow[1] = true,
                StatementKind::Show => allow[2] = true,
                StatementKind::Describe => allow[3] = true,
                other => {
                    return Err(format!(
                        "statement kind '{}' is not read-only and can never be allowed via configuration",
                        other.as_str()
                    ));
                }
            }
        }
        self.allow = Some(allow);
        Ok(self)
    }

    /// Append dialect function-blacklist entries (append only; entries must be
    /// valid identifier shapes).
    ///
    /// Entries are stored lowercased and deduplicated; dialect ids are postgres
    /// / mysql / sqlite.
    pub fn extend_fn_blacklist<I, S>(
        &mut self,
        dialect: &str,
        names: I,
    ) -> Result<&mut Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let id = match dialect.trim().to_ascii_lowercase().as_str() {
            "postgres" => "postgres",
            "mysql" => "mysql",
            "sqlite" => "sqlite",
            other => {
                return Err(format!(
                    "unknown dialect '{other}' for function blacklist; supported: postgres, mysql, sqlite"
                ));
            }
        };
        let entries = self.extra_fn_blacklist.entry(id.to_string()).or_default();
        for name in names {
            let raw = name.as_ref().trim();
            if raw.is_empty() || !raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!(
                    "invalid function name '{raw}': expected a plain identifier (letters, digits, underscore)"
                ));
            }
            let lowered = raw.to_ascii_lowercase();
            if !entries.contains(&lowered) {
                entries.push(lowered);
            }
        }
        Ok(self)
    }

    /// Build the policy.
    pub fn build(&self) -> Policy {
        Policy {
            allow: self.allow.unwrap_or([true; 4]),
            extra_fn_blacklist: self.extra_fn_blacklist.clone(),
        }
    }
}

/// Dialect interface: the four responsibility points where dialects differ,
/// invoked by the common skeleton.
///
/// Implementations must be stateless static instances (the registry holds
/// `&'static` references).
pub(crate) trait DialectRule: Sync {
    /// Dialect identifier (registry key; matches the `dialect` field in db-query's config).
    fn id(&self) -> &'static str;

    /// The sqlparser parse dialect for this dialect.
    fn parser(&self) -> &'static dyn Dialect;

    /// Built-in function blacklist (lowercase; non-removable entries accumulated over four rounds of security hardening).
    fn function_blacklist(&self) -> &'static [&'static str];

    /// Function-name normalization: raw SQL identifier value → the shape
    /// comparable against the blacklist.
    ///
    /// After sqlparser parses, `Ident.value` is already unquoted (quotes /
    /// backticks / brackets); PG additionally decodes U& Unicode escapes on
    /// top, while the other dialects only lowercase.
    fn normalize_function_name(&self, raw: &str) -> String;

    /// Category mapping for dialect-specific statement variants (common
    /// variants are classified by the skeleton).
    ///
    /// Returning `None` falls into the catch-all [`StatementKind::Other`];
    /// allow-side kinds (e.g. sqlite read-only PRAGMA → Describe) can also be
    /// produced here.
    fn classify(&self, statement: &Statement) -> Option<StatementKind>;

    /// Dialect-specific whole-statement verdict hook (returning `Some` denies;
    /// none by default).
    ///
    /// Invoked before common classification; dialects needing Denial-level
    /// customization (non-category wording) override this method. Currently
    /// every dialect's specifics are carried by classify.
    fn special_checks(&self, _statement: &Statement, _index: usize) -> Option<Denial> {
        None
    }
}

/// Resolve a dialect identifier into the registry implementation.
///
/// Identifiers are case-insensitive with surrounding whitespace ignored;
/// empty / unknown ids are rejected via [`BatchError`] (the English message
/// includes the supported list), never panicking.
pub(crate) fn resolve_rule(identifier: &str) -> Result<&'static dyn DialectRule, BatchError> {
    match identifier.trim().to_ascii_lowercase().as_str() {
        "postgres" => Ok(&PG_RULE),
        "mysql" => Ok(&MY_RULE),
        "sqlite" => Ok(&SQLITE_RULE),
        "" => Err(BatchError::EmptyDialect),
        other => Err(BatchError::UnsupportedDialect(other.to_string())),
    }
}

/// Parse SQL text into a statement list per dialect.
///
/// Parse failures propagate as [`BatchError::Parse`]; successfully parsing to
/// nothing (empty string / bare semicolons / comments only) yields
/// [`BatchError::EmptyInput`].
pub(crate) fn parse_statements(
    dialect: &'static dyn Dialect,
    sql: &str,
) -> Result<Vec<Statement>, BatchError> {
    let statements =
        Parser::parse_sql(dialect, sql).map_err(|e| BatchError::Parse(e.to_string()))?;
    if statements.is_empty() {
        return Err(BatchError::EmptyInput);
    }
    Ok(statements)
}

use sqlparser::parser::Parser;

/// Verdict each statement in the list and return reports for all denied
/// statements; an empty list passes the whole batch.
///
/// Indices start at 1; statements that pass validation never appear in the
/// returned value.
pub(crate) fn judge_statements(
    statements: &[Statement],
    rule: &'static dyn DialectRule,
    policy: &Policy,
) -> Vec<Denial> {
    statements
        .iter()
        .enumerate()
        .filter_map(|(i, statement)| judge_one(i + 1, statement, rule, policy))
        .collect()
}

/// Verdict a single statement; `None` means allowed, `Some(denial)` is the denial report.
fn judge_one(
    index: usize,
    statement: &Statement,
    rule: &'static dyn DialectRule,
    policy: &Policy,
) -> Option<Denial> {
    // Dialect-specific whole-statement verdict first (Denial-level customization hook).
    if let Some(denial) = rule.special_checks(statement, index) {
        return Some(denial);
    }
    match statement {
        // Pure query: policy tightening point → function-blacklist scan → locking clauses / CTEs / body.
        Statement::Query(query) => {
            if let Some(denial) = check_policy(index, StatementKind::Query, statement, policy) {
                return Some(denial);
            }
            if let Some(hit) = scan_forbidden_function(statement, rule, policy) {
                return Some(render_scan_hit(index, &hit, &statement.to_string()));
            }
            judge_query(index, query, None, &statement.to_string())
        }
        // EXPLAIN / EXPLAIN ANALYZE: the same verdict applies recursively to the inner statement.
        Statement::Explain {
            statement: inner, ..
        } => {
            if let Some(denial) = check_policy(index, StatementKind::Explain, statement, policy) {
                return Some(denial);
            }
            if let Some(hit) = scan_forbidden_function(statement, rule, policy) {
                return Some(render_scan_hit(index, &hit, &statement.to_string()));
            }
            judge_one(index, inner, rule, policy)
        }
        // Remaining statements branch by kind: the allow side passes the policy check, the deny side renders a denial report.
        other => {
            let kind = classify_statement(other, rule);
            if kind.is_allow_side() {
                check_policy(index, kind, other, policy)
            } else {
                Some(render_non_read_only(
                    index,
                    kind.render(),
                    &other.to_string(),
                ))
            }
        }
    }
}

/// Verdict a query statement: locking clauses, CTE bodies (recursive, covering
/// nesting) and DML variants of the body.
///
/// Data-modifying CTEs (`WITH ins AS (INSERT … RETURNING *) SELECT …`) are
/// still Query in sqlparser: CTE bodies hang off `with.cte_tables`, and the
/// body may also directly be `SetExpr::Insert/Update/Delete/Merge` — both must
/// be denied.
///
/// `cte_label` is the CTE name that triggered this verdict (`None` for the
/// top-level query); `root` is the full statement text (referenced by denial
/// reports so users see the complete WITH shape).
fn judge_query(index: usize, query: &Query, cte_label: Option<&str>, root: &str) -> Option<Denial> {
    if !query.locks.is_empty() {
        return Some(crate::error::render_locking_clause(index, root));
    }
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            // A CTE body is a full Query: apply the same verdict recursively
            // (including its own with and body, naturally covering nested
            // data-modifying CTEs), passing the CTE name down.
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
            classify_statement(stmt, &PG_RULE_FALLBACK).render(),
            root,
        )),
        // Select / Query / SetOperation / Values / Table: read-only shapes pass
        // (deeper nodes of subqueries and set operations are covered by the
        // statement-level catch-all denial for non-read-only shapes).
        _ => None,
    }
}

/// Category rendering for body DML variants is dialect-independent (the four
/// variants are common enums); invokes common classification with the PG rule
/// as a placeholder.
static PG_RULE_FALLBACK: crate::pg::PgRule = crate::pg::PgRule;

/// Statement-kind classification: common variants are mapped here,
/// dialect-specific variants delegate to `rule.classify`.
///
/// The Show-variant enumeration matches the previous implementation item by
/// item (unlisted Show variants fall into the catch-all denial, zero
/// regression); dialects can extend their own extra Show forms.
fn classify_statement(statement: &Statement, rule: &'static dyn DialectRule) -> StatementKind {
    match statement {
        Statement::Query(_) => StatementKind::Query,
        Statement::Explain { .. } => StatementKind::Explain,
        Statement::ExplainTable { .. } => StatementKind::Describe,
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
        | Statement::ShowCollation { .. } => StatementKind::Show,
        Statement::Insert { .. }
        | Statement::Update { .. }
        | Statement::Delete { .. }
        | Statement::Merge { .. } => StatementKind::Dml,
        Statement::CreateTable { .. }
        | Statement::CreateIndex { .. }
        | Statement::CreateView { .. }
        | Statement::CreateSchema { .. }
        | Statement::CreateFunction { .. }
        | Statement::CreateProcedure { .. }
        | Statement::AlterTable { .. }
        | Statement::Drop { .. }
        | Statement::Truncate { .. } => StatementKind::Ddl,
        Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. } => StatementKind::Transaction,
        Statement::Grant { .. } | Statement::Revoke { .. } => StatementKind::Privilege,
        Statement::Set { .. } | Statement::Use { .. } => StatementKind::Session,
        Statement::Call { .. } => StatementKind::ProcedureCall,
        Statement::Copy { .. } => StatementKind::Copy,
        // Dialect-specific variants (including unrecognized shapes) delegate to
        // the dialect; None falls into the catch-all.
        other => rule.classify(other).unwrap_or(StatementKind::Other),
    }
}

/// Policy check for allow-side kinds: tightened kinds render a PolicyRestricted denial.
fn check_policy(
    index: usize,
    kind: StatementKind,
    statement: &Statement,
    policy: &Policy,
) -> Option<Denial> {
    if policy.allows(kind) {
        None
    } else {
        Some(render_policy_restricted(
            index,
            kind.as_str(),
            &statement.to_string(),
        ))
    }
}

/// Expression-level function-blacklist scanner: recursively visits every `Expr`
/// in the statement, breaking on a hit; also denies SELECTs with an INTO
/// clause (the SELECT-shaped DDL write channel).
///
/// Blacklist = dialect built-in entries + policy-appended entries (compared
/// merged — the structural anchor of "append only"); name normalization goes
/// through the dialect implementation (quotes / casing / escapes cannot
/// bypass).
struct ForbiddenFunctionScanner<'a> {
    rule: &'static dyn DialectRule,
    extras: &'a [String],
    hit: Option<String>,
}

impl Visitor for ForbiddenFunctionScanner<'_> {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::Function(func) = expr {
            // Function names take the last segment (pg_catalog.pg_advisory_lock
            // equals the bare name); after normalization (dialect: after quote
            // stripping + U& decoding (PG) + lowercasing) they are compared
            // against the blacklist and the policy-appended entries — quoted,
            // mixed-case and escaped forms cannot bypass.
            let name = func
                .name
                .0
                .last()
                .and_then(|p| p.as_ident())
                .map(|ident| self.rule.normalize_function_name(&ident.value))
                .unwrap_or_default();
            if self.rule.function_blacklist().contains(&name.as_str())
                || self.extras.iter().any(|e| e == &name)
            {
                self.hit = Some(name);
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, select: &sqlparser::ast::Select) -> ControlFlow<Self::Break> {
        // SELECT ... INTO (including INTO TEMP) is the Query-shaped DDL write
        // channel (MySQL's INTO OUTFILE is likewise a file write channel,
        // denied generically).
        if select.into.is_some() {
            self.hit = Some("<select-into>".to_string());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Scan the statement's expression layer for blacklisted functions and INTO
/// clauses; a hit returns the identifier (blacklisted function name or
/// `<select-into>`).
fn scan_forbidden_function(
    statement: &Statement,
    rule: &'static dyn DialectRule,
    policy: &Policy,
) -> Option<String> {
    let mut scanner = ForbiddenFunctionScanner {
        rule,
        extras: policy.extra_blacklist(rule.id()),
        hit: None,
    };
    if statement.visit(&mut scanner).is_break() {
        scanner.hit
    } else {
        None
    }
}

/// Render a scan hit into a denial report (functions go through
/// ForbiddenFunction; INTO goes through NonReadOnly with the SELECT INTO
/// channel explanation).
fn render_scan_hit(index: usize, hit: &str, statement: &str) -> Denial {
    if hit == "<select-into>" {
        render_non_read_only(index, "SELECT INTO", statement)
    } else {
        render_forbidden_function(index, hit, statement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_rule_supports_three_dialects() {
        assert_eq!(resolve_rule("postgres").unwrap().id(), "postgres");
        assert_eq!(resolve_rule("MySQL").unwrap().id(), "mysql");
        assert_eq!(resolve_rule(" sqlite ").unwrap().id(), "sqlite");
    }

    #[test]
    fn test_resolve_rule_rejects_empty_and_unknown() {
        assert!(matches!(resolve_rule(""), Err(BatchError::EmptyDialect)));
        let Err(err) = resolve_rule("oracle") else {
            panic!("oracle must be unsupported");
        };
        let msg = err.to_string();
        assert!(msg.contains("Unsupported dialect 'oracle'"), "{msg}");
        assert!(
            msg.contains("Supported dialects: postgres, mysql, sqlite"),
            "{msg}"
        );
    }

    #[test]
    fn test_statement_kind_render_matches_legacy_texts() {
        // Deny-side wording matches the existing PG error messages verbatim
        // (zero-regression anchor).
        assert_eq!(StatementKind::Dml.render(), "DML");
        assert_eq!(StatementKind::Ddl.render(), "DDL");
        assert_eq!(StatementKind::Transaction.render(), "transaction control");
        assert_eq!(StatementKind::Privilege.render(), "privilege statement");
        assert_eq!(StatementKind::Session.render(), "session statement");
        assert_eq!(StatementKind::ProcedureCall.render(), "procedure call");
        assert_eq!(StatementKind::Copy.render(), "COPY");
        assert_eq!(StatementKind::Other.render(), "non-read-only statement");
        // New dialect categories (unreachable on the PG path).
        assert_eq!(StatementKind::Pragma.render(), "pragma statement");
        assert_eq!(StatementKind::Attach.render(), "attach statement");
        assert_eq!(StatementKind::Vacuum.render(), "vacuum statement");
    }

    #[test]
    fn test_parse_allow_name_domain() {
        assert_eq!(
            StatementKind::parse_allow_name("explain"),
            Some(StatementKind::Explain)
        );
        assert_eq!(
            StatementKind::parse_allow_name(" SHOW "),
            Some(StatementKind::Show)
        );
        // Deny-side and unknown names are outside the value domain.
        assert_eq!(StatementKind::parse_allow_name("DML"), None);
        assert_eq!(StatementKind::parse_allow_name("FOO"), None);
    }

    #[test]
    fn test_policy_default_is_full_allow() {
        let policy = Policy::default();
        for kind in [
            StatementKind::Query,
            StatementKind::Explain,
            StatementKind::Show,
            StatementKind::Describe,
        ] {
            assert!(policy.allows(kind));
        }
        assert!(!policy.allows(StatementKind::Dml));
        assert!(policy.extra_blacklist("postgres").is_empty());
    }

    #[test]
    fn test_policy_builder_restricts_and_appends() {
        // Subset tightening: with only QUERY, EXPLAIN is denied.
        let policy = Policy::builder()
            .allow_kinds(&[StatementKind::Query])
            .unwrap()
            .build();
        assert!(policy.allows(StatementKind::Query));
        assert!(!policy.allows(StatementKind::Explain));

        // Empty slice = built-in full set.
        let policy = Policy::builder().allow_kinds(&[]).unwrap().build();
        assert!(policy.allows(StatementKind::Describe));

        // Deny-side kinds cannot be allowed.
        let err = Policy::builder()
            .allow_kinds(&[StatementKind::Dml])
            .unwrap_err();
        assert!(err.contains("never be allowed"), "{err}");

        // Appended entries: lowercased, deduplicated, isolated per dialect.
        let policy = Policy::builder()
            .extend_fn_blacklist("postgres", ["My_Func", "my_func"])
            .unwrap()
            .extend_fn_blacklist("mysql", ["get_lock_extra"])
            .unwrap()
            .build();
        assert_eq!(policy.extra_blacklist("postgres"), &["my_func".to_string()]);
        assert_eq!(
            policy.extra_blacklist("mysql"),
            &["get_lock_extra".to_string()]
        );
        assert!(policy.extra_blacklist("sqlite").is_empty());

        // Invalid dialects and invalid function shapes are rejected.
        assert!(
            Policy::builder()
                .extend_fn_blacklist("oracle", ["f"])
                .is_err()
        );
        assert!(
            Policy::builder()
                .extend_fn_blacklist("pg", ["bad;name"])
                .is_err()
        );
        assert!(Policy::builder().extend_fn_blacklist("pg", [""]).is_err());
    }
}
