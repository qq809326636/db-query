//! App config: loads and validates `config.toml` per the structure of
//! `config.template.toml`.
//!
//! Structure: `[app]` (data directory `[app.data]`, the three `[app.log]`
//! sections, MCP `[app.mcp]`, global watch `[app.databases]`) plus
//! `[[databases]]` multi-database connections.
//! Validation failures return English errors naming the field path; error
//! messages never contain credential values.
//! The legacy flat field `app.log_level` is deprecated: its presence errors
//! with a migration hint.

use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

/// Valid log levels.
const LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];

/// Valid log output formats.
const LOG_FORMATS: &[&str] = &["text", "json"];

/// Valid file rolling policies.
const ROLLING_KINDS: &[&str] = &["daily", "hourly", "size"];

/// Lower bound for `rolling_max_size` (bytes); effective only when
/// `rolling = "size"`.
const ROLLING_MAX_SIZE_MIN: u64 = 1048576;

/// Valid range for `watch_interval` (seconds).
const WATCH_INTERVAL_MIN: u64 = 1;
const WATCH_INTERVAL_MAX: u64 = 3600;

/// Validate the listen address shape: IPv4 / IPv6 (standard-library parsing)
/// or a hostname (alphanumerics plus `-` and `.`; segments neither start nor
/// end with `-`; total length ≤ 253).
fn is_valid_addr(addr: &str) -> bool {
    if addr.is_empty() {
        return false;
    }
    if addr.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if addr.len() > 253 {
        return false;
    }
    addr.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            // Purely numeric labels count as malformed IPs (e.g. 1.2.3.4.5);
            // rejected in the listen-address context.
            && !label.chars().all(|c| c.is_ascii_digit())
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// App config, corresponding to the `config.toml` root table.
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    /// The `[app]` section (with its subsections); may be omitted entirely.
    #[serde(default)]
    pub app: AppConfigSection,
    /// The `[validator]` section (SQL validation policy); may be omitted
    /// entirely (= built-in policy).
    #[serde(default)]
    pub validator: ValidatorConfig,
    /// Multi-database connection configs; query targets are distinguished by
    /// `name`.
    pub databases: Vec<DatabaseConfig>,
}

/// The `[validator]` section: SQL validation policy (kinds subsetting to
/// tighten + function-blacklist appends).
///
/// Default (omitted entirely or an empty section) = the built-in policy;
/// invalid values fail fast during semantic validation.
#[derive(Debug, Default, Deserialize)]
pub struct ValidatorConfig {
    /// The `[validator.sql]` subsection.
    #[serde(default)]
    pub sql: SqlValidatorConfig,
}

/// The `[validator.sql]` subsection: the common whitelist section + three
/// dialect sections (unknown sections rejected).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlValidatorConfig {
    /// `validator.sql.whitelist` (kinds subsetting).
    #[serde(default)]
    pub whitelist: ValidatorWhitelistConfig,
    /// `validator.sql.pg` (pg dialect policy).
    #[serde(default)]
    pub pg: DialectPolicyConfig,
    /// `validator.sql.mysql` (mysql dialect policy).
    #[serde(default)]
    pub mysql: DialectPolicyConfig,
    /// `validator.sql.sqlite` (sqlite dialect policy).
    #[serde(default)]
    pub sqlite: DialectPolicyConfig,
}

/// `[validator.sql.whitelist]`: allow-kind subsetting (tighten only).
#[derive(Debug, Default, Deserialize)]
pub struct ValidatorWhitelistConfig {
    /// Subset of allowed statement kinds; empty = the built-in full set
    /// (QUERY / EXPLAIN / SHOW / DESCRIBE). Non-read-only kinds are outside
    /// the value domain (error during validation).
    #[serde(default)]
    pub kinds: Vec<String>,
}

/// `[validator.sql.<dialect>]`: dialect policy section (function-blacklist
/// appends).
#[derive(Debug, Default, Deserialize)]
pub struct DialectPolicyConfig {
    /// `<dialect>.blacklist` (function appends).
    #[serde(default)]
    pub blacklist: DialectBlacklistConfig,
}

/// `[validator.sql.<dialect>.blacklist]`: appended function denials.
#[derive(Debug, Default, Deserialize)]
pub struct DialectBlacklistConfig {
    /// Appended entries (merged and deduplicated with the built-ins; must be
    /// valid identifier shapes).
    #[serde(default)]
    pub function: Vec<String>,
}

/// Value domain for kinds (same source as the allow side of sql-validator's
/// StatementKind).
const VALIDATOR_KINDS: &[&str] = &["QUERY", "EXPLAIN", "SHOW", "DESCRIBE"];

/// `[app]` section config; subsections map through their own structs. Default
/// is derivable: every field's default matches its type default (Option → None,
/// child structs → their own hand-written Defaults).
#[derive(Debug, Default, Deserialize)]
pub struct AppConfigSection {
    /// Legacy flat field (deprecated): only its presence is captured; presence
    /// errors during semantic validation with a migration hint to
    /// `app.log.level`, participating in no behavior.
    #[serde(default)]
    pub log_level: Option<String>,
    /// The `[app.data]` subsection (data root directory); may be omitted.
    #[serde(default)]
    pub data: AppDataSection,
    /// The `[app.log]` subsection (logging config); may be omitted.
    #[serde(default)]
    pub log: LogSection,
    /// The `[app.mcp]` subsection (MCP service parameters); may be omitted.
    #[serde(default)]
    pub mcp: McpSection,
    /// The `[app.databases]` subsection (global database watch parameters); may
    /// be omitted.
    #[serde(default)]
    pub databases: AppDatabasesSection,
}

// McpSection contains only one child struct whose field-level default is
// correct, so deriving is safe; the other structs with non-type defaults stay
// hand-written (deriving would bypass field-level functions with type
// defaults).
#[derive(Debug, Default, Deserialize)]
pub struct McpSection {
    /// The `[app.mcp.streamable]` subsection (Streamable HTTP listen
    /// parameters); may be omitted.
    #[serde(default)]
    pub streamable: StreamableSection,
}

/// The `[app.data]` subsection: data-file root directory (reserved for
/// multiple uses).
#[derive(Debug, Deserialize)]
pub struct AppDataSection {
    /// Data root directory; relative paths resolve against the process working
    /// directory, defaulting to `./data`.
    #[serde(default = "default_data_dir")]
    pub dir: String,
}

/// The `[app.log]` subsection: overall logging config (level and format).
#[derive(Debug, Deserialize)]
pub struct LogSection {
    /// Log output format (the console inheritance source), defaulting to
    /// `text`.
    #[serde(default = "default_log_format")]
    pub format: String,
    /// Log level, defaulting to `info`.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// The `[app.log.console]` subsection; may be omitted.
    #[serde(default)]
    pub console: LogConsoleSection,
    /// The `[app.log.file]` subsection; may be omitted.
    #[serde(default)]
    pub file: LogFileSection,
}

/// The `[app.log.console]` subsection: the console output target.
#[derive(Debug, Default, Deserialize)]
pub struct LogConsoleSection {
    /// Whether console output is enabled, defaulting to `false` (the type
    /// default matches the field default, so deriving is safe).
    #[serde(default)]
    pub enabled: bool,
    /// Console output format: an empty string inherits `app.log.format`,
    /// defaulting to the empty string.
    #[serde(default)]
    pub format: String,
}

/// The `[app.log.file]` subsection: the file output target (rolling and
/// retention policies).
#[derive(Debug, Deserialize)]
pub struct LogFileSection {
    /// Whether file output is enabled, defaulting to `true`.
    #[serde(default = "default_file_enabled")]
    pub enabled: bool,
    /// File output format, defaulting to `json` (independent of console).
    #[serde(default = "default_file_format")]
    pub format: String,
    /// Log directory: an empty string falls back to `<app.data.dir>/logs` (the
    /// synthesis happens at logging initialization); the config object keeps
    /// the raw value, defaulting to the empty string.
    #[serde(default)]
    pub dir: String,
    /// Rolling segment policy, defaulting to `daily`.
    #[serde(default = "default_rolling")]
    pub rolling: String,
    /// Per-segment size ceiling in size mode (bytes), defaulting to 10 MB;
    /// effective only when `rolling = "size"`.
    #[serde(default = "default_rolling_max_size")]
    pub rolling_max_size: u64,
    /// Days to keep log segments, defaulting to 7, minimum 1 (0 is invalid).
    #[serde(default = "default_max_days")]
    pub max_days: u32,
}

/// The `[app.mcp.streamable]` subsection: Streamable HTTP service listen
/// parameters.
#[derive(Debug, Deserialize)]
pub struct StreamableSection {
    /// Listen address, defaulting to `127.0.0.1` (IPv4 / IPv6 or hostname
    /// shape).
    #[serde(default = "default_streamable_addr")]
    pub addr: String,
    /// Listen port, defaulting to 8000, ranging 1–65535.
    #[serde(default = "default_streamable_port")]
    pub port: u16,
}

/// The `[app.databases]` subsection: global parameters applied to all
/// `[[databases]]` entries.
#[derive(Debug, Deserialize)]
pub struct AppDatabasesSection {
    /// Watch interval (seconds), defaulting to 30. The field name keeps the
    /// spelling used in the config template.
    #[serde(default = "default_watch_interval")]
    pub watch_interval: u64,
}

// Hand-written Default instead of derived: a derived Default overwrites
// field-level serde default functions with type defaults (empty string / 0),
// making the default semantics of "whole section omitted" inconsistent with
// "field omitted" (the trap was verified on the existing structs); deriving is
// safe only when the field default matches the type default (see
// AppConfigSection / LogConsoleSection).
impl Default for AppDataSection {
    fn default() -> Self {
        Self {
            dir: default_data_dir(),
        }
    }
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            format: default_log_format(),
            level: default_log_level(),
            console: LogConsoleSection::default(),
            file: LogFileSection::default(),
        }
    }
}

impl Default for LogFileSection {
    fn default() -> Self {
        Self {
            enabled: default_file_enabled(),
            format: default_file_format(),
            dir: String::new(),
            rolling: default_rolling(),
            rolling_max_size: default_rolling_max_size(),
            max_days: default_max_days(),
        }
    }
}

impl Default for StreamableSection {
    fn default() -> Self {
        Self {
            addr: default_streamable_addr(),
            port: default_streamable_port(),
        }
    }
}

impl Default for AppDatabasesSection {
    fn default() -> Self {
        Self {
            watch_interval: default_watch_interval(),
        }
    }
}

fn default_data_dir() -> String {
    "./data".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_file_enabled() -> bool {
    true
}

fn default_file_format() -> String {
    "json".to_string()
}

fn default_rolling() -> String {
    "daily".to_string()
}

fn default_rolling_max_size() -> u64 {
    10485760
}

fn default_max_days() -> u32 {
    7
}

fn default_streamable_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_streamable_port() -> u16 {
    8000
}

fn default_watch_interval() -> u64 {
    30
}

/// A single database connection config, corresponding to one `[[databases]]`
/// table.
///
/// Fields like `dialect` / `password` / `extra_opts` are read by the connection
/// execution layer later.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Unique connection identifier; duplicates error.
    pub uid: String,
    /// Name, for users to recognize.
    pub name: String,
    /// Brief description of the database coverage, etc., as a reference when
    /// clients pick a query target.
    pub description: String,
    /// Database type (postgres / mysql / sqlite / redis).
    #[serde(rename = "type")]
    pub db_type: String,
    /// SQL dialect (e.g. postgres / mysql).
    pub dialect: String,
    /// Connection username.
    pub username: String,
    /// Connection password.
    pub password: String,
    /// Hostname.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Database name.
    pub db: String,
    /// Extra connection parameters; may be omitted.
    #[serde(default)]
    pub extra_opts: String,
}

impl AppConfig {
    /// Parse and validate the config from TOML text.
    ///
    /// Errors are English and name the field path; parse errors pass through
    /// toml's line/column information.
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: AppConfig =
            toml::from_str(text).map_err(|e| format!("failed to parse config: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    /// Load and validate the config from a file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file '{}': {e}", path.display()))?;
        Self::parse(&text)
    }

    /// Ensure the data root directory exists: created recursively when missing
    /// (including all parents), idempotently.
    ///
    /// Separated from load-time validation: an invalid config is refused at
    /// load, while a directory-creation failure is an environment error the
    /// caller triggers explicitly at the right moment.
    pub fn ensure_data_dir(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.app.data.dir).map_err(|e| {
            format!(
                "failed to create data directory '{}': {e}",
                self.app.data.dir
            )
        })
    }

    /// Semantic validation: returns on the first error.
    ///
    /// Order: the new sections (legacy-field migration → the app.log items)
    /// precede the existing checks (streamable → watch_interval → databases
    /// uniqueness). Baseline configs (without `[app.log]`) pass all new checks
    /// on their default values, and existing first-error positions are
    /// unaffected.
    fn validate(&self) -> Result<(), String> {
        if self.app.log_level.is_some() {
            return Err(
                "app.log_level is no longer supported: migrate to app.log.level in [app.log]"
                    .to_string(),
            );
        }
        if !LOG_LEVELS.contains(&self.app.log.level.as_str()) {
            return Err(format!(
                "invalid value '{}' for app.log.level: expected one of error, warn, info, debug, trace",
                self.app.log.level
            ));
        }
        if !LOG_FORMATS.contains(&self.app.log.format.as_str()) {
            return Err(format!(
                "invalid value '{}' for app.log.format: expected one of text, json",
                self.app.log.format
            ));
        }
        let console_format = &self.app.log.console.format;
        if !console_format.is_empty() && !LOG_FORMATS.contains(&console_format.as_str()) {
            return Err(format!(
                "invalid value '{}' for app.log.console.format: expected one of text, json, or empty string",
                console_format
            ));
        }
        if !LOG_FORMATS.contains(&self.app.log.file.format.as_str()) {
            return Err(format!(
                "invalid value '{}' for app.log.file.format: expected one of text, json",
                self.app.log.file.format
            ));
        }
        if !ROLLING_KINDS.contains(&self.app.log.file.rolling.as_str()) {
            return Err(format!(
                "invalid value '{}' for app.log.file.rolling: expected one of daily, hourly, size",
                self.app.log.file.rolling
            ));
        }
        if self.app.log.file.rolling == "size"
            && self.app.log.file.rolling_max_size < ROLLING_MAX_SIZE_MIN
        {
            return Err(format!(
                "invalid value {} for app.log.file.rolling_max_size: expected at least {} bytes",
                self.app.log.file.rolling_max_size, ROLLING_MAX_SIZE_MIN
            ));
        }
        if self.app.log.file.max_days < 1 {
            return Err(format!(
                "invalid value {} for app.log.file.max_days: expected at least 1 day",
                self.app.log.file.max_days
            ));
        }
        if !is_valid_addr(&self.app.mcp.streamable.addr) {
            return Err(format!(
                "invalid value '{}' for app.mcp.streamable.addr: expected an IPv4/IPv6 address or hostname",
                self.app.mcp.streamable.addr
            ));
        }
        if self.app.mcp.streamable.port == 0 {
            return Err(format!(
                "invalid value {} for app.mcp.streamable.port: expected 1..=65535",
                self.app.mcp.streamable.port
            ));
        }
        if !(WATCH_INTERVAL_MIN..=WATCH_INTERVAL_MAX).contains(&self.app.databases.watch_interval) {
            return Err(format!(
                "invalid value {} for app.databases.watch_interval: expected 1..=3600 seconds",
                self.app.databases.watch_interval
            ));
        }
        if self.databases.is_empty() {
            return Err("at least one [[databases]] entry is required".to_string());
        }

        self.validate_validator()?;

        let mut uids = HashSet::new();
        let mut names = HashSet::new();
        for db in &self.databases {
            if db.uid.trim().is_empty() {
                return Err("database uid must not be empty".to_string());
            }
            if db.name.trim().is_empty() {
                return Err("database name must not be empty".to_string());
            }
            if !uids.insert(db.uid.as_str()) {
                return Err(format!("duplicate database uid '{}'", db.uid));
            }
            if !names.insert(db.name.as_str()) {
                return Err(format!("duplicate database name '{}'", db.name));
            }
        }
        Ok(())
    }

    /// Semantic validation of the `[validator]` section (fail-fast classes):
    ///
    /// 1. kinds containing words outside the value domain (unknown names or
    ///    non-read-only kinds) — non-read-only kinds get a dedicated error
    ///    (explaining they cannot be allowed via config);
    /// 2. Unknown dialect sections (serde's `deny_unknown_fields` already
    ///    rejects `[validator.sql.<other>]` at the parse layer; the entries
    ///    inside dialect sections are validated here);
    /// 3. Function entries must be valid identifier shapes (non-empty, no
    ///    quotes / semicolons / whitespace).
    ///
    /// Empty config (missing section / empty kinds / empty function) = the
    /// built-in policy, passing everything.
    fn validate_validator(&self) -> Result<(), String> {
        let sql = &self.validator.sql;
        for kind in &sql.whitelist.kinds {
            let normalized = kind.trim().to_ascii_uppercase();
            if VALIDATOR_KINDS.contains(&normalized.as_str()) {
                continue;
            }
            // Non-read-only kinds (a common misconfiguration: DML / DDL, etc.)
            // get a dedicated explanation.
            if matches!(
                normalized.as_str(),
                "DML"
                    | "DDL"
                    | "TRANSACTION"
                    | "PROCEDURE"
                    | "COPY"
                    | "PRAGMA"
                    | "ATTACH"
                    | "OTHER"
            ) {
                return Err(format!(
                    "invalid value '{kind}' for validator.sql.whitelist.kinds: '{normalized}' is not read-only and can never be allowed via configuration (read-only guarantee)"
                ));
            }
            return Err(format!(
                "invalid value '{kind}' for validator.sql.whitelist.kinds: expected one of QUERY, EXPLAIN, SHOW, DESCRIBE"
            ));
        }
        for (dialect, policy) in [
            ("pg", &sql.pg),
            ("mysql", &sql.mysql),
            ("sqlite", &sql.sqlite),
        ] {
            for func in &policy.blacklist.function {
                let raw = func.trim();
                if raw.is_empty() || !raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(format!(
                        "invalid function name '{func}' in validator.sql.{dialect}.blacklist.function: expected a plain identifier (letters, digits, underscore)"
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete template consistent with the new config.template.toml
    /// structure (test baseline).
    const TEMPLATE: &str = r#"
[app.data]
dir = "./data"

[app.log]
format = "text"
level = "info"

[app.log.console]
enabled = false
format = ""

[app.log.file]
enabled = true
format = "json"
dir = ""
rolling = "daily"
rolling_max_size = 10485760
max_days = 7

[app.mcp.streamable]
addr = "127.0.0.1"
port = 8000

[app.databases]
watch_interval = 30

[[databases]]
uid = "primary"
name = "primary"
description = "primary database"
type = "postgres"
dialect = "postgres"
username = "user"
password = "password"
host = "localhost"
port = 5432
db = "app"
extra_opts = ""
"#;

    #[test]
    fn test_parse_full_template() {
        let config = AppConfig::parse(TEMPLATE).unwrap();
        assert_eq!(config.app.data.dir, "./data");
        assert_eq!(config.app.log.format, "text");
        assert_eq!(config.app.log.level, "info");
        assert!(!config.app.log.console.enabled);
        assert_eq!(config.app.log.console.format, "");
        assert!(config.app.log.file.enabled);
        assert_eq!(config.app.log.file.format, "json");
        assert_eq!(config.app.log.file.dir, "");
        assert_eq!(config.app.log.file.rolling, "daily");
        assert_eq!(config.app.log.file.rolling_max_size, 10485760);
        assert_eq!(config.app.log.file.max_days, 7);
        assert_eq!(config.app.mcp.streamable.addr, "127.0.0.1");
        assert_eq!(config.app.mcp.streamable.port, 8000);
        assert_eq!(config.app.databases.watch_interval, 30);
        assert_eq!(config.databases.len(), 1);
        assert_eq!(config.databases[0].uid, "primary");
        assert_eq!(config.databases[0].db_type, "postgres");
        assert_eq!(config.databases[0].port, 5432);
    }

    #[test]
    fn test_app_section_omitted_full_defaults() {
        // Whole section omitted: all new fields fall back to defaults.
        let text = r#"
[[databases]]
uid = "primary"
name = "primary"
description = "d"
type = "postgres"
dialect = "postgres"
username = "user"
password = "password"
host = "localhost"
port = 5432
db = "app"
"#;
        let config = AppConfig::parse(text).unwrap();
        assert_eq!(config.app.log_level, None);
        assert_eq!(config.app.data.dir, "./data");
        assert_eq!(config.app.log.format, "text");
        assert_eq!(config.app.log.level, "info");
        assert!(!config.app.log.console.enabled);
        assert_eq!(config.app.log.console.format, "");
        assert!(config.app.log.file.enabled);
        assert_eq!(config.app.log.file.format, "json");
        assert_eq!(config.app.log.file.dir, "");
        assert_eq!(config.app.log.file.rolling, "daily");
        assert_eq!(config.app.log.file.rolling_max_size, 10485760);
        assert_eq!(config.app.log.file.max_days, 7);
        assert_eq!(config.app.databases.watch_interval, 30);
    }

    #[test]
    fn test_log_subsections_independently_omittable() {
        // Only the [app.log] main fields written; the console / file
        // subsections are omitted entirely, taking defaults.
        let text = r#"
[app.log]
level = "debug"
format = "json"

[[databases]]
uid = "primary"
name = "primary"
description = "d"
type = "postgres"
dialect = "postgres"
username = "user"
password = "password"
host = "localhost"
port = 5432
db = "app"
"#;
        let config = AppConfig::parse(text).unwrap();
        assert_eq!(config.app.log.level, "debug");
        assert_eq!(config.app.log.format, "json");
        assert!(!config.app.log.console.enabled);
        assert!(config.app.log.file.enabled);
        assert_eq!(config.app.log.file.format, "json");
        assert_eq!(config.app.databases.watch_interval, 30);
    }

    #[test]
    fn test_log_field_level_defaults() {
        // Field-level omission: only level and console.enabled are written; the
        // remaining fields fall back to defaults.
        let text = r#"
[app.log]
level = "warn"

[app.log.console]
enabled = true

[[databases]]
uid = "primary"
name = "primary"
description = "d"
type = "postgres"
dialect = "postgres"
username = "user"
password = "password"
host = "localhost"
port = 5432
db = "app"
"#;
        let config = AppConfig::parse(text).unwrap();
        assert_eq!(config.app.log.level, "warn");
        assert_eq!(config.app.log.format, "text");
        assert!(config.app.log.console.enabled);
        // console.format unwritten → empty string (inheritance semantics).
        assert_eq!(config.app.log.console.format, "");
        assert!(config.app.log.file.enabled);
        assert_eq!(config.app.log.file.format, "json");
    }

    #[test]
    fn test_rejects_legacy_log_level_with_migration_hint() {
        let text = r#"
[app]
log_level = "info"

[[databases]]
uid = "primary"
name = "primary"
description = "d"
type = "postgres"
dialect = "postgres"
username = "user"
password = "password"
host = "localhost"
port = 5432
db = "app"
"#;
        let err = AppConfig::parse(text).unwrap_err();
        assert!(
            err.contains("app.log_level is no longer supported"),
            "unexpected: {err}"
        );
        assert!(
            err.contains("migrate to app.log.level in [app.log]"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_rejects_invalid_log_level() {
        let text = TEMPLATE.replace(r#"level = "info""#, r#"level = "verbose""#);
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("app.log.level"), "unexpected: {err}");
        assert!(err.contains("verbose"));
    }

    #[test]
    fn test_rejects_invalid_log_formats() {
        // app.log.format invalid.
        let text = TEMPLATE.replace(r#"format = "text""#, r#"format = "xml""#);
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("app.log.format"), "unexpected: {err}");

        // console.format invalid (non-empty and outside the enum).
        let text = TEMPLATE.replace(
            "enabled = false\nformat = \"\"",
            "enabled = false\nformat = \"yaml\"",
        );
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("app.log.console.format"), "unexpected: {err}");

        // file.format invalid.
        let text = TEMPLATE.replace(
            "format = \"json\"\ndir = \"\"",
            "format = \"plain\"\ndir = \"\"",
        );
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("app.log.file.format"), "unexpected: {err}");
    }

    #[test]
    fn test_console_format_empty_string_accepted() {
        // The empty string is a valid console.format value (inherits
        // app.log.format).
        let config = AppConfig::parse(TEMPLATE).unwrap();
        assert_eq!(config.app.log.console.format, "");
    }

    #[test]
    fn test_rejects_invalid_rolling() {
        let text = TEMPLATE.replace(r#"rolling = "daily""#, r#"rolling = "weekly""#);
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("app.log.file.rolling"), "unexpected: {err}");
        assert!(err.contains("weekly"));
    }

    #[test]
    fn test_rolling_max_size_only_enforced_in_size_mode() {
        // In daily mode any non-negative rolling_max_size is accepted and
        // ignored.
        let text = TEMPLATE.replace(
            "rolling = \"daily\"\nrolling_max_size = 10485760",
            "rolling = \"daily\"\nrolling_max_size = 1",
        );
        assert!(AppConfig::parse(&text).is_ok());

        // size mode: the lower-bound boundary 1048576 is accepted, 1048575
        // rejected.
        for (value, ok) in [("1048576", true), ("1048575", false)] {
            let text = TEMPLATE.replace(
                "rolling = \"daily\"\nrolling_max_size = 10485760",
                &format!("rolling = \"size\"\nrolling_max_size = {value}"),
            );
            let result = AppConfig::parse(&text);
            assert_eq!(result.is_ok(), ok, "value {value} expected ok={ok}");
            if !ok {
                let err = result.unwrap_err();
                assert!(
                    err.contains("app.log.file.rolling_max_size"),
                    "value {value}: {err}"
                );
            }
        }
    }

    #[test]
    fn test_max_days_boundary() {
        for (value, ok) in [("1", true), ("0", false)] {
            let text = TEMPLATE.replace("max_days = 7", &format!("max_days = {value}"));
            let result = AppConfig::parse(&text);
            assert_eq!(result.is_ok(), ok, "value {value} expected ok={ok}");
            if !ok {
                let err = result.unwrap_err();
                assert!(err.contains("app.log.file.max_days"), "{value}: {err}");
            }
        }
        // Negative values are rejected at deserialization (u32 takes no
        // negatives), with the field path.
        let text = TEMPLATE.replace("max_days = 7", "max_days = -1");
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("max_days"), "unexpected: {err}");
    }

    #[test]
    fn test_rejects_watch_interval_out_of_range() {
        for value in ["0", "3601"] {
            let text =
                TEMPLATE.replace("watch_interval = 30", &format!("watch_interval = {value}"));
            let err = AppConfig::parse(&text).unwrap_err();
            assert!(
                err.contains("app.databases.watch_interval"),
                "value {value}: {err}"
            );
        }
        // Negative numbers are rejected at deserialization (u64 takes no
        // negatives), likewise with the field path.
        let text = TEMPLATE.replace("watch_interval = 30", "watch_interval = -1");
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("watch_interval"), "unexpected: {err}");
    }

    #[test]
    fn test_rejects_type_mismatch_with_field_path() {
        let text = TEMPLATE.replace(r#"level = "info""#, "level = 3");
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("failed to parse config"));
        assert!(
            err.contains("app.log.level") || err.contains("level"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_rejects_invalid_toml_syntax() {
        let err = AppConfig::parse("[[databases").unwrap_err();
        assert!(err.contains("failed to parse config"));
    }

    #[test]
    fn test_rejects_duplicate_uid() {
        // Two entries with distinct uid/name make the app section valid; used
        // only to trigger the uid-conflict path.
        let second = r#"
[[databases]]
uid = "primary"
name = "another"
description = "d"
type = "postgres"
dialect = "postgres"
username = "user"
password = "password"
host = "localhost"
port = 5432
db = "app"
"#;
        let text = format!("{TEMPLATE}{second}");
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(
            err.starts_with("duplicate database uid"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_rejects_empty_databases() {
        // The app section kept (valid) but [[databases]] missing:
        // deserialization reports missing field.
        let err = AppConfig::parse("[app.log]\nlevel = \"info\"\n").unwrap_err();
        assert!(
            err.contains("missing field") && err.contains("databases"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_error_messages_contain_no_password_value() {
        let text = TEMPLATE.replace(r#"level = "info""#, r#"level = "nope""#);
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(!err.contains("password"));
    }

    #[test]
    fn test_boundary_watch_interval_values_accepted() {
        for value in ["1", "3600"] {
            let text =
                TEMPLATE.replace("watch_interval = 30", &format!("watch_interval = {value}"));
            assert!(
                AppConfig::parse(&text).is_ok(),
                "value {value} should be accepted"
            );
        }
    }

    #[test]
    fn test_repeated_parse_is_deterministic() {
        let first = AppConfig::parse(TEMPLATE).unwrap();
        let second = AppConfig::parse(TEMPLATE).unwrap();
        assert_eq!(first.app.log.level, second.app.log.level);
        assert_eq!(first.app.log.file.max_days, second.app.log.file.max_days);
        assert_eq!(
            first.app.databases.watch_interval,
            second.app.databases.watch_interval
        );
        assert_eq!(first.databases.len(), second.databases.len());
    }

    #[test]
    fn test_streamable_section_parsed() {
        let text = TEMPLATE.replace(
            "[app.mcp.streamable]\naddr = \"127.0.0.1\"\nport = 8000",
            "[app.mcp.streamable]\naddr = \"0.0.0.0\"\nport = 9000",
        );
        let config = AppConfig::parse(&text).unwrap();
        assert_eq!(config.app.mcp.streamable.addr, "0.0.0.0");
        assert_eq!(config.app.mcp.streamable.port, 9000);
    }

    #[test]
    fn test_streamable_defaults_when_section_missing() {
        let text = TEMPLATE.replace(
            "[app.mcp.streamable]\naddr = \"127.0.0.1\"\nport = 8000\n\n",
            "",
        );
        let config = AppConfig::parse(&text).unwrap();
        assert_eq!(config.app.mcp.streamable.addr, "127.0.0.1");
        assert_eq!(config.app.mcp.streamable.port, 8000);
    }

    #[test]
    fn test_streamable_field_level_defaults() {
        let text = TEMPLATE.replace(
            "[app.mcp.streamable]\naddr = \"127.0.0.1\"\nport = 8000",
            "[app.mcp.streamable]\nport = 9001",
        );
        let config = AppConfig::parse(&text).unwrap();
        assert_eq!(config.app.mcp.streamable.addr, "127.0.0.1");
        assert_eq!(config.app.mcp.streamable.port, 9001);
    }

    #[test]
    fn test_streamable_addr_validation() {
        for (value, ok) in [
            ("0.0.0.0", true),
            ("127.0.0.1", true),
            ("::1", true),
            ("db.internal", true),
            ("", false),
            ("1.2.3.4.5", false),
            ("http://x", false),
            ("-bad", false),
            ("bad-", false),
        ] {
            let text = TEMPLATE.replace(
                "[app.mcp.streamable]\naddr = \"127.0.0.1\"",
                &format!("[app.mcp.streamable]\naddr = \"{value}\""),
            );
            let result = AppConfig::parse(&text);
            assert_eq!(result.is_ok(), ok, "addr {value:?} expected ok={ok}");
            if !ok {
                let err = result.unwrap_err();
                assert!(err.contains("app.mcp.streamable.addr"), "{value}: {err}");
            }
        }
    }

    #[test]
    fn test_streamable_port_validation() {
        for (value, ok) in [("1", true), ("65535", true), ("0", false)] {
            let text = TEMPLATE.replace(
                "[app.mcp.streamable]\naddr = \"127.0.0.1\"\nport = 8000",
                &format!("[app.mcp.streamable]\naddr = \"127.0.0.1\"\nport = {value}"),
            );
            let result = AppConfig::parse(&text);
            assert_eq!(result.is_ok(), ok, "port {value} expected ok={ok}");
            if !ok {
                let err = result.unwrap_err();
                assert!(err.contains("app.mcp.streamable.port"), "{value}: {err}");
            }
        }
        // 65536 and negative values are rejected at deserialization (outside
        // the u16 range), with the field path.
        let text = TEMPLATE.replace(
            "[app.mcp.streamable]\naddr = \"127.0.0.1\"\nport = 8000",
            "[app.mcp.streamable]\naddr = \"127.0.0.1\"\nport = 65536",
        );
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("port"), "{err}");
    }

    #[test]
    fn test_streamable_type_mismatch_rejected() {
        let text = TEMPLATE.replace(
            "[app.mcp.streamable]\naddr = \"127.0.0.1\"",
            "[app.mcp.streamable]\naddr = 3",
        );
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(
            err.contains("addr") || err.contains("failed to parse"),
            "{err}"
        );
    }

    #[test]
    fn test_existing_sections_unchanged_with_streamable() {
        // Regression: existing fields behave unchanged under the new-structure
        // config.
        let text = TEMPLATE.replace(
            "[app.mcp.streamable]\naddr = \"127.0.0.1\"\nport = 8000",
            "[app.mcp.streamable]\nport = 9002",
        );
        let config = AppConfig::parse(&text).unwrap();
        assert_eq!(config.app.log.level, "info");
        assert_eq!(config.app.databases.watch_interval, 30);
        assert_eq!(config.databases.len(), 1);
    }

    #[test]
    fn test_load_missing_file_error_contains_path() {
        let err = AppConfig::load(Path::new("/nonexistent/config.toml")).unwrap_err();
        assert!(err.contains("/nonexistent/config.toml"));
    }

    #[test]
    fn test_ensure_data_dir_creates_recursively_and_is_idempotent() {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "db-query-conf-data-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&root);

        let text = TEMPLATE.replace(
            r#"dir = "./data""#,
            &format!("dir = {:?}", root.join("a/b/c")),
        );
        let config = AppConfig::parse(&text).unwrap();

        // Created recursively when missing.
        config.ensure_data_dir().unwrap();
        assert!(root.join("a/b/c").is_dir());

        // Idempotent success when it already exists; existing content
        // untouched.
        std::fs::write(root.join("a/b/c/keep.txt"), "x").unwrap();
        config.ensure_data_dir().unwrap();
        assert!(root.join("a/b/c/keep.txt").is_file());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_ensure_data_dir_failure_contains_path() {
        // The parent path is a file: create_dir_all necessarily fails with the
        // target path in the error.
        let mut parent = std::env::temp_dir();
        parent.push(format!(
            "db-query-conf-file-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&parent, "x").unwrap();

        let target = format!("{}/child", parent.to_str().unwrap());
        let text = TEMPLATE.replace(r#"dir = "./data""#, &format!("dir = {target:?}"));
        let config = AppConfig::parse(&text).unwrap();

        let err = config.ensure_data_dir().unwrap_err();
        assert!(err.starts_with("failed to create data directory"), "{err}");
        assert!(err.contains("child"), "{err}");

        let _ = std::fs::remove_file(&parent);
    }

    #[test]
    fn test_validator_section_defaults_to_builtin() {
        // The template has no [validator] section: kinds empty (= built-in full
        // set), function empty for all three dialects.
        let config = AppConfig::parse(TEMPLATE).unwrap();
        assert!(config.validator.sql.whitelist.kinds.is_empty());
        assert!(config.validator.sql.pg.blacklist.function.is_empty());
        assert!(config.validator.sql.mysql.blacklist.function.is_empty());
        assert!(config.validator.sql.sqlite.blacklist.function.is_empty());
    }

    #[test]
    fn test_validator_kinds_reject_unknown_and_non_readonly() {
        // Unknown name.
        let text = format!("{TEMPLATE}\n[validator.sql.whitelist]\nkinds = [\"FOO\"]\n");
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(
            err.contains("expected one of QUERY, EXPLAIN, SHOW, DESCRIBE"),
            "{err}"
        );

        // Non-read-only kind: a dedicated error explaining it cannot be
        // allowed.
        let text = format!("{TEMPLATE}\n[validator.sql.whitelist]\nkinds = [\"QUERY\", \"DML\"]\n");
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(
            err.contains("can never be allowed via configuration"),
            "{err}"
        );

        // A valid subset (including lowercase forms) passes.
        let text =
            format!("{TEMPLATE}\n[validator.sql.whitelist]\nkinds = [\"query\", \"Explain\"]\n");
        let config = AppConfig::parse(&text).unwrap();
        assert_eq!(config.validator.sql.whitelist.kinds.len(), 2);
    }

    #[test]
    fn test_validator_unknown_dialect_section_rejected() {
        let text = format!("{TEMPLATE}\n[validator.sql.oracle.blacklist]\nfunction = [\"f\"]\n");
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("unknown field"), "{err}");
        assert!(err.contains("oracle"), "{err}");
    }

    #[test]
    fn test_validator_function_name_must_be_plain_identifier() {
        let text = format!("{TEMPLATE}\n[validator.sql.pg.blacklist]\nfunction = [\"bad;name\"]\n");
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("plain identifier"), "{err}");

        let text = format!("{TEMPLATE}\n[validator.sql.pg.blacklist]\nfunction = [\"my_func\"]\n");
        let config = AppConfig::parse(&text).unwrap();
        assert_eq!(config.validator.sql.pg.blacklist.function, ["my_func"]);
    }
}
