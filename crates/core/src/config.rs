//! Application config: load and validate `config.toml` following the
//! structure of `config.template.toml`.
//!
//! Three sections: `[app]` (log level), `[app.databases]` (global watch
//! parameters), and `[[databases]]` (multiple database connections).
//! Failed validation returns an English error naming the field path;
//! error messages never contain any credential values.

use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;

/// Legal values for the log level.
const LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];

/// Legal range for `watch_interval` (seconds).
const WATCH_INTERVAL_MIN: u64 = 1;
const WATCH_INTERVAL_MAX: u64 = 3600;

/// Validate the listen address form: IPv4 / IPv6 (standard library
/// parsing) or a hostname (alphanumerics plus `-` and `.`, labels not
/// starting/ending with `-`, total length <= 253).
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
            // All-numeric labels are treated as malformed IPs (e.g.
            // 1.2.3.4.5) and rejected for listen addresses.
            && !label.chars().all(|c| c.is_ascii_digit())
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Application config, corresponding to the root table of `config.toml`.
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    /// The `[app]` section (including its `[app.databases]` sub-table);
    /// may be omitted entirely.
    #[serde(default)]
    pub app: AppConfigSection,
    /// Multiple database connection configs; the query target is selected
    /// by `name`.
    pub databases: Vec<DatabaseConfig>,
}

/// The `[app]` section config; `[app.databases]` is its sub-table, mapped
/// via [`AppDatabasesSection`].
#[derive(Debug, Deserialize)]
pub struct AppConfigSection {
    /// Log level, defaults to `info`.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// The `[app.mcp]` sub-table (MCP service parameters); may be omitted.
    #[serde(default)]
    pub mcp: McpSection,
    /// The `[app.databases]` sub-table (global database watch parameters);
    /// may be omitted.
    #[serde(default)]
    pub databases: AppDatabasesSection,
}

// McpSection contains only one sub-struct whose field-level defaults are
// derive-safe; StreamableSection stays hand-written (deriving would use
// type defaults and bypass the field-level functions).
#[derive(Debug, Default, Deserialize)]
pub struct McpSection {
    /// The `[app.mcp.streamable]` sub-table (Streamable HTTP listen
    /// parameters); may be omitted.
    #[serde(default)]
    pub streamable: StreamableSection,
}

/// The `[app.mcp.streamable]` sub-table: listen parameters for the
/// Streamable HTTP service.
#[derive(Debug, Deserialize)]
pub struct StreamableSection {
    /// Listen address, defaults to `127.0.0.1` (IPv4 / IPv6 or hostname
    /// form).
    #[serde(default = "default_streamable_addr")]
    pub addr: String,
    /// Listen port, defaults to 8000, range 1-65535.
    #[serde(default = "default_streamable_port")]
    pub port: u16,
}

/// The `[app.databases]` sub-table: global parameters applied to all
/// `[[databases]]` entries.
#[derive(Debug, Deserialize)]
pub struct AppDatabasesSection {
    /// Watch interval (seconds), defaults to 30. The field name keeps the
    /// spelling used in the config template.
    #[serde(default = "default_watch_interval")]
    pub watch_interval: u64,
}

// Hand-written Default instead of derive: derived Default overwrites
// field-level serde default functions with type defaults (empty string / 0),
// making the default semantics of "whole section omitted" and "field
// omitted" inconsistent.
impl Default for AppConfigSection {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            mcp: McpSection::default(),
            databases: AppDatabasesSection::default(),
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

fn default_streamable_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_streamable_port() -> u16 {
    8000
}

impl Default for AppDatabasesSection {
    fn default() -> Self {
        Self {
            watch_interval: default_watch_interval(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_watch_interval() -> u64 {
    30
}

/// A single database connection config, corresponding to a
/// `[[databases]]` table.
///
/// Fields like `dialect` / `password` / `extra_opts` are read later by the
/// connection execution layer.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Unique connection identifier; duplicates are rejected.
    pub uid: String,
    /// Name, for users to recognize the target.
    pub name: String,
    /// Brief description of the database scope, to help clients choose a
    /// query target.
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
    /// Extra connection options; may be omitted.
    #[serde(default)]
    pub extra_opts: String,
}

impl AppConfig {
    /// Parse and validate config from TOML text.
    ///
    /// Errors are in English and name the field path; parse errors pass
    /// through toml's line/column information.
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: AppConfig =
            toml::from_str(text).map_err(|e| format!("failed to parse config: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    /// Load and validate config from a file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config file '{}': {e}", path.display()))?;
        Self::parse(&text)
    }

    fn validate(&self) -> Result<(), String> {
        if !LOG_LEVELS.contains(&self.app.log_level.as_str()) {
            return Err(format!(
                "invalid value '{}' for app.log_level: expected one of error, warn, info, debug, trace",
                self.app.log_level
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEMPLATE: &str = r#"
[app]
log_level = "info"

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
        assert_eq!(config.app.log_level, "info");
        assert_eq!(config.app.databases.watch_interval, 30);
        assert_eq!(config.databases.len(), 1);
        assert_eq!(config.databases[0].uid, "primary");
        assert_eq!(config.databases[0].db_type, "postgres");
        assert_eq!(config.databases[0].port, 5432);
    }

    #[test]
    fn test_app_section_optional_defaults() {
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
        assert_eq!(config.app.log_level, "info");
        assert_eq!(config.app.databases.watch_interval, 30);
    }

    #[test]
    fn test_app_databases_subsection_optional() {
        let text = r#"
[app]
log_level = "debug"

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
        assert_eq!(config.app.log_level, "debug");
        assert_eq!(config.app.databases.watch_interval, 30);
    }

    #[test]
    fn test_rejects_invalid_log_level() {
        let text = TEMPLATE.replace(r#"log_level = "info""#, r#"log_level = "verbose""#);
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("app.log_level"), "unexpected: {err}");
        assert!(err.contains("verbose"));
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
        // Negative values are rejected at deserialization (u64 accepts no
        // negatives), also including the field path.
        let text = TEMPLATE.replace("watch_interval = 30", "watch_interval = -1");
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("watch_interval"), "unexpected: {err}");
    }

    #[test]
    fn test_rejects_type_mismatch_with_field_path() {
        let text = TEMPLATE.replace(r#"log_level = "info""#, "log_level = 3");
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("failed to parse config"));
        assert!(
            err.contains("app.log_level") || err.contains("log_level"),
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
        // Two entries with distinct uid/name keep the app section legal,
        // just to trigger the uid-conflict path.
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
        // Keep the app section (legal) and omit only [[databases]]:
        // deserialization reports a missing field.
        let err = AppConfig::parse("[app]\nlog_level = \"info\"\n").unwrap_err();
        assert!(
            err.contains("missing field") && err.contains("databases"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_error_messages_contain_no_password_value() {
        let text = TEMPLATE.replace(r#"log_level = "info""#, r#"log_level = "nope""#);
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
        assert_eq!(first.app.log_level, second.app.log_level);
        assert_eq!(
            first.app.databases.watch_interval,
            second.app.databases.watch_interval
        );
        assert_eq!(first.databases.len(), second.databases.len());
    }

    #[test]
    fn test_streamable_section_parsed() {
        let text = TEMPLATE.replace(
            "[app]\nlog_level = \"info\"",
            "[app]\nlog_level = \"info\"\n\n[app.mcp.streamable]\naddr = \"0.0.0.0\"\nport = 9000",
        );
        let config = AppConfig::parse(&text).unwrap();
        assert_eq!(config.app.mcp.streamable.addr, "0.0.0.0");
        assert_eq!(config.app.mcp.streamable.port, 9000);
    }

    #[test]
    fn test_streamable_defaults_when_section_missing() {
        let config = AppConfig::parse(TEMPLATE).unwrap();
        assert_eq!(config.app.mcp.streamable.addr, "127.0.0.1");
        assert_eq!(config.app.mcp.streamable.port, 8000);
    }

    #[test]
    fn test_streamable_field_level_defaults() {
        let text = TEMPLATE.replace(
            "[app]\nlog_level = \"info\"",
            "[app]\nlog_level = \"info\"\n\n[app.mcp.streamable]\nport = 9001",
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
                "[app]\nlog_level = \"info\"",
                &format!("[app]\nlog_level = \"info\"\n\n[app.mcp.streamable]\naddr = \"{value}\""),
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
                "[app]\nlog_level = \"info\"",
                &format!("[app]\nlog_level = \"info\"\n\n[app.mcp.streamable]\nport = {value}"),
            );
            let result = AppConfig::parse(&text);
            assert_eq!(result.is_ok(), ok, "port {value} expected ok={ok}");
            if !ok {
                let err = result.unwrap_err();
                assert!(err.contains("app.mcp.streamable.port"), "{value}: {err}");
            }
        }
        // 65536 and negatives are rejected at deserialization (out of u16
        // range), including the field path.
        let text = TEMPLATE.replace(
            "[app]\nlog_level = \"info\"",
            "[app]\nlog_level = \"info\"\n\n[app.mcp.streamable]\nport = 65536",
        );
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(err.contains("port"), "{err}");
    }

    #[test]
    fn test_streamable_type_mismatch_rejected() {
        let text = TEMPLATE.replace(
            "[app]\nlog_level = \"info\"",
            "[app]\nlog_level = \"info\"\n\n[app.mcp.streamable]\naddr = 3",
        );
        let err = AppConfig::parse(&text).unwrap_err();
        assert!(
            err.contains("addr") || err.contains("failed to parse"),
            "{err}"
        );
    }

    #[test]
    fn test_existing_sections_unchanged_with_streamable() {
        // Regression: existing fields behave unchanged in configs
        // containing the new section.
        let text = TEMPLATE.replace(
            "[app]\nlog_level = \"info\"",
            "[app]\nlog_level = \"debug\"\n\n[app.mcp.streamable]\nport = 9002",
        );
        let config = AppConfig::parse(&text).unwrap();
        assert_eq!(config.app.log_level, "debug");
        assert_eq!(config.app.databases.watch_interval, 30);
        assert_eq!(config.databases.len(), 1);
    }

    #[test]
    fn test_load_missing_file_error_contains_path() {
        let err = AppConfig::load(Path::new("/nonexistent/config.toml")).unwrap_err();
        assert!(err.contains("/nonexistent/config.toml"));
    }
}
