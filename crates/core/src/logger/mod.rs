//! Logging init: assembles console / file output targets per the
//! `[app.log]` config.
//!
//! Each binary calls [`init`] at the earliest point of startup; a
//! repeated init in the same process returns the `logging is already
//! initialized` error (the tracing global subscriber can be installed
//! only once — returning an error instead of an idempotent success
//! avoids masking config races where a second set of parameters never
//! takes effect).
//!
//! Output targets: console (stdout) and file (rolling segments, the
//! `rotation` submodule) start and stop independently; `text` / `json`
//! formats apply independently. The two warnings (console disabled in
//! stdio mode, all targets off) are written directly to stderr once
//! each, before the subscriber is installed.

mod rotation;

use crate::config::AppConfig;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Transport mode: decides how the console output target is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// Regular mode: the console target (when enabled) writes stdout.
    Standard,
    /// stdio MCP transport: stdout is the protocol channel, so the
    /// console target is forcibly disabled (one warning printed to
    /// stderr); the file target is unaffected.
    Stdio,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    /// Human-readable text (the existing format semantics).
    Text,
    /// Structured output, one JSON object per line.
    Json,
}

/// Initialize global logging from the config and transport mode.
///
/// - The level comes from `app.log.level` (already validated at load
///   time) and applies uniformly to all enabled targets;
/// - console layer: writes stdout when `Standard` and `console.enabled`,
///   with `console.format` (empty string inherits `app.log.format`);
/// - file layer: writes rolling segments when `file.enabled` (a
///   construction failure fails the init), with `file.format`
///   (default json);
/// - `Stdio` with `console.enabled`: disables console and writes one
///   warning directly to stderr;
/// - all targets off: installs a zero-output subscriber (all events
///   dropped), writes one warning directly to stderr, and runs
///   silently;
/// - calling again after success returns `Err("logging is already
///   initialized")` without panicking.
pub fn init(config: &AppConfig, mode: TransportMode) -> Result<(), String> {
    let log = &config.app.log;

    // Pure in-memory parsing first: invalid values return before any
    // IO resource is constructed (defensive fallback; the normal path
    // is guaranteed by load-time validation).
    let level =
        parse_level(&log.level).ok_or_else(|| format!("unknown log level: {}", log.level))?;
    let console_format = parse_format(&resolve_console_format(log))?;
    let file_format = parse_format(&log.file.format)?;

    // File target construction (fail fast: directory creation / unknown
    // policy fails the init). When disabled, a sink placeholder keeps
    // the subscriber structure constant; the off semantics are
    // expressed via the OFF filter.
    let file_writer = if log.file.enabled {
        rotation::RollingWriter::new(
            &log.file,
            &config.app.data.dir,
            std::sync::Arc::new(chrono::Local::now),
        )?
    } else {
        rotation::RollingWriter::sink()
    };

    let console_enabled = mode == TransportMode::Standard && log.console.enabled;

    // The two warnings: written directly to stderr before the subscriber
    // is installed (not via tracing — in the all-off scenario, output
    // via tracing would be dropped by the empty subscriber), once each
    // over the process lifetime.
    if mode == TransportMode::Stdio && log.console.enabled {
        eprintln!(
            "warning: console logging is disabled in stdio mode (stdout is reserved for the MCP protocol channel)"
        );
    }
    if !console_enabled && !log.file.enabled {
        eprintln!(
            "warning: no log output target is enabled (app.log.console.enabled and app.log.file.enabled are both disabled); running silently"
        );
    }

    // Assembly: Registry + console layer + file layer; level filtering
    // is set uniformly via with_filter on each layer, applying to all
    // enabled targets consistently; disabled targets use the OFF filter
    // (zero output). text / json are type-level differences (different
    // EventFormatters), and a generic assembly function removes the
    // duplication across the four combination paths.
    let console_filter = if console_enabled {
        level
    } else {
        LevelFilter::OFF
    };
    let file_filter = if log.file.enabled {
        level
    } else {
        LevelFilter::OFF
    };

    match (console_format, file_format) {
        (LogFormat::Text, LogFormat::Text) => assemble(
            fmt::Layer::default()
                .with_writer(std::io::stdout)
                .with_filter(console_filter),
            fmt::Layer::default()
                .with_writer(file_writer)
                .with_filter(file_filter),
        ),
        (LogFormat::Text, LogFormat::Json) => assemble(
            fmt::Layer::default()
                .with_writer(std::io::stdout)
                .with_filter(console_filter),
            fmt::Layer::default()
                .json()
                .with_writer(file_writer)
                .with_filter(file_filter),
        ),
        (LogFormat::Json, LogFormat::Text) => assemble(
            fmt::Layer::default()
                .json()
                .with_writer(std::io::stdout)
                .with_filter(console_filter),
            fmt::Layer::default()
                .with_writer(file_writer)
                .with_filter(file_filter),
        ),
        (LogFormat::Json, LogFormat::Json) => assemble(
            fmt::Layer::default()
                .json()
                .with_writer(std::io::stdout)
                .with_filter(console_filter),
            fmt::Layer::default()
                .json()
                .with_writer(file_writer)
                .with_filter(file_filter),
        ),
    }
}

/// Stack the two layers onto the Registry and install the global
/// subscriber (repeated init returns an English error).
fn assemble<C, F>(console: C, file: F) -> Result<(), String>
where
    C: Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
    F: Layer<tracing_subscriber::layer::Layered<C, tracing_subscriber::Registry>>
        + Send
        + Sync
        + 'static,
{
    tracing_subscriber::registry()
        .with(console)
        .with(file)
        .try_init()
        .map_err(|_| "logging is already initialized".to_string())
}

/// Resolve the console format: an empty `console.format` inherits
/// `app.log.format`; a non-empty one overrides it.
fn resolve_console_format(log: &crate::config::LogSection) -> String {
    if log.console.format.is_empty() {
        log.format.clone()
    } else {
        log.console.format.clone()
    }
}

/// Map a config format string to an output format.
///
/// Config loading has already validated the enum; the normal path
/// always hits. A miss returns an error the caller turns into an init
/// failure (defensive fallback, not a second validation path).
fn parse_format(value: &str) -> Result<LogFormat, String> {
    match value {
        "text" => Ok(LogFormat::Text),
        "json" => Ok(LogFormat::Json),
        other => Err(format!("unknown log format: {other}")),
    }
}

/// Map a config level string to a tracing level filter.
///
/// Config loading has already validated the enum; the normal path
/// always hits. A miss returns None, which the caller turns into an
/// error (defensive fallback, not a second validation path).
fn parse_level(level: &str) -> Option<LevelFilter> {
    match level {
        "error" => Some(LevelFilter::ERROR),
        "warn" => Some(LevelFilter::WARN),
        "info" => Some(LevelFilter::INFO),
        "debug" => Some(LevelFilter::DEBUG),
        "trace" => Some(LevelFilter::TRACE),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_text(log_body: &str) -> String {
        format!(
            "[app.log]\n{log_body}\n\n[[databases]]\n\
             uid = \"a\"\nname = \"a\"\ndescription = \"d\"\ntype = \"postgres\"\n\
             dialect = \"postgres\"\nusername = \"u\"\npassword = \"p\"\n\
             host = \"localhost\"\nport = 5432\ndb = \"app\"\n"
        )
    }

    #[test]
    fn test_parse_level_maps_all_five_levels() {
        assert_eq!(parse_level("error"), Some(LevelFilter::ERROR));
        assert_eq!(parse_level("warn"), Some(LevelFilter::WARN));
        assert_eq!(parse_level("info"), Some(LevelFilter::INFO));
        assert_eq!(parse_level("debug"), Some(LevelFilter::DEBUG));
        assert_eq!(parse_level("trace"), Some(LevelFilter::TRACE));
        assert_eq!(parse_level("verbose"), None);
    }

    #[test]
    fn test_parse_format_maps_both_formats() {
        assert_eq!(parse_format("text"), Ok(LogFormat::Text));
        assert_eq!(parse_format("json"), Ok(LogFormat::Json));
        assert!(parse_format("xml").is_err());
    }

    #[test]
    fn test_resolve_console_format_inherits_and_overrides() {
        // Empty string inherits the upper level.
        let config = AppConfig::parse(&config_text(
            "format = \"text\"\nlevel = \"info\"\n\n[app.log.console]\nformat = \"\"",
        ))
        .unwrap();
        assert_eq!(resolve_console_format(&config.app.log), "text");

        // Non-empty overrides.
        let config = AppConfig::parse(&config_text(
            "format = \"text\"\nlevel = \"info\"\n\n[app.log.console]\nformat = \"json\"",
        ))
        .unwrap();
        assert_eq!(resolve_console_format(&config.app.log), "json");
    }

    #[test]
    fn test_transport_mode_enum_semantics() {
        // The two modes are distinguishable and the enum is complete
        // (Standard / Stdio, two values).
        assert_ne!(TransportMode::Standard, TransportMode::Stdio);
    }

    #[test]
    fn test_init_rejects_unknown_level_defensively() {
        // Construct an invalid level that bypasses load validation:
        // init must return an error instead of panicking.
        let mut config = AppConfig::parse(&config_text("level = \"info\"")).unwrap();
        config.app.log.level = "loud".to_string();
        let err = init(&config, TransportMode::Standard).unwrap_err();
        assert!(err.contains("unknown log level"), "unexpected: {err}");
    }

    #[test]
    fn test_init_rejects_unknown_format_defensively() {
        // Construct an invalid format that bypasses load validation:
        // init returns the error before constructing any IO resource.
        let mut config = AppConfig::parse(&config_text("level = \"info\"")).unwrap();
        config.app.log.format = "xml".to_string();
        let err = init(&config, TransportMode::Standard).unwrap_err();
        assert!(err.contains("unknown log format"), "unexpected: {err}");
    }

    #[test]
    fn test_init_succeeds_then_repeat_returns_error() {
        // The first initializer within the test process; if another
        // test already initialized, the first assertion is skipped
        // (the tracing global subscriber is unique).
        let config = AppConfig::parse(&config_text(
            "level = \"info\"\n\n[app.log.console]\nenabled = true\n\n[app.log.file]\nenabled = false",
        ))
        .unwrap();
        let first = init(&config, TransportMode::Standard);
        if first.is_ok() {
            let second_config = AppConfig::parse(&config_text(
                "level = \"debug\"\n\n[app.log.console]\nenabled = true\n\n[app.log.file]\nenabled = false",
            ))
            .unwrap();
            let second = init(&second_config, TransportMode::Standard);
            assert_eq!(second.unwrap_err(), "logging is already initialized");
        }
    }
}
