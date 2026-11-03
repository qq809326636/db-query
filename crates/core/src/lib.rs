//! core crate: technical infrastructure shared across servers.
//!
//! Hosts purely technical components such as state storage (AppState) and
//! config loading (`config.toml` -> `AppConfig`) for reuse by binaries
//! like sql-mcp / cli.
//! Constraint: no business logic, no global static state.

pub mod config;
pub mod logger;
pub mod watch;
