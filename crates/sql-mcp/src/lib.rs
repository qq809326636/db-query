//! db-query MCP server: MCP wrapper over the validate->execute pipeline
//! (six tools, dual transports).

pub mod bootstrap;
pub mod prompts;
pub mod state;
pub mod tools;

pub use bootstrap::{run_stdio, run_streamable};
pub use state::{ConnectionInfo, ExecutorSet, SharedState};
pub use tools::DbQueryServer;
