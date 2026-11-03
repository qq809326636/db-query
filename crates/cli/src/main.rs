//! excapp-db CLI: entry point and dispatch for the conf / mcp / sql
//! command groups.

mod conf;
mod mcp;
mod sql;

use clap::Parser;

/// excapp-db: db-query read-only database query toolset.
#[derive(Debug, Parser)]
#[command(name = "excapp-db", version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

/// Top-level subcommands.
#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Config management: load / show / validate / generate.
    Conf(conf::ConfArgs),
    /// MCP server lifecycle: start / stop.
    Mcp(mcp::McpArgs),
    /// SQL validation and execution.
    Sql(sql::SqlArgs),
}

fn main() {
    let args = Args::parse();
    let code = match args.command {
        Command::Conf(cmd) => conf::run(cmd),
        Command::Mcp(cmd) => mcp::run(cmd),
        Command::Sql(cmd) => {
            let runtime = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
            runtime.block_on(sql::run(cmd))
        }
    };
    std::process::exit(code);
}
