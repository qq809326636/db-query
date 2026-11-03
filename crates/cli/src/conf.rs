//! conf command group: load / show / validate / generate.

use clap::Args as ClapArgs;

/// Built-in config template: embedded at compile time from the repo
/// root's config.template.toml as the single source of truth.
const TEMPLATE: &str = include_str!("../../../config.template.toml");

/// `excapp-db conf` arguments.
#[derive(Debug, ClapArgs)]
pub struct ConfArgs {
    #[command(subcommand)]
    command: ConfCommand,
}

/// conf subcommands.
#[derive(Debug, clap::Subcommand)]
enum ConfCommand {
    /// Load and validate the config, printing a key-info summary.
    Load {
        /// Config file path.
        #[arg(long, default_value = "config.toml")]
        config: std::path::PathBuf,
    },
    /// Print the full parsed result (password shown as a placeholder).
    Show {
        /// Config file path.
        #[arg(long, default_value = "config.toml")]
        config: std::path::PathBuf,
    },
    /// Validate the config only (no output when valid).
    Validate {
        /// Config file path.
        #[arg(long, default_value = "config.toml")]
        config: std::path::PathBuf,
    },
    /// Generate a config file from the built-in template.
    Generate {
        /// Output path (defaults to printing to stdout).
        #[arg(long)]
        output: Option<std::path::PathBuf>,
        /// Force overwrite when the target exists.
        #[arg(long)]
        force: bool,
    },
}

/// conf command entry: returns the process exit code.
pub fn run(args: ConfArgs) -> i32 {
    match args.command {
        ConfCommand::Load { config } => load(&config),
        ConfCommand::Show { config } => show(&config),
        ConfCommand::Validate { config } => validate(&config),
        ConfCommand::Generate { output, force } => generate(output, force),
    }
}

fn load(path: &std::path::Path) -> i32 {
    let config = match excapp_db_core::config::AppConfig::load(path) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    println!("config: {}", path.display());
    println!(
        "log_level: {}  watch_interval: {}s",
        config.app.log_level, config.app.databases.watch_interval
    );
    println!(
        "streamable: {}:{}",
        config.app.mcp.streamable.addr, config.app.mcp.streamable.port
    );
    println!("databases: {}", config.databases.len());
    for db in &config.databases {
        println!(
            "  - {}  {}  ({})  {}:{}/{}",
            db.uid, db.name, db.db_type, db.host, db.port, db.db
        );
    }
    0
}

fn show(path: &std::path::Path) -> i32 {
    let config = match excapp_db_core::config::AppConfig::load(path) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    println!("log_level = {:?}", config.app.log_level);
    println!("watch_interval = {}", config.app.databases.watch_interval);
    println!("streamable.addr = {:?}", config.app.mcp.streamable.addr);
    println!("streamable.port = {}", config.app.mcp.streamable.port);
    for db in &config.databases {
        println!("[[databases]]");
        println!("uid = {:?}", db.uid);
        println!("name = {:?}", db.name);
        println!("description = {:?}", db.description);
        println!("type = {:?}", db.db_type);
        println!("dialect = {:?}", db.dialect);
        println!("username = {:?}", db.username);
        println!("password = <hidden>");
        println!("host = {:?}", db.host);
        println!("port = {}", db.port);
        println!("db = {:?}", db.db);
        println!("extra_opts = {:?}", db.extra_opts);
    }
    0
}

fn validate(path: &std::path::Path) -> i32 {
    match excapp_db_core::config::AppConfig::load(path) {
        Ok(_) => 0,
        Err(e) => fail(&e),
    }
}

fn generate(output: Option<std::path::PathBuf>, force: bool) -> i32 {
    let Some(path) = output else {
        print!("{TEMPLATE}");
        return 0;
    };
    if path.exists() && !force {
        return fail(&format!(
            "file '{}' already exists; use --force to overwrite",
            path.display()
        ));
    }
    if let Err(e) = std::fs::write(&path, TEMPLATE) {
        return fail(&format!("failed to write '{}': {e}", path.display()));
    }
    println!("generated: {}", path.display());
    0
}

fn fail(message: &str) -> i32 {
    eprintln!("excapp-db: {message}");
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_embedded_matches_source() {
        // The built-in template is byte-identical to the repo file (a
        // compile-time guarantee of the single source of truth).
        // The test cwd is the crate root (crates/cli).
        let repo = std::fs::read_to_string("../../config.template.toml").unwrap();
        assert_eq!(TEMPLATE, repo);
    }
}
