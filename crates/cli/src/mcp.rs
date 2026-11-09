//! (SIGTERM shutdown).

use clap::Args as ClapArgs;
use std::path::PathBuf;

/// `excapp-db mcp` arguments.
#[derive(Debug, ClapArgs)]
pub struct McpArgs {
    #[command(subcommand)]
    command: McpCommand,
}

/// mcp subcommands.
#[derive(Debug, clap::Subcommand)]
enum McpCommand {
    /// Start the MCP server in the foreground (streamable mode writes a
    Start {
        /// Transport mode.
        #[arg(long, value_enum, default_value_t = Transport::Stdio)]
        transport: Transport,
        /// Config file path.
        #[arg(long, default_value = "config.toml")]
        config: PathBuf,
        /// dir).
        #[arg(long)]
        pidfile: Option<PathBuf>,
    },
    /// Stop a running MCP server (reads the pid file and sends SIGTERM).
    Stop {
        /// Pid file path (same as start).
        #[arg(long)]
        pidfile: Option<PathBuf>,
    },
}

/// Transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Transport {
    /// stdin/stdout protocol (local clients).
    Stdio,
    /// Streamable HTTP (listens on the configured address).
    Streamable,
}

/// mcp command entry: returns the process exit code.
pub fn run(args: McpArgs) -> i32 {
    match args.command {
        McpCommand::Start {
            transport,
            config,
            pidfile,
        } => start(transport, &config, pidfile),
        McpCommand::Stop { pidfile } => stop(pidfile),
    }
}

/// Default pid file path: excapp-db.pid under the system temp dir.
fn default_pidfile() -> PathBuf {
    std::env::temp_dir().join("excapp-db.pid")
}

fn start(transport: Transport, config: &std::path::Path, pidfile: Option<PathBuf>) -> i32 {
    let pid_path = pidfile.unwrap_or_else(default_pidfile);

    // streamable: pid management (pre-write + rollback on failure; stale
    let pid_guard = if transport == Transport::Streamable {
        match check_existing_pid(&pid_path) {
            Ok(()) => {}
            Err(code) => return code,
        }
        let pid = std::process::id();
        if let Err(e) = std::fs::write(&pid_path, format!("{pid}\n")) {
            return fail(&format!(
                "failed to write pid file '{}': {e}",
                pid_path.display()
            ));
        }
        Some(PidGuard { path: pid_path })
    } else {
        None // stdio mode writes no pid (the local client manages the
        // process).
    };

    let code = match transport {
        Transport::Stdio => {
            let runtime = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
            runtime.block_on(excapp_db_sql_mcp::run_stdio(config))
        }
        Transport::Streamable => {
            let runtime = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
            let code = runtime.block_on(excapp_db_sql_mcp::run_streamable(config));
            // Failure rollback: clean up the pre-written pid file on
            if code != 0
                && let Some(guard) = &pid_guard
            {
                guard.remove();
            }
            code
        }
    };

    // Normal exit (including graceful SIGTERM exit): clean up the pid
    if code == 0
        && let Some(guard) = &pid_guard
    {
        guard.remove();
    }
    code
}

/// Pid file guard: Drop / explicit removal.
struct PidGuard {
    path: PathBuf,
}

impl PidGuard {
    fn remove(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        // Last-resort cleanup: explicit remove already handles the
        let _ = std::fs::remove_file(&self.path);
    }
}
/// Check the pid file: a live instance is rejected (returns an exit
/// code); a stale one is overwritten and startup continues.
fn check_existing_pid(path: &std::path::Path) -> Result<(), i32> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Ok(()); // No pid file: start normally.
    };
    let Ok(pid) = content.trim().parse::<i32>() else {
        // Corrupted file: clean up and continue.
        let _ = std::fs::remove_file(path);
        return Ok(());
    };
    if is_alive(pid) {
        return Err(fail(&format!(
            "another excapp-db instance is running (pid {pid}); pid file: {}",
            path.display()
        )));
    }
    // Stale: overwrite (the caller writes the new pid).
    Ok(())
}

fn stop(pidfile: Option<PathBuf>) -> i32 {
    let pid_path = pidfile.unwrap_or_else(default_pidfile);

    let content = match std::fs::read_to_string(&pid_path) {
        Ok(c) => c,
        Err(_) => {
            return fail(&format!(
                "no running instance found; pid file '{}' does not exist",
                pid_path.display()
            ));
        }
    };
    let pid = match content.trim().parse::<i32>() {
        Ok(p) => p,
        Err(_) => {
            let _ = std::fs::remove_file(&pid_path);
            return fail(&format!(
                "pid file '{}' is corrupted; removed",
                pid_path.display()
            ));
        }
    };

    if !is_alive(pid) {
        let _ = std::fs::remove_file(&pid_path);
        return fail(&format!(
            "stale pid file (pid {pid} not running); removed '{}'",
            pid_path.display()
        ));
    }

    // SIGTERM.
    if let Err(e) = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGTERM,
    ) {
        return fail(&format!("failed to send SIGTERM to pid {pid}: {e}"));
    }

    // Liveness polling: 100ms granularity, 10-second cap.
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if !is_alive(pid) {
            let _ = std::fs::remove_file(&pid_path);
            println!("stopped excapp-db (pid {pid})");
            return 0;
        }
    }
    eprintln!(
        "excapp-db: pid {pid} did not exit within 10s; consider 'kill -9 {pid}' (pid file kept)"
    );
    1
}

/// kill(pid, 0) zero-signal liveness probe: true means the process
fn is_alive(pid: i32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
}

fn fail(message: &str) -> i32 {
    eprintln!("excapp-db: {message}");
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_alive_self() {
        assert!(is_alive(std::process::id() as i32));
    }

    #[test]
    fn test_is_alive_dead_pid() {
        // A pid that cannot exist (beyond the pid_max limit).
        assert!(!is_alive(4_194_303));
    }

    #[test]
    fn test_stop_missing_pidfile() {
        let path =
            std::env::temp_dir().join(format!("excapp-db-test-missing-{}.pid", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let code = stop(Some(path.clone()));
        assert_eq!(code, 1);
        assert!(!path.exists());
    }

    #[test]
    fn test_stop_stale_pidfile() {
        let path =
            std::env::temp_dir().join(format!("excapp-db-test-stale-{}.pid", std::process::id()));
        std::fs::write(&path, "4194303\n").unwrap();
        let code = stop(Some(path.clone()));
        assert_eq!(code, 1);
        assert!(!path.exists(), "stale pid file should be removed");
    }

    #[test]
    fn test_stop_corrupted_pidfile() {
        let path =
            std::env::temp_dir().join(format!("excapp-db-test-corrupt-{}.pid", std::process::id()));
        std::fs::write(&path, "not-a-pid").unwrap();
        let code = stop(Some(path.clone()));
        assert_eq!(code, 1);
        assert!(!path.exists(), "corrupted pid file should be removed");
    }

    #[test]
    fn test_check_existing_pid_alive_rejects() {
        let path =
            std::env::temp_dir().join(format!("excapp-db-test-alive-{}.pid", std::process::id()));
        std::fs::write(&path, format!("{}\n", std::process::id())).unwrap();
        let result = check_existing_pid(&path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(&path);
    }
}
