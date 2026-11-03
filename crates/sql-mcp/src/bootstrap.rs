//! Server startup assembly: config -> logging -> executor set ->
//! scheduler -> transport server.
//!
//! Fail fast: an invalid config / unsupported db_type exits (non-zero);
//! an unreachable database does not block startup (lazy connections, the
//! health check discovers it later). Config hot reload: the
//! WatchScheduler change callback atomically swaps the executor set
//! without restarting the transport server.

use crate::{DbQueryServer, ExecutorSet, SharedState};
use std::path::Path;
use std::sync::Arc;

/// Common startup sequence: returns (config, shared state).
///
/// Any structural error returns an English message (printed to stderr,
/// non-zero exit).
async fn setup(
    config_path: &Path,
    log_target: excapp_db_core::logger::LogTarget,
) -> Result<(excapp_db_core::config::AppConfig, SharedState), String> {
    let config = excapp_db_core::config::AppConfig::load(config_path)?;

    // Logging init: stdio mode logs to stderr (stdout is the protocol
    // channel).
    excapp_db_core::logger::init_with_target(&config, log_target)
        .map_err(|e| format!("logging initialization failed: {e}"))?;

    // Executor set: an unsupported db_type fails the whole set (fail
    // fast, database name included).
    let set = ExecutorSet::build(&config)?;
    let state = SharedState::new(set);

    Ok((config, state))
}

/// Start the WatchScheduler: health checks (per database) + config hot
/// reload (atomic swap).
fn start_scheduler(
    config_path: &Path,
    config: &excapp_db_core::config::AppConfig,
    state: &SharedState,
) -> excapp_db_core::watch::WatchHandle {
    let interval = config.app.databases.watch_interval;
    let path = config_path.to_path_buf();
    let state = state.clone();

    // Health checks: one per database (sql-executor's PgHealthCheck).
    // The scheduler accepts a single HealthCheck implementation; a
    // combinator aggregates the per-database checks.
    let mut checks: Vec<excapp_db_sql_executor::pg::PgHealthCheck> = Vec::new();
    for db in &config.databases {
        if let Some(executor) = state.executor(&db.uid) {
            checks.push(excapp_db_sql_executor::pg::PgHealthCheck::new(
                executor.shared_pool(),
            ));
        }
    }
    let health = CombinedHealthCheck { checks };

    excapp_db_core::watch::start(path.clone(), interval, health, move |new_config| {
        // Config change: build a new set and swap atomically; on failure
        // the scheduler layer keeps the old set.
        match ExecutorSet::build(&new_config) {
            Ok(new_set) => {
                state.replace(new_set);
                tracing::info!(
                    "config reloaded: {} database(s) active",
                    new_config.databases.len()
                );
            }
            Err(e) => {
                // Theoretically unreachable (the scheduler layer already
                // validated the config); logged defensively.
                tracing::error!("config reload produced invalid executor set: {e}");
            }
        }
    })
}

/// Multi-database health check combinator: probes each database,
/// aggregating failures into one English message.
struct CombinedHealthCheck {
    checks: Vec<excapp_db_sql_executor::pg::PgHealthCheck>,
}

impl excapp_db_core::watch::HealthCheck for CombinedHealthCheck {
    fn check(&mut self) -> Result<(), String> {
        let mut failures: Vec<String> = Vec::new();
        for check in &mut self.checks {
            if let Err(e) = excapp_db_core::watch::HealthCheck::check(check) {
                failures.push(e);
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

/// stdio mode: MCP protocol over stdin/stdout, logs to stderr.
pub async fn run_stdio(config_path: &Path) -> i32 {
    let (_config, state) = match setup(config_path, excapp_db_core::logger::LogTarget::Stderr).await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sql-mcp: {e}");
            return 1;
        }
    };

    let server = DbQueryServer::new(state);
    let _scheduler_guard = SchedulerStarter::start_for(config_path, &_config, &server.state);

    // rmcp stdio: stdin EOF means exit (exit code 0).
    let transport = rmcp::transport::stdio();
    match rmcp::serve_server(server, transport).await {
        Ok(running) => {
            let _ = running.waiting().await;
            0
        }
        Err(e) => {
            eprintln!("sql-mcp: stdio server failed: {e}");
            1
        }
    }
}

/// streamable mode: HTTP listener + graceful shutdown.
pub async fn run_streamable(config_path: &Path) -> i32 {
    let (config, state) = match setup(config_path, excapp_db_core::logger::LogTarget::Stdout).await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sql-mcp: {e}");
            return 1;
        }
    };
    let addr = format!(
        "{}:{}",
        config.app.mcp.streamable.addr, config.app.mcp.streamable.port
    );
    let server = DbQueryServer::new(state);
    let _scheduler_guard = SchedulerStarter::start_for(config_path, &config, &server.state);

    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };

    // Disable DNS rebinding protection (Host header validation): any
    // Host header is accepted, which suits LAN IP / domain / port-mapping
    // deployments. The security boundary is delegated to the deployment
    // layer (network isolation / reverse proxy) — consistent with this
    // project's "MCP access implies trust" model.
    let http_config = StreamableHttpServerConfig::default().disable_allowed_hosts();

    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        http_config,
    );

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sql-mcp: failed to bind {addr}: {e}");
            return 1;
        }
    };
    tracing::info!("streamable http server listening on http://{addr}/mcp");
    eprintln!("sql-mcp: streamable http server listening on http://{addr}/mcp");

    // axum routing: StreamableHttpService mounted at /mcp; 1 MB request
    // body limit.
    let app = axum_router(service);

    // Graceful shutdown: SIGTERM/SIGINT -> stop accepting connections ->
    // drain (10 s cap).
    let shutdown = async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("failed to install SIGINT handler");
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
    };

    match axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sql-mcp: http server failed: {e}");
            1
        }
    }
}

/// rmcp Streamable HTTP service type (this server + local session
/// manager).
type McpService = rmcp::transport::streamable_http_server::StreamableHttpService<
    DbQueryServer,
    rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
>;

/// axum routing assembly: `/mcp` nests the rmcp StreamableHttpService
/// (a tower Service).
fn axum_router(service: McpService) -> axum::Router {
    axum::Router::new().nest_service("/mcp", service)
}

/// Scheduler startup wrapper: stops on Drop (same lifetime as the
/// transport server).
struct SchedulerStarter;

impl SchedulerStarter {
    fn start_for(
        config_path: &Path,
        config: &excapp_db_core::config::AppConfig,
        state: &SharedState,
    ) -> Box<dyn std::ops::Deref<Target = excapp_db_core::watch::WatchHandle>> {
        let handle = start_scheduler(config_path, config, state);
        Box::new(SchedulerGuard(handle))
    }
}

/// Scheduler handle guard (stops on Drop, avoiding a lifetime-shortening
/// warning).
struct SchedulerGuard(excapp_db_core::watch::WatchHandle);

impl std::ops::Deref for SchedulerGuard {
    type Target = excapp_db_core::watch::WatchHandle;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
