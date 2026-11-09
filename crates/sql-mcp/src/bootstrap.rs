//!
//! Fail fast: an invalid config or an unsupported db_type exits non-zero; an
//! unreachable database does not block startup (lazy connections, health checks
//! find out later). Config hot reload: the WatchScheduler change callback
//! atomically swaps the executor set without restarting the transport server.

use crate::{DbQueryServer, ExecutorSet, SharedState};
use std::path::Path;
use std::sync::Arc;
/// Common startup sequence: returns (config, shared state, schedule handle).
///
/// Any structural error returns an English message (printed to stderr, exiting
/// non-zero).
async fn setup(
    config_path: &Path,
    mode: excapp_db_core::logger::TransportMode,
) -> Result<(excapp_db_core::config::AppConfig, SharedState), String> {
    let config = excapp_db_core::config::AppConfig::load(config_path)?;

    // Data root directory: ensured to exist after loading (idempotent creation;
    config.ensure_data_dir()?;
    // Logging initialization: console is disabled in stdio mode (stdout is the
    // protocol channel).
    excapp_db_core::logger::init(&config, mode)
        .map_err(|e| format!("logging initialization failed: {e}"))?;
    // Executor set: an unsupported db_type fails the whole set (fail fast, with
    // the database name); the validation policy is built alongside (core already
    // ran startup validation; this second line of defense also fails fast).
    let set = ExecutorSet::build(&config)?;
    let policy = ExecutorSet::build_policy(&config)?;
    let state = SharedState::with_policy(set, policy);

    Ok((config, state))
}
/// Start the WatchScheduler: health checks (per database) + config hot reload
/// (atomic swap).
fn start_scheduler(
    config_path: &Path,
    config: &excapp_db_core::config::AppConfig,
    state: &SharedState,
) -> excapp_db_core::watch::WatchHandle {
    let interval = config.app.databases.watch_interval;
    let path = config_path.to_path_buf();
    let state = state.clone();

    // Health checks: one per database (the matching implementation per db_type).
    // The scheduler accepts a single HealthCheck implementation; a combinator
    let mut checks: Vec<Box<dyn excapp_db_core::watch::HealthCheck>> = Vec::new();
    for db in &config.databases {
        if let Some(executor) = state.executor(&db.uid) {
            let check: Box<dyn excapp_db_core::watch::HealthCheck> = match &*executor {
                excapp_db_sql_executor::DatabaseExecutor::Pg(e) => Box::new(
                    excapp_db_sql_executor::pg::PgHealthCheck::new(e.shared_pool()),
                ),
                excapp_db_sql_executor::DatabaseExecutor::MySql(e) => Box::new(
                    excapp_db_sql_executor::mysql::MyHealthCheck::new(e.shared_pool()),
                ),
                excapp_db_sql_executor::DatabaseExecutor::Sqlite(e) => Box::new(
                    excapp_db_sql_executor::sqlite::SqliteHealthCheck::new(e.shared_pool()),
                ),
                excapp_db_sql_executor::DatabaseExecutor::Redis(e) => Box::new(
                    excapp_db_sql_executor::redis::RedisHealthCheck::new(e.shared_pool()),
                ),
            };
            checks.push(check);
        }
    }
    let health = CombinedHealthCheck { checks };

    excapp_db_core::watch::start(path.clone(), interval, health, move |new_config| {
        // scheduler layer keeps the old set.
        match ExecutorSet::build(&new_config) {
            Ok(new_set) => {
                // (logged only, not blocking the executor-set swap).
                match ExecutorSet::build_policy(&new_config) {
                    Ok(new_policy) => state.replace_policy(new_policy),
                    Err(e) => {
                        tracing::error!("config reload produced invalid validator policy: {e}");
                    }
                }
                state.replace(new_set);
                tracing::info!(
                    "config reloaded: {} database(s) active",
                    new_config.databases.len()
                );
            }
            Err(e) => {
                // Theoretically unreachable (the scheduler layer already validated
                tracing::error!("config reload produced invalid executor set: {e}");
            }
        }
    })
}
/// Multi-database health-check combinator: probes each database, aggregating
/// failures into a single English message.
struct CombinedHealthCheck {
    checks: Vec<Box<dyn excapp_db_core::watch::HealthCheck>>,
}

impl excapp_db_core::watch::HealthCheck for CombinedHealthCheck {
    fn check(&mut self) -> Result<(), String> {
        let mut failures: Vec<String> = Vec::new();
        for check in &mut self.checks {
            if let Err(e) = check.check() {
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

/// stdio mode: the stdin/stdout MCP protocol, logging to stderr.
pub async fn run_stdio(config_path: &Path) -> i32 {
    let (_config, state) =
        match setup(config_path, excapp_db_core::logger::TransportMode::Stdio).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("sql-mcp: {e}");
                return 1;
            }
        };

    let server = DbQueryServer::new(state);
    let _scheduler_guard = SchedulerStarter::start_for(config_path, &_config, &server.state);

    // rmcp stdio: stdin EOF exits (exit code 0).
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

/// streamable mode: HTTP listening + graceful shutdown.
pub async fn run_streamable(config_path: &Path) -> i32 {
    let (config, state) =
        match setup(config_path, excapp_db_core::logger::TransportMode::Standard).await {
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

    // DNS rebinding protection (Host header validation) disabled: any Host
    // header is accepted, suiting LAN IP / domain / port-mapping deployments.
    // The security boundary is delegated to the deployment layer (network
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

    // axum routing: /mcp mounts the StreamableHttpService; 1 MB request body
    let app = axum_router(service);
    // Graceful shutdown: SIGTERM/SIGINT → stop accepting new connections →
    // drain (10 s ceiling).
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

/// The rmcp Streamable HTTP service type (this service + local session
type McpService = rmcp::transport::streamable_http_server::StreamableHttpService<
    DbQueryServer,
    rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
>;

/// axum route assembly: `/mcp` embeds the rmcp StreamableHttpService (a tower
fn axum_router(service: McpService) -> axum::Router {
    axum::Router::new().nest_service("/mcp", service)
}
/// Schedule-start wrapper: stopped on Drop (same lifecycle as the transport
/// server).
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

/// Schedule handle guard (stops on Drop, avoiding shortened-lifetime warnings).
struct SchedulerGuard(excapp_db_core::watch::WatchHandle);

impl std::ops::Deref for SchedulerGuard {
    type Target = excapp_db_core::watch::WatchHandle;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
