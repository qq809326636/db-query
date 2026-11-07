//! Shared state of the executor set: uid addressing, atomic swap on hot reload.
//!
//! The read path (tool calls fetching executors by uid) is lock-free: arc-swap's
//! `load` yields a snapshot reference; the write path (config hot reload)
//! replaces the snapshot wholesale, and in-flight calls holding the old
//! reference finish naturally. Connection metadata (uid / name / description) is
//! maintained with the snapshot for list-connection's local reads.

use excapp_db_core::config::AppConfig;
use excapp_db_sql_executor::DatabaseExecutor;
use excapp_db_sql_validator::{Policy, PolicyBuilder, StatementKind};
use std::collections::HashMap;
use std::sync::Arc;

/// Metadata of a single connection (list-connection output; no connection details).
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Unique config identifier.
    pub uid: String,
    /// Human-recognizable name.
    pub name: String,
    /// Coverage description.
    pub description: String,
    /// SQL dialect (for execute-sql validation; not exposed externally).
    pub dialect: String,
    /// Configured default database name (for database-parameter consistency checks).
    pub db: String,
    /// Database type (output as type by list-connection).
    pub db_type: String,
}

/// Executor-set snapshot (immutable, swapped wholesale).
#[derive(Debug, Default)]
pub struct ExecutorSet {
    /// uid → executor.
    executors: HashMap<String, Arc<DatabaseExecutor>>,
    /// Connection metadata (list-connection).
    connections: Vec<ConnectionInfo>,
}

impl ExecutorSet {
    /// Build the whole set from config.
    ///
    /// An unsupported `db_type` on any database fails the whole set (fail fast,
    /// error carrying the database name); unreachable connections do not error
    /// here (lazy connections, handled at runtime).
    pub fn build(config: &excapp_db_core::config::AppConfig) -> Result<Self, String> {
        let mut executors = HashMap::new();
        let mut connections = Vec::new();
        for db in &config.databases {
            let executor = excapp_db_sql_executor::build_executor(db).map_err(|e| e.to_string())?;
            executors.insert(db.uid.clone(), Arc::new(executor));
            connections.push(ConnectionInfo {
                uid: db.uid.clone(),
                name: db.name.clone(),
                description: db.description.clone(),
                dialect: db.dialect.clone(),
                db: db.db.clone(),
                db_type: db.db_type.clone(),
            });
        }
        Ok(Self {
            executors,
            connections,
        })
    }

    /// Build the validation policy from config (kinds subsetting + function
    /// blacklist appends).
    ///
    /// The config already passed core's startup validation; the value-domain /
    /// shape checks in this conversion are a second line of defense (failures
    /// likewise fail fast, exiting at startup).
    pub fn build_policy(config: &AppConfig) -> Result<Policy, String> {
        let sql = &config.validator.sql;
        let mut builder = PolicyBuilder::default();
        let kinds: Vec<StatementKind> = sql
            .whitelist
            .kinds
            .iter()
            .map(|k| StatementKind::parse_allow_name(k))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                "invalid validator.sql.whitelist.kinds entry (already validated by core)"
                    .to_string()
            })?;
        builder
            .allow_kinds(&kinds)
            .map_err(|e| format!("validator.sql.whitelist.kinds: {e}"))?;
        for (dialect, section) in [
            ("postgres", &sql.pg),
            ("mysql", &sql.mysql),
            ("sqlite", &sql.sqlite),
        ] {
            builder
                .extend_fn_blacklist(dialect, &section.blacklist.function)
                .map_err(|e| format!("validator.sql.{dialect}.blacklist.function: {e}"))?;
        }
        Ok(builder.build())
    }

    /// Fetch the executor by uid.
    pub fn executor(&self, uid: &str) -> Option<Arc<DatabaseExecutor>> {
        self.executors.get(uid).cloned()
    }

    /// Connection metadata (list-connection).
    pub fn connections(&self) -> &[ConnectionInfo] {
        &self.connections
    }

    /// The connection's configured default database name.
    pub fn database_of(&self, uid: &str) -> Option<String> {
        self.connections
            .iter()
            .find(|c| c.uid == uid)
            .map(|c| c.db.clone())
    }

    /// The target database's SQL dialect (for execute-sql validation).
    pub fn dialect_of(&self, uid: &str) -> Option<String> {
        self.connections
            .iter()
            .find(|c| c.uid == uid)
            .map(|c| c.dialect.clone())
    }
}

/// Shared state: the atomically swappable executor set and validation policy.
#[derive(Default, Clone)]
pub struct SharedState {
    set: std::sync::Arc<arc_swap::ArcSwap<ExecutorSet>>,
    /// The validation policy (swapped wholesale on hot reload; the old policy is
    /// kept on failure).
    policy: std::sync::Arc<arc_swap::ArcSwap<Policy>>,
}

impl SharedState {
    /// Create with an initial set (built-in default policy).
    pub fn new(initial: ExecutorSet) -> Self {
        Self {
            set: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(initial)),
            policy: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(Policy::default())),
        }
    }

    /// Create with an initial set and policy (for startup assembly).
    pub fn with_policy(initial: ExecutorSet, policy: Policy) -> Self {
        Self {
            set: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(initial)),
            policy: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(policy)),
        }
    }

    /// Atomically replace the validation policy (config hot reload).
    pub fn replace_policy(&self, policy: Policy) {
        self.policy.store(std::sync::Arc::new(policy));
    }

    /// The current validation policy snapshot (lock-free read).
    pub fn policy(&self) -> std::sync::Arc<Policy> {
        self.policy.load_full()
    }

    /// Fetch the executor by uid (lock-free read).
    pub fn executor(&self, uid: &str) -> Option<Arc<DatabaseExecutor>> {
        self.set.load().executor(uid)
    }

    /// Connection metadata (lock-free read).
    pub fn connections(&self) -> Vec<ConnectionInfo> {
        self.set.load().connections().to_vec()
    }

    /// All uids (the available list for uid error responses).
    pub fn uids(&self) -> Vec<String> {
        self.set
            .load()
            .connections()
            .iter()
            .map(|c| c.uid.clone())
            .collect()
    }

    /// The connection's configured default database name.
    pub fn database_of(&self, uid: &str) -> Option<String> {
        self.set.load().database_of(uid)
    }

    /// The target database's SQL dialect (for execute-sql validation).
    pub fn dialect_of(&self, uid: &str) -> Option<String> {
        self.set.load().dialect_of(uid)
    }

    /// Atomically replace the whole set (hot-reload callback).
    pub fn replace(&self, new_set: ExecutorSet) {
        self.set.store(Arc::new(new_set));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_app_config() -> excapp_db_core::config::AppConfig {
        excapp_db_core::config::AppConfig::parse(
            "[[databases]]\nuid = \"u1\"\nname = \"One\"\ndescription = \"first\"\n\
             type = \"postgres\"\ndialect = \"postgres\"\nusername = \"t\"\npassword = \"t\"\n\
             host = \"localhost\"\nport = 15432\ndb = \"testdb\"\n",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_build_fails_on_unsupported_db_type() {
        // mysql / sqlite are supported; redis is still a fail-closed unsupported type.
        let text = "[[databases]]\nuid = \"u1\"\nname = \"One\"\ndescription = \"d\"\n\
                    type = \"redis\"\ndialect = \"postgres\"\nusername = \"t\"\npassword = \"t\"\n\
                    host = \"localhost\"\nport = 6379\ndb = \"app\"\n";
        let config = excapp_db_core::config::AppConfig::parse(text).unwrap();
        let err = ExecutorSet::build(&config).unwrap_err();
        assert!(err.contains("redis") && err.contains("One"), "{err}");
    }

    #[tokio::test]
    async fn test_build_lazy_on_unreachable_db() {
        // Unreachable databases do not block construction (lazy connections).
        let mut config = test_app_config();
        config.databases[0].port = 59999;
        assert!(ExecutorSet::build(&config).is_ok());
    }

    #[tokio::test]
    async fn test_lookup_and_replace() {
        let state = SharedState::new(ExecutorSet::build(&test_app_config()).unwrap());
        assert!(state.executor("u1").is_some());
        assert!(state.executor("nope").is_none());
        assert_eq!(state.uids(), vec!["u1".to_string()]);
        assert_eq!(state.connections()[0].name, "One");

        // The new set takes effect after the swap.
        let mut config2 = test_app_config();
        config2.databases[0].uid = "u2".into();
        config2.databases[0].name = "Two".into();
        state.replace(ExecutorSet::build(&config2).unwrap());
        assert!(state.executor("u1").is_none());
        assert!(state.executor("u2").is_some());
        assert_eq!(state.connections()[0].name, "Two");
    }
}
