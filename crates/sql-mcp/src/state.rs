//! Shared state of the executor set: uid addressing, atomic hot-reload
//! replacement.
//!
//! The read path (tool calls fetching executors by uid) is lock-free:
//! arc-swap's `load` yields a snapshot reference; the write path (config
//! hot reload) swaps the whole snapshot, and in-flight calls holding the
//! old reference complete naturally. Connection metadata (uid / name /
//! description) is maintained alongside the snapshot for list-conf's
//! local reads.

use excapp_db_sql_executor::pg::PgExecutor;
use std::collections::HashMap;
use std::sync::Arc;

/// Metadata for a single connection (list-conf output; no connection
/// details).
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Unique config identifier.
    pub uid: String,
    /// Human-friendly name.
    pub name: String,
    /// Scope description.
    pub description: String,
    /// SQL dialect (for execute-sql validation; not exposed outward).
    pub dialect: String,
    /// Configured default database name (for database parameter
    /// consistency checks).
    pub db: String,
    /// Database type (output as type by list-conf).
    pub db_type: String,
}

/// Executor set snapshot (immutable, replaced wholesale).
#[derive(Debug, Default)]
pub struct ExecutorSet {
    /// uid -> executor.
    executors: HashMap<String, Arc<PgExecutor>>,
    /// Connection metadata (list-conf).
    connections: Vec<ConnectionInfo>,
}

impl ExecutorSet {
    /// Build the full set from the config.
    ///
    /// Any unsupported `db_type` fails the whole set (fail fast, error
    /// includes the database name); unreachable connections do not error
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

    /// Fetch an executor by uid.
    pub fn executor(&self, uid: &str) -> Option<Arc<PgExecutor>> {
        self.executors.get(uid).cloned()
    }

    /// Connection metadata (list-conf).
    pub fn connections(&self) -> &[ConnectionInfo] {
        &self.connections
    }

    /// Default database name of the connection's config.
    pub fn database_of(&self, uid: &str) -> Option<String> {
        self.connections
            .iter()
            .find(|c| c.uid == uid)
            .map(|c| c.db.clone())
    }

    /// SQL dialect of the target database (for execute-sql validation).
    pub fn dialect_of(&self, uid: &str) -> Option<String> {
        self.connections
            .iter()
            .find(|c| c.uid == uid)
            .map(|c| c.dialect.clone())
    }
}

/// Shared state: an atomically swappable executor set.
#[derive(Debug, Default, Clone)]
pub struct SharedState {
    set: std::sync::Arc<arc_swap::ArcSwap<ExecutorSet>>,
}

impl SharedState {
    /// Create with an initial set.
    pub fn new(initial: ExecutorSet) -> Self {
        Self {
            set: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(initial)),
        }
    }

    /// Fetch an executor by uid (lock-free read).
    pub fn executor(&self, uid: &str) -> Option<Arc<PgExecutor>> {
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

    /// Default database name of the connection's config.
    pub fn database_of(&self, uid: &str) -> Option<String> {
        self.set.load().database_of(uid)
    }

    /// SQL dialect of the target database (for execute-sql validation).
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

    #[test]
    fn test_build_fails_on_unsupported_db_type() {
        let text = "[[databases]]\nuid = \"u1\"\nname = \"One\"\ndescription = \"d\"\n\
                    type = \"mysql\"\ndialect = \"mysql\"\nusername = \"t\"\npassword = \"t\"\n\
                    host = \"localhost\"\nport = 3306\ndb = \"app\"\n";
        let config = excapp_db_core::config::AppConfig::parse(text).unwrap();
        let err = ExecutorSet::build(&config).unwrap_err();
        assert!(err.contains("mysql") && err.contains("One"), "{err}");
    }

    #[test]
    fn test_build_lazy_on_unreachable_db() {
        // An unreachable database does not block the build (lazy
        // connections).
        let mut config = test_app_config();
        config.databases[0].port = 59999;
        assert!(ExecutorSet::build(&config).is_ok());
    }

    #[test]
    fn test_lookup_and_replace() {
        let state = SharedState::new(ExecutorSet::build(&test_app_config()).unwrap());
        assert!(state.executor("u1").is_some());
        assert!(state.executor("nope").is_none());
        assert_eq!(state.uids(), vec!["u1".to_string()]);
        assert_eq!(state.connections()[0].name, "One");

        // The new set takes effect after replacement.
        let mut config2 = test_app_config();
        config2.databases[0].uid = "u2".into();
        config2.databases[0].name = "Two".into();
        state.replace(ExecutorSet::build(&config2).unwrap());
        assert!(state.executor("u1").is_none());
        assert!(state.executor("u2").is_some());
        assert_eq!(state.connections()[0].name, "Two");
    }
}
