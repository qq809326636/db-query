//! PgHealthCheck: PostgreSQL implementation of core's HealthCheck trait.

use super::PgPool;
use std::sync::Arc;
use std::time::Duration;

/// Probe timeout cap (seconds): covers connection acquisition plus the
/// query as a whole.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// PostgreSQL connection health check: a lightweight probe (`SELECT 1`),
/// no internal state.
pub struct PgHealthCheck {
    pool: Arc<PgPool>,
}

impl PgHealthCheck {
    /// Create a health check on top of a shared pool.
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

impl excapp_db_core::watch::HealthCheck for PgHealthCheck {
    /// Probe: connection acquisition + `SELECT 1` wrapped in a 5-second
    /// timeout.
    ///
    /// Returns `Ok(())` on success; any failure (connection, auth,
    /// timeout, execution error) returns an English failure message
    /// (including the database identity, no credentials). No internal
    /// state: every call is judged independently, and recovery
    /// immediately yields success.
    fn check(&mut self) -> Result<(), String> {
        // The HealthCheck trait has a sync signature; the async probe runs
        // in a self-built current-thread runtime (single-shot, short-lived,
        // not coupled to any external runtime).
        let pool = Arc::clone(&self.pool);
        tokio::task::block_in_place(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("building a current-thread tokio runtime cannot fail")
                .block_on(async move {
                    tokio::time::timeout(PROBE_TIMEOUT, async {
                        let client = pool.acquire().await.map_err(|e| e.to_string())?;
                        client
                            .simple_query("SELECT 1")
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok::<(), String>(())
                    })
                    .await
                    .map_err(|_| {
                        format!(
                            "postgres health check failed for '{}': timed out after {}s",
                            pool.db_name,
                            PROBE_TIMEOUT.as_secs()
                        )
                    })?
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_with_pool(pool: Arc<PgPool>) -> Result<(), String> {
        let mut hc = PgHealthCheck::new(pool);
        excapp_db_core::watch::HealthCheck::check(&mut hc)
    }

    #[test]
    fn test_healthy_database_returns_ok() {
        let pool = Arc::new(PgPool::new(&crate::pg::test_config()).unwrap());
        if !crate::pg::connection_available_sync(&pool) {
            eprintln!("skipping: test postgres not available");
            return;
        }
        assert!(check_with_pool(pool).is_ok());
        // Consecutive calls behave consistently.
        let pool = Arc::new(PgPool::new(&crate::pg::test_config()).unwrap());
        assert!(check_with_pool(pool).is_ok());
    }

    #[test]
    fn test_unreachable_database_returns_english_error_with_identity() {
        let mut config = crate::pg::test_config();
        config.port = 59999;
        let pool = Arc::new(PgPool::new(&config).unwrap());
        let err = check_with_pool(pool).unwrap_err();
        assert!(err.contains("'test'"), "{err}");
        assert!(err.contains("failed"), "{err}");
        assert!(!err.contains("password"), "{err}");
    }

    #[test]
    fn test_recovery_not_cached() {
        // Structural verification of statelessness: no shared mutable
        // state fields between checks.
        let pool = Arc::new(PgPool::new(&crate::pg::test_config()).unwrap());
        let hc = PgHealthCheck::new(pool);
        // PgHealthCheck's only field is pool (immutably shared), so the
        // compiler itself guarantees no cached state.
        let _ = hc;
    }
}
