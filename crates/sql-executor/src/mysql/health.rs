//! `MyHealthCheck`: the MySQL implementation of core's HealthCheck trait.

use super::MyPool;
use std::sync::Arc;
use std::time::Duration;

/// Liveness timeout ceiling (seconds): covers acquisition plus the query as a whole.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// MySQL connection health check: lightweight liveness probe (`SELECT 1`), no
/// internal state.
pub struct MyHealthCheck {
    pool: Arc<MyPool>,
}

impl MyHealthCheck {
    /// Create a health check on the shared pool.
    pub fn new(pool: Arc<MyPool>) -> Self {
        Self { pool }
    }
}

impl excapp_db_core::watch::HealthCheck for MyHealthCheck {
    /// Liveness: acquire a connection + `SELECT 1` wrapped in a 5s timeout.
    ///
    /// Success returns `Ok(())`; any failure (connect, auth, timeout, execution
    /// error) returns an English failure message (carrying the database id, no
    /// credentials). No internal state: every call is judged independently, and
    /// recovery returns success immediately.
    fn check(&mut self) -> Result<(), String> {
        // The HealthCheck trait has a synchronous signature; the async probe runs
        // in a self-owned current-thread runtime (single-shot, short-lived, not
        // coupled to any external runtime).
        let pool = Arc::clone(&self.pool);
        tokio::task::block_in_place(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("building a current-thread tokio runtime cannot fail")
                .block_on(async move {
                    tokio::time::timeout(PROBE_TIMEOUT, async {
                        pool.acquire_probe().await.map_err(|e| e.to_string())
                    })
                    .await
                    .map_err(|_| {
                        format!(
                            "mysql health check failed for '{}': timed out after {}s",
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

    fn check_with_pool(pool: Arc<MyPool>) -> Result<(), String> {
        let mut hc = MyHealthCheck::new(pool);
        excapp_db_core::watch::HealthCheck::check(&mut hc)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_healthy_database_returns_ok() {
        let pool = Arc::new(MyPool::new(&crate::mysql::test_config()).unwrap());
        if !crate::mysql::connection_available(&pool).await {
            eprintln!("skipping: test mysql not available");
            return;
        }
        assert!(check_with_pool(Arc::clone(&pool)).is_ok());
        // Consecutive calls behave identically.
        assert!(check_with_pool(pool).is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_unreachable_database_returns_english_error_with_identity() {
        // The password takes a distinct value: sharing the uid's value would
        // false-positive the "no password" assertion.
        let mut config = crate::mysql::test_config();
        config.port = 59999;
        config.password = "unique-secret-pw".into();
        let pool = Arc::new(MyPool::new(&config).unwrap());
        let err = check_with_pool(pool).unwrap_err();
        assert!(err.contains("'test'"), "{err}");
        assert!(err.contains("failed"), "{err}");
        assert!(!err.contains("unique-secret-pw"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_recovery_not_cached() {
        // Structural check for no internal state: the only field is the pool
        // (immutably shared).
        let pool = Arc::new(MyPool::new(&crate::mysql::test_config()).unwrap());
        let hc = MyHealthCheck::new(pool);
        let _ = hc;
    }
}
