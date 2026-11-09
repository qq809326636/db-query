//! RedisHealthCheck: the Redis implementation of core's HealthCheck trait.

use super::RedisPool;
use std::sync::Arc;
use std::time::Duration;

/// Liveness timeout cap (seconds): covers acquire + PING as a whole.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Redis connection health check: lightweight liveness probe (`PING`), stateless.
pub struct RedisHealthCheck {
    pool: Arc<RedisPool>,
}

impl RedisHealthCheck {
    /// Create a health check on top of the shared pool.
    pub fn new(pool: Arc<RedisPool>) -> Self {
        Self { pool }
    }
}

impl excapp_db_core::watch::HealthCheck for RedisHealthCheck {
    /// Liveness: acquire + `PING` wrapped in a 5s timeout.
    ///
    /// Success returns `Ok(())`; any failure (connect, auth, timeout, execution error) returns
    /// an English failure message (database id included, never credentials). Stateless: each call judges
    /// independently, and success returns once recovered.
    fn check(&mut self) -> Result<(), String> {
        // The HealthCheck trait has a sync signature; the async probe runs in a purpose-built
        // current-thread runtime (aligned with the pg / mysql / sqlite precedent).
        let pool = Arc::clone(&self.pool);
        tokio::task::block_in_place(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("building a current-thread tokio runtime cannot fail")
                .block_on(async move {
                    tokio::time::timeout(PROBE_TIMEOUT, async {
                        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;
                        redis::cmd("PING")
                            .query_async::<redis::Value>(&mut conn)
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok::<(), String>(())
                    })
                    .await
                    .map_err(|_| {
                        format!(
                            "redis health check failed for '{}': timed out after {}s",
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

    #[test]
    fn test_unreachable_database_reports_english_failure() {
        let pool =
            Arc::new(RedisPool::new(&crate::redis::test_config("127.0.0.1", 1, "0")).unwrap());
        let mut hc = RedisHealthCheck::new(pool);
        let err = excapp_db_core::watch::HealthCheck::check(&mut hc).unwrap_err();
        // Connection refused goes through the Connection error path: English, database id included, no credentials.
        assert!(
            err.contains("redis connection failed for database 'test'"),
            "{err}"
        );
        assert!(!err.contains("password"), "{err}");
    }
}
