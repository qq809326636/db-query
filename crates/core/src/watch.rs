//! Watch scheduling: run health checks and config change detection
//! periodically at the configured interval.
//!
//! Single-threaded loop + sliced sleep (guarantees stop responds within
//! 1 second); change detection is based on a content hash (unchanged
//! content never triggers); after a change the config is reloaded and
//! validated via [`crate::config`], and the callback fires only when
//! validation passes (carrying the new config); panics in the callback
//! and the check are isolated by `catch_unwind` so scheduling is never
//! interrupted. core only schedules; liveness probes are injected by
//! sql-executor (in the future) via [`HealthCheck`].

use crate::config::AppConfig;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// Polling granularity of the stop signal: guarantees stop/Drop takes
/// effect within 1 second.
const STOP_POLL_SLICE: Duration = Duration::from_millis(500);

/// Database connection health check interface; sql-executor provides the
/// implementation.
///
/// `Err` means the check failed (logged, retried next cycle); panics
/// inside an implementation are isolated by the scheduler.
pub trait HealthCheck: Send + 'static {
    /// Run one health check.
    fn check(&mut self) -> Result<(), String>;
}

/// Scheduler handle: stops explicitly or automatically on Drop.
pub struct WatchHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl WatchHandle {
    /// Stop scheduling and wait for the thread to exit (completes within
    /// 1 second).
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            // The thread polls the signal at STOP_POLL_SLICE granularity,
            // so join waits no longer than that granularity plus the
            // remaining work within one cycle; the design acceptance
            // criterion is completion within 1 second.
            let _ = thread.join();
        }
    }

    /// Whether scheduling is still running.
    pub fn is_running(&self) -> bool {
        !self.stop.load(Ordering::SeqCst)
    }
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start watch scheduling.
///
/// - `config_path`: path of the config file to watch;
/// - `watch_interval_secs`: scheduling interval (seconds), from
///   `app.databases.watch_interval`;
/// - `health_check`: health check implementation (a test implementation
///   or the future sql-executor one);
/// - `on_change`: change callback, taking the newly reloaded and validated
///   config.
///
/// Returns a handle; stop explicitly via `stop` or via Drop.
pub fn start<F>(
    config_path: PathBuf,
    watch_interval_secs: u64,
    mut health_check: impl HealthCheck,
    mut on_change: F,
) -> WatchHandle
where
    F: FnMut(AppConfig) + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);

    let thread = std::thread::spawn(move || {
        let interval = Duration::from_secs(watch_interval_secs);
        let mut last_hash = hash_file(&config_path);

        loop {
            // Sliced sleep: poll the stop signal at fine granularity to
            // guarantee a response within 1 second.
            let mut remaining = interval;
            while remaining > Duration::ZERO {
                if thread_stop.load(Ordering::SeqCst) {
                    return;
                }
                let slice = remaining.min(STOP_POLL_SLICE);
                std::thread::sleep(slice);
                remaining -= slice;
            }
            if thread_stop.load(Ordering::SeqCst) {
                return;
            }

            // Health check: log failures and continue; panics are isolated.
            match catch_unwind(AssertUnwindSafe(|| health_check.check())) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!("health check failed: {e}");
                }
                Err(_) => {
                    tracing::error!("health check panicked; continuing next cycle");
                }
            }

            // Change detection: content hash; read failures are made
            // observable, then continue.
            let current = hash_file(&config_path);
            if current.is_none() {
                tracing::error!(
                    "failed to read config file for change detection: {}",
                    config_path.display()
                );
                continue;
            }
            if current == last_hash {
                continue;
            }

            // Content changed: reload and validate; on failure keep the
            // old config and retry next cycle.
            match AppConfig::load(&config_path) {
                Ok(new_config) => {
                    last_hash = current;
                    if catch_unwind(AssertUnwindSafe(|| on_change(new_config))).is_err() {
                        tracing::error!("change callback panicked; continuing next cycle");
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "config file changed but reload failed, keeping old config: {e}"
                    );
                    // Do not update last_hash: retry loading the same
                    // content next cycle.
                }
            }
        }
    });

    WatchHandle {
        stop,
        thread: Some(thread),
    }
}

/// Hash the file content; returns None on read failure.
fn hash_file(path: &Path) -> Option<u64> {
    let content = std::fs::read(path).ok()?;
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    Some(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    struct CountingCheck {
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    impl HealthCheck for CountingCheck {
        fn check(&mut self) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err("unhealthy".to_string())
            } else {
                Ok(())
            }
        }
    }

    struct PanickingCheck;

    impl HealthCheck for PanickingCheck {
        fn check(&mut self) -> Result<(), String> {
            panic!("boom");
        }
    }

    fn write_config(path: &Path, log_level: &str) {
        let content = format!(
            "[app.log]\nlevel = \"{log_level}\"\n\n[[databases]]\n\
             uid = \"a\"\nname = \"a\"\ndescription = \"d\"\ntype = \"postgres\"\n\
             dialect = \"postgres\"\nusername = \"u\"\npassword = \"p\"\n\
             host = \"localhost\"\nport = 5432\ndb = \"app\"\n"
        );
        std::fs::write(path, content).unwrap();
    }

    fn temp_config_path(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "db-query-watch-test-{tag}-{}.toml",
            std::process::id()
        ));
        path
    }

    #[test]
    fn test_first_cycle_runs_check_and_establishes_baseline() {
        let path = temp_config_path("baseline");
        write_config(&path, "info");

        let calls = Arc::new(AtomicUsize::new(0));
        let changes = Arc::new(AtomicUsize::new(0));
        let changes_ref = Arc::clone(&changes);

        let mut handle = start(
            path.clone(),
            1,
            CountingCheck {
                calls: Arc::clone(&calls),
                fail: false,
            },
            move |_| {
                changes_ref.fetch_add(1, Ordering::SeqCst);
            },
        );

        // The first cycle runs the check about 1 second after startup.
        std::thread::sleep(Duration::from_millis(1800));
        handle.stop();
        assert!(
            calls.load(Ordering::SeqCst) >= 1,
            "health check should run on first cycle"
        );
        // No change: the callback does not fire.
        assert_eq!(changes.load(Ordering::SeqCst), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_config_change_triggers_callback_with_new_config() {
        let path = temp_config_path("change");
        write_config(&path, "info");

        let levels = Arc::new(Mutex::new(Vec::new()));
        let levels_ref = Arc::clone(&levels);

        let mut handle = start(
            path.clone(),
            1,
            CountingCheck {
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            },
            move |config| {
                levels_ref
                    .lock()
                    .unwrap()
                    .push(config.app.log.level.clone());
            },
        );

        std::thread::sleep(Duration::from_millis(1300));
        write_config(&path, "debug");
        std::thread::sleep(Duration::from_millis(1500));
        handle.stop();

        let got = levels.lock().unwrap();
        assert_eq!(
            *got,
            vec!["debug".to_string()],
            "callback should fire once with new level"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_invalid_change_does_not_trigger_and_keeps_retrying_semantics() {
        let path = temp_config_path("invalid");
        write_config(&path, "info");

        let changes = Arc::new(AtomicUsize::new(0));
        let changes_ref = Arc::clone(&changes);

        let mut handle = start(
            path.clone(),
            1,
            CountingCheck {
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            },
            move |_| {
                changes_ref.fetch_add(1, Ordering::SeqCst);
            },
        );

        std::thread::sleep(Duration::from_millis(1300));
        // Write an invalid config (level outside the enum).
        let bad = "[app.log]\nlevel = \"loud\"\n\n[[databases]]\nuid = \"a\"\nname = \"a\"\ndescription = \"d\"\ntype = \"postgres\"\ndialect = \"postgres\"\nusername = \"u\"\npassword = \"p\"\nhost = \"localhost\"\nport = 5432\ndb = \"app\"\n";
        std::fs::write(&path, bad).unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        // The callback does not fire while the config is invalid.
        assert_eq!(changes.load(Ordering::SeqCst), 0);
        // Fix to a valid config with changed content: the callback fires
        // (the failed state was not cached as notified).
        write_config(&path, "trace");
        std::thread::sleep(Duration::from_millis(1500));
        handle.stop();
        assert!(
            changes.load(Ordering::SeqCst) >= 1,
            "valid change after invalid should fire"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_deleted_config_does_not_stop_scheduler() {
        let path = temp_config_path("deleted");
        write_config(&path, "info");

        let calls = Arc::new(AtomicUsize::new(0));
        let changes = Arc::new(AtomicUsize::new(0));
        let changes_ref = Arc::clone(&changes);

        let mut handle = start(
            path.clone(),
            1,
            CountingCheck {
                calls: Arc::clone(&calls),
                fail: false,
            },
            move |_| {
                changes_ref.fetch_add(1, Ordering::SeqCst);
            },
        );

        std::thread::sleep(Duration::from_millis(1300));
        let _ = std::fs::remove_file(&path);
        std::thread::sleep(Duration::from_millis(1200));
        // Scheduling is not interrupted: health checks keep running
        // after deletion.
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "scheduler should keep running after deletion"
        );
        assert_eq!(changes.load(Ordering::SeqCst), 0);
        handle.stop();
    }

    #[test]
    fn test_stop_completes_within_one_second() {
        let path = temp_config_path("stop");
        write_config(&path, "info");

        let mut handle = start(
            path,
            3600,
            CountingCheck {
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            },
            |_| {},
        );

        std::thread::sleep(Duration::from_millis(100));
        let start = std::time::Instant::now();
        handle.stop();
        assert!(
            start.elapsed() <= Duration::from_secs(1),
            "stop must complete within 1s"
        );
    }

    #[test]
    fn test_drop_stops_scheduler() {
        let path = temp_config_path("drop");
        write_config(&path, "info");

        let calls = Arc::new(AtomicUsize::new(0));
        let handle = start(
            path.clone(),
            1,
            CountingCheck {
                calls: Arc::clone(&calls),
                fail: false,
            },
            |_| {},
        );

        drop(handle);
        let baseline = calls.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            baseline,
            "no more checks after drop"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_health_check_panic_does_not_kill_scheduler() {
        let path = temp_config_path("panic");
        write_config(&path, "info");

        let changes = Arc::new(AtomicUsize::new(0));
        let changes_ref = Arc::clone(&changes);

        let mut handle = start(path.clone(), 1, PanickingCheck, move |_| {
            changes_ref.fetch_add(1, Ordering::SeqCst);
        });

        // After the check panics for several cycles, change detection and
        // the callback still work.
        std::thread::sleep(Duration::from_millis(1300));
        write_config(&path, "debug");
        std::thread::sleep(Duration::from_millis(1500));
        handle.stop();
        assert!(
            changes.load(Ordering::SeqCst) >= 1,
            "callback must still fire despite panicking check"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_callback_panic_does_not_kill_scheduler() {
        let path = temp_config_path("cbpanic");
        write_config(&path, "info");

        let changes = Arc::new(AtomicUsize::new(0));
        let changes_ref = Arc::clone(&changes);

        let mut handle = start(
            path.clone(),
            1,
            CountingCheck {
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            },
            move |_| -> () {
                changes_ref.fetch_add(1, Ordering::SeqCst);
                panic!("callback boom");
            },
        );

        std::thread::sleep(Duration::from_millis(1300));
        write_config(&path, "debug");
        std::thread::sleep(Duration::from_millis(1500));
        // Callback panics are isolated: another change still fires (the
        // scheduler is alive).
        write_config(&path, "trace");
        std::thread::sleep(Duration::from_millis(1500));
        handle.stop();
        assert!(
            changes.load(Ordering::SeqCst) >= 2,
            "scheduler must survive callback panics"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_mtime_touch_without_content_change_does_not_fire() {
        let path = temp_config_path("touch");
        write_config(&path, "info");

        let changes = Arc::new(AtomicUsize::new(0));
        let changes_ref = Arc::clone(&changes);

        let mut handle = start(
            path.clone(),
            1,
            CountingCheck {
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            },
            move |_| {
                changes_ref.fetch_add(1, Ordering::SeqCst);
            },
        );

        std::thread::sleep(Duration::from_millis(1300));
        // Rewrite with identical content (mtime changes, content hash
        // does not).
        write_config(&path, "info");
        std::thread::sleep(Duration::from_millis(1500));
        handle.stop();
        assert_eq!(
            changes.load(Ordering::SeqCst),
            0,
            "content-identical rewrite must not fire"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_failed_health_check_does_not_stop_scheduler() {
        let path = temp_config_path("failcheck");
        write_config(&path, "info");

        let calls = Arc::new(AtomicUsize::new(0));
        let mut handle = start(
            path.clone(),
            1,
            CountingCheck {
                calls: Arc::clone(&calls),
                fail: true,
            },
            |_| {},
        );

        std::thread::sleep(Duration::from_millis(2500));
        handle.stop();
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "failing check must not stop scheduling"
        );
        let _ = std::fs::remove_file(&path);
    }
}
