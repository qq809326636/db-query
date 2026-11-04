//! File log rotation: log directory resolution and creation, three
//! segment policies (daily / hourly / size), and day-based expiry
//! cleanup.
//!
//! Lazy first open: construction only resolves the directory, creates
//! it, and runs one cleanup pass; the segment file is opened only when
//! the first log line is written (no business logs, no empty segment).
//! Rolling happens synchronously inside the write path (close old →
//! cleanup → open new); cleanup is best-effort: a failure only writes
//! one English warning directly to stderr (not via tracing, avoiding a
//! self-deadlock in the write path) and does not interrupt init or
//! subsequent writes.

use crate::config::LogFileSection;
use chrono::{DateTime, Local};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Unified prefix of segment file names; also the match basis for
/// expiry cleanup (only matching files are deleted).
const SLICE_PREFIX: &str = "db-query.log.";

/// Upper bound of sequence numbers for same-second conflicts in size
/// mode (guards against infinite loops in a corrupted directory).
const SIZE_SEQ_LIMIT: u32 = 1000;

/// Injectable internal time source: shared by rolling periods and
/// expiry decisions (tests inject a fixed time).
pub(crate) type Clock = Arc<dyn Fn() -> DateTime<Local> + Send + Sync>;

/// Rolling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RollingPolicy {
    /// Switch on local calendar-day boundaries.
    Daily,
    /// Switch on local clock-hour boundaries.
    Hourly,
    /// Switch on a byte threshold (timestamp naming + conflict
    /// sequence numbers).
    Size,
}

impl RollingPolicy {
    /// Parse from the config string (the enum is already validated at
    /// load time; defensive error return).
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "daily" => Ok(Self::Daily),
            "hourly" => Ok(Self::Hourly),
            "size" => Ok(Self::Size),
            other => Err(format!("unknown rolling policy: {other}")),
        }
    }
}

/// Rolling writer: the writer for the tracing file layer (MakeWriter
/// clones one handle per event; internal state is shared via
/// `Arc<Mutex<..>>`, serializing the write path).
#[derive(Clone)]
pub(crate) struct RollingWriter {
    /// Current segment handle and counters (mutual-exclusion protected
    /// in the write path).
    state: Arc<Mutex<WriterState>>,
    policy: RollingPolicy,
    dir: PathBuf,
    max_size: u64,
    max_days: u32,
    clock: Clock,
    /// Sink mode: all writes are dropped (a placeholder when the file
    /// target is disabled, with no IO at all).
    sink: bool,
}

/// Write state of a single segment.
struct WriterState {
    /// Current segment handle; None means not yet opened (lazy first
    /// open).
    file: Option<File>,
    /// Raw bytes written to the current segment so far (the size-mode
    /// rolling basis).
    written: u64,
    /// Current period key (daily: YYYYMMDD; hourly: YYYYMMDD-HH;
    /// unused for size).
    period_key: String,
}

impl std::fmt::Debug for RollingWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RollingWriter")
            .field("policy", &self.policy)
            .field("dir", &self.dir.display().to_string())
            .field("max_size", &self.max_size)
            .field("max_days", &self.max_days)
            .field("sink", &self.sink)
            .finish_non_exhaustive()
    }
}

impl RollingWriter {
    /// Construct: resolve the directory (empty string falls back to
    /// `<data_dir>/logs`), create it idempotently, and start cleanup.
    ///
    /// Construction failures (directory creation failure / unknown
    /// policy) return English errors; cleanup failures do not fail.
    pub(crate) fn new(
        file_cfg: &LogFileSection,
        data_dir: &str,
        clock: Clock,
    ) -> Result<Self, String> {
        let dir = if file_cfg.dir.is_empty() {
            Path::new(data_dir).join("logs")
        } else {
            PathBuf::from(&file_cfg.dir)
        };
        let policy = RollingPolicy::parse(&file_cfg.rolling)?;

        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("failed to create log directory '{}': {e}", dir.display()))?;

        let now = clock();
        cleanup_expired(&dir, file_cfg.max_days, now);

        let period_key = match policy {
            RollingPolicy::Daily | RollingPolicy::Hourly => period_key_for(now, policy),
            RollingPolicy::Size => String::new(),
        };

        Ok(Self {
            state: Arc::new(Mutex::new(WriterState {
                file: None,
                written: 0,
                period_key,
            })),
            policy,
            dir,
            max_size: file_cfg.rolling_max_size,
            max_days: file_cfg.max_days,
            clock,
            sink: false,
        })
    }

    /// Construct the sink placeholder: all writes are dropped, touching
    /// no filesystem resources at all (keeps the subscriber structure
    /// constant when the file target is disabled; the off semantics are
    /// expressed via the OFF level filter).
    pub(crate) fn sink() -> Self {
        Self {
            state: Arc::new(Mutex::new(WriterState {
                file: None,
                written: 0,
                period_key: String::new(),
            })),
            policy: RollingPolicy::Daily,
            dir: PathBuf::new(),
            max_size: 0,
            max_days: 1,
            clock: Arc::new(Local::now),
            sink: true,
        }
    }

    /// Lock the internal state; poisoning (a panicking lock holder)
    /// becomes an io error instead of a panic.
    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, WriterState>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("log writer state poisoned"))
    }

    /// Write one already-formatted event: rolling decision first, then
    /// write and accumulate bytes.
    fn write_event(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.sink {
            return Ok(buf.len());
        }
        let mut state = self.lock()?;
        let now = (self.clock)();

        let need_roll = match self.policy {
            RollingPolicy::Daily | RollingPolicy::Hourly => {
                let key = period_key_for(now, self.policy);
                state.file.is_none() || key != state.period_key
            }
            // size pre-write check: written + this line > threshold
            // triggers the switch (segments stay under the threshold; an
            // event that alone exceeds the threshold is written intact,
            // not split or dropped, and no empty segment is left). When
            // file is None, roll is mandatory to complete the lazy
            // first open.
            RollingPolicy::Size => {
                state.file.is_none()
                    || (state.written > 0 && state.written + buf.len() as u64 > self.max_size)
            }
        };
        if need_roll {
            self.roll(&mut state, now)?;
        }

        let file = state
            .file
            .as_mut()
            .expect("slice file must be open after roll decision");
        let n = file.write(buf)?;
        state.written += n as u64;
        Ok(n)
    }

    /// Rolling switch: close old → expiry cleanup (best-effort) → open
    /// new.
    fn roll(&self, state: &mut WriterState, now: DateTime<Local>) -> io::Result<()> {
        state.file = None;
        state.written = 0;
        cleanup_expired(&self.dir, self.max_days, now);
        match self.policy {
            RollingPolicy::Daily | RollingPolicy::Hourly => {
                let key = period_key_for(now, self.policy);
                state.file = Some(open_append(&self.dir, &key)?);
                state.period_key = key;
            }
            RollingPolicy::Size => {
                state.file = Some(open_new_timestamped(&self.dir, now)?);
                state.period_key = String::new();
            }
        }
        Ok(())
    }

    /// Flush the current segment, if any.
    fn flush_state(&self) -> io::Result<()> {
        let mut state = self.lock()?;
        if let Some(file) = state.file.as_mut() {
            file.flush()?;
        }
        Ok(())
    }
}

impl io::Write for RollingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_event(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_state()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RollingWriter {
    type Writer = RollingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Compute the period key (local timezone).
fn period_key_for(now: DateTime<Local>, policy: RollingPolicy) -> String {
    match policy {
        RollingPolicy::Daily => now.format("%Y%m%d").to_string(),
        RollingPolicy::Hourly => now.format("%Y%m%d-%H").to_string(),
        RollingPolicy::Size => String::new(),
    }
}

/// Open a period segment (daily / hourly): append mode; existing files
/// are continued (restarts do not overwrite).
fn open_append(dir: &Path, key: &str) -> io::Result<File> {
    let path = dir.join(format!("{SLICE_PREFIX}{key}"));
    OpenOptions::new().create(true).append(true).open(path)
}

/// Open a new timestamped segment (size): no append; same-second
/// conflicts increment a sequence number.
fn open_new_timestamped(dir: &Path, now: DateTime<Local>) -> io::Result<File> {
    let base = format!("{SLICE_PREFIX}{}", now.format("%Y%m%d-%H%M%S"));
    for seq in 0..=SIZE_SEQ_LIMIT {
        let name = if seq == 0 {
            base.clone()
        } else {
            format!("{base}.{seq}")
        };
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name))
        {
            Ok(file) => return Ok(file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "exhausted slice sequence numbers for the current second",
    ))
}

/// Expiry cleanup: delete segments dated earlier than "today −
/// max_days", best-effort.
///
/// Only files matching the `db-query.log.<date-key>` naming are deleted
/// (the date key takes the first 8 digits parsed as a local date);
/// non-matching files are never touched. A single deletion failure
/// skips that file and continues; if any failure occurred in the pass,
/// one English warning is written directly to stderr.
fn cleanup_expired(dir: &Path, max_days: u32, now: DateTime<Local>) {
    let cutoff = now.date_naive() - chrono::Duration::days(max_days as i64);
    let mut had_failure = false;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(date) = slice_file_date(&name) else {
            continue;
        };
        if date < cutoff && std::fs::remove_file(entry.path()).is_err() {
            had_failure = true;
        }
    }
    if had_failure {
        // Direct stderr write: cleanup happens inside the tracing write
        // path; going through tracing would self-deadlock.
        eprintln!(
            "warning: failed to delete some expired log slices in {}",
            dir.display()
        );
    }
}

/// Parse the date part of a segment file name; returns None when the
/// naming pattern does not match.
fn slice_file_date(name: &str) -> Option<chrono::NaiveDate> {
    let rest = name.strip_prefix(SLICE_PREFIX)?;
    if rest.len() < 8 || !rest[..8].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let year: i32 = rest[0..4].parse().ok()?;
    let month: u32 = rest[4..6].parse().ok()?;
    let day: u32 = rest[6..8].parse().ok()?;
    chrono::NaiveDate::from_ymd_opt(year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// Construct a file section config directly (bypassing load
    /// validation; unit tests use small thresholds for rolling logic).
    fn file_cfg(dir: &str, rolling: &str, max_size: u64, max_days: u32) -> LogFileSection {
        LogFileSection {
            enabled: true,
            format: "json".to_string(),
            dir: dir.to_string(),
            rolling: rolling.to_string(),
            rolling_max_size: max_size,
            max_days,
        }
    }

    /// Mutable clock: tests advance time across boundaries without real
    /// waiting.
    fn mutable_clock(initial: DateTime<Local>) -> (Arc<Mutex<DateTime<Local>>>, Clock) {
        let time = Arc::new(Mutex::new(initial));
        let shared = Arc::clone(&time);
        let clock: Clock = Arc::new(move || *shared.lock().unwrap());
        (time, clock)
    }

    fn temp_root(tag: &str) -> PathBuf {
        let mut root = std::env::temp_dir();
        root.push(format!("db-query-rot-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn write_line(writer: &mut RollingWriter, line: &str) {
        writer
            .write_all(format!("{line}\n").as_bytes())
            .expect("write should succeed");
    }

    fn slice_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read_dir should succeed")
            .filter_map(|e| {
                let name = e.ok()?.file_name().into_string().ok()?;
                name.starts_with(SLICE_PREFIX).then_some(name)
            })
            .collect();
        names.sort();
        names
    }

    fn at(date: chrono::NaiveDate, h: u32, m: u32, s: u32) -> DateTime<Local> {
        Local
            .from_local_datetime(&date.and_hms_opt(h, m, s).expect("valid time"))
            .single()
            .expect("unambiguous local time")
    }

    #[test]
    fn test_dir_fallback_to_data_logs() {
        let root = temp_root("fallback");
        let (time, clock) = mutable_clock(at(
            chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap(),
            8,
            30,
            0,
        ));
        let data_dir = root.join("data");
        let mut writer = RollingWriter::new(
            &file_cfg("", "daily", 10485760, 7),
            data_dir.to_str().unwrap(),
            clock,
        )
        .unwrap();
        write_line(&mut writer, "hello");

        let logs = data_dir.join("logs");
        assert_eq!(
            slice_names(&logs),
            vec!["db-query.log.20261104".to_string()]
        );
        let _ = time; // The mutable clock is not advanced in this test.
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_explicit_dir_used() {
        let root = temp_root("explicit");
        let (_, clock) = mutable_clock(at(
            chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap(),
            8,
            30,
            0,
        ));
        let explicit = root.join("custom-logs");
        let mut writer = RollingWriter::new(
            &file_cfg(explicit.to_str().unwrap(), "daily", 10485760, 7),
            root.join("data").to_str().unwrap(),
            clock,
        )
        .unwrap();
        write_line(&mut writer, "hello");

        assert_eq!(
            slice_names(&explicit),
            vec!["db-query.log.20261104".to_string()]
        );
        // An explicit directory does not fall back to data/logs.
        assert!(!root.join("data/logs").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_dir_created_recursively() {
        let root = temp_root("recursive");
        let (_, clock) = mutable_clock(at(
            chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap(),
            8,
            30,
            0,
        ));
        let deep = root.join("a/b/c/logs");
        let result = RollingWriter::new(
            &file_cfg(deep.to_str().unwrap(), "daily", 10485760, 7),
            "",
            clock,
        );
        assert!(result.is_ok(), "deep dir should be created: {result:?}");
        assert!(deep.is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_dir_creation_failure_contains_path() {
        // Parent path is a file: create_dir_all necessarily fails and
        // the error contains the target path.
        let root = temp_root("failpath");
        std::fs::create_dir_all(&root).unwrap();
        let blocker = root.join("blocker.txt");
        std::fs::write(&blocker, "x").unwrap();

        let target = root.join("blocker.txt/logs");
        let (_, clock) = mutable_clock(at(
            chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap(),
            8,
            30,
            0,
        ));
        let err = RollingWriter::new(
            &file_cfg(target.to_str().unwrap(), "daily", 10485760, 7),
            "",
            clock,
        )
        .unwrap_err();
        assert!(err.starts_with("failed to create log directory"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_daily_roll_across_day_boundary() {
        let root = temp_root("daily");
        let day1 = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap();
        let (time, clock) = mutable_clock(at(day1, 23, 59, 0));
        let mut writer = RollingWriter::new(
            &file_cfg(root.to_str().unwrap(), "daily", 10485760, 7),
            "",
            clock,
        )
        .unwrap();
        write_line(&mut writer, "day1");

        // Across the day boundary: the first log line is written to the
        // new period's segment.
        *time.lock().unwrap() = at(day1 + chrono::Duration::days(1), 0, 0, 30);
        write_line(&mut writer, "day2");

        assert_eq!(
            slice_names(&root),
            vec![
                "db-query.log.20261104".to_string(),
                "db-query.log.20261105".to_string(),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_hourly_roll_across_hour_boundary() {
        let root = temp_root("hourly");
        let day = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap();
        let (time, clock) = mutable_clock(at(day, 8, 59, 0));
        let mut writer = RollingWriter::new(
            &file_cfg(root.to_str().unwrap(), "hourly", 10485760, 7),
            "",
            clock,
        )
        .unwrap();
        write_line(&mut writer, "h8");

        *time.lock().unwrap() = at(day, 9, 0, 30);
        write_line(&mut writer, "h9");

        assert_eq!(
            slice_names(&root),
            vec![
                "db-query.log.20261104-08".to_string(),
                "db-query.log.20261104-09".to_string(),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_size_roll_over_threshold() {
        let root = temp_root("size");
        let day = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap();
        let (time, clock) = mutable_clock(at(day, 8, 30, 12));
        let mut writer =
            RollingWriter::new(&file_cfg(root.to_str().unwrap(), "size", 20, 7), "", clock)
                .unwrap();

        // Each line is 11 bytes (with newline): after 2 lines the 3rd
        // triggers the switch (pre-write check).
        write_line(&mut writer, "aaaaaaaaaa"); // 10 + \n = 11
        write_line(&mut writer, "bbbbbbbbbb"); // 22 > 20 triggers? Pre-write
        // check: before line 2 written=11, 11+11=22 > 20 → roll first,
        // then write.
        write_line(&mut writer, "cccccccccc");

        assert_eq!(
            slice_names(&root).len(),
            3,
            "slices: {:?}",
            slice_names(&root)
        );
        // Each segment ≤ threshold (guaranteed by the pre-write check).
        for name in slice_names(&root) {
            let size = std::fs::metadata(root.join(&name)).unwrap().len();
            assert!(size <= 20, "slice {name} exceeds threshold: {size}");
        }
        let _ = time;
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_size_single_oversize_event_written_intact() {
        let root = temp_root("oversize");
        let day = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap();
        let (_, clock) = mutable_clock(at(day, 8, 30, 12));
        let mut writer =
            RollingWriter::new(&file_cfg(root.to_str().unwrap(), "size", 20, 7), "", clock)
                .unwrap();

        // A single line exceeding the threshold on its own: written
        // intact, not split, not dropped.
        let big = "x".repeat(100);
        write_line(&mut writer, &big);

        let names = slice_names(&root);
        assert_eq!(names.len(), 1, "slices: {names:?}");
        let content = std::fs::read_to_string(root.join(&names[0])).unwrap();
        assert_eq!(content.trim_end().len(), 100);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_size_same_second_conflict_increments_seq() {
        let root = temp_root("seq");
        let day = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap();
        let (time, clock) = mutable_clock(at(day, 8, 30, 12));
        let mut writer =
            RollingWriter::new(&file_cfg(root.to_str().unwrap(), "size", 10, 7), "", clock)
                .unwrap();

        // Multiple rolls within the same second: same timestamp,
        // incrementing sequence numbers.
        write_line(&mut writer, "aaaaaaaaaa");
        write_line(&mut writer, "bbbbbbbbbb");
        write_line(&mut writer, "cccccccccc");

        let names = slice_names(&root);
        assert_eq!(
            names,
            vec![
                "db-query.log.20261104-083012".to_string(),
                "db-query.log.20261104-083012.1".to_string(),
                "db-query.log.20261104-083012.2".to_string(),
            ],
            "slices: {names:?}"
        );
        let _ = time;
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_restart_appends_to_existing_period_slice() {
        let root = temp_root("restart");
        let day = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap();

        // Pre-seed a same-period segment with content (simulating a
        // previous run).
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("db-query.log.20261104"), "previous\n").unwrap();

        let (_, clock) = mutable_clock(at(day, 12, 0, 0));
        let mut writer = RollingWriter::new(
            &file_cfg(root.to_str().unwrap(), "daily", 10485760, 7),
            "",
            clock,
        )
        .unwrap();
        write_line(&mut writer, "current");

        let content = std::fs::read_to_string(root.join("db-query.log.20261104")).unwrap();
        assert_eq!(content, "previous\ncurrent\n");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_cleanup_removes_only_expired_slices() {
        let root = temp_root("cleanup");
        let today = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap();
        std::fs::create_dir_all(&root).unwrap();

        // Pre-seed: today / yesterday / 3-days-ago segments plus one
        // non-matching file name.
        for name in [
            "db-query.log.20261104",
            "db-query.log.20261103",
            "db-query.log.20261101",
            "unrelated.txt",
        ] {
            std::fs::write(root.join(name), "x").unwrap();
        }

        let (_, clock) = mutable_clock(at(today, 12, 0, 0));
        let writer = RollingWriter::new(
            &file_cfg(root.to_str().unwrap(), "daily", 10485760, 1),
            "",
            clock,
        )
        .unwrap();
        drop(writer);

        // max_days=1: today and yesterday are kept, earlier ones
        // deleted; non-matching files untouched.
        assert!(root.join("db-query.log.20261104").exists());
        assert!(root.join("db-query.log.20261103").exists());
        assert!(!root.join("db-query.log.20261101").exists());
        assert!(root.join("unrelated.txt").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_cleanup_failure_does_not_break_init() {
        let root = temp_root("cleanfail");
        let today = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap();
        std::fs::create_dir_all(&root).unwrap();

        // An expired segment is a directory: remove_file fails
        // (best-effort skip).
        std::fs::create_dir_all(root.join("db-query.log.20261001")).unwrap();

        let (_, clock) = mutable_clock(at(today, 12, 0, 0));
        let result = RollingWriter::new(
            &file_cfg(root.to_str().unwrap(), "daily", 10485760, 7),
            "",
            clock,
        );
        assert!(result.is_ok(), "cleanup failure must not break init");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_no_empty_slice_when_no_writes() {
        let root = temp_root("noempty");
        let day = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap();
        let (_, clock) = mutable_clock(at(day, 12, 0, 0));
        let writer = RollingWriter::new(
            &file_cfg(root.to_str().unwrap(), "daily", 10485760, 7),
            "",
            clock,
        )
        .unwrap();

        // No log lines written after construction: no new segment is
        // created in the directory.
        drop(writer);
        assert!(slice_names(&root).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_write_failure_returns_error_and_recovers_to_roll() {
        let root = temp_root("writefail");
        let day = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap();
        let (time, clock) = mutable_clock(at(day, 12, 0, 0));
        let mut writer = RollingWriter::new(
            &file_cfg(root.to_str().unwrap(), "daily", 10485760, 7),
            "",
            clock,
        )
        .unwrap();
        write_line(&mut writer, "before");

        // After the directory is removed: on Unix the already-open
        // handle remains writable (unlink does not invalidate the fd),
        // so writes within the same period succeeding is expected
        // behavior; when rolling across a period, open fails with an io
        // error and the process does not crash.
        let _ = std::fs::remove_dir_all(&root);
        *time.lock().unwrap() = at(day + chrono::Duration::days(1), 0, 0, 30);
        let rolled = writer.write_all(b"broken\n");
        assert!(rolled.is_err(), "roll after dir removal should fail");
        // Write again (cross-period retry): the directory is still
        // missing; keep erroring without panicking.
        assert!(writer.write_all(b"still-broken\n").is_err());
    }
}
