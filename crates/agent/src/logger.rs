//! A small size-capped log file. The agent has no console when it runs as
//! a service, so everything worth knowing goes here.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BYTES: u64 = 2 * 1024 * 1024;

struct Logger {
    path: PathBuf,
    file: Option<File>,
    written: u64,
    echo: bool,
}

static LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();

/// Starts logging to `path`. With `echo`, lines are also printed to stderr.
pub fn init(path: &Path, echo: bool) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let file = OpenOptions::new().create(true).append(true).open(path).ok();
    let written = file.as_ref().and_then(|f| f.metadata().ok()).map_or(0, |m| m.len());
    let _ = LOGGER.set(Mutex::new(Logger { path: path.to_path_buf(), file, written, echo }));
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn stamp() -> String {
    let secs = now_ms() / 1000;
    let (h, m, s) = (secs % 86_400 / 3600, secs % 3600 / 60, secs % 60);
    let days = secs / 86_400;
    // Civil date from day count (Howard Hinnant's algorithm), UTC.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}Z")
}

pub fn write(line: std::fmt::Arguments) {
    let text = format!("{} {}\n", stamp(), line);
    let Some(lock) = LOGGER.get() else {
        eprint!("{text}");
        return;
    };
    let mut log = lock.lock().unwrap_or_else(|p| p.into_inner());
    if log.echo {
        eprint!("{text}");
    }
    if log.written > MAX_BYTES {
        // Keep one previous file; that is plenty for diagnosing a problem.
        log.file = None;
        let old = log.path.with_extension("log.1");
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(&log.path, &old);
        log.file = OpenOptions::new().create(true).append(true).open(&log.path).ok();
        log.written = 0;
    }
    if let Some(f) = log.file.as_mut() {
        if f.write_all(text.as_bytes()).is_ok() {
            log.written += text.len() as u64;
        }
    }
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => { $crate::logger::write(format_args!($($arg)*)) };
}
