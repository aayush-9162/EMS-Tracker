//! Durable upload queue.
//!
//! Rows are appended to `live.jsonl` as they happen. When it is time to
//! upload, the live file is renamed to `batch-<seq>.jsonl` and sent as one
//! batch. A batch file is deleted only after the server acknowledges that
//! exact `seq`, so nothing is lost across crashes, reboots or outages, and
//! a batch that is re-sent keeps its `seq` so the server can recognise it.

use ems_proto::{AppUse, Batch, Event, Visit};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// A batch is sealed when it reaches this many rows...
pub const BATCH_ROWS: usize = 500;
/// ...or this many bytes, whichever comes first. One batch is one HTTP
/// request, and web servers in front of the EMS server commonly refuse
/// request bodies over 1 MB, so batches stay well under that.
pub const BATCH_BYTES: u64 = 256 * 1024;
/// Oldest batches are dropped beyond this, bounding disk use at roughly
/// 500 MB for a machine that stays offline for a very long time.
const MAX_BATCH_FILES: usize = 2_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "k")]
pub enum Row {
    #[serde(rename = "v")]
    Visit(Visit),
    #[serde(rename = "a")]
    App(AppUse),
    #[serde(rename = "e")]
    Event(Event),
}

pub struct Spool {
    dir: PathBuf,
    live: Option<File>,
    live_rows: usize,
    live_bytes: u64,
    last_seq: u64,
    /// Rows waiting in batch files, counted once at startup and kept current.
    batched_rows: usize,
}

fn count_lines(path: &Path) -> usize {
    File::open(path).map(|f| BufReader::new(f).lines().map_while(Result::ok).filter(|l| !l.trim().is_empty()).count()).unwrap_or(0)
}

fn batch_seq(path: &Path) -> Option<u64> {
    path.file_name()?.to_str()?.strip_prefix("batch-")?.strip_suffix(".jsonl")?.parse().ok()
}

impl Spool {
    pub fn open(dir: &Path) -> std::io::Result<Spool> {
        std::fs::create_dir_all(dir)?;
        let mut spool = Spool { dir: dir.to_path_buf(), live: None, live_rows: 0, live_bytes: 0, last_seq: 0, batched_rows: 0 };
        spool.live_rows = count_lines(&spool.live_path());
        spool.live_bytes = std::fs::metadata(spool.live_path()).map_or(0, |m| m.len());
        for (seq, path) in spool.batches() {
            spool.last_seq = spool.last_seq.max(seq);
            spool.batched_rows += count_lines(&path);
        }
        Ok(spool)
    }

    fn live_path(&self) -> PathBuf {
        self.dir.join("live.jsonl")
    }

    /// Batch files waiting to be uploaded, oldest first.
    pub fn batches(&self) -> Vec<(u64, PathBuf)> {
        let mut out: Vec<(u64, PathBuf)> = std::fs::read_dir(&self.dir)
            .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).filter_map(|p| batch_seq(&p).map(|s| (s, p))).collect())
            .unwrap_or_default();
        out.sort();
        out
    }

    pub fn pending_rows(&self) -> usize {
        self.live_rows + self.batched_rows
    }

    pub fn push(&mut self, row: &Row) -> std::io::Result<()> {
        if self.live.is_none() {
            self.live = Some(OpenOptions::new().create(true).append(true).open(self.live_path())?);
        }
        let mut line = serde_json::to_vec(row)?;
        line.push(b'\n');
        let file = self.live.as_mut().expect("opened above");
        file.write_all(&line)?;
        self.live_rows += 1;
        self.live_bytes += line.len() as u64;
        if self.live_rows >= BATCH_ROWS || self.live_bytes >= BATCH_BYTES {
            self.rotate(crate::logger::now_ms() as u64)?;
        }
        Ok(())
    }

    /// Seals the live file into a batch. `hint` is normally the current
    /// time; the sequence is forced upward so it is unique even if the
    /// clock stands still or moves backwards.
    pub fn rotate(&mut self, hint: u64) -> std::io::Result<Option<u64>> {
        if self.live_rows == 0 {
            return Ok(None);
        }
        self.live = None;
        let seq = hint.max(self.last_seq + 1);
        std::fs::rename(self.live_path(), self.dir.join(format!("batch-{seq}.jsonl")))?;
        self.last_seq = seq;
        self.batched_rows += self.live_rows;
        self.live_rows = 0;
        self.live_bytes = 0;
        self.enforce_cap();
        Ok(Some(seq))
    }

    fn enforce_cap(&mut self) {
        let batches = self.batches();
        if batches.len() > MAX_BATCH_FILES {
            for (_, path) in &batches[..batches.len() - MAX_BATCH_FILES] {
                self.batched_rows = self.batched_rows.saturating_sub(count_lines(path));
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// The oldest batch waiting to be sent.
    pub fn next_batch(&self) -> Option<Batch> {
        let (seq, path) = self.batches().into_iter().next()?;
        Some(read_batch(seq, &path))
    }

    /// Removes a batch the server has stored.
    pub fn ack(&mut self, seq: u64) {
        let path = self.dir.join(format!("batch-{seq}.jsonl"));
        if path.exists() {
            self.batched_rows = self.batched_rows.saturating_sub(count_lines(&path));
            let _ = std::fs::remove_file(path);
        }
    }
}

fn read_batch(seq: u64, path: &Path) -> Batch {
    let mut batch = Batch { seq, ..Default::default() };
    let Ok(file) = File::open(path) else { return batch };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        // A torn final line from a crash is skipped rather than failing the batch.
        match serde_json::from_str::<Row>(&line) {
            Ok(Row::Visit(v)) => batch.visits.push(v),
            Ok(Row::App(a)) => batch.apps.push(a),
            Ok(Row::Event(e)) => batch.events.push(e),
            Err(_) => {}
        }
    }
    batch
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        crate::config::temp_dir("spool")
    }

    fn app(start_ms: i64) -> Row {
        Row::App(AppUse { user: "u".into(), app: "Notepad".into(), title: None, exe: None, start_ms, dur_s: 5 })
    }

    #[test]
    fn rows_survive_restart_until_acknowledged() {
        let d = dir();
        {
            let mut s = Spool::open(&d).unwrap();
            s.push(&app(1)).unwrap();
            s.push(&app(2)).unwrap();
            assert_eq!(s.pending_rows(), 2);
        }
        // "Restart": a new instance sees what the old one wrote.
        let mut s = Spool::open(&d).unwrap();
        assert_eq!(s.pending_rows(), 2);
        let seq = s.rotate(1000).unwrap().unwrap();
        s.push(&app(3)).unwrap();

        let batch = s.next_batch().unwrap();
        assert_eq!((batch.seq, batch.apps.len()), (seq, 2));
        // Not acknowledged yet: asking again returns the same batch with the same seq.
        assert_eq!(s.next_batch().unwrap().seq, seq);

        s.ack(seq);
        assert!(s.next_batch().is_none());
        assert_eq!(s.pending_rows(), 1, "the row written after rotation is still live");
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn sequences_increase_even_if_the_clock_does_not() {
        let d = dir();
        let mut s = Spool::open(&d).unwrap();
        s.push(&app(1)).unwrap();
        let a = s.rotate(5000).unwrap().unwrap();
        s.push(&app(2)).unwrap();
        let b = s.rotate(5000).unwrap().unwrap();
        s.push(&app(3)).unwrap();
        let c = s.rotate(10).unwrap().unwrap();
        assert!(a < b && b < c, "{a} {b} {c}");
        assert_eq!(s.rotate(99_999).unwrap(), None, "nothing to seal");
        assert_eq!(s.batches().iter().map(|(q, _)| *q).collect::<Vec<_>>(), [a, b, c]);
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn a_torn_line_is_skipped() {
        let d = dir();
        std::fs::create_dir_all(&d).unwrap();
        let good = serde_json::to_string(&app(1)).unwrap();
        std::fs::write(d.join("batch-7.jsonl"), format!("{good}\n{{\"k\":\"a\",\"user\":\"u\",\"app\":\"No")).unwrap();
        let s = Spool::open(&d).unwrap();
        let batch = s.next_batch().unwrap();
        assert_eq!((batch.seq, batch.apps.len()), (7, 1));
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn batches_stay_small_enough_for_one_request() {
        let d = dir();
        let mut s = Spool::open(&d).unwrap();
        // Rows with the longest address and title the agent ever records.
        let big = Row::Visit(Visit {
            user: "u".into(),
            domain: "example.com".into(),
            url: Some(format!("https://example.com/{}", "a".repeat(1_980))),
            title: Some("t".repeat(500)),
            browser: None,
            start_ms: 1,
            dur_s: 5,
        });
        for _ in 0..400 {
            s.push(&big).unwrap();
        }
        let _ = s.rotate(1);
        let files = s.batches();
        assert!(files.len() >= 3, "large rows are split across several batches");
        for (_, path) in &files {
            let size = std::fs::metadata(path).unwrap().len();
            assert!(size < 300 * 1024, "{} bytes is too big for one request", size);
        }
        let total: usize = files.iter().map(|(seq, path)| read_batch(*seq, path).visits.len()).sum();
        assert_eq!(total, 400, "and no row is lost in the splitting");
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn a_full_live_file_seals_itself() {
        let d = dir();
        let mut s = Spool::open(&d).unwrap();
        for i in 0..BATCH_ROWS as i64 + 3 {
            s.push(&app(i)).unwrap();
        }
        assert_eq!(s.batches().len(), 1);
        assert_eq!(s.next_batch().unwrap().apps.len(), BATCH_ROWS);
        assert_eq!(s.pending_rows(), BATCH_ROWS + 3);
        std::fs::remove_dir_all(d).ok();
    }
}
