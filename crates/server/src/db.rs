//! SQLite storage.
//!
//! One thread owns the only write connection and drains a queue. Batches
//! arriving from many machines at once are committed together in a single
//! transaction, so disk work grows with time rather than with the number of
//! machines. Reads use a small pool of read-only connections and never wait
//! on the writer (WAL mode).

use anyhow::{anyhow, bail, Context};
use ems_proto::{truncate, valid_host, Batch, EventKind, MAX_TITLE_LEN, MAX_URL_LEN};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use tokio::sync::oneshot;

const SCHEMA: &str = include_str!("schema.sql");
/// Version of the layout in `schema.sql`, kept in SQLite's `user_version`.
const SCHEMA_VERSION: i64 = 6;
/// Name of the organisation that takes over everything recorded before
/// organisations existed. It can be renamed in the console.
pub const FIRST_ORG_NAME: &str = "Default";
const READERS: usize = 4;
/// Most batches committed in one transaction.
const COALESCE: usize = 256;
/// Upper bound on remembered hostnames, so junk input cannot grow memory forever.
const MAX_KNOWN_HOSTS: usize = 200_000;

type WriteFn = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

pub struct IngestJob {
    pub machine_id: i64,
    pub batch: Batch,
    pub now_ms: i64,
    pub tz_offset_min: i32,
    pub done: oneshot::Sender<anyhow::Result<IngestOutcome>>,
}

#[derive(Debug, Default)]
pub struct IngestOutcome {
    pub stored: usize,
    /// Hostnames seen for the first time in this batch.
    pub new_hosts: Vec<String>,
}

enum Job {
    Write(WriteFn),
    Ingest(IngestJob),
}

pub type KnownHosts = Arc<RwLock<HashSet<String>>>;

#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
}

struct Inner {
    tx: mpsc::Sender<Job>,
    readers: Vec<Mutex<Connection>>,
    next: AtomicUsize,
    known_hosts: KnownHosts,
}

fn tune(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA cache_size = -16000;
         PRAGMA temp_store = MEMORY;
         PRAGMA wal_autocheckpoint = 2000;",
    )
}

/// Moves a database from before organisations existed to the current
/// layout. Everything it holds goes to one organisation, which keeps the
/// old agent key so that computers already installed carry on reporting.
fn upgrade_to_v2(tx: &Transaction) -> rusqlite::Result<()> {
    let setting = |key: &str| tx.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get::<_, String>(0)).optional();
    let old_key = setting("agent_key")?.filter(|k| !k.is_empty());
    let api_key_hash = setting("api_key_hash")?;
    let settings = setting("settings")?;
    let has_data: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM machines) OR EXISTS (SELECT 1 FROM blocked_domains) OR EXISTS (SELECT 1 FROM blacklist_words)
             OR EXISTS (SELECT 1 FROM domain_categories) OR EXISTS (SELECT 1 FROM category_keywords)",
        [],
        |r| r.get(0),
    )?;

    // Tables whose rows now belong to an organisation are rebuilt; activity tables are untouched.
    const REBUILT: [&str; 5] = ["machines", "blocked_domains", "blacklist_words", "domain_categories", "category_keywords"];
    for table in REBUILT {
        tx.execute_batch(&format!("ALTER TABLE {table} RENAME TO {table}_v1;"))?;
    }
    tx.execute_batch(SCHEMA)?;
    if has_data || old_key.is_some() {
        tx.execute(
            "INSERT INTO orgs (id, name, name_key, agent_key, api_key_hash, settings, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![FIRST_ORG_NAME, FIRST_ORG_NAME.to_lowercase(), old_key.unwrap_or_else(|| crate::util::random_hex(16)), api_key_hash, settings, crate::util::now_s()],
        )?;
    }
    tx.execute_batch(
        "INSERT INTO machines (id, org_id, machine_uuid, hostname, os_user, label, os_version, agent_version, ip, first_seen, last_seen)
           SELECT id, 1, machine_uuid, hostname, os_user, label, os_version, agent_version, ip, first_seen, last_seen FROM machines_v1;
         INSERT INTO blocked_domains (id, org_id, domain, machine_uuid, note, created_at)
           SELECT id, 1, domain, machine_uuid, note, created_at FROM blocked_domains_v1;
         INSERT INTO blacklist_words (id, org_id, word, note, created_at)
           SELECT id, 1, word, note, created_at FROM blacklist_words_v1;
         INSERT INTO domain_categories (org_id, domain, category, updated_at)
           SELECT 1, domain, category, updated_at FROM domain_categories_v1;
         INSERT INTO category_keywords (id, org_id, keyword, category, created_at)
           SELECT id, 1, keyword, category, created_at FROM category_keywords_v1;",
    )?;
    for table in REBUILT {
        tx.execute_batch(&format!("DROP TABLE {table}_v1;"))?;
    }
    // Its three values now live with the organisation.
    tx.execute_batch("DROP TABLE settings;")
}

/// Adds a column to a table that an older database is missing. Harmless on a
/// database that already has it.
fn ensure_column(conn: &Connection, table: &str, column: &str, decl: &str) -> anyhow::Result<()> {
    let present: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?1"), [column], |r| r.get(0))?;
    if present == 0 {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl};"))?;
    }
    Ok(())
}

/// Creates the tables, upgrading an older database first. An upgrade keeps
/// a copy of the file as it was, next to it.
fn prepare(conn: &mut Connection, path: &Path) -> anyhow::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        bail!("{} was written by a newer EMS server (layout {version}, this program knows up to {SCHEMA_VERSION})", path.display());
    }
    let has_tables: bool = conn.query_row("SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'machines')", [], |r| r.get(0))?;
    if has_tables && version < 2 {
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        let backup = path.with_extension("db.before-organisations");
        std::fs::copy(path, &backup).with_context(|| format!("keeping a copy of the database at {}", backup.display()))?;
        let tx = conn.transaction()?;
        upgrade_to_v2(&tx).context("upgrading the database for organisations")?;
        tx.pragma_update(None, "user_version", 2)?;
        tx.commit()?;
        crate::logln!("database upgraded for organisations; the previous file is kept at {}", backup.display());
    }
    conn.execute_batch(SCHEMA).context("applying schema")?;
    ensure_column(conn, "inventory", "logs", "TEXT")?;
    // An existing single-admin database: that admin becomes the owner.
    ensure_column(conn, "admins", "role", "TEXT NOT NULL DEFAULT 'owner'")?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Db> {
        let mut conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        // Must be set before the first table exists to take effect.
        conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
        tune(&conn)?;
        prepare(&mut conn, path)?;

        let known: HashSet<String> = {
            let mut st = conn.prepare("SELECT host FROM known_hosts")?;
            let rows = st.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let known_hosts: KnownHosts = Arc::new(RwLock::new(known));

        let mut readers = Vec::with_capacity(READERS);
        for _ in 0..READERS {
            let r = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI,
            )?;
            r.execute_batch("PRAGMA busy_timeout = 5000; PRAGMA cache_size = -8000; PRAGMA temp_store = MEMORY;")?;
            readers.push(Mutex::new(r));
        }

        let (tx, rx) = mpsc::channel::<Job>();
        let writer_known = known_hosts.clone();
        std::thread::Builder::new()
            .name("db-writer".into())
            .spawn(move || writer_loop(conn, rx, writer_known))
            .context("starting the database writer thread")?;

        Ok(Db { inner: Arc::new(Inner { tx, readers, next: AtomicUsize::new(0), known_hosts }) })
    }

    pub fn known_hosts(&self) -> KnownHosts {
        self.inner.known_hosts.clone()
    }

    /// Runs `f` inside a write transaction on the writer thread.
    pub async fn write<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Transaction) -> rusqlite::Result<T> + Send + 'static,
    {
        let (otx, orx) = oneshot::channel();
        let job: WriteFn = Box::new(move |conn| {
            let result = (|| {
                let tx = conn.transaction()?;
                let value = f(&tx)?;
                tx.commit()?;
                Ok::<T, rusqlite::Error>(value)
            })();
            let _ = otx.send(result);
        });
        self.inner.tx.send(Job::Write(job)).map_err(|_| anyhow!("database writer has stopped"))?;
        Ok(orx.await.map_err(|_| anyhow!("database writer dropped the request"))??)
    }

    /// Runs `f` outside any transaction on the writer connection. Needed for
    /// statements SQLite refuses inside a transaction, such as checkpoints.
    pub async fn maintenance<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let (otx, orx) = oneshot::channel();
        let job: WriteFn = Box::new(move |conn| {
            let _ = otx.send(f(conn));
        });
        self.inner.tx.send(Job::Write(job)).map_err(|_| anyhow!("database writer has stopped"))?;
        Ok(orx.await.map_err(|_| anyhow!("database writer dropped the request"))??)
    }

    /// Runs a read-only query on one of the pooled reader connections.
    pub async fn read<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let inner = self.inner.clone();
        let out = tokio::task::spawn_blocking(move || {
            let idx = inner.next.fetch_add(1, Ordering::Relaxed) % inner.readers.len();
            let conn = inner.readers[idx].lock().unwrap_or_else(|p| p.into_inner());
            f(&conn)
        })
        .await
        .context("database reader task failed")?;
        Ok(out?)
    }

    /// Queues a batch from an agent. Resolves once the rows are committed.
    pub async fn ingest(&self, machine_id: i64, batch: Batch, now_ms: i64, tz_offset_min: i32) -> anyhow::Result<IngestOutcome> {
        let (done, rx) = oneshot::channel();
        self.inner
            .tx
            .send(Job::Ingest(IngestJob { machine_id, batch, now_ms, tz_offset_min, done }))
            .map_err(|_| anyhow!("database writer has stopped"))?;
        rx.await.map_err(|_| anyhow!("database writer dropped the batch"))?
    }
}

fn writer_loop(mut conn: Connection, rx: mpsc::Receiver<Job>, known: KnownHosts) {
    while let Ok(job) = rx.recv() {
        match job {
            Job::Write(f) => f(&mut conn),
            Job::Ingest(first) => {
                let mut jobs = vec![first];
                let mut deferred: Option<WriteFn> = None;
                while jobs.len() < COALESCE {
                    match rx.try_recv() {
                        Ok(Job::Ingest(j)) => jobs.push(j),
                        Ok(Job::Write(f)) => {
                            deferred = Some(f);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                ingest_many(&mut conn, jobs, &known);
                if let Some(f) = deferred {
                    f(&mut conn);
                }
            }
        }
    }
}

/// Commits every queued batch in one transaction. If that fails, each batch
/// is retried on its own so one bad batch cannot sink the others.
fn ingest_many(conn: &mut Connection, jobs: Vec<IngestJob>, known: &KnownHosts) {
    let together = (|| -> rusqlite::Result<Vec<IngestOutcome>> {
        let tx = conn.transaction()?;
        let mut seen = HashSet::new();
        let mut outcomes = Vec::with_capacity(jobs.len());
        for job in &jobs {
            outcomes.push(ingest_one(&tx, job, known, &mut seen)?);
        }
        tx.commit()?;
        Ok(outcomes)
    })();

    match together {
        Ok(outcomes) => {
            remember_hosts(known, outcomes.iter().flat_map(|o| o.new_hosts.iter()));
            for (job, outcome) in jobs.into_iter().zip(outcomes) {
                let _ = job.done.send(Ok(outcome));
            }
        }
        Err(_) => {
            for job in jobs {
                let single = (|| -> rusqlite::Result<IngestOutcome> {
                    let tx = conn.transaction()?;
                    let outcome = ingest_one(&tx, &job, known, &mut HashSet::new())?;
                    tx.commit()?;
                    Ok(outcome)
                })();
                if let Ok(o) = &single {
                    remember_hosts(known, o.new_hosts.iter());
                }
                let _ = job.done.send(single.map_err(anyhow::Error::from));
            }
        }
    }
}

fn remember_hosts<'a>(known: &KnownHosts, hosts: impl Iterator<Item = &'a String>) {
    let mut set = known.write().unwrap_or_else(|p| p.into_inner());
    for h in hosts {
        if set.len() >= MAX_KNOWN_HOSTS {
            break;
        }
        set.insert(h.clone());
    }
}

fn clip(s: &str, max: usize) -> String {
    truncate(s.trim(), max)
}

fn clip_opt(s: &Option<String>, max: usize) -> Option<String> {
    s.as_deref().map(|v| clip(v, max)).filter(|v| !v.is_empty())
}

/// Keeps a URL only if it is plain http(s). The admin console renders these
/// as links, so nothing like `javascript:` may ever be stored.
fn clip_url(s: &Option<String>) -> Option<String> {
    clip_opt(s, MAX_URL_LEN).filter(|u| {
        let lower = u.get(..8).unwrap_or(u).to_ascii_lowercase();
        lower.starts_with("http://") || lower.starts_with("https://")
    })
}

/// Rejects timestamps that cannot be right: more than a day in the future
/// or more than a year in the past. Such rows come from a broken clock.
fn plausible(ms: i64, now_ms: i64) -> bool {
    ms <= now_ms + 86_400_000 && ms >= now_ms - 366 * 86_400_000
}

fn ingest_one(tx: &Transaction, job: &IngestJob, known: &KnownHosts, seen: &mut HashSet<String>) -> rusqlite::Result<IngestOutcome> {
    let mut out = IngestOutcome::default();
    let mut last_user: Option<(i64, String)> = None;
    let mut note_user = |ms: i64, user: &str| {
        if !user.is_empty() && last_user.as_ref().map_or(true, |(t, _)| ms >= *t) {
            last_user = Some((ms, user.to_string()));
        }
    };

    if !job.batch.visits.is_empty() {
        let mut ins = tx.prepare_cached(
            "INSERT OR IGNORE INTO visits (machine_id, os_user, domain, url, title, browser, start_ms, dur_s)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        let mut host_ins = tx.prepare_cached("INSERT OR IGNORE INTO known_hosts (host) VALUES (?1)")?;
        for v in &job.batch.visits {
            let domain = v.domain.trim().to_ascii_lowercase();
            if v.dur_s == 0 || !valid_host(&domain) || !plausible(v.start_ms, job.now_ms) {
                continue;
            }
            let user = clip(&v.user, 255);
            out.stored += ins.execute(params![
                job.machine_id,
                user,
                domain,
                clip_url(&v.url),
                clip_opt(&v.title, MAX_TITLE_LEN),
                clip_opt(&v.browser, 64),
                v.start_ms,
                v.dur_s.min(86_400),
            ])?;
            note_user(v.start_ms, &user);

            let is_new = !seen.contains(&domain) && !known.read().unwrap_or_else(|p| p.into_inner()).contains(&domain);
            if is_new {
                host_ins.execute([&domain])?;
                seen.insert(domain.clone());
                out.new_hosts.push(domain);
            }
        }
    }

    if !job.batch.apps.is_empty() {
        let mut ins = tx.prepare_cached(
            "INSERT OR IGNORE INTO app_usage (machine_id, os_user, app, title, exe, start_ms, dur_s)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for a in &job.batch.apps {
            let app = clip(&a.app, 255);
            if a.dur_s == 0 || app.is_empty() || !plausible(a.start_ms, job.now_ms) {
                continue;
            }
            let user = clip(&a.user, 255);
            out.stored += ins.execute(params![
                job.machine_id,
                user,
                app,
                clip_opt(&a.title, MAX_TITLE_LEN),
                clip_opt(&a.exe, 500),
                a.start_ms,
                a.dur_s.min(86_400),
            ])?;
            note_user(a.start_ms, &user);
        }
    }

    for e in &job.batch.events {
        let domain = e.domain.trim().to_ascii_lowercase();
        if !valid_host(&domain) || !plausible(e.at_ms, job.now_ms) {
            continue;
        }
        let user = clip(&e.user, 255);
        let url = clip_url(&e.url);
        match e.kind {
            EventKind::Blocked => {
                let day = (e.at_ms + i64::from(job.tz_offset_min) * 60_000).div_euclid(86_400_000);
                tx.prepare_cached(
                    "INSERT INTO block_events (machine_id, os_user, domain, url, day, hit_count, first_ms, last_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)
                     ON CONFLICT (machine_id, os_user, domain, day) DO UPDATE SET
                       hit_count = hit_count + 1,
                       last_ms   = MAX(last_ms, excluded.last_ms),
                       url       = COALESCE(excluded.url, url)",
                )?
                .execute(params![job.machine_id, user, domain, url, day, e.at_ms])?;
            }
            EventKind::Word => {
                let Some(word) = e.word.as_deref().map(|w| clip(w, 255)).filter(|w| !w.is_empty()) else {
                    continue;
                };
                tx.prepare_cached(
                    "INSERT INTO blacklist_hits (machine_id, os_user, word, domain, url, hit_count, first_hit_ms, last_hit_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)
                     ON CONFLICT (machine_id, os_user, word, domain) DO UPDATE SET
                       hit_count   = hit_count + 1,
                       last_hit_ms = MAX(last_hit_ms, excluded.last_hit_ms),
                       url         = COALESCE(excluded.url, url)",
                )?
                .execute(params![job.machine_id, user, word, domain, url, e.at_ms])?;
            }
        }
        out.stored += 1;
        note_user(e.at_ms, &user);
    }

    let now_s = job.now_ms / 1000;
    match last_user {
        Some((_, user)) => tx
            .prepare_cached("UPDATE machines SET last_seen = ?1, os_user = ?2 WHERE id = ?3")?
            .execute(params![now_s, user, job.machine_id])?,
        None => tx
            .prepare_cached("UPDATE machines SET last_seen = ?1 WHERE id = ?2")?
            .execute(params![now_s, job.machine_id])?,
    };
    Ok(out)
}

impl Db {
    /// Replaces a computer's stored snapshot with a newer one.
    pub async fn store_inventory(&self, machine_id: i64, system: String, apps: String, app_count: i64, logs: String) -> anyhow::Result<()> {
        let now = crate::util::now_s();
        self.write(move |tx| {
            tx.execute(
                "INSERT INTO inventory (machine_id, system, apps, app_count, logs, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (machine_id) DO UPDATE SET system = excluded.system, apps = excluded.apps, app_count = excluded.app_count, logs = excluded.logs, updated_at = excluded.updated_at",
                rusqlite::params![machine_id, system, apps, app_count, logs, now],
            )
        })
        .await?;
        Ok(())
    }
}

/// The four tables that hold recorded activity, with the column that dates a row.
const ACTIVITY: [(&str, &str); 4] = [("visits", "start_ms"), ("app_usage", "start_ms"), ("block_events", "last_ms"), ("blacklist_hits", "last_hit_ms")];
/// Rows deleted per transaction, so the writer is never held for long.
const DELETE_SLICE: usize = 20_000;

async fn delete_in_slices(db: &Db, sql: String, args: Vec<i64>) -> anyhow::Result<usize> {
    let mut total = 0usize;
    loop {
        let (statement, values) = (sql.clone(), args.clone());
        let n = db.write(move |tx| tx.execute(&statement, rusqlite::params_from_iter(values))).await?;
        total += n;
        if n < DELETE_SLICE {
            return Ok(total);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Deletes one organisation's activity older than `cutoff_ms`. Returns the
/// number of rows removed.
pub async fn prune(db: &Db, org: i64, cutoff_ms: i64) -> anyhow::Result<usize> {
    let mut total = 0usize;
    for (table, col) in ACTIVITY {
        let sql = format!(
            "DELETE FROM {table} WHERE id IN (SELECT id FROM {table}
              WHERE {col} < ?1 AND machine_id IN (SELECT id FROM machines WHERE org_id = ?2) LIMIT {DELETE_SLICE})"
        );
        total += delete_in_slices(db, sql, vec![cutoff_ms, org]).await?;
    }
    Ok(total)
}

/// Removes an organisation with its computers and everything recorded for them.
pub async fn delete_org(db: &Db, org: i64) -> anyhow::Result<()> {
    for (table, _) in ACTIVITY {
        let sql = format!(
            "DELETE FROM {table} WHERE id IN (SELECT id FROM {table}
              WHERE machine_id IN (SELECT id FROM machines WHERE org_id = ?1) LIMIT {DELETE_SLICE})"
        );
        delete_in_slices(db, sql, vec![org]).await?;
    }
    db.write(move |tx| {
        tx.execute("DELETE FROM inventory WHERE machine_id IN (SELECT id FROM machines WHERE org_id = ?1)", [org])?;
        tx.execute("DELETE FROM commands WHERE machine_id IN (SELECT id FROM machines WHERE org_id = ?1)", [org])?;
        tx.execute("DELETE FROM user_orgs WHERE org_id = ?1", [org])?;
        for table in ["machines", "blocked_domains", "blacklist_words", "domain_categories", "category_keywords"] {
            tx.execute(&format!("DELETE FROM {table} WHERE org_id = ?1"), [org])?;
        }
        tx.execute("DELETE FROM orgs WHERE id = ?1", [org])
    })
    .await?;
    Ok(())
}

/// Daily tidying that is not tied to an organisation.
pub async fn housekeeping(db: &Db) -> anyhow::Result<()> {
    db.write(|tx| tx.execute("DELETE FROM sessions WHERE expires_at < ?1", [crate::util::now_s()])).await?;
    db.maintenance(|c| c.execute_batch("PRAGMA incremental_vacuum(5000); PRAGMA wal_checkpoint(TRUNCATE); PRAGMA optimize;"))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ems_proto::{AppUse, Event, Visit};

    fn temp_db() -> (Db, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ems-test-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        (Db::open(&dir.join("ems.db")).unwrap(), dir)
    }

    fn visit(start_ms: i64, domain: &str) -> Visit {
        Visit { user: "alice".into(), domain: domain.into(), url: Some(format!("https://{domain}/")), title: None, browser: None, start_ms, dur_s: 30 }
    }

    async fn machine_in(db: &Db, org: i64, name: &'static str) -> i64 {
        db.write(move |tx| {
            tx.query_row("INSERT INTO machines (org_id, machine_uuid, first_seen, last_seen) VALUES (?1, ?2, 0, 0) RETURNING id", params![org, name], |r| r.get(0))
        })
        .await
        .unwrap()
    }

    async fn machine(db: &Db) -> i64 {
        machine_in(db, 1, "m-1").await
    }

    async fn count(db: &Db, sql: &'static str) -> i64 {
        db.read(move |c| c.query_row(sql, [], |r| r.get(0))).await.unwrap()
    }

    #[tokio::test]
    async fn resending_a_batch_stores_nothing_twice() {
        let (db, dir) = temp_db();
        let id = machine(&db).await;
        let now = crate::util::now_ms();
        let batch = Batch {
            seq: 1,
            visits: vec![visit(now - 60_000, "example.com"), visit(now - 30_000, "sub.example.com")],
            apps: vec![AppUse { user: "alice".into(), app: "Excel".into(), title: None, exe: None, start_ms: now - 60_000, dur_s: 60 }],
            events: vec![],
        };
        let first = db.ingest(id, batch.clone(), now, 0).await.unwrap();
        assert_eq!(first.stored, 3);
        assert_eq!(first.new_hosts.len(), 2);

        let again = db.ingest(id, batch, now, 0).await.unwrap();
        assert_eq!(again.stored, 0, "duplicate rows must be ignored");
        assert!(again.new_hosts.is_empty(), "hosts are only new once");

        let (visits, user): (i64, String) = db
            .read(move |c| c.query_row("SELECT (SELECT COUNT(*) FROM visits), (SELECT os_user FROM machines WHERE id = ?1)", [id], |r| Ok((r.get(0)?, r.get(1)?))))
            .await
            .unwrap();
        assert_eq!((visits, user.as_str()), (2, "alice"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn bad_rows_are_dropped_and_events_are_counted() {
        let (db, dir) = temp_db();
        let id = machine(&db).await;
        let now = crate::util::now_ms();
        let ev = |kind, word: Option<&str>| Event { user: "bob".into(), kind, domain: "bad.example".into(), url: None, word: word.map(str::to_string), at_ms: now };
        let batch = Batch {
            seq: 2,
            visits: vec![
                visit(now, "4592.19"),                       // not a host
                visit(now + 3 * 86_400_000, "future.com"),   // clock far ahead
                Visit { dur_s: 0, ..visit(now - 1, "zero.com") },
                visit(now - 2, "ok.com"),
            ],
            apps: vec![],
            events: vec![ev(EventKind::Blocked, None), ev(EventKind::Blocked, None), ev(EventKind::Word, Some("casino")), ev(EventKind::Word, None)],
        };
        let out = db.ingest(id, batch, now, 0).await.unwrap();
        assert_eq!(out.stored, 4, "one visit, two block events, one word hit");
        let (v, attempts, hits): (i64, i64, i64) = db
            .read(|c| {
                c.query_row(
                    "SELECT (SELECT COUNT(*) FROM visits), (SELECT hit_count FROM block_events), (SELECT hit_count FROM blacklist_hits)",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
            })
            .await
            .unwrap();
        assert_eq!((v, attempts, hits), (1, 2, 1));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn prune_removes_only_old_rows() {
        let (db, dir) = temp_db();
        let id = machine(&db).await;
        let now = crate::util::now_ms();
        let batch = Batch { seq: 3, visits: vec![visit(now - 100 * 86_400_000, "old.com"), visit(now - 1000, "new.com")], ..Default::default() };
        db.ingest(id, batch, now, 0).await.unwrap();
        // Another organisation's old rows are not this organisation's to remove.
        let other = machine_in(&db, 2, "m-1").await;
        db.ingest(other, Batch { seq: 4, visits: vec![visit(now - 100 * 86_400_000, "theirs.com")], ..Default::default() }, now, 0).await.unwrap();

        let removed = prune(&db, 1, now - 90 * 86_400_000).await.unwrap();
        assert_eq!(removed, 1);
        let left: Vec<String> = db
            .read(|c| c.prepare("SELECT domain FROM visits ORDER BY domain")?.query_map([], |r| r.get(0))?.collect())
            .await
            .unwrap();
        assert_eq!(left, ["new.com", "theirs.com"]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn two_organisations_can_have_a_computer_with_the_same_name() {
        let (db, dir) = temp_db();
        let a = machine_in(&db, 1, "RECEPTION").await;
        let b = machine_in(&db, 2, "RECEPTION").await;
        assert_ne!(a, b);
        let again = db
            .write(|tx| tx.execute("INSERT INTO machines (org_id, machine_uuid, first_seen, last_seen) VALUES (1, 'RECEPTION', 0, 0)", []))
            .await;
        assert!(again.is_err(), "within one organisation a name is one computer");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn removing_an_organisation_takes_its_data_and_nothing_else() {
        let (db, dir) = temp_db();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO orgs (id, name, name_key, agent_key, created_at) VALUES (1, 'Acme', 'acme', 'key-a', 0), (2, 'Globex', 'globex', 'key-b', 0);
                 INSERT INTO blocked_domains (org_id, domain, created_at) VALUES (1, 'youtube.com', 0), (2, 'youtube.com', 0);
                 INSERT INTO blacklist_words (org_id, word, created_at) VALUES (1, 'casino', 0), (2, 'casino', 0);",
            )
        })
        .await
        .unwrap();
        let now = crate::util::now_ms();
        for (org, seq) in [(1, 1), (2, 2)] {
            let id = machine_in(&db, org, "PC-1").await;
            db.ingest(id, Batch { seq, visits: vec![visit(now - 1000, "example.com")], ..Default::default() }, now, 0).await.unwrap();
        }

        delete_org(&db, 1).await.unwrap();
        assert_eq!(count(&db, "SELECT COUNT(*) FROM orgs").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM machines WHERE org_id = 2").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM machines WHERE org_id = 1").await, 0);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM visits").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM blocked_domains").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM blacklist_words").await, 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_database_from_before_organisations_is_upgraded_in_place() {
        let dir = std::env::temp_dir().join(format!("ems-test-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ems.db");
        {
            let old = Connection::open(&path).unwrap();
            old.execute_batch(include_str!("schema_v1.sql")).unwrap();
            old.execute_batch(
                "INSERT INTO machines (id, machine_uuid, hostname, label, first_seen, last_seen) VALUES (7, 'DESKTOP-OLD', 'DESKTOP-OLD', 'Front desk', 10, 20);
                 INSERT INTO visits (machine_id, os_user, domain, start_ms, dur_s) VALUES (7, 'alice', 'example.com', 1000, 30);
                 INSERT INTO blocked_domains (domain, machine_uuid, created_at) VALUES ('youtube.com', '*', 5), ('x.com', 'DESKTOP-OLD', 6);
                 INSERT INTO blacklist_words (word, created_at) VALUES ('casino', 5);
                 INSERT INTO domain_categories (domain, category, updated_at) VALUES ('github.com', 'productive', 5);
                 INSERT INTO category_keywords (keyword, category, created_at) VALUES ('docs', 'productive', 5);
                 INSERT INTO settings (key, value) VALUES ('agent_key', 'old-key-123'), ('api_key_hash', 'abc'), ('settings', '{\"upload_interval_s\":120}');
                 INSERT INTO admins (username, password_hash, created_at) VALUES ('admin', 'hash', 1);",
            )
            .unwrap();
        }

        let db = Db::open(&path).unwrap();
        let org: (i64, String, String, Option<String>, Option<String>) = db
            .read(|c| c.query_row("SELECT id, name, agent_key, api_key_hash, settings FROM orgs", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))))
            .await
            .unwrap();
        assert_eq!(org, (1, FIRST_ORG_NAME.to_string(), "old-key-123".to_string(), Some("abc".to_string()), Some("{\"upload_interval_s\":120}".to_string())));
        assert_eq!(count(&db, "SELECT COUNT(*) FROM machines WHERE id = 7 AND org_id = 1 AND label = 'Front desk'").await, 1, "computers keep their ids, so their history stays attached");
        assert_eq!(count(&db, "SELECT COUNT(*) FROM visits v JOIN machines m ON m.id = v.machine_id WHERE m.org_id = 1").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM blocked_domains WHERE org_id = 1").await, 2);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM blacklist_words WHERE org_id = 1").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM domain_categories WHERE org_id = 1").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM category_keywords WHERE org_id = 1").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM admins").await, 1, "the administrator can still sign in");
        assert_eq!(count(&db, "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%_v1' OR name = 'settings'").await, 0);
        assert!(dir.join("ems.db.before-organisations").is_file(), "the file as it was is kept");

        // The same name can now exist in a second organisation.
        machine_in(&db, 2, "DESKTOP-OLD").await;
        drop(db);

        // Opening it again changes nothing.
        let db = Db::open(&path).unwrap();
        assert_eq!(count(&db, "SELECT COUNT(*) FROM orgs").await, 1);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM machines").await, 2);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_new_database_starts_with_no_organisation() {
        let (db, dir) = temp_db();
        assert_eq!(count(&db, "SELECT COUNT(*) FROM orgs").await, 0);
        assert_eq!(count(&db, "PRAGMA user_version").await, SCHEMA_VERSION);
        std::fs::remove_dir_all(dir).ok();
    }
}
