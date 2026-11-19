//! The background half of the agent: talks to the server, owns the upload
//! queue and applies the blocking policy. Runs as a Windows service when
//! installed.

use crate::config::{self, AgentConfig};
use crate::guard::Guard;
use crate::ipc::Status;
use crate::paths::Ctx;
use crate::spool::{Row, Spool};
use anyhow::Context;
use ems_proto::{Inventory, Policy};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{watch, Notify};

pub struct Shared {
    pub ctx: Ctx,
    pub cfg: AgentConfig,
    pub spool: Mutex<Spool>,
    pub policy: watch::Sender<Policy>,
    pub status: watch::Sender<Status>,
    /// Woken by "Sync now" in the tray menu to check in without waiting for the next interval.
    pub sync_now: Notify,
    /// A fresh system-and-programs snapshot waiting to go up at the next
    /// check-in, set when it differs from the last one uploaded.
    pub pending_inventory: Mutex<Option<Inventory>>,
    /// Woken when a development run must end so that an update can replace it.
    pub quit: Notify,
    /// Fingerprint of the program that is running, sent with every check-in.
    pub exe_sha: String,
    /// Windows session id -> number of tray helpers connected from it.
    pub sessions: Mutex<HashMap<u32, u32>>,
    /// This computer's name: its identity on the server.
    pub hostname: String,
    pub os_version: String,
}

pub fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Shared {
    /// Adopts a policy from the server: persisted first, then announced to
    /// the blocking layer and every tray helper.
    pub fn apply_policy(&self, policy: Policy) {
        if *self.policy.borrow() == policy {
            return;
        }
        if let Err(e) = config::save_policy(&self.ctx.policy_path(), &policy) {
            crate::log!("could not cache the policy: {e:#}");
        }
        crate::log!("policy updated: {} blocked site(s), {} blacklist word(s)", policy.blocked.len(), policy.words.len());
        if !policy.org.is_empty() {
            let org = policy.org.clone();
            self.update_status(|s| s.org = org);
        }
        self.policy.send_replace(policy);
    }

    /// Queues a row on disk. Everything, blocked attempts included, waits
    /// there for the next check-in: the server is not contacted in between.
    pub fn push_row(&self, row: &Row) {
        if let Err(e) = lock(&self.spool).push(row) {
            crate::log!("could not queue a row: {e}");
        }
    }

    pub fn update_status(&self, f: impl FnOnce(&mut Status)) {
        self.status.send_if_modified(|s| {
            let before = s.clone();
            f(s);
            *s != before
        });
    }

    pub fn refresh_pending(&self) {
        let pending = lock(&self.spool).pending_rows() as u64;
        self.update_status(|s| s.pending = pending);
    }

    /// Records that `sent` is now stored on the server, so it is not
    /// gathered-and-sent again until the computer actually changes.
    pub fn mark_inventory_sent(&self, sent: &Inventory) {
        let fingerprint = sent.fingerprint();
        if let Err(e) = std::fs::write(self.ctx.inventory_hash_path(), &fingerprint) {
            crate::log!("could not note the inventory as sent: {e}");
        }
        let mut pending = lock(&self.pending_inventory);
        if pending.as_ref().is_some_and(|i| i.fingerprint() == fingerprint) {
            *pending = None;
        }
    }
}

pub fn computer_name() -> String {
    std::env::var("COMPUTERNAME").ok().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| "UNKNOWN".into())
}

pub(crate) fn os_version() -> String {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let Ok(key) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") else {
        return "Windows".into();
    };
    let get = |name: &str| key.get_value::<String, _>(name).unwrap_or_default();
    let build = get("CurrentBuild");
    let mut product = get("ProductName");
    // Windows 11 still reports "Windows 10" here; the build number tells them apart.
    if build.parse::<u32>().is_ok_and(|b| b >= 22_000) {
        product = product.replace("Windows 10", "Windows 11");
    }
    format!("{product} {} (build {build})", get("DisplayVersion")).split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Loads state from disk and builds the shared context.
pub fn init(ctx: Ctx) -> anyhow::Result<Arc<Shared>> {
    std::fs::create_dir_all(&ctx.data_dir).with_context(|| format!("creating {}", ctx.data_dir.display()))?;
    let cfg = AgentConfig::load(&ctx.config_path()).context("the agent has not been set up on this computer; run the installer")?;
    let policy = config::load_policy(&ctx.policy_path()).unwrap_or_default();
    let spool = Spool::open(&ctx.spool_dir()).context("opening the upload queue")?;
    let hostname = computer_name();

    let status = Status {
        connected: false,
        server: cfg.server_url.clone(),
        // The server's word for the name wins; before the first check-in, the installer's.
        org: if policy.org.is_empty() { cfg.org.clone().unwrap_or_default() } else { policy.org.clone() },
        hostname: hostname.clone(),
        pending: spool.pending_rows() as u64,
        last_sync_ms: None,
        enforcement: String::new(),
        version: crate::version().into(),
    };
    Ok(Arc::new(Shared {
        ctx,
        cfg,
        spool: Mutex::new(spool),
        policy: watch::channel(policy).0,
        status: watch::channel(status).0,
        sync_now: Notify::new(),
        pending_inventory: Mutex::new(None),
        quit: Notify::new(),
        exe_sha: crate::update::own_fingerprint(),
        sessions: Mutex::new(HashMap::new()),
        hostname,
        os_version: os_version(),
    }))
}

/// Applies the policy whenever it changes, and re-checks every ten minutes
/// so that anything else rewriting the hosts file or the policy keys is put right.
async fn guard_task(shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let guard = Arc::new(Guard::new(&shared.ctx, config::server_host(&shared.cfg.server_url)));
    let mut rx = shared.policy.subscribe();
    loop {
        let policy = rx.borrow_and_update().clone();
        let g = guard.clone();
        if let Ok(outcome) = tokio::task::spawn_blocking(move || g.apply(&policy)).await {
            if outcome.changed || !outcome.ok {
                crate::log!("blocking: {}", outcome.summary);
            }
            shared.update_status(|s| s.enforcement = outcome.summary.clone());
        }
        tokio::select! {
            changed = rx.changed() => if changed.is_err() { return },
            _ = tokio::time::sleep(Duration::from_secs(600)) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// Gathers the system summary and installed-programs list now and then,
/// and queues it for the next check-in when it differs from the last one
/// uploaded. Reading it is cheap, so this costs almost nothing.
async fn inventory_task(shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    // A short delay first, so a fresh start is not held up gathering it, then once a day.
    let mut wait = Duration::from_secs(20);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => return,
        }
        wait = Duration::from_secs(24 * 3600);
        let (server_url, log_path) = (shared.cfg.server_url.clone(), shared.ctx.log_path());
        let Ok(inv) = tokio::task::spawn_blocking(move || crate::inventory::collect(&server_url, &log_path)).await else { continue };
        let last = std::fs::read_to_string(shared.ctx.inventory_hash_path()).unwrap_or_default();
        if inv.fingerprint() != last.trim() {
            crate::log!("inventory changed: {} program(s) installed; will upload at the next check-in", inv.apps.len());
            *lock(&shared.pending_inventory) = Some(inv);
            // Push it promptly rather than waiting for the interval.
            shared.sync_now.notify_one();
        }
    }
}

/// Runs until `shutdown` flips to true.
pub async fn run(shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    crate::log!("agent {} starting: {} reports to {}", crate::version(), shared.hostname, shared.cfg.server_url);
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(guard_task(shared.clone(), shutdown.clone()));
    tasks.spawn(crate::pipe::serve(shared.clone(), shutdown.clone()));
    tasks.spawn(crate::sync::run(shared.clone(), shutdown.clone()));
    tasks.spawn(inventory_task(shared.clone(), shutdown.clone()));
    if shared.ctx.launch_sessions {
        tasks.spawn(crate::launcher::run(shared.clone(), shutdown.clone()));
    }

    let _ = shutdown.changed().await;
    // Give the last check-in a moment to hand over what is queued, then stop.
    let _ = tokio::time::timeout(Duration::from_secs(6), async { while tasks.join_next().await.is_some() {} }).await;
    crate::log!("agent stopped");
}
