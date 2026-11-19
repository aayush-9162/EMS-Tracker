//! Talking to the server.
//!
//! Once per interval (five minutes unless changed) the agent makes a single
//! HTTPS request that reports the computer as alive, uploads the activity
//! that has been waiting on disk, and brings back the policy if it has
//! changed. Nothing is sent or fetched in between. While the server cannot
//! be reached, rows keep waiting and the last known policy stays in force.

use crate::config;
use crate::core::{lock, Shared};
use anyhow::anyhow;
use ems_proto::{AgentCommand, AgentUpdate, Batch, CommandKind, Inventory, SyncRequest, SyncResponse, KEY_HEADER, PROTOCOL_VERSION};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(40);
/// Longest wait between attempts while the server is unreachable.
const BACKOFF_MAX_S: u64 = 600;
/// Batches sent back to back when catching up after an outage.
const MAX_DRAIN: usize = 25;
/// Once the agent has run this long, files left by an update are removed.
const TIDY_AFTER: Duration = Duration::from_secs(120);

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    u64::from_le_bytes(b)
}

/// `base` seconds, varied by up to a quarter either way so a whole office
/// of computers never checks in at the same instant.
fn jittered(base: u64) -> Duration {
    let ms = base.max(1) * 1000;
    let spread = ms / 2;
    Duration::from_millis(ms - spread / 2 + random_u64() % (spread + 1))
}

fn http_client() -> ureq::Agent {
    use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
    // Windows' own TLS and certificate store, so a company's own certificate authority is honoured.
    let tls = TlsConfig::builder().provider(TlsProvider::NativeTls).root_certs(RootCerts::PlatformVerifier).build();
    ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .tls_config(tls)
        .user_agent(concat!("ems-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent()
}

fn describe(err: ureq::Error) -> anyhow::Error {
    match err {
        ureq::Error::StatusCode(401) => anyhow!("the server does not accept this computer's agent key (its organisation may have been removed, or the installer was made for another server)"),
        ureq::Error::StatusCode(code) => anyhow!("the server answered with HTTP {code}"),
        other => anyhow!("{other}"),
    }
}

/// One request, made on a worker thread because the HTTP client blocks.
async fn post(http: &ureq::Agent, shared: &Arc<Shared>, batch: Option<Batch>, inventory: Option<Inventory>) -> anyhow::Result<SyncResponse> {
    let (http, shared) = (http.clone(), shared.clone());
    tokio::task::spawn_blocking(move || {
        let request = SyncRequest {
            v: PROTOCOL_VERSION,
            hostname: shared.hostname.clone(),
            local_ip: config::local_ip(&shared.cfg.server_url),
            os_version: shared.os_version.clone(),
            agent_version: crate::version().into(),
            agent_sha: shared.exe_sha.clone(),
            policy_hash: shared.policy.borrow().hash(),
            batch,
            inventory,
        };
        let mut call = http.post(config::sync_url(&shared.cfg.server_url));
        if let Some(key) = &shared.cfg.key {
            call = call.header(KEY_HEADER, key.as_str());
        }
        let mut response = call.send_json(&request).map_err(describe)?;
        response.body_mut().read_json::<SyncResponse>().map_err(|e| anyhow!("unreadable reply from the server: {e}"))
    })
    .await
    .map_err(|e| anyhow!("{e}"))?
}

/// Checks in and uploads until the queue is empty. Returns the first error,
/// or anything the server sent back for the agent to act on.
async fn sync(http: &ureq::Agent, shared: &Arc<Shared>) -> anyhow::Result<(Option<AgentUpdate>, Option<AgentCommand>)> {
    lock(&shared.spool).rotate(crate::logger::now_ms() as u64)?;
    // The inventory, if one is waiting, rides along on the first request of this round.
    let pending_inventory = lock(&shared.pending_inventory).clone();
    let mut inventory = pending_inventory.clone();
    let mut update = None;
    let mut command = None;
    for _ in 0..MAX_DRAIN {
        let batch = lock(&shared.spool).next_batch();
        if let Some(b) = &batch {
            if b.is_empty() {
                // Nothing readable in the file; drop it rather than resend it forever.
                lock(&shared.spool).ack(b.seq);
                continue;
            }
        }
        let had_batch = batch.is_some();
        let sending_inventory = inventory.is_some();
        let reply = post(http, shared, batch, inventory.take()).await?;
        if sending_inventory {
            // The request was accepted, so the server now holds this snapshot.
            if let Some(inv) = &pending_inventory {
                shared.mark_inventory_sent(inv);
            }
        }
        if let Some(seq) = reply.ack {
            lock(&shared.spool).ack(seq);
        }
        if let Some(policy) = reply.policy {
            shared.apply_policy(policy);
        }
        update = reply.update;
        command = command.or(reply.command);
        if !had_batch || lock(&shared.spool).batches().is_empty() {
            break;
        }
    }
    Ok((update, command))
}

/// Runs for the life of the agent.
pub async fn run(shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let http = http_client();
    let started = Instant::now();
    let mut tidied = false;
    let mut failures = 0u32;
    // First check-in a moment after start, so a fresh install shows up at once.
    let mut wait = Duration::from_secs(2);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            // "Sync now" was chosen in the tray menu.
            _ = shared.sync_now.notified() => {}
            _ = shutdown.changed() => {
                // Hand over what is queued before stopping, without holding the shutdown up for long.
                let _ = tokio::time::timeout(Duration::from_secs(4), sync(&http, &shared)).await;
                return;
            }
        }

        match sync(&http, &shared).await {
            Ok((update, command)) => {
                if failures > 0 || !shared.status.borrow().connected {
                    crate::log!("reporting to {}", shared.cfg.server_url);
                }
                failures = 0;
                let now = crate::logger::now_ms();
                shared.update_status(|s| {
                    s.connected = true;
                    s.last_sync_ms = Some(now);
                });
                // A restart or shutdown is carried out after everything waiting has gone up.
                if let Some(cmd) = command {
                    crate::log!("server asked this computer to {}", cmd.kind.as_str());
                    let _ = tokio::task::spawn_blocking(move || {
                        let result = match cmd.kind {
                            CommandKind::Lock => crate::launcher::lock_active_sessions(),
                            CommandKind::Restart | CommandKind::Shutdown => crate::power::execute(&cmd),
                        };
                        if let Err(e) = result {
                            crate::log!("could not carry out the {}: {e:#}", cmd.kind.as_str());
                        }
                    })
                    .await;
                }
                // Everything waiting has been handed over, so this is the moment to change programs.
                match update {
                    Some(offer) => crate::update::offered(&http, &shared, offer).await,
                    None if !tidied && started.elapsed() > TIDY_AFTER => {
                        tidied = true;
                        let worker = shared.clone();
                        let _ = tokio::task::spawn_blocking(move || crate::update::tidy(&worker)).await;
                    }
                    None => {}
                }
            }
            Err(e) => {
                // Say so when the server first becomes unreachable, then stay quiet until it is back.
                if failures == 0 {
                    crate::log!("cannot reach the server, will keep trying: {e:#}");
                }
                failures += 1;
                shared.update_status(|s| s.connected = false);
            }
        }
        shared.refresh_pending();

        let every = u64::from(shared.policy.borrow().upload_interval_s);
        wait = if failures == 0 { jittered(every) } else { jittered((every << failures.min(4)).min(BACKOFF_MAX_S)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_a_quarter_of_the_base() {
        for base in [1u64, 2, 60, 120, 300] {
            for _ in 0..200 {
                let ms = jittered(base).as_millis() as u64;
                assert!(ms >= base * 750 && ms <= base * 1250, "{base}s -> {ms}ms");
            }
        }
    }
}
