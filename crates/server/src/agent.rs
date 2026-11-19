//! What agents use: `POST /api/agent/sync` and `GET /api/agent/update`.
//!
//! A single check-in does everything a computer needs: it announces that
//! the computer is alive, uploads the activity that is waiting, and returns
//! the policy if (and only if) it has changed since the agent last received
//! it. For a computer with nothing new to say, the whole exchange is
//! answered from memory without touching the database.
//!
//! The key an agent presents is the one built into its installer. It both
//! lets the agent in and says which organisation the computer belongs to.

use crate::api::{ApiError, ApiResult};
use crate::state::AppState;
use crate::util::{now_ms, now_s};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ems_proto::{truncate, valid_hostname, AgentUpdate, SyncRequest, SyncResponse, KEY_HEADER, MAX_BATCH_ROWS, PROTOCOL_VERSION};
use rusqlite::params;
use std::net::SocketAddr;
use std::sync::Arc;

/// Refuse to create computers beyond this, so junk requests cannot grow the table without limit.
const MAX_MACHINES: usize = 20_000;

/// Computer names are compared without regard to case, as Windows does.
pub fn normalize_hostname(raw: &str) -> Option<String> {
    let name = raw.trim().to_ascii_uppercase();
    valid_hostname(&name).then_some(name)
}

/// The organisation whose key the request carries.
fn org_of(st: &AppState, headers: &HeaderMap) -> ApiResult<i64> {
    let presented = headers.get(KEY_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("").trim();
    st.org_by_agent_key(presented).ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "bad_agent_key"))
}

/// A fingerprint is 64 hex digits; anything else is treated as not given.
fn clean_sha(raw: &str) -> &str {
    let s = raw.trim();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        s
    } else {
        ""
    }
}

pub async fn sync(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SyncRequest>,
) -> ApiResult<Json<SyncResponse>> {
    let org = org_of(&st, &headers)?;
    if req.v != PROTOCOL_VERSION {
        return Err(ApiError::bad("unsupported_agent_version"));
    }
    let Some(host) = normalize_hostname(&req.hostname) else {
        return Err(ApiError::bad("invalid_hostname"));
    };

    // The address the computer has on its own network says more than the
    // office's shared public address, so prefer it when the agent sends one.
    let reported_ip = truncate(req.local_ip.trim(), 64);
    let ip = if reported_ip.is_empty() { st.client_ip(&headers, peer) } else { reported_ip };
    let os_version = truncate(req.os_version.trim(), 255);
    let agent_version = truncate(req.agent_version.trim(), 64);
    let agent_sha = clean_sha(&req.agent_sha).to_ascii_lowercase();
    let details = format!("{ip}|{os_version}|{agent_version}|{agent_sha}");
    let now = now_s();

    let id = match st.hub.check_in(org, &host, &details, now) {
        Some(id) => id,
        None => {
            if st.hub.known() >= MAX_MACHINES {
                return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too_many_computers"));
            }
            let name = host.clone();
            let id: i64 = st
                .db
                .write(move |tx| {
                    tx.query_row(
                        "INSERT INTO machines (org_id, machine_uuid, hostname, os_version, agent_version, ip, first_seen, last_seen)
                         VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6, ?6)
                         ON CONFLICT (org_id, machine_uuid) DO UPDATE SET
                           os_version = excluded.os_version, agent_version = excluded.agent_version,
                           ip = excluded.ip, last_seen = excluded.last_seen
                         RETURNING id",
                        params![org, name, os_version, agent_version, ip, now],
                        |r| r.get(0),
                    )
                })
                .await?;
            st.hub.remember(org, &host, id, &details, &agent_sha, now);
            id
        }
    };

    let settings = st.policy.settings(org);
    let mut ack = None;
    if let Some(batch) = req.batch {
        if batch.len() > MAX_BATCH_ROWS {
            return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "batch_too_large"));
        }
        let seq = batch.seq;
        // A batch that arrives twice (the reply to the first attempt was lost) is acknowledged, not stored again.
        if !st.hub.already_stored(id, seq) {
            let outcome = st.db.ingest(id, batch, now_ms(), settings.tz_offset_min).await?;
            st.hub.mark_stored(id, seq);
            st.policy.learn_hosts(&outcome.new_hosts);
        }
        ack = Some(seq);
    }

    // A fresh system-and-programs snapshot, when the agent sends one.
    if let Some(inv) = req.inventory {
        let public_ip = st.client_ip(&headers, peer);
        store_inventory(&st, id, inv, public_ip).await?;
    }

    // A restart or shutdown waiting for this computer rides along on the reply.
    let command = st.take_command(id).await;

    let policy = st.policy.effective(org, &host);
    let changed = policy.hash() != req.policy_hash;
    // An agent that says which program it is running is told when the
    // server holds a different one. Older agents say nothing and are left alone.
    let update = st
        .agent_build()
        .filter(|build| settings.auto_update && !agent_sha.is_empty() && build.sha256 != agent_sha)
        .map(|build| AgentUpdate { sha256: build.sha256.clone(), size: build.bytes.len() as u64, version: build.version.clone() });
    Ok(Json(SyncResponse { ok: true, ack, policy: changed.then_some(policy), update, command, server_ms: now_ms() }))
}

/// Largest number of installed programs stored for one computer.
const MAX_APPS: usize = 2000;

/// Validates and stores a computer's snapshot, capping the list and the
/// string lengths so one machine cannot send an unbounded payload.
async fn store_inventory(st: &AppState, machine_id: i64, mut inv: ems_proto::Inventory, public_ip: String) -> ApiResult<()> {
    inv.apps.truncate(MAX_APPS);
    for app in &mut inv.apps {
        app.name = truncate(app.name.trim(), 255);
        app.version = app.version.as_deref().map(|v| truncate(v.trim(), 100)).filter(|v| !v.is_empty());
        app.publisher = app.publisher.as_deref().map(|v| truncate(v.trim(), 255)).filter(|v| !v.is_empty());
        app.installed_on = app.installed_on.as_deref().map(|v| truncate(v.trim(), 32)).filter(|v| !v.is_empty());
    }
    inv.apps.retain(|a| !a.name.is_empty());
    // The server knows the address the check-in came from; the agent does not.
    inv.system.public_ip = (!public_ip.is_empty()).then_some(public_ip);
    inv.log_tail.truncate(200);
    let count = inv.apps.len() as i64;
    let system = serde_json::to_string(&inv.system).unwrap_or_default();
    let apps = serde_json::to_string(&inv.apps).unwrap_or_else(|_| "[]".into());
    let logs = serde_json::to_string(&inv.log_tail).unwrap_or_else(|_| "[]".into());
    st.db.store_inventory(machine_id, system, apps, count, logs).await?;
    Ok(())
}

/// Hands an agent the program the server holds, without any organisation's
/// settings attached: an installed agent already has its own.
pub async fn update(State(st): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Response> {
    org_of(&st, &headers)?;
    let Some(build) = st.agent_build() else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "agent_not_available"));
    };
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], build.bytes.clone()).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Settings;
    use crate::state::tests::state;
    use crate::state::AGENT_FILE;
    use ems_proto::{Batch, Visit};

    fn key(k: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(KEY_HEADER, k.parse().unwrap());
        h
    }

    async fn check_in(st: &Arc<AppState>, agent_key: &str, req: SyncRequest) -> Result<SyncResponse, StatusCode> {
        let peer = ConnectInfo("10.1.2.3:5000".parse().unwrap());
        match sync(State(st.clone()), peer, key(agent_key), Json(req)).await {
            Ok(Json(reply)) => Ok(reply),
            Err(e) => Err(e.into_response().status()),
        }
    }

    fn hello(name: &str) -> SyncRequest {
        SyncRequest { v: PROTOCOL_VERSION, hostname: name.into(), agent_version: "1.1.0".into(), ..Default::default() }
    }

    #[test]
    fn names_are_case_insensitive_and_checked() {
        assert_eq!(normalize_hostname(" desktop-ab12 ").as_deref(), Some("DESKTOP-AB12"));
        assert_eq!(normalize_hostname("Front.Desk_2").as_deref(), Some("FRONT.DESK_2"));
        assert_eq!(normalize_hostname("bad name"), None);
        assert_eq!(normalize_hostname(""), None);
        assert_eq!(clean_sha(&"a".repeat(64)).len(), 64);
        assert_eq!(clean_sha("abc"), "");
        assert_eq!(clean_sha(&"z".repeat(64)), "");
    }

    #[tokio::test]
    async fn the_key_in_the_installer_decides_the_organisation() {
        let (st, dir) = state();
        let st = Arc::new(st);
        let acme = st.create_org("Acme").await.unwrap();
        let globex = st.create_org("Globex").await.unwrap();
        st.db
            .write(move |tx| {
                tx.execute("INSERT INTO blocked_domains (org_id, domain, created_at) VALUES (?1, 'youtube.com', 0)", [acme.id])?;
                tx.execute("INSERT INTO blocked_domains (org_id, domain, created_at) VALUES (?1, 'netflix.com', 0)", [globex.id])
            })
            .await
            .unwrap();
        st.policy.reload(&st.db).await.unwrap();

        // No key, or a key nobody has: turned away, and nothing is created.
        assert_eq!(check_in(&st, "", hello("PC-1")).await.unwrap_err(), StatusCode::UNAUTHORIZED);
        assert_eq!(check_in(&st, "0123456789abcdef0123456789abcdef", hello("PC-1")).await.unwrap_err(), StatusCode::UNAUTHORIZED);

        // Two computers with the same name, one in each organisation.
        let now = now_ms();
        let visit = |domain: &str| Visit { user: "u".into(), domain: domain.into(), url: None, title: None, browser: None, start_ms: now - 5000, dur_s: 30 };
        let a = check_in(&st, &acme.agent_key, SyncRequest { batch: Some(Batch { seq: 1, visits: vec![visit("a-only.example")], ..Default::default() }), ..hello("reception") }).await.unwrap();
        let b = check_in(&st, &globex.agent_key, SyncRequest { batch: Some(Batch { seq: 1, visits: vec![visit("b-only.example")], ..Default::default() }), ..hello("RECEPTION") }).await.unwrap();
        assert_eq!((a.ack, b.ack), (Some(1), Some(1)), "the same batch number from two organisations is two batches");
        let (pa, pb) = (a.policy.unwrap(), b.policy.unwrap());
        assert_eq!((pa.blocked, pa.org.as_str()), (vec!["youtube.com".to_string()], "Acme"));
        assert_eq!((pb.blocked, pb.org.as_str()), (vec!["netflix.com".to_string()], "Globex"));

        let rows: Vec<(i64, String, String)> = st
            .db
            .read(|c| {
                c.prepare("SELECT m.org_id, m.machine_uuid, v.domain FROM visits v JOIN machines m ON m.id = v.machine_id ORDER BY m.org_id")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect()
            })
            .await
            .unwrap();
        assert_eq!(rows, [(acme.id, "RECEPTION".to_string(), "a-only.example".to_string()), (globex.id, "RECEPTION".to_string(), "b-only.example".to_string())]);
        assert_eq!((st.online_count(acme.id), st.online_count(globex.id)), (1, 1));

        // Removing an organisation locks its computers out and leaves the other alone.
        st.delete_org(acme.id).await.unwrap();
        assert_eq!(check_in(&st, &acme.agent_key, hello("RECEPTION")).await.unwrap_err(), StatusCode::UNAUTHORIZED);
        assert!(check_in(&st, &globex.agent_key, hello("RECEPTION")).await.is_ok());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_restart_is_delivered_once_and_can_be_cancelled() {
        use ems_proto::CommandKind;
        let (st, dir) = state();
        let st = Arc::new(st);
        let acme = st.create_org("Acme").await.unwrap();
        // Register the computer by checking in once; no command yet.
        assert!(check_in(&st, &acme.agent_key, hello("PC-1")).await.unwrap().command.is_none());
        let id: i64 = st.db.read(|c| c.query_row("SELECT id FROM machines", [], |r| r.get(0))).await.unwrap();

        st.queue_command(id, CommandKind::Restart, 60, None, "admin").await.unwrap();
        // The next check-in carries it, exactly once — so a reboot can never loop.
        assert_eq!(check_in(&st, &acme.agent_key, hello("PC-1")).await.unwrap().command.map(|c| c.kind), Some(CommandKind::Restart));
        assert!(check_in(&st, &acme.agent_key, hello("PC-1")).await.unwrap().command.is_none(), "never handed over twice");

        // A cancelled command is never delivered.
        st.queue_command(id, CommandKind::Shutdown, 0, None, "admin").await.unwrap();
        assert_eq!(st.cancel_commands(id).await.unwrap(), 1);
        assert!(check_in(&st, &acme.agent_key, hello("PC-1")).await.unwrap().command.is_none());

        // An undelivered command survives a server restart (reload from the database).
        st.queue_command(id, CommandKind::Restart, 60, None, "admin").await.unwrap();
        st.reload_commands().await.unwrap();
        assert!(check_in(&st, &acme.agent_key, hello("PC-1")).await.unwrap().command.is_some());
        // Only this organisation's computer is reachable; a command needs a real machine id.
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn an_update_is_offered_only_to_agents_running_something_else() {
        let (st, dir) = state();
        let st = Arc::new(st);
        let acme = st.create_org("Acme").await.unwrap();
        let globex = st.create_org("Globex").await.unwrap();
        let with_sha = |sha: &str| SyncRequest { agent_sha: sha.into(), ..hello("PC-1") };
        let old = "a".repeat(64);

        // Nothing on the server to update to.
        assert_eq!(check_in(&st, &acme.agent_key, with_sha(&old)).await.unwrap().update, None);
        assert_eq!(update(State(st.clone()), key(&acme.agent_key)).await.err().unwrap().into_response().status(), StatusCode::NOT_FOUND);

        let program = crate::state::tests::fake_agent("2.0.0", 6000, 7);
        std::fs::write(dir.join(AGENT_FILE), &program).unwrap();
        st.refresh_agent_build(true);
        let current = ems_proto::sha256_hex(&program);

        let offer = check_in(&st, &acme.agent_key, with_sha(&old)).await.unwrap().update.expect("an older agent is offered the update");
        assert_eq!((offer.sha256.as_str(), offer.size, offer.version.as_deref()), (current.as_str(), 6000, Some("2.0.0")));
        assert_eq!(check_in(&st, &acme.agent_key, with_sha(&current)).await.unwrap().update, None, "already running it");
        assert_eq!(check_in(&st, &acme.agent_key, with_sha(&current.to_uppercase())).await.unwrap().update, None);
        assert_eq!(check_in(&st, &acme.agent_key, hello("PC-OLD")).await.unwrap().update, None, "an agent from before updates existed is left alone");

        // Turned off for one organisation: only that one stops being offered updates.
        st.save_settings(acme.id, &Settings { auto_update: false, ..Settings::default() }).await.unwrap();
        assert_eq!(check_in(&st, &acme.agent_key, with_sha(&old)).await.unwrap().update, None);
        assert!(check_in(&st, &globex.agent_key, with_sha(&old)).await.unwrap().update.is_some());

        // The download needs an organisation's key and returns the program exactly.
        assert_eq!(update(State(st.clone()), key("wrong")).await.err().unwrap().into_response().status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(update(State(st.clone()), key(&globex.agent_key)).await.ok().unwrap().into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], &program[..]);
        std::fs::remove_dir_all(dir).ok();
    }
}
