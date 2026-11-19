//! EMS server: agent check-in endpoint, storage and admin console in one process.

mod agent;
mod api;
mod auth;
mod db;
mod hub;
mod policy;
mod state;
mod ui;
mod util;

use anyhow::{bail, Context};
use axum::extract::Request;
use axum::http::{header, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use state::{AppState, Config};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;

const USAGE: &str = "\
EMS server

USAGE:
  ems-server                               start the server
  ems-server set-password <user> [pass]    create an admin or reset a password
                                           (reads EMS_ADMIN_PASSWORD if [pass] is omitted)
  ems-server orgs                          list organisations with the agent key of each
                                           (the key is built into installers downloaded
                                           from the console; this is for scripted installs)

ENVIRONMENT (also read from a .env file in the working directory):
  EMS_BIND            listen address              (default 0.0.0.0:2021)
  EMS_DATA_DIR        where the database lives    (default ./data)
  EMS_TRUST_PROXY     set to 1 behind a reverse proxy that terminates TLS
  EMS_ADMIN_USER      first-run admin name        (default admin)
  EMS_ADMIN_PASSWORD  first-run admin password    (generated and printed if unset)
";

fn main() -> anyhow::Result<()> {
    state::load_dotenv();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        match args.first().map(String::as_str) {
            None | Some("run") => run().await,
            Some("set-password") => {
                let user = args.get(1).context("usage: ems-server set-password <user> [pass]")?;
                let pass = match args.get(2) {
                    Some(p) => p.clone(),
                    None => std::env::var("EMS_ADMIN_PASSWORD").context("give a password or set EMS_ADMIN_PASSWORD")?,
                };
                if pass.chars().count() < auth::MIN_PASSWORD_LEN {
                    bail!("the password must be at least {} characters", auth::MIN_PASSWORD_LEN);
                }
                let st = open_state().await?;
                auth::set_password(&st, user, &pass).await?;
                println!("password set for {user}");
                Ok(())
            }
            Some("orgs") => {
                let st = open_state().await?;
                let orgs = st.orgs();
                if orgs.is_empty() {
                    println!("no organisations yet: create one in the console");
                }
                for org in orgs {
                    println!("{}\t{}\t{}", org.id, org.agent_key, org.name);
                }
                Ok(())
            }
            Some("-h" | "--help" | "help") => {
                print!("{USAGE}");
                Ok(())
            }
            Some(other) => bail!("unknown command {other:?}\n\n{USAGE}"),
        }
    })
}

async fn open_state() -> anyhow::Result<Arc<AppState>> {
    let cfg = Config::from_env()?;
    std::fs::create_dir_all(&cfg.data_dir).with_context(|| format!("creating {}", cfg.data_dir.display()))?;
    let db = db::Db::open(&cfg.data_dir.join("ems.db"))?;
    let st = Arc::new(AppState::new(cfg, db));
    st.reload_orgs().await?;
    st.reload_users().await?;
    Ok(st)
}

/// On the very first start there is no administrator yet: create one.
async fn bootstrap_admin(st: &AppState) -> anyhow::Result<()> {
    let admins: i64 = st.db.read(|c| c.query_row("SELECT COUNT(*) FROM admins", [], |r| r.get(0))).await?;
    if admins > 0 {
        return Ok(());
    }
    let user = std::env::var("EMS_ADMIN_USER").unwrap_or_else(|_| "admin".into());
    let (pass, generated) = match std::env::var("EMS_ADMIN_PASSWORD") {
        Ok(p) if p.chars().count() >= auth::MIN_PASSWORD_LEN => (p, false),
        _ => (util::random_hex(8), true),
    };
    auth::set_password(st, &user, &pass).await?;
    st.reload_users().await?;
    if generated {
        eprintln!("\n  First start: created administrator account");
        eprintln!("    username: {user}");
        eprintln!("    password: {pass}");
        eprintln!("  Sign in and change it under Settings. This is shown only once.\n");
    } else {
        logln!("created administrator {user:?} from EMS_ADMIN_PASSWORD");
    }
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    );
    res
}

fn router(st: Arc<AppState>) -> Router {
    let admin = api::routes()
        .route_layer(middleware::from_fn_with_state(st.clone(), auth::authorize))
        .route_layer(middleware::from_fn_with_state(st.clone(), auth::require_auth));
    let web = Router::new()
        .route("/api/health", get(health))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .merge(admin)
        .fallback(ui::serve)
        .layer(CompressionLayer::new())
        .layer(middleware::from_fn(security_headers));
    Router::new().route(ems_proto::SYNC_PATH, post(agent::sync)).route(ems_proto::UPDATE_PATH, get(agent::update)).merge(web).with_state(st)
}

/// Writes changed "last seen" times to disk in one transaction.
async fn flush_last_seen(st: &AppState) {
    let dirty = st.hub.take_dirty();
    if dirty.is_empty() {
        return;
    }
    let result = st
        .db
        .write(move |tx| {
            let mut up = tx.prepare_cached("UPDATE machines SET last_seen = MAX(last_seen, ?1) WHERE id = ?2")?;
            for (id, seen) in &dirty {
                up.execute([seen, id])?;
            }
            Ok(())
        })
        .await;
    if let Err(e) = result {
        logln!("could not flush last-seen times: {e:#}");
    }
}

fn spawn_background(st: Arc<AppState>) {
    let seen = st.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(120));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            flush_last_seen(&seen).await;
        }
    });

    // A new agent program copied into the data directory is picked up
    // within half a minute, without restarting the server.
    let agent = st.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await;
        loop {
            tick.tick().await;
            let st = agent.clone();
            let _ = tokio::task::spawn_blocking(move || st.refresh_agent_build(false)).await;
        }
    });

    tokio::spawn(async move {
        // Housekeeping runs shortly after start and then once a day.
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            // Each organisation keeps its activity for as long as its own setting says.
            for org in st.orgs() {
                let days = st.policy.settings(org.id).retention_days;
                if days == 0 {
                    continue;
                }
                match db::prune(&st.db, org.id, util::now_ms() - i64::from(days) * 86_400_000).await {
                    Ok(n) if n > 0 => logln!("retention: removed {n} rows older than {days} days for {:?}", org.name),
                    Ok(_) => {}
                    Err(e) => logln!("retention failed for {:?}: {e:#}", org.name),
                }
            }
            if let Err(e) = db::housekeeping(&st.db).await {
                logln!("housekeeping failed: {e:#}");
            }
            tokio::time::sleep(Duration::from_secs(86_400)).await;
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("installing SIGTERM handler");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    ctrl_c.await;
}

async fn run() -> anyhow::Result<()> {
    let st = open_state().await?;
    bootstrap_admin(&st).await?;
    st.refresh_agent_build(true);
    spawn_background(st.clone());

    let listener = tokio::net::TcpListener::bind(st.cfg.bind).await.with_context(|| format!("binding {}", st.cfg.bind))?;
    logln!("EMS server {} listening on http://{}", env!("CARGO_PKG_VERSION"), st.cfg.bind);
    logln!("data directory: {}", st.cfg.data_dir.display());
    logln!("organisations: {}", st.orgs().len());
    if !st.cfg.trust_proxy {
        logln!("note: serving plain HTTP. Put a TLS reverse proxy in front for internet use and set EMS_TRUST_PROXY=1");
    }

    axum::serve(listener, router(st.clone()).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    logln!("shutting down");
    flush_last_seen(&st).await;
    let _ = st.db.maintenance(|c| c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")).await;
    Ok(())
}
