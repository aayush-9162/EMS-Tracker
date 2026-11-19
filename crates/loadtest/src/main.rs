//! Simulates many EMS agents against a server.
//!
//! Each simulated computer checks in on its interval exactly as the real
//! agent does: one HTTP request that uploads a batch of plausible activity
//! and picks up the policy if it changed.
//!
//! The simulated computers belong to one organisation. Give its agent key
//! with `--key` (see `ems-server orgs`), or give admin credentials and the
//! tool finds or creates the organisation named by `--org` itself. With
//! admin credentials it also blocks a site for that organisation and
//! reports how long the block took to reach every computer.
//!
//!   ems-loadtest --server 127.0.0.1:2021 --agents 500 --duration 120 \
//!                --interval 60 --rows 20 [--key <agent-key>] \
//!                [--admin admin:password] [--org "Load test"] [--backfill-hours 8]

use anyhow::{bail, Context};
use ems_proto::{AppUse, Batch, Event, EventKind, SyncRequest, SyncResponse, Visit, KEY_HEADER, PROTOCOL_VERSION, SYNC_PATH};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DOMAINS: &[&str] = &[
    "mail.google.com", "docs.google.com", "github.com", "stackoverflow.com", "youtube.com", "linkedin.com", "wikipedia.org", "amazon.in",
    "web.whatsapp.com", "facebook.com", "instagram.com", "news.ycombinator.com", "reddit.com", "netflix.com", "flipkart.com", "zoom.us",
    "slack.com", "atlassian.net", "office.com", "canva.com", "figma.com", "notion.so", "x.com", "cricbuzz.com",
];
const APPS: &[&str] = &["Google Chrome", "Microsoft Excel", "Microsoft Word", "Visual Studio Code", "Microsoft Outlook", "Microsoft Teams", "File Explorer", "Notepad", "Tally", "Adobe Acrobat"];

#[derive(Default)]
struct Stats {
    check_ins: AtomicU64,
    failures: AtomicU64,
    rows_stored: AtomicU64,
    latency_ms: Mutex<Vec<u64>>,
    /// When each computer first received a changed policy, in ms since the test started.
    policy_ms: Mutex<Vec<u64>>,
}

struct Opts {
    host: String,
    key: Option<String>,
    agents: usize,
    duration: u64,
    interval: u64,
    rows: usize,
    admin: Option<(String, String)>,
    org_name: String,
    backfill_hours: u64,
}

/// An administrator session and the organisation the test runs in.
struct Admin {
    cookie: String,
    org_id: String,
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("random source");
    u64::from_le_bytes(b)
}

fn pick<'a>(list: &'a [&'a str]) -> &'a str {
    list[(rand_u64() % list.len() as u64) as usize]
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// `rows` visits and `rows` app rows laid end to end across `[from_ms, to_ms)`.
fn make_batch(seq: u64, user: &str, from_ms: i64, to_ms: i64, rows: usize) -> Batch {
    let mut batch = Batch { seq, ..Default::default() };
    let slice = ((to_ms - from_ms) / rows.max(1) as i64).max(1000);
    for i in 0..rows {
        let start_ms = from_ms + i as i64 * slice + (rand_u64() % 400) as i64;
        let dur_s = ((slice / 1000) as u64 * (40 + rand_u64() % 60) / 100).max(1) as u32;
        let domain = pick(DOMAINS);
        batch.visits.push(Visit {
            user: user.into(),
            domain: domain.into(),
            url: Some(format!("https://{domain}/page/{}", rand_u64() % 40)),
            title: Some(format!("{domain} - page")),
            browser: Some("Google Chrome".into()),
            start_ms,
            dur_s,
        });
        let app = pick(APPS);
        batch.apps.push(AppUse { user: user.into(), app: app.into(), title: Some(format!("Document {} - {app}", rand_u64() % 20)), exe: None, start_ms, dur_s });
    }
    if rand_u64() % 6 == 0 {
        batch.events.push(Event { user: user.into(), kind: EventKind::Blocked, domain: "facebook.com".into(), url: Some("https://facebook.com/".into()), word: None, at_ms: to_ms - 1 });
    }
    batch
}

/// Minimal HTTP/1.1 request: enough for the check-in endpoint and the admin API.
async fn http(host: &str, method: &str, path: &str, headers: &[(&str, &str)], body: Option<&str>) -> anyhow::Result<(u16, String, String)> {
    let mut stream = tokio::net::TcpStream::connect(host).await?;
    let body = body.unwrap_or("");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    Ok((status, head.to_string(), rest.to_string()))
}

async fn check_in(opts: &Opts, hostname: &str, policy_hash: &str, batch: Option<Batch>) -> anyhow::Result<SyncResponse> {
    let request = SyncRequest {
        v: PROTOCOL_VERSION,
        hostname: hostname.into(),
        local_ip: format!("192.168.{}.{}", 1 + rand_u64() % 4, 2 + rand_u64() % 250),
        os_version: "Windows 11 Pro (simulated)".into(),
        agent_version: "loadtest".into(),
        agent_sha: String::new(),
        policy_hash: policy_hash.into(),
        batch,
        inventory: None,
    };
    let body = serde_json::to_string(&request)?;
    let headers: Vec<(&str, &str)> = opts.key.as_deref().map(|k| vec![(KEY_HEADER, k)]).unwrap_or_default();
    let (status, _, reply) = http(&opts.host, "POST", SYNC_PATH, &headers, Some(&body)).await?;
    if status != 200 {
        bail!("HTTP {status}: {reply}");
    }
    Ok(serde_json::from_str(&reply)?)
}

async fn agent(id: usize, opts: Arc<Opts>, stats: Arc<Stats>, started: Instant) {
    let hostname = format!("PC-{id:04}");
    let user = format!("user{id:04}");
    let mut policy_hash = String::new();
    let mut seq = (id as u64) << 32 | (now_ms() as u64 & 0xffff_ffff);

    // Optional history so dashboards have something to show.
    let now = now_ms();
    for h in (1..=opts.backfill_hours as i64).rev() {
        // Not every simulated person works every hour.
        if rand_u64() % 10 < 7 {
            seq += 1;
            let batch = make_batch(seq, &user, now - h * 3_600_000, now - (h - 1) * 3_600_000 - 600_000, 6);
            if let Ok(reply) = check_in(&opts, &hostname, &policy_hash, Some(batch)).await {
                if let Some(p) = reply.policy {
                    policy_hash = p.hash();
                }
            }
        }
    }

    let interval = Duration::from_secs(opts.interval);
    // Spread first check-ins across one interval, as jitter does for real agents.
    let mut next = tokio::time::Instant::now() + Duration::from_millis(rand_u64() % (interval.as_millis() as u64).max(1));
    let mut first = true;
    loop {
        tokio::time::sleep_until(next).await;
        next += interval;
        seq += 1;
        let to = now_ms();
        let batch = (opts.rows > 0).then(|| make_batch(seq, &user, to - opts.interval as i64 * 1000, to, opts.rows));
        let rows = batch.as_ref().map_or(0, Batch::len) as u64;
        let sent = Instant::now();
        match check_in(&opts, &hostname, &policy_hash, batch).await {
            Ok(reply) => {
                stats.check_ins.fetch_add(1, Ordering::Relaxed);
                stats.rows_stored.fetch_add(rows, Ordering::Relaxed);
                stats.latency_ms.lock().unwrap().push(sent.elapsed().as_millis() as u64);
                if let Some(policy) = reply.policy {
                    policy_hash = policy.hash();
                    // The very first reply always carries the policy; only later ones mean it changed.
                    if !first {
                        stats.policy_ms.lock().unwrap().push(started.elapsed().as_millis() as u64);
                    }
                }
                first = false;
            }
            Err(e) => {
                if stats.failures.fetch_add(1, Ordering::Relaxed) == 0 {
                    eprintln!("first failure ({hostname}): {e:#}");
                }
            }
        }
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

/// Signs in, finds or creates the organisation to test in, and reads its agent key.
async fn prepare(host: &str, user: &str, pass: &str, org_name: &str) -> anyhow::Result<(Admin, String)> {
    let body = serde_json::json!({ "username": user, "password": pass }).to_string();
    let (status, head, _) = http(host, "POST", "/api/login", &[], Some(&body)).await?;
    if status != 200 {
        bail!("admin sign-in failed with HTTP {status}");
    }
    let cookie = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().starts_with("set-cookie:").then(|| l[11..].trim().split(';').next().unwrap_or("").to_string()))
        .context("no session cookie")?;
    let auth = [("Cookie", cookie.as_str())];

    let list: serde_json::Value = serde_json::from_str(&http(host, "GET", "/api/orgs", &auth, None).await?.2)?;
    let existing = list["orgs"].as_array().and_then(|orgs| orgs.iter().find(|o| o["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(org_name))).and_then(|o| o["id"].as_i64()));
    let org_id = match existing {
        Some(id) => id,
        None => {
            let (status, _, reply) = http(host, "POST", "/api/orgs", &auth, Some(&serde_json::json!({ "name": org_name }).to_string())).await?;
            if status != 200 {
                bail!("creating the organisation failed with HTTP {status}: {reply}");
            }
            serde_json::from_str::<serde_json::Value>(&reply)?["org"]["id"].as_i64().context("no organisation id in the reply")?
        }
    };
    // The organisation's settings file is what an installer carries; the key is in it.
    let (status, _, setup) = http(host, "GET", &format!("/api/download/agent-setup?org={org_id}&server=http://{host}"), &auth, None).await?;
    if status != 200 {
        bail!("reading the organisation's agent key failed with HTTP {status}");
    }
    let key = serde_json::from_str::<serde_json::Value>(&setup)?["key"].as_str().context("no key in the settings file")?.to_string();
    Ok((Admin { cookie, org_id: org_id.to_string() }, key))
}

/// Blocks a domain through the admin API and reports how long it took to reach the fleet.
async fn measure_block(opts: &Opts, admin: Option<&Admin>, stats: &Stats, started: Instant) -> anyhow::Result<()> {
    let Some(admin) = admin else { return Ok(()) };
    let auth = [("Cookie", admin.cookie.as_str()), ("X-EMS-Org", admin.org_id.as_str())];

    stats.policy_ms.lock().unwrap().clear();
    let domain = format!("push-test-{}.example", rand_u64() % 1_000_000);
    let sent_at = started.elapsed().as_millis() as u64;
    let (status, _, resp) = http(&opts.host, "POST", "/api/blocked-domains", &auth, Some(&serde_json::json!({ "domain": domain }).to_string())).await?;
    if status != 200 {
        bail!("blocking failed with HTTP {status}: {resp}");
    }

    // Everyone should have it within one interval (plus a little slack).
    let deadline = Instant::now() + Duration::from_secs(opts.interval + 5);
    while stats.policy_ms.lock().unwrap().len() < opts.agents && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut arrivals: Vec<u64> = stats.policy_ms.lock().unwrap().iter().map(|t| t.saturating_sub(sent_at)).collect();
    arrivals.sort_unstable();
    println!("\nnew block: reached {}/{} computers (check-in interval {} s)", arrivals.len(), opts.agents, opts.interval);
    println!(
        "  time until a computer had it: first {:.1} s, median {:.1} s, last {:.1} s",
        arrivals.first().copied().unwrap_or(0) as f64 / 1000.0,
        percentile(&arrivals, 0.5) as f64 / 1000.0,
        arrivals.last().copied().unwrap_or(0) as f64 / 1000.0
    );

    // Leave the server as it was found.
    let id = serde_json::from_str::<serde_json::Value>(&http(&opts.host, "GET", "/api/blocked-domains", &auth, None).await?.2)
        .ok()
        .and_then(|v| v.as_array().and_then(|rows| rows.iter().find(|r| r["domain"] == domain.as_str()).and_then(|r| r["id"].as_i64())));
    if let Some(id) = id {
        http(&opts.host, "DELETE", &format!("/api/blocked-domains/{id}"), &auth, None).await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let num = |name: &str, default: u64| arg(&args, name).and_then(|v| v.parse().ok()).unwrap_or(default);
    let mut opts = Opts {
        host: arg(&args, "--server").unwrap_or_else(|| "127.0.0.1:2021".into()),
        key: arg(&args, "--key"),
        agents: num("--agents", 100) as usize,
        duration: num("--duration", 60),
        interval: num("--interval", 60).max(1),
        rows: num("--rows", 20) as usize,
        admin: arg(&args, "--admin").and_then(|a| a.split_once(':').map(|(u, p)| (u.to_string(), p.to_string()))),
        org_name: arg(&args, "--org").unwrap_or_else(|| "Load test".into()),
        backfill_hours: num("--backfill-hours", 0),
    };
    let mut admin = None;
    if let Some((user, pass)) = opts.admin.clone() {
        let (session, key) = prepare(&opts.host, &user, &pass, &opts.org_name).await?;
        println!("organisation: {} (id {})", opts.org_name, session.org_id);
        opts.key.get_or_insert(key);
        admin = Some(session);
    }
    if opts.key.is_none() {
        bail!("give --key <agent-key> (see `ems-server orgs`), or --admin user:password to let the tool set up an organisation");
    }
    let opts = Arc::new(opts);
    let stats = Arc::new(Stats::default());
    let started = Instant::now();

    println!("{} simulated computers checking in with {} every {} s, {} rows per check-in", opts.agents, opts.host, opts.interval, opts.rows * 2);
    for id in 0..opts.agents {
        tokio::spawn(agent(id, opts.clone(), stats.clone(), started));
    }

    // Let every computer check in at least once before changing the policy.
    let settle = opts.interval + 2;
    tokio::time::sleep(Duration::from_secs(settle)).await;
    if let Err(e) = measure_block(&opts, admin.as_ref(), &stats, started).await {
        eprintln!("block measurement failed: {e:#}");
    }
    let elapsed = started.elapsed().as_secs();
    if opts.duration > elapsed {
        tokio::time::sleep(Duration::from_secs(opts.duration - elapsed)).await;
    }

    let mut latency = stats.latency_ms.lock().unwrap().clone();
    latency.sort_unstable();
    let secs = started.elapsed().as_secs_f64();
    let (ok, rows) = (stats.check_ins.load(Ordering::Relaxed), stats.rows_stored.load(Ordering::Relaxed));
    println!("\nafter {secs:.0} s:");
    println!("  check-ins answered   {ok} ({:.1} per second)", ok as f64 / secs);
    println!("  check-ins failed     {}", stats.failures.load(Ordering::Relaxed));
    println!("  rows stored          {rows} ({:.0} per second)", rows as f64 / secs);
    println!("  time per check-in    median {} ms, 95th {} ms, max {} ms", percentile(&latency, 0.5), percentile(&latency, 0.95), latency.last().copied().unwrap_or(0));
    Ok(())
}
