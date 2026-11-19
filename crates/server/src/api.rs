//! Admin HTTP API. Every route here sits behind [`crate::auth::require_auth`].
//!
//! Apart from the list of organisations itself, every route is about one
//! organisation, named by the request (see [`OrgId`]). Each query is limited
//! to that organisation, so nothing of one client is ever shown under another.

use crate::auth::OrgId;
use crate::policy::{Settings, GLOBAL};
use crate::state::{AppState, OrgError, UserError};
use crate::util::{day_start_ms, fmt_local, now_ms, now_s};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ems_proto::{domain_covers, normalize_block_entry, normalize_word};
use rusqlite::types::Value as Sql;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub struct ApiError {
    status: StatusCode,
    code: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &str) -> ApiError {
        ApiError { status, code: code.into() }
    }
    pub fn bad(code: &str) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, code)
    }
    pub fn not_found() -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, "not_found")
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        crate::logln!("request failed: {e:#}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
    }
}

impl From<UserError> for ApiError {
    fn from(e: UserError) -> Self {
        match e {
            UserError::BadName => ApiError::bad("user_name_invalid"),
            UserError::NameTaken => ApiError::new(StatusCode::CONFLICT, "user_name_taken"),
            UserError::WeakPassword => ApiError::bad("password_too_short"),
            UserError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "unknown_user"),
            UserError::NotSelf => ApiError::bad("cannot_remove_self"),
            UserError::LastOwner => ApiError::bad("last_owner"),
            UserError::OwnerFixed => ApiError::bad("owner_has_all_access"),
            UserError::Failed(e) => e.into(),
        }
    }
}

impl From<OrgError> for ApiError {
    fn from(e: OrgError) -> Self {
        match e {
            OrgError::BadName => ApiError::bad("org_name_invalid"),
            OrgError::NameTaken => ApiError::new(StatusCode::CONFLICT, "org_name_taken"),
            OrgError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "unknown_organisation"),
            OrgError::Failed(e) => e.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.code }))).into_response()
    }
}

type St = State<Arc<AppState>>;
type Q = Query<HashMap<String, String>>;

// ---------------------------------------------------------------------------
// Query-string helpers
// ---------------------------------------------------------------------------

const CATEGORIES: [&str; 3] = ["suspicious", "neutral", "productive"];

fn category_of(raw: Option<&str>) -> Option<&'static str> {
    let raw = raw?.trim().to_ascii_lowercase();
    CATEGORIES.into_iter().find(|c| *c == raw)
}

struct Params(HashMap<String, String>);

impl Params {
    fn text(&self, key: &str) -> Option<String> {
        self.0.get(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    }
    fn int(&self, key: &str) -> Option<i64> {
        self.0.get(key)?.trim().parse().ok()
    }
    /// `since`/`until` in Unix ms. Defaults to the last seven days.
    fn range(&self) -> (i64, i64) {
        let now = now_ms();
        (self.int("since").unwrap_or(now - 7 * 86_400_000), self.int("until").unwrap_or(now + 86_400_000))
    }
    fn limit(&self, default: i64, max: i64) -> i64 {
        self.int("limit").unwrap_or(default).clamp(1, max)
    }
}

/// Limits a query on an activity table to one organisation's computers, or
/// to a single one of them. `column` is that table's `machine_id`.
fn in_org(sql: &mut String, args: &mut Vec<Sql>, column: &str, org: i64, machine: Option<String>) {
    sql.push_str(&format!(" AND {column} IN (SELECT id FROM machines WHERE org_id = ?"));
    args.push(org.into());
    if let Some(m) = machine {
        sql.push_str(" AND machine_uuid = ?");
        args.push(m.into());
    }
    sql.push(')');
}

/// Escapes `%` and `_` so user text is matched literally by `LIKE ... ESCAPE '\'`.
fn like_contains(text: &str) -> String {
    let mut s = String::with_capacity(text.len() + 2);
    s.push('%');
    for ch in text.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            s.push('\\');
        }
        s.push(ch);
    }
    s.push('%');
    s
}

// ---------------------------------------------------------------------------
// Categories
// ---------------------------------------------------------------------------

/// Resolves a visit's category: an explicit category for the domain (or the
/// nearest parent domain) wins, then the first matching word rule, and
/// anything left over is "suspicious" until someone reviews it.
pub struct Categorizer {
    domains: HashMap<String, String>,
    keywords: Vec<(String, String)>,
}

impl Categorizer {
    pub fn load(c: &Connection, org: i64) -> rusqlite::Result<Categorizer> {
        let mut st = c.prepare("SELECT domain, category FROM domain_categories WHERE org_id = ?1")?;
        let domains = st.query_map([org], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<rusqlite::Result<_>>()?;
        let mut st = c.prepare(
            "SELECT keyword, category FROM category_keywords WHERE org_id = ?1
             ORDER BY CASE category WHEN 'productive' THEN 0 WHEN 'neutral' THEN 1 ELSE 2 END, id",
        )?;
        let keywords = st.query_map([org], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<rusqlite::Result<_>>()?;
        Ok(Categorizer { domains, keywords })
    }

    pub fn of(&self, domain: &str, url: Option<&str>) -> &str {
        let mut d = domain;
        loop {
            if let Some(c) = self.domains.get(d) {
                return c;
            }
            match d.split_once('.') {
                Some((_, parent)) if parent.contains('.') => d = parent,
                _ => break,
            }
        }
        if !self.keywords.is_empty() {
            let text = format!("{domain} {}", url.unwrap_or("")).to_lowercase();
            if let Some((_, c)) = self.keywords.iter().find(|(k, _)| text.contains(k.as_str())) {
                return c;
            }
        }
        "suspicious"
    }
}

async fn list_domain_categories(State(st): St, OrgId(org): OrgId) -> ApiResult<Json<Value>> {
    let rows = st
        .db
        .read(move |c| {
            let mut s = c.prepare("SELECT domain, category, updated_at FROM domain_categories WHERE org_id = ?1 ORDER BY updated_at DESC, domain")?;
            let rows = s
                .query_map([org], |r| Ok(json!({ "domain": r.get::<_, String>(0)?, "category": r.get::<_, String>(1)?, "updated_at": r.get::<_, i64>(2)? })))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
struct CategoryBody {
    category: Option<String>,
}

async fn put_domain_category(State(st): St, OrgId(org): OrgId, Path(domain): Path<String>, Json(body): Json<CategoryBody>) -> ApiResult<Json<Value>> {
    let domain = normalize_block_entry(&domain).ok_or_else(|| ApiError::bad("invalid_domain"))?;
    let category = category_of(body.category.as_deref()).ok_or_else(|| ApiError::bad("valid_category_required"))?;
    let d = domain.clone();
    st.db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO domain_categories (org_id, domain, category, updated_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (org_id, domain) DO UPDATE SET category = excluded.category, updated_at = excluded.updated_at",
                params![org, d, category, now_s()],
            )
        })
        .await?;
    Ok(Json(json!({ "ok": true, "domain": domain, "category": category })))
}

async fn delete_domain_category(State(st): St, OrgId(org): OrgId, Path(domain): Path<String>) -> ApiResult<Json<Value>> {
    let domain = domain.trim().to_ascii_lowercase();
    st.db.write(move |tx| tx.execute("DELETE FROM domain_categories WHERE org_id = ?1 AND domain = ?2", params![org, domain])).await?;
    Ok(Json(json!({ "ok": true })))
}

async fn list_keywords(State(st): St, OrgId(org): OrgId) -> ApiResult<Json<Value>> {
    let rows = st
        .db
        .read(move |c| {
            let mut s = c.prepare("SELECT id, keyword, category, created_at FROM category_keywords WHERE org_id = ?1 ORDER BY category, keyword")?;
            let rows = s
                .query_map([org], |r| {
                    Ok(json!({ "id": r.get::<_, i64>(0)?, "keyword": r.get::<_, String>(1)?, "category": r.get::<_, String>(2)?, "created_at": r.get::<_, i64>(3)? }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
struct KeywordBody {
    keyword: Option<String>,
    category: Option<String>,
}

async fn add_keyword(State(st): St, OrgId(org): OrgId, Json(body): Json<KeywordBody>) -> ApiResult<Json<Value>> {
    let keyword = body.keyword.as_deref().and_then(normalize_word).ok_or_else(|| ApiError::bad("keyword_required"))?;
    let category = category_of(body.category.as_deref()).ok_or_else(|| ApiError::bad("valid_category_required"))?;
    let k = keyword.clone();
    st.db
        .write(move |tx| tx.execute("INSERT OR IGNORE INTO category_keywords (org_id, keyword, category, created_at) VALUES (?1, ?2, ?3, ?4)", params![org, k, category, now_s()]))
        .await?;
    Ok(Json(json!({ "ok": true, "keyword": keyword, "category": category })))
}

async fn delete_keyword(State(st): St, OrgId(org): OrgId, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    st.db.write(move |tx| tx.execute("DELETE FROM category_keywords WHERE id = ?1 AND org_id = ?2", [id, org])).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Visits
// ---------------------------------------------------------------------------

struct VisitRow {
    machine_uuid: String,
    hostname: Option<String>,
    label: Option<String>,
    os_user: String,
    domain: String,
    url: Option<String>,
    title: Option<String>,
    visits: i64,
    total_sec: i64,
    first_ms: i64,
    last_ms: i64,
}

/// One organisation's activity grouped per (machine, user, domain, url), newest first.
fn query_visits(c: &Connection, org: i64, since: i64, until: i64, machine: Option<&str>, domain: Option<&str>, limit: Option<i64>) -> rusqlite::Result<Vec<VisitRow>> {
    let mut sql = String::from(
        "SELECT m.machine_uuid, m.hostname, m.label, v.os_user, v.domain, v.url, MAX(v.title),
                COUNT(*), SUM(v.dur_s), MIN(v.start_ms), MAX(v.start_ms) AS last_ms
           FROM visits v JOIN machines m ON m.id = v.machine_id
          WHERE m.org_id = ? AND v.start_ms >= ? AND v.start_ms <= ?",
    );
    let mut args: Vec<Sql> = vec![org.into(), since.into(), until.into()];
    if let Some(m) = machine {
        sql.push_str(" AND m.machine_uuid = ?");
        args.push(m.to_string().into());
    }
    if let Some(d) = domain {
        sql.push_str(" AND v.domain LIKE ? ESCAPE '\\'");
        args.push(like_contains(&d.to_lowercase()).into());
    }
    sql.push_str(" GROUP BY v.machine_id, v.os_user, v.domain, v.url ORDER BY last_ms DESC");
    if let Some(l) = limit {
        sql.push_str(" LIMIT ?");
        args.push(l.into());
    }
    let mut st = c.prepare(&sql)?;
    let rows = st.query_map(params_from_iter(args.iter()), |r| {
        Ok(VisitRow {
            machine_uuid: r.get(0)?,
            hostname: r.get(1)?,
            label: r.get(2)?,
            os_user: r.get(3)?,
            domain: r.get(4)?,
            url: r.get(5)?,
            title: r.get(6)?,
            visits: r.get(7)?,
            total_sec: r.get(8)?,
            first_ms: r.get(9)?,
            last_ms: r.get(10)?,
        })
    })?;
    rows.collect()
}

async fn visits(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Json<Value>> {
    let p = Params(q);
    let (since, until) = p.range();
    let category = category_of(p.text("category").as_deref());
    let limit = p.limit(200, 1000);
    // Categories are resolved after the query, so over-fetch when filtering by one.
    let fetch = if category.is_some() { (limit * 5).min(5000) } else { limit };
    let (machine, domain) = (p.text("machine_uuid"), p.text("domain"));

    let rows = st
        .db
        .read(move |c| {
            let cat = Categorizer::load(c, org)?;
            let rows = query_visits(c, org, since, until, machine.as_deref(), domain.as_deref(), Some(fetch))?;
            let mut out = Vec::new();
            for r in rows {
                let cat_name = cat.of(&r.domain, r.url.as_deref()).to_string();
                if category.is_some_and(|want| want != cat_name) {
                    continue;
                }
                out.push(json!({
                    "machine_uuid": r.machine_uuid, "hostname": r.hostname, "label": r.label, "os_user": r.os_user,
                    "domain": r.domain, "url": r.url, "title": r.title, "visits": r.visits, "total_sec": r.total_sec,
                    "first_seen": r.first_ms, "last_seen": r.last_ms, "category": cat_name,
                }));
                if out.len() as i64 >= limit {
                    break;
                }
            }
            Ok(out)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

async fn visits_summary(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Json<Value>> {
    let p = Params(q);
    let (since, until) = p.range();
    let machine = p.text("machine_uuid");
    let limit = p.limit(100, 500);
    let rows = st
        .db
        .read(move |c| {
            let cat = Categorizer::load(c, org)?;
            let mut sql = String::from(
                "SELECT v.domain, SUM(v.dur_s) AS total, COUNT(*), COUNT(DISTINCT v.machine_id)
                   FROM visits v WHERE v.start_ms >= ? AND v.start_ms <= ?",
            );
            let mut args: Vec<Sql> = vec![since.into(), until.into()];
            in_org(&mut sql, &mut args, "v.machine_id", org, machine);
            sql.push_str(" GROUP BY v.domain ORDER BY total DESC LIMIT ?");
            args.push(limit.into());
            let mut s = c.prepare(&sql)?;
            let rows = s
                .query_map(params_from_iter(args.iter()), |r| {
                    let domain: String = r.get(0)?;
                    Ok(json!({ "category": cat.of(&domain, None), "domain": domain, "total_sec": r.get::<_, i64>(1)?, "visits": r.get::<_, i64>(2)?, "machines": r.get::<_, i64>(3)? }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

/// Machine-readable report for one calendar day: suspicious visits only,
/// each marked blocked or unblocked.
///   GET /api/visits/report/suspicious?date=YYYY-MM-DD[&machine_uuid=][&min_sec=]
async fn suspicious_report(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Json<Value>> {
    let p = Params(q);
    let tz = st.policy.settings(org).tz_offset_min;
    let date = p.text("date").unwrap_or_default();
    let Some(since) = day_start_ms(&date, tz) else {
        return Err(ApiError::bad("date_required"));
    };
    let until = since + 86_400_000 - 1;
    let min_sec = p.int("min_sec").unwrap_or(0).max(0);
    let machine = p.text("machine_uuid");

    let visits = st
        .db
        .read(move |c| {
            let cat = Categorizer::load(c, org)?;
            let mut s = c.prepare("SELECT domain, machine_uuid FROM blocked_domains WHERE org_id = ?1")?;
            let blocks = s.query_map([org], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let rows = query_visits(c, org, since, until, machine.as_deref(), None, None)?;
            let mut out = Vec::new();
            for r in rows {
                let category = cat.of(&r.domain, r.url.as_deref());
                if category != "suspicious" || r.total_sec < min_sec {
                    continue;
                }
                let blocked = blocks.iter().any(|(d, m)| (m == GLOBAL || *m == r.machine_uuid) && domain_covers(d, &r.domain));
                out.push(json!({
                    "machine_uuid": r.machine_uuid, "label": r.label, "hostname": r.hostname, "os_user": r.os_user,
                    "domain": r.domain, "url": r.url, "visits": r.visits, "total_sec": r.total_sec,
                    "first_seen": fmt_local(r.first_ms, tz), "last_seen": fmt_local(r.last_ms, tz),
                    "first_seen_ms": r.first_ms, "last_seen_ms": r.last_ms,
                    "category": category, "blocked": blocked, "status": if blocked { "blocked" } else { "unblocked" },
                }));
            }
            Ok(out)
        })
        .await?;
    Ok(Json(json!({ "date": date, "count": visits.len(), "visits": visits })))
}

// ---------------------------------------------------------------------------
// Application usage
// ---------------------------------------------------------------------------

async fn app_usage(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Json<Value>> {
    let p = Params(q);
    let (since, until) = p.range();
    let limit = p.limit(200, 1000);
    let (machine, app) = (p.text("machine_uuid"), p.text("app"));
    let rows = st
        .db
        .read(move |c| {
            let mut sql = String::from(
                "SELECT m.machine_uuid, m.hostname, m.label, a.os_user, a.app, COUNT(*), SUM(a.dur_s), MIN(a.start_ms), MAX(a.start_ms) AS last_ms
                   FROM app_usage a JOIN machines m ON m.id = a.machine_id
                  WHERE m.org_id = ? AND a.start_ms >= ? AND a.start_ms <= ?",
            );
            let mut args: Vec<Sql> = vec![org.into(), since.into(), until.into()];
            if let Some(m) = machine {
                sql.push_str(" AND m.machine_uuid = ?");
                args.push(m.into());
            }
            if let Some(a) = app {
                sql.push_str(" AND a.app LIKE ? ESCAPE '\\'");
                args.push(like_contains(&a).into());
            }
            sql.push_str(" GROUP BY a.machine_id, a.os_user, a.app ORDER BY last_ms DESC LIMIT ?");
            args.push(limit.into());
            let mut s = c.prepare(&sql)?;
            let rows = s
                .query_map(params_from_iter(args.iter()), |r| {
                    Ok(json!({
                        "machine_uuid": r.get::<_, String>(0)?, "hostname": r.get::<_, Option<String>>(1)?, "label": r.get::<_, Option<String>>(2)?,
                        "os_user": r.get::<_, String>(3)?, "app_name": r.get::<_, String>(4)?, "sessions": r.get::<_, i64>(5)?,
                        "total_sec": r.get::<_, i64>(6)?, "first_seen": r.get::<_, i64>(7)?, "last_seen": r.get::<_, i64>(8)?,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

async fn app_usage_summary(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Json<Value>> {
    let p = Params(q);
    let (since, until) = p.range();
    let machine = p.text("machine_uuid");
    let limit = p.limit(100, 500);
    let rows = st
        .db
        .read(move |c| {
            let mut sql = String::from("SELECT a.app, SUM(a.dur_s) AS total, COUNT(*), COUNT(DISTINCT a.machine_id) FROM app_usage a WHERE a.start_ms >= ? AND a.start_ms <= ?");
            let mut args: Vec<Sql> = vec![since.into(), until.into()];
            in_org(&mut sql, &mut args, "a.machine_id", org, machine);
            sql.push_str(" GROUP BY a.app ORDER BY total DESC LIMIT ?");
            args.push(limit.into());
            let mut s = c.prepare(&sql)?;
            let rows = s
                .query_map(params_from_iter(args.iter()), |r| {
                    Ok(json!({ "app_name": r.get::<_, String>(0)?, "total_sec": r.get::<_, i64>(1)?, "sessions": r.get::<_, i64>(2)?, "machines": r.get::<_, i64>(3)? }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

/// Window titles for one application: what was actually open.
async fn app_titles(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Json<Value>> {
    let p = Params(q);
    let (since, until) = p.range();
    let app = p.text("app").ok_or_else(|| ApiError::bad("app_required"))?;
    let machine = p.text("machine_uuid");
    let rows = st
        .db
        .read(move |c| {
            let mut sql = String::from(
                "SELECT COALESCE(a.title, ''), SUM(a.dur_s) AS total, COUNT(*), MAX(a.start_ms)
                   FROM app_usage a WHERE a.start_ms >= ? AND a.start_ms <= ? AND a.app = ?",
            );
            let mut args: Vec<Sql> = vec![since.into(), until.into(), app.into()];
            in_org(&mut sql, &mut args, "a.machine_id", org, machine);
            sql.push_str(" GROUP BY a.title ORDER BY total DESC LIMIT 200");
            let mut s = c.prepare(&sql)?;
            let rows = s
                .query_map(params_from_iter(args.iter()), |r| {
                    Ok(json!({ "title": r.get::<_, String>(0)?, "total_sec": r.get::<_, i64>(1)?, "sessions": r.get::<_, i64>(2)?, "last_seen": r.get::<_, i64>(3)? }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

// ---------------------------------------------------------------------------
// Blocking
// ---------------------------------------------------------------------------

async fn list_blocked(State(st): St, OrgId(org): OrgId) -> ApiResult<Json<Value>> {
    let rows = st
        .db
        .read(move |c| {
            let mut s = c.prepare(
                "SELECT b.id, b.domain, b.machine_uuid, b.note, b.created_at, m.hostname, m.os_user, m.label
                   FROM blocked_domains b LEFT JOIN machines m ON m.org_id = b.org_id AND m.machine_uuid = b.machine_uuid
                  WHERE b.org_id = ?1
                  ORDER BY (b.machine_uuid = '*') DESC, b.domain",
            )?;
            let rows = s
                .query_map([org], |r| {
                    Ok(json!({
                        "id": r.get::<_, i64>(0)?, "domain": r.get::<_, String>(1)?, "machine_uuid": r.get::<_, String>(2)?,
                        "note": r.get::<_, Option<String>>(3)?, "created_at": r.get::<_, i64>(4)?,
                        "hostname": r.get::<_, Option<String>>(5)?, "os_user": r.get::<_, Option<String>>(6)?, "label": r.get::<_, Option<String>>(7)?,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
struct BlockBody {
    domain: Option<String>,
    machine_uuid: Option<String>,
    note: Option<String>,
}

/// The host the administrator used to reach this console, without the port.
fn request_host(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("x-forwarded-host").or_else(|| headers.get("host"))?.to_str().ok()?;
    ems_proto::host_of(raw)
}

async fn add_blocked(State(st): St, OrgId(org): OrgId, headers: HeaderMap, Json(body): Json<BlockBody>) -> ApiResult<Json<Value>> {
    let domain = body.domain.as_deref().and_then(normalize_block_entry).ok_or_else(|| ApiError::bad("invalid_domain"))?;
    // Blocking the address agents use to reach this server would cut them
    // off from ever receiving the unblock.
    if request_host(&headers).is_some_and(|h| domain_covers(&domain, &h)) {
        return Err(ApiError::bad("cannot_block_this_server"));
    }
    let machine = body.machine_uuid.map(|m| m.trim().to_string()).filter(|m| !m.is_empty() && m != GLOBAL).unwrap_or_else(|| GLOBAL.into());
    let note = body.note.map(|n| ems_proto::truncate(n.trim(), 500)).filter(|n| !n.is_empty());
    let (d, m) = (domain.clone(), machine.clone());
    st.db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO blocked_domains (org_id, domain, machine_uuid, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (org_id, domain, machine_uuid) DO UPDATE SET note = excluded.note",
                params![org, d, m, note, now_s()],
            )
        })
        .await?;
    st.policy.reload(&st.db).await?;
    Ok(Json(json!({ "ok": true, "domain": domain, "machine_uuid": machine, "online": st.online_count(org), "within_s": st.policy.settings(org).upload_interval_s })))
}

async fn delete_blocked(State(st): St, OrgId(org): OrgId, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    st.db.write(move |tx| tx.execute("DELETE FROM blocked_domains WHERE id = ?1 AND org_id = ?2", [id, org])).await?;
    st.policy.reload(&st.db).await?;
    Ok(Json(json!({ "ok": true, "online": st.online_count(org) })))
}

async fn block_events(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Json<Value>> {
    let p = Params(q);
    let (since, until) = p.range();
    let limit = p.limit(200, 1000);
    let machine = p.text("machine_uuid");
    let rows = st
        .db
        .read(move |c| {
            let mut sql = String::from(
                "SELECT e.id, m.machine_uuid, m.hostname, m.label, e.os_user, e.domain, e.url, e.hit_count, e.first_ms, e.last_ms
                   FROM block_events e JOIN machines m ON m.id = e.machine_id
                  WHERE m.org_id = ? AND e.last_ms >= ? AND e.last_ms <= ?",
            );
            let mut args: Vec<Sql> = vec![org.into(), since.into(), until.into()];
            if let Some(m) = machine {
                sql.push_str(" AND m.machine_uuid = ?");
                args.push(m.into());
            }
            sql.push_str(" ORDER BY e.last_ms DESC LIMIT ?");
            args.push(limit.into());
            let mut s = c.prepare(&sql)?;
            let rows = s
                .query_map(params_from_iter(args.iter()), |r| {
                    Ok(json!({
                        "id": r.get::<_, i64>(0)?, "machine_uuid": r.get::<_, String>(1)?, "hostname": r.get::<_, Option<String>>(2)?,
                        "label": r.get::<_, Option<String>>(3)?, "os_user": r.get::<_, String>(4)?, "domain": r.get::<_, String>(5)?,
                        "url": r.get::<_, Option<String>>(6)?, "hit_count": r.get::<_, i64>(7)?, "first_seen": r.get::<_, i64>(8)?, "last_seen": r.get::<_, i64>(9)?,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

// ---------------------------------------------------------------------------
// Blacklist words
// ---------------------------------------------------------------------------

async fn list_words(State(st): St, OrgId(org): OrgId) -> ApiResult<Json<Value>> {
    let rows = st
        .db
        .read(move |c| {
            let mut s = c.prepare("SELECT id, word, note, created_at FROM blacklist_words WHERE org_id = ?1 ORDER BY word")?;
            let rows = s
                .query_map([org], |r| {
                    Ok(json!({ "id": r.get::<_, i64>(0)?, "word": r.get::<_, String>(1)?, "note": r.get::<_, Option<String>>(2)?, "created_at": r.get::<_, i64>(3)? }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
struct WordBody {
    word: Option<String>,
    note: Option<String>,
}

async fn add_word(State(st): St, OrgId(org): OrgId, Json(body): Json<WordBody>) -> ApiResult<Json<Value>> {
    let word = body.word.as_deref().and_then(normalize_word).ok_or_else(|| ApiError::bad("invalid_word"))?;
    let note = body.note.map(|n| ems_proto::truncate(n.trim(), 500)).filter(|n| !n.is_empty());
    let w = word.clone();
    st.db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO blacklist_words (org_id, word, note, created_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (org_id, word) DO UPDATE SET note = excluded.note",
                params![org, w, note, now_s()],
            )
        })
        .await?;
    st.policy.reload(&st.db).await?;
    Ok(Json(json!({ "ok": true, "word": word })))
}

async fn delete_word(State(st): St, OrgId(org): OrgId, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    st.db.write(move |tx| tx.execute("DELETE FROM blacklist_words WHERE id = ?1 AND org_id = ?2", [id, org])).await?;
    st.policy.reload(&st.db).await?;
    Ok(Json(json!({ "ok": true })))
}

async fn word_hits(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Json<Value>> {
    let p = Params(q);
    let limit = p.limit(200, 1000);
    let machine = p.text("machine_uuid");
    let rows = st
        .db
        .read(move |c| {
            let mut sql = String::from(
                "SELECT h.id, m.machine_uuid, m.hostname, m.label, h.os_user, h.word, h.domain, h.url, h.hit_count, h.first_hit_ms, h.last_hit_ms
                   FROM blacklist_hits h JOIN machines m ON m.id = h.machine_id
                  WHERE m.org_id = ?",
            );
            let mut args: Vec<Sql> = vec![org.into()];
            if let Some(m) = machine {
                sql.push_str(" AND m.machine_uuid = ?");
                args.push(m.into());
            }
            sql.push_str(" ORDER BY h.last_hit_ms DESC LIMIT ?");
            args.push(limit.into());
            let mut s = c.prepare(&sql)?;
            let rows = s
                .query_map(params_from_iter(args.iter()), |r| {
                    Ok(json!({
                        "id": r.get::<_, i64>(0)?, "machine_uuid": r.get::<_, String>(1)?, "hostname": r.get::<_, Option<String>>(2)?,
                        "label": r.get::<_, Option<String>>(3)?, "os_user": r.get::<_, String>(4)?, "word": r.get::<_, String>(5)?,
                        "domain": r.get::<_, String>(6)?, "url": r.get::<_, Option<String>>(7)?, "hit_count": r.get::<_, i64>(8)?,
                        "first_hit": r.get::<_, i64>(9)?, "last_hit": r.get::<_, i64>(10)?,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

// ---------------------------------------------------------------------------
// Machines
// ---------------------------------------------------------------------------

async fn list_machines(State(st): St, OrgId(org): OrgId) -> ApiResult<Json<Value>> {
    let online = st.online_ids(org);
    let live_seen = st.hub.last_seen();
    // How each computer's agent compares with the one the server holds:
    // "current", "pending" (it will update itself at a coming check-in) or
    // "held" (it differs, and updates are turned off for the organisation).
    // Unknown (null) for a computer that has not checked in since the server
    // started, and for agents from before they reported which program they are.
    let wanted = st.agent_build().map(|b| b.sha256.clone());
    let running = st.hub.agent_shas(org);
    let behind = if st.policy.settings(org).auto_update { "pending" } else { "held" };
    let pending_commands = st.pending_commands();
    let rows = st
        .db
        .read(move |c| {
            let mut s = c.prepare(
                "SELECT id, machine_uuid, hostname, os_user, label, os_version, agent_version, ip, first_seen, last_seen
                   FROM machines WHERE org_id = ?1 ORDER BY last_seen DESC",
            )?;
            let rows = s
                .query_map([org], |r| {
                    let id: i64 = r.get(0)?;
                    let stored_seen: i64 = r.get(9)?;
                    let agent_state = wanted.as_ref().and_then(|w| running.get(&id).map(|sha| if sha == w { "current" } else { behind }));
                    Ok(json!({
                        "machine_uuid": r.get::<_, String>(1)?, "hostname": r.get::<_, Option<String>>(2)?, "os_user": r.get::<_, Option<String>>(3)?,
                        "label": r.get::<_, Option<String>>(4)?, "os_version": r.get::<_, Option<String>>(5)?, "agent_version": r.get::<_, Option<String>>(6)?,
                        "ip": r.get::<_, Option<String>>(7)?,
                        "first_seen": r.get::<_, i64>(8)?,
                        "last_seen": live_seen.get(&id).copied().unwrap_or(0).max(stored_seen),
                        "online": online.contains(&id),
                        "agent_state": agent_state,
                        "pending_command": pending_commands.get(&id).copied(),
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(Value::Array(rows)))
}

#[derive(Deserialize)]
struct LabelBody {
    label: Option<String>,
}

async fn patch_machine(State(st): St, OrgId(org): OrgId, Path(uuid): Path<String>, Json(body): Json<LabelBody>) -> ApiResult<Json<Value>> {
    let label = body.label.map(|l| ems_proto::truncate(l.trim(), 255)).filter(|l| !l.is_empty());
    let n = st.db.write(move |tx| tx.execute("UPDATE machines SET label = ?1 WHERE org_id = ?2 AND machine_uuid = ?3", params![label, org, uuid])).await?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    Ok(Json(json!({ "ok": true })))
}

/// Removes a machine and everything recorded for it, and drops its connection.
async fn delete_machine(State(st): St, OrgId(org): OrgId, Path(uuid): Path<String>) -> ApiResult<Json<Value>> {
    let lookup = uuid.clone();
    let id: Option<i64> = st
        .db
        .read(move |c| c.query_row("SELECT id FROM machines WHERE org_id = ?1 AND machine_uuid = ?2", params![org, lookup], |r| r.get(0)).optional())
        .await?;
    let Some(id) = id else {
        return Err(ApiError::not_found());
    };
    st.db
        .write(move |tx| {
            for table in ["visits", "app_usage", "block_events", "blacklist_hits", "inventory", "commands"] {
                tx.execute(&format!("DELETE FROM {table} WHERE machine_id = ?1"), [id])?;
            }
            tx.execute("DELETE FROM blocked_domains WHERE org_id = ?1 AND machine_uuid = ?2", params![org, uuid])?;
            tx.execute("DELETE FROM machines WHERE id = ?1", [id])
        })
        .await?;
    st.hub.forget(id);
    st.forget_commands(id);
    st.policy.reload(&st.db).await?;
    Ok(Json(json!({ "ok": true })))
}

/// The recent lines of a computer's agent log.
///   GET /api/machines/{uuid}/logs
async fn machine_logs(State(st): St, OrgId(org): OrgId, Path(uuid): Path<String>) -> ApiResult<Json<Value>> {
    let row: Option<(Option<String>, i64)> = st
        .db
        .read(move |c| {
            c.query_row(
                "SELECT i.logs, i.updated_at FROM inventory i JOIN machines m ON m.id = i.machine_id WHERE m.org_id = ?1 AND m.machine_uuid = ?2",
                params![org, uuid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
        })
        .await?;
    let (lines, updated_at) = match row {
        Some((logs, updated_at)) => (logs.and_then(|l| serde_json::from_str::<Value>(&l).ok()).unwrap_or_else(|| json!([])), updated_at),
        None => (json!([]), 0),
    };
    Ok(Json(json!({ "updated_at": updated_at, "lines": lines })))
}

// ---------------------------------------------------------------------------
// Restart / shut down a computer
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CommandBody {
    kind: Option<String>,
    /// Seconds to warn the person at the keyboard. Defaults to a minute.
    delay_s: Option<u32>,
    message: Option<String>,
}

/// Resolves one of this organisation's computer names to its id.
async fn machine_id_of(st: &AppState, org: i64, uuid: &str) -> ApiResult<i64> {
    let uuid = uuid.to_string();
    let id: Option<i64> = st
        .db
        .read(move |c| c.query_row("SELECT id FROM machines WHERE org_id = ?1 AND machine_uuid = ?2", params![org, uuid], |r| r.get(0)).optional())
        .await?;
    id.ok_or_else(ApiError::not_found)
}

/// Queues a restart or shutdown for one computer.
///   POST /api/machines/{uuid}/command   body: { "kind": "restart" | "shutdown", "delay_s"?, "message"? }
async fn command_machine(
    State(st): St,
    OrgId(org): OrgId,
    axum::Extension(admin): axum::Extension<crate::auth::Admin>,
    Path(uuid): Path<String>,
    Json(body): Json<CommandBody>,
) -> ApiResult<Json<Value>> {
    let kind = body.kind.as_deref().and_then(ems_proto::CommandKind::parse).ok_or_else(|| ApiError::bad("bad_command"))?;
    let id = machine_id_of(&st, org, &uuid).await?;
    // A warning the person can read, and not so long it is forgotten.
    let delay_s = body.delay_s.unwrap_or(60).clamp(0, 600);
    let message = body.message.map(|m| ems_proto::truncate(m.trim(), 300)).filter(|m| !m.is_empty());
    st.queue_command(id, kind, delay_s, message, &admin.username).await?;
    crate::logln!("{} queued for {:?} by {:?}", kind.as_str(), uuid, admin.username);
    let online = st.online_ids(org).contains(&id);
    Ok(Json(json!({ "ok": true, "kind": kind.as_str(), "online": online, "within_s": st.policy.settings(org).upload_interval_s })))
}

/// Cancels a restart or shutdown that has not reached the computer yet.
async fn cancel_command(State(st): St, OrgId(org): OrgId, Path(uuid): Path<String>) -> ApiResult<Json<Value>> {
    let id = machine_id_of(&st, org, &uuid).await?;
    let cancelled = st.cancel_commands(id).await?;
    Ok(Json(json!({ "ok": true, "cancelled": cancelled })))
}

// ---------------------------------------------------------------------------
// System inventory (system summary + installed programs)
// ---------------------------------------------------------------------------

/// System summary for the Overview page: a count of computers needing a
/// restart to finish updates, and — when one computer is selected — its full
/// system card.
///   GET /api/system[?machine_uuid=]
async fn system_overview(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Json<Value>> {
    let want = Params(q).text("machine_uuid");
    let body = st
        .db
        .read(move |c| {
            let machines: i64 = c.query_row("SELECT COUNT(*) FROM machines WHERE org_id = ?1", [org], |r| r.get(0))?;
            let mut s = c.prepare(
                "SELECT m.machine_uuid, i.system, i.app_count, i.updated_at
                   FROM inventory i JOIN machines m ON m.id = i.machine_id WHERE m.org_id = ?1",
            )?;
            let rows = s
                .query_map([org], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let (mut reported, mut reboot_pending) = (0i64, 0i64);
            let mut machine = Value::Null;
            for (uuid, system, app_count, updated_at) in rows {
                reported += 1;
                let sys: Value = serde_json::from_str(&system).unwrap_or(Value::Null);
                if sys.get("reboot_pending").and_then(Value::as_bool).unwrap_or(false) {
                    reboot_pending += 1;
                }
                if want.as_deref() == Some(uuid.as_str()) {
                    machine = json!({ "machine_uuid": uuid, "system": sys, "app_count": app_count, "updated_at": updated_at });
                }
            }
            Ok(json!({ "fleet": { "machines": machines, "reported": reported, "reboot_pending": reboot_pending }, "machine": machine }))
        })
        .await?;
    Ok(Json(body))
}

/// The full installed-programs list of one computer.
///   GET /api/machines/{uuid}/apps
async fn machine_apps(State(st): St, OrgId(org): OrgId, Path(uuid): Path<String>) -> ApiResult<Json<Value>> {
    let row: Option<(String, i64, i64)> = st
        .db
        .read(move |c| {
            c.query_row(
                "SELECT i.apps, i.app_count, i.updated_at FROM inventory i JOIN machines m ON m.id = i.machine_id
                  WHERE m.org_id = ?1 AND m.machine_uuid = ?2",
                params![org, uuid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
        })
        .await?;
    let (apps, count, updated_at) = match row {
        Some((apps, count, updated_at)) => (serde_json::from_str(&apps).unwrap_or_else(|_| json!([])), count, updated_at),
        None => (json!([]), 0, 0),
    };
    Ok(Json(json!({ "count": count, "updated_at": updated_at, "apps": apps })))
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

async fn overview(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Json<Value>> {
    let p = Params(q);
    let (since, until) = p.range();
    let bucket_ms = p.int("bucket_ms").unwrap_or(3_600_000).clamp(600_000, 7 * 86_400_000);
    if (until - since) / bucket_ms > 400 {
        return Err(ApiError::bad("range_too_wide_for_bucket"));
    }
    let machine = p.text("machine_uuid");
    let online = st.online_count(org);
    let mut body = st
        .db
        .read(move |c| {
            let cat = Categorizer::load(c, org)?;
            // Every figure covers the organisation's computers, or the one picked in the console.
            // ?1 organisation, ?2 computer (or NULL for all), ?3 and ?4 the period.
            const MINE: &str = "machine_id IN (SELECT id FROM machines WHERE org_id = ?1 AND (?2 IS NULL OR machine_uuid = ?2))";
            let range = params![org, machine, since, until];

            let machines_total: i64 = c.query_row("SELECT COUNT(*) FROM machines WHERE org_id = ?1", [org], |r| r.get(0))?;
            let (active_sec, active_machines): (i64, i64) = c.query_row(
                &format!("SELECT COALESCE(SUM(dur_s), 0), COUNT(DISTINCT machine_id) FROM app_usage WHERE start_ms >= ?3 AND start_ms <= ?4 AND {MINE}"),
                range,
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let attempts: i64 =
                c.query_row(&format!("SELECT COALESCE(SUM(hit_count), 0) FROM block_events WHERE last_ms >= ?3 AND last_ms <= ?4 AND {MINE}"), range, |r| r.get(0))?;
            let word_hits: i64 =
                c.query_row(&format!("SELECT COALESCE(SUM(hit_count), 0) FROM blacklist_hits WHERE last_hit_ms >= ?3 AND last_hit_ms <= ?4 AND {MINE}"), range, |r| r.get(0))?;

            let mut s = c.prepare(&format!("SELECT domain, SUM(dur_s) AS total, COUNT(*) FROM visits WHERE start_ms >= ?3 AND start_ms <= ?4 AND {MINE} GROUP BY domain ORDER BY total DESC"))?;
            let domains = s.query_map(range, |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let mut by_category: HashMap<&str, i64> = CATEGORIES.iter().map(|c| (*c, 0)).collect();
            let mut web_sec = 0i64;
            let mut top_domains = Vec::new();
            for (domain, total, visits) in &domains {
                let category = cat.of(domain, None).to_string();
                web_sec += total;
                if let Some(slot) = by_category.get_mut(category.as_str()) {
                    *slot += total;
                }
                if top_domains.len() < 10 {
                    top_domains.push(json!({ "domain": domain, "total_sec": total, "visits": visits, "category": category }));
                }
            }

            let mut s = c.prepare(&format!("SELECT app, SUM(dur_s) AS total, COUNT(*) FROM app_usage WHERE start_ms >= ?3 AND start_ms <= ?4 AND {MINE} GROUP BY app ORDER BY total DESC LIMIT 10"))?;
            let top_apps = s
                .query_map(range, |r| Ok(json!({ "app_name": r.get::<_, String>(0)?, "total_sec": r.get::<_, i64>(1)?, "sessions": r.get::<_, i64>(2)? })))?
                .collect::<rusqlite::Result<Vec<_>>>()?;

            let mut s = c.prepare(
                "SELECT m.machine_uuid, m.hostname, m.label, SUM(a.dur_s) AS total
                   FROM app_usage a JOIN machines m ON m.id = a.machine_id
                  WHERE m.org_id = ?1 AND (?2 IS NULL OR m.machine_uuid = ?2) AND a.start_ms >= ?3 AND a.start_ms <= ?4
                  GROUP BY a.machine_id ORDER BY total DESC LIMIT 10",
            )?;
            let top_machines = s
                .query_map(range, |r| {
                    Ok(json!({ "machine_uuid": r.get::<_, String>(0)?, "hostname": r.get::<_, Option<String>>(1)?, "label": r.get::<_, Option<String>>(2)?, "total_sec": r.get::<_, i64>(3)? }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;

            let mut s = c.prepare(&format!("SELECT (start_ms - ?3) / ?5 AS bucket, SUM(dur_s) FROM app_usage WHERE start_ms >= ?3 AND start_ms <= ?4 AND {MINE} GROUP BY bucket ORDER BY bucket"))?;
            let series = s
                .query_map(params![org, machine, since, until, bucket_ms], |r| Ok(json!({ "t": since + r.get::<_, i64>(0)? * bucket_ms, "sec": r.get::<_, i64>(1)? })))?
                .collect::<rusqlite::Result<Vec<_>>>()?;

            Ok(json!({
                "machines_total": machines_total, "active_machines": active_machines, "active_sec": active_sec, "web_sec": web_sec,
                "blocked_attempts": attempts, "word_hits": word_hits, "by_category": by_category,
                "top_domains": top_domains, "top_apps": top_apps, "top_machines": top_machines,
                "series": series, "bucket_ms": bucket_ms, "since": since, "until": until,
            }))
        })
        .await?;
    body["machines_online"] = json!(online);
    Ok(Json(body))
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// What the console needs to know about the agent program the server holds.
fn agent_info(st: &AppState) -> Value {
    match st.agent_build() {
        Some(build) => json!({ "available": true, "version": build.version, "fingerprint": &build.sha256[..12] }),
        None => json!({ "available": false }),
    }
}

async fn get_settings(State(st): St, OrgId(org): OrgId) -> ApiResult<Json<Value>> {
    let org_row = st.org(org).ok_or_else(ApiError::not_found)?;
    let db_bytes: u64 = ["ems.db", "ems.db-wal"].iter().filter_map(|f| std::fs::metadata(st.cfg.data_dir.join(f)).ok()).map(|m| m.len()).sum();
    let (machines, machines_all): (i64, i64) = st
        .db
        .read(move |c| c.query_row("SELECT (SELECT COUNT(*) FROM machines WHERE org_id = ?1), (SELECT COUNT(*) FROM machines)", [org], |r| Ok((r.get(0)?, r.get(1)?))))
        .await?;
    Ok(Json(json!({
        "org": { "id": org_row.id, "name": org_row.name, "created_at": org_row.created_at, "machines": machines, "online": st.online_count(org) },
        "settings": st.policy.settings(org),
        "agent": agent_info(&st),
        "api_key_enabled": org_row.api_key_hash.is_some(),
        "server": {
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_s": now_s() - st.started_s,
            "db_bytes": db_bytes,
            "organisations": st.orgs().len(),
            "machines": machines_all,
        },
    })))
}

async fn put_settings(State(st): St, OrgId(org): OrgId, Json(body): Json<Settings>) -> ApiResult<Json<Value>> {
    let settings = body.sanitized();
    st.save_settings(org, &settings).await?;
    Ok(Json(json!({ "ok": true, "settings": settings })))
}

async fn create_api_key(State(st): St, OrgId(org): OrgId) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "ok": true, "api_key": st.set_api_key(org, true).await? })))
}

async fn revoke_api_key(State(st): St, OrgId(org): OrgId) -> ApiResult<Json<Value>> {
    st.set_api_key(org, false).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Installers
// ---------------------------------------------------------------------------

/// The address agents should report to, as the console passes it: the
/// address the administrator is using to reach this server.
fn server_param(p: &Params) -> ApiResult<String> {
    p.text("server")
        .filter(|s| (s.starts_with("https://") || s.starts_with("http://")) && s.len() <= 300 && !s.contains(|c: char| c.is_control() || c.is_whitespace() || c == '"' || c == '\\'))
        .ok_or_else(|| ApiError::bad("server_required"))
}

/// An organisation's name as part of a file name: plain letters and digits, the rest as dashes.
fn file_slug(name: &str, id: i64) -> String {
    let mut slug = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
        if slug.len() >= 40 {
            break;
        }
    }
    let slug = slug.trim_end_matches('-');
    if slug.is_empty() {
        format!("org-{id}")
    } else {
        slug.to_string()
    }
}

fn attachment(filename: &str, content_type: &'static str, body: Vec<u8>) -> Response {
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).unwrap_or_else(|_| HeaderValue::from_static("attachment"));
    ([(axum::http::header::CONTENT_TYPE, HeaderValue::from_static(content_type)), (axum::http::header::CONTENT_DISPOSITION, disposition)], body).into_response()
}

fn setup_for(st: &AppState, org: i64, server: String) -> ApiResult<(ems_proto::SetupFile, String)> {
    let org = st.org(org).ok_or_else(ApiError::not_found)?;
    let slug = file_slug(&org.name, org.id);
    Ok((ems_proto::SetupFile { server, key: Some(org.agent_key), org: Some(org.name) }, slug))
}

/// Hands out the agent as one ready-to-run installer made for one
/// organisation: the program with this server's address, the organisation's
/// key and its name attached. A computer it is run on belongs to that
/// organisation from its first check-in.
///   GET /api/download/agent-installer?org=<id>&server=https://ems.example.com
async fn download_installer(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Response> {
    let server = server_param(&Params(q))?;
    let (setup, slug) = setup_for(&st, org, server)?;
    let Some(build) = st.agent_build() else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "agent_not_available"));
    };
    let mut exe = Vec::with_capacity(build.bytes.len() + 512);
    exe.extend_from_slice(&build.bytes);
    ems_proto::append_setup(&mut exe, &setup);
    Ok(attachment(&format!("EMS-Agent-{slug}.exe"), "application/octet-stream", exe))
}

/// The same settings as a small file, for when the agent program itself is
/// not on the server: saved next to `ems-agent.exe`, it turns that into the
/// organisation's installer.
async fn download_setup(State(st): St, OrgId(org): OrgId, Query(q): Q) -> ApiResult<Response> {
    let server = server_param(&Params(q))?;
    let (setup, _) = setup_for(&st, org, server)?;
    let mut text = serde_json::to_string_pretty(&setup).map_err(anyhow::Error::from)?;
    text.push('\n');
    Ok(attachment("ems-agent.json", "application/json", text.into_bytes()))
}

// ---------------------------------------------------------------------------
// Releasing a new agent
// ---------------------------------------------------------------------------

/// Largest agent program accepted.
const MAX_AGENT_BYTES: usize = 64 * 1024 * 1024;
/// Header carrying the administrator's password, percent-encoded so any character fits.
const PASSWORD_HEADER: &str = "x-ems-password";

/// Undoes the console's `encodeURIComponent`.
fn percent_decode(s: &str) -> String {
    let hex = |b: Option<&u8>| b.and_then(|b| (*b as char).to_digit(16)).map(|d| d as u8);
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(hi), Some(lo)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Replaces the agent program the server holds with an uploaded one.
///   POST /api/agent-program   body: the new ems-agent.exe
///
/// From then on every organisation's installer is made from it, and every
/// installed computer whose organisation has updates on moves to it at its
/// next check-in. The program is the same for all organisations: which one
/// a computer belongs to is kept on the computer, not in the program, so an
/// update cannot move a computer from one organisation to another.
///
/// Because this reaches every computer, the administrator's password is
/// asked for again, even though they are signed in.
async fn upload_agent(
    State(st): St,
    axum::Extension(admin): axum::Extension<crate::auth::Admin>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let ip = st.client_ip(&headers, peer);
    if st.limiter.blocked(&ip) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"));
    }
    let password = headers.get(PASSWORD_HEADER).and_then(|v| v.to_str().ok()).map(percent_decode).unwrap_or_default();
    if password.is_empty() || !crate::auth::check_password(&st, admin.id, password).await? {
        st.limiter.fail(&ip);
        return Err(ApiError::new(StatusCode::FORBIDDEN, "wrong_current_password"));
    }
    st.limiter.clear(&ip);

    // An organisation's installer is accepted too: the settings attached to it are left off.
    let exe = ems_proto::exe_part(&body);
    if !ems_proto::is_windows_program(exe) {
        return Err(ApiError::bad("not_an_agent_program"));
    }
    // Agents older than 1.1 carry no version and cannot update themselves; installers made from one would be a dead end.
    let Some(version) = ems_proto::find_version_tag(exe) else {
        return Err(ApiError::bad("not_an_agent_program"));
    };
    let sha256 = ems_proto::sha256_hex(exe);
    let previous = st.agent_build();
    let unchanged = previous.as_ref().is_some_and(|b| b.sha256 == sha256);
    if !unchanged {
        let (worker, bytes) = (st.clone(), body.slice_ref(exe));
        tokio::task::spawn_blocking(move || worker.store_agent_program(&bytes)).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        if !st.agent_build().is_some_and(|b| b.sha256 == sha256) {
            return Err(anyhow::anyhow!("the uploaded agent program was stored but could not be loaded").into());
        }
        crate::logln!(
            "agent program released by {:?}: version {version}, fingerprint {} (was {})",
            admin.username,
            &sha256[..12],
            previous.as_ref().map_or("none".to_string(), |b| format!("{} {}", b.version.as_deref().unwrap_or("unknown"), &b.sha256[..12]))
        );
    }
    Ok(Json(json!({ "ok": true, "version": version, "fingerprint": &sha256[..12], "size": exe.len(), "unchanged": unchanged })))
}

// ---------------------------------------------------------------------------
// Organisations
// ---------------------------------------------------------------------------

fn org_json(st: &AppState, org: &crate::state::Org, machines: i64) -> Value {
    // How far the organisation's computers have got with the agent the
    // server holds, counting those that have checked in since the server started.
    let running = st.hub.agent_shas(org.id);
    let current = st.agent_build().map_or(0, |b| running.values().filter(|sha| **sha == b.sha256).count());
    json!({
        "id": org.id, "name": org.name, "created_at": org.created_at, "machines": machines, "online": st.online_count(org.id),
        "agent_current": current, "agent_behind": running.len() - current, "auto_update": st.policy.settings(org.id).auto_update,
    })
}

async fn list_orgs(State(st): St, axum::Extension(admin): axum::Extension<crate::auth::Admin>) -> ApiResult<Json<Value>> {
    let counts: HashMap<i64, i64> = st
        .db
        .read(|c| c.prepare("SELECT org_id, COUNT(*) FROM machines GROUP BY org_id")?.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect())
        .await?;
    // A member sees only the organisations granted to them.
    let allowed = st.accessible_orgs(admin.id);
    let orgs: Vec<Value> = st
        .orgs()
        .iter()
        .filter(|o| allowed.as_ref().map_or(true, |set| set.contains(&o.id)))
        .map(|o| org_json(&st, o, counts.get(&o.id).copied().unwrap_or(0)))
        .collect();
    Ok(Json(json!({ "orgs": orgs, "agent": agent_info(&st) })))
}

// ---------------------------------------------------------------------------
// Users and permissions (owner only)
// ---------------------------------------------------------------------------

async fn list_users(State(st): St) -> ApiResult<Json<Value>> {
    let orgs: Vec<Value> = st.orgs().iter().map(|o| json!({ "id": o.id, "name": o.name })).collect();
    Ok(Json(json!({ "users": st.list_users().await?, "permissions": crate::state::PERMISSIONS, "orgs": orgs })))
}

#[derive(Deserialize)]
struct NewUserBody {
    username: Option<String>,
    password: Option<String>,
    owner: Option<bool>,
}

async fn create_user(State(st): St, Json(body): Json<NewUserBody>) -> ApiResult<Json<Value>> {
    let id = st.create_user(body.username.as_deref().unwrap_or("").trim(), body.password.as_deref().unwrap_or(""), body.owner.unwrap_or(false)).await?;
    crate::logln!("user created: id {id}");
    Ok(Json(json!({ "ok": true, "id": id })))
}

async fn delete_user(State(st): St, axum::Extension(admin): axum::Extension<crate::auth::Admin>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    st.delete_user(id, admin.id).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct UserPasswordBody {
    password: Option<String>,
}

async fn reset_user_password(State(st): St, Path(id): Path<i64>, Json(body): Json<UserPasswordBody>) -> ApiResult<Json<Value>> {
    st.set_user_password(id, body.password.as_deref().unwrap_or("")).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct AccessGrant {
    org_id: i64,
    #[serde(default)]
    perms: Vec<String>,
}

#[derive(Deserialize)]
struct AccessBody {
    #[serde(default)]
    grants: Vec<AccessGrant>,
}

async fn set_user_access(State(st): St, Path(id): Path<i64>, Json(body): Json<AccessBody>) -> ApiResult<Json<Value>> {
    st.set_user_access(id, body.grants.into_iter().map(|g| (g.org_id, g.perms)).collect()).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Clearing recorded activity
// ---------------------------------------------------------------------------

/// Deletes all recorded website and application activity for one organisation
/// (including the attempt and word-hit logs). Block lists, blacklist words,
/// categories, computers and their system inventory are kept.
///   DELETE /api/activity
async fn clear_activity(State(st): St, OrgId(org): OrgId) -> ApiResult<Json<Value>> {
    let removed = crate::db::prune(&st.db, org, i64::MAX).await?;
    crate::logln!("activity cleared for organisation {org}: {removed} rows");
    Ok(Json(json!({ "ok": true, "removed": removed })))
}

#[derive(Deserialize)]
struct OrgBody {
    name: Option<String>,
}

async fn create_org(State(st): St, Json(body): Json<OrgBody>) -> ApiResult<Json<Value>> {
    let org = st.create_org(body.name.as_deref().unwrap_or("")).await?;
    crate::logln!("organisation created: {:?} (id {})", org.name, org.id);
    Ok(Json(json!({ "ok": true, "org": org_json(&st, &org, 0) })))
}

async fn rename_org(State(st): St, Path(id): Path<i64>, Json(body): Json<OrgBody>) -> ApiResult<Json<Value>> {
    let org = st.rename_org(id, body.name.as_deref().unwrap_or("")).await?;
    Ok(Json(json!({ "ok": true, "id": org.id, "name": org.name })))
}

/// Removes an organisation with its computers and everything recorded for
/// them. The caller repeats the name, so that a slip cannot remove a client.
async fn delete_org(State(st): St, Path(id): Path<i64>, Json(body): Json<OrgBody>) -> ApiResult<Json<Value>> {
    let org = st.org(id).ok_or(OrgError::NotFound)?;
    let typed = crate::state::clean_org_name(body.name.as_deref().unwrap_or("")).unwrap_or_default();
    if typed.to_lowercase() != org.name.to_lowercase() {
        return Err(ApiError::bad("org_name_mismatch"));
    }
    st.delete_org(id).await?;
    crate::logln!("organisation removed: {:?} (id {})", org.name, org.id);
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::{delete, get, patch, post, put};
    axum::Router::new()
        .route("/api/me", get(crate::auth::me))
        .route("/api/password", post(crate::auth::change_password))
        .route("/api/orgs", get(list_orgs).post(create_org))
        .route("/api/orgs/{id}", patch(rename_org).delete(delete_org))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/{id}", delete(delete_user))
        .route("/api/users/{id}/password", post(reset_user_password))
        .route("/api/users/{id}/access", put(set_user_access))
        .route("/api/activity", delete(clear_activity))
        .route("/api/agent-program", post(upload_agent).layer(DefaultBodyLimit::max(MAX_AGENT_BYTES)))
        .route("/api/overview", get(overview))
        .route("/api/visits", get(visits))
        .route("/api/visits/summary", get(visits_summary))
        .route("/api/visits/report/suspicious", get(suspicious_report))
        .route("/api/categories/domains", get(list_domain_categories))
        .route("/api/categories/domains/{domain}", put(put_domain_category).delete(delete_domain_category))
        .route("/api/categories/keywords", get(list_keywords).post(add_keyword))
        .route("/api/categories/keywords/{id}", delete(delete_keyword))
        .route("/api/app-usage", get(app_usage))
        .route("/api/app-usage/summary", get(app_usage_summary))
        .route("/api/app-usage/titles", get(app_titles))
        .route("/api/blocked-domains", get(list_blocked).post(add_blocked))
        .route("/api/blocked-domains/{id}", delete(delete_blocked))
        .route("/api/block-events", get(block_events))
        .route("/api/blacklist-words", get(list_words).post(add_word))
        .route("/api/blacklist-words/hits", get(word_hits))
        .route("/api/blacklist-words/{id}", delete(delete_word))
        .route("/api/machines", get(list_machines))
        .route("/api/machines/{uuid}", patch(patch_machine).delete(delete_machine))
        .route("/api/machines/{uuid}/apps", get(machine_apps))
        .route("/api/machines/{uuid}/logs", get(machine_logs))
        .route("/api/machines/{uuid}/command", post(command_machine).delete(cancel_command))
        .route("/api/system", get(system_overview))
        .route("/api/settings", get(get_settings).put(put_settings))
        .route("/api/settings/api-key", post(create_api_key).delete(revoke_api_key))
        .route("/api/download/agent-installer", get(download_installer))
        .route("/api/download/agent-setup", get(download_setup))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(domains: &[(&str, &str)], keywords: &[(&str, &str)]) -> Categorizer {
        Categorizer {
            domains: domains.iter().map(|(d, c)| (d.to_string(), c.to_string())).collect(),
            keywords: keywords.iter().map(|(k, c)| (k.to_string(), c.to_string())).collect(),
        }
    }

    #[test]
    fn explicit_domain_beats_keyword_and_default_is_suspicious() {
        let c = cat(&[("github.com", "productive")], &[("git", "neutral"), ("docs", "productive")]);
        assert_eq!(c.of("github.com", None), "productive");
        assert_eq!(c.of("gitlab.com", None), "neutral");
        assert_eq!(c.of("example.com", Some("https://example.com/docs/x")), "productive");
        assert_eq!(c.of("example.com", None), "suspicious");
    }

    #[test]
    fn subdomains_inherit_the_parent_category_unless_overridden() {
        let c = cat(&[("google.com", "productive"), ("mail.google.com", "neutral")], &[]);
        assert_eq!(c.of("docs.google.com", None), "productive");
        assert_eq!(c.of("mail.google.com", None), "neutral");
        assert_eq!(c.of("a.mail.google.com", None), "neutral");
        // A bare TLD entry must never be consulted.
        assert_eq!(cat(&[("com", "productive")], &[]).of("x.com", None), "suspicious");
    }

    #[test]
    fn a_password_survives_the_trip_in_a_header() {
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("p%40ss%20w%C3%B6rd%25"), "p@ss wörd%");
        // Not valid escapes: left as they are, never a panic.
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
    }

    #[tokio::test]
    async fn releasing_an_agent_needs_the_password_and_a_real_agent_program() {
        use crate::state::tests::{fake_agent, state};
        let (st, dir) = state();
        let st = Arc::new(st);
        crate::auth::set_password(&st, "admin", "correct horse").await.unwrap();
        let admin_id: i64 = st.db.read(|c| c.query_row("SELECT id FROM admins", [], |r| r.get(0))).await.unwrap();
        let acme = st.create_org("Acme").await.unwrap();

        let upload = |password: &'static str, body: Vec<u8>| {
            let st = st.clone();
            async move {
                let mut headers = HeaderMap::new();
                headers.insert(PASSWORD_HEADER, password.parse().unwrap());
                let admin = crate::auth::Admin { id: admin_id, username: "admin".into(), role: "owner".into() };
                match upload_agent(State(st), axum::Extension(admin), ConnectInfo("10.0.0.1:1".parse().unwrap()), headers, Bytes::from(body)).await {
                    Ok(Json(v)) => Ok(v),
                    Err(e) => Err(e.into_response().status()),
                }
            }
        };
        let v1 = fake_agent("1.1.0", 6000, 1);

        assert_eq!(upload("wrong", v1.clone()).await.unwrap_err(), StatusCode::FORBIDDEN);
        assert_eq!(upload("", v1.clone()).await.unwrap_err(), StatusCode::FORBIDDEN);
        assert!(st.agent_build().is_none(), "nothing is stored without the password");
        assert_eq!(upload("correct%20horse", b"<html>oops</html>".to_vec()).await.unwrap_err(), StatusCode::BAD_REQUEST);
        // A program, but not an agent that can update itself (no version in it).
        let mut other_program = v1.clone();
        other_program[0x100..0x120].fill(0);
        assert_eq!(upload("correct%20horse", other_program).await.unwrap_err(), StatusCode::BAD_REQUEST);
        assert!(st.agent_build().is_none());

        let first = upload("correct%20horse", v1.clone()).await.unwrap();
        assert_eq!((first["version"].as_str(), first["unchanged"].as_bool()), (Some("1.1.0"), Some(false)));
        assert_eq!(&st.agent_build().unwrap().bytes[..], &v1[..]);
        assert_eq!(upload("correct%20horse", v1.clone()).await.unwrap()["unchanged"], true);

        // An organisation's installer uploaded by mistake: only the program is kept, its key is not.
        let v2 = fake_agent("1.2.0", 7000, 2);
        let mut installer = v2.clone();
        ems_proto::append_setup(&mut installer, &ems_proto::SetupFile { server: "https://ems.example.com".into(), key: Some(acme.agent_key.clone()), org: Some("Acme".into()) });
        assert_eq!(upload("correct%20horse", installer).await.unwrap()["version"], "1.2.0");
        let stored = std::fs::read(dir.join(crate::state::AGENT_FILE)).unwrap();
        assert_eq!(stored, v2);
        assert!(!stored.windows(acme.agent_key.len()).any(|w| w == acme.agent_key.as_bytes()), "no organisation's key is in the program every organisation receives");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn installer_file_names_are_plain() {
        assert_eq!(file_slug("Acme Traders Pvt. Ltd.", 3), "Acme-Traders-Pvt-Ltd");
        assert_eq!(file_slug("  A&B  ", 3), "A-B");
        assert_eq!(file_slug("\"quoted\"/..\\x", 3), "quoted-x");
        assert_eq!(file_slug("संस्था", 7), "org-7", "a name with no plain letters falls back to the id");
        assert!(file_slug(&"long name ".repeat(20), 1).len() <= 40);
    }

    #[test]
    fn like_patterns_match_user_text_literally() {
        assert_eq!(like_contains("a_b%c"), "%a\\_b\\%c%");
        assert_eq!(category_of(Some(" Neutral ")), Some("neutral"));
        assert_eq!(category_of(Some("other")), None);
    }
}
