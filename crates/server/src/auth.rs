//! Administrator sign-in: Argon2 password hashes, opaque session cookies,
//! and an optional read-only API key per organisation for scripts that pull
//! its reports.

use crate::api::{ApiError, ApiResult};
use crate::state::AppState;
use crate::util::{now_s, random_hex, sha256_hex};
use anyhow::anyhow;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

const COOKIE: &str = "ems_session";
const SESSION_TTL_S: i64 = 7 * 86_400;
pub const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, Clone)]
pub struct Admin {
    pub id: i64,
    pub username: String,
    /// "owner" sees and manages everything; "member" is limited to granted
    /// organisations and permissions; "api-key" is a read-only report key.
    pub role: String,
}

/// Header in which the console names the organisation a request is about.
/// Downloads, which are plain links, use `?org=` instead.
pub const ORG_HEADER: &str = "x-ems-org";

/// Put on a request made with a report API key: the one organisation that key may read.
#[derive(Debug, Clone, Copy)]
pub struct KeyOrg(pub i64);

/// The organisation a request is about. A signed-in administrator names
/// it; a report API key can only ever mean its own.
pub struct OrgId(pub i64);

fn query_value<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').filter_map(|pair| pair.split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v)
}

impl FromRequestParts<std::sync::Arc<AppState>> for OrgId {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &std::sync::Arc<AppState>) -> Result<Self, Self::Rejection> {
        if let Some(KeyOrg(id)) = parts.extensions.get::<KeyOrg>() {
            return Ok(OrgId(*id));
        }
        let named = parts.headers.get(ORG_HEADER).and_then(|v| v.to_str().ok()).or_else(|| query_value(parts.uri.query().unwrap_or(""), "org"));
        let id: i64 = named.and_then(|v| v.trim().parse().ok()).ok_or_else(|| ApiError::bad("organisation_required"))?;
        match st.org(id) {
            Some(org) => Ok(OrgId(org.id)),
            None => Err(ApiError::new(StatusCode::NOT_FOUND, "unknown_organisation")),
        }
    }
}

/// What a report API key may read: activity and the list of computers.
/// Everything else, including the installer with the organisation's agent
/// key in it, needs an administrator.
const REPORT_PATHS: [&str; 7] = ["/api/overview", "/api/visits", "/api/app-usage", "/api/block-events", "/api/blacklist-words/hits", "/api/machines", "/api/system"];

fn is_report_path(path: &str) -> bool {
    REPORT_PATHS.iter().any(|p| path.strip_prefix(p).is_some_and(|rest| rest.is_empty() || rest.starts_with('/')))
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| anyhow!("random source: {e}"))?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow!("salt: {e}"))?;
    Ok(Argon2::default().hash_password(password.as_bytes(), &salt).map_err(|e| anyhow!("hash: {e}"))?.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Creates the administrator, or replaces the password if the name exists.
pub async fn set_password(st: &AppState, username: &str, password: &str) -> anyhow::Result<()> {
    let hash = hash_password(password)?;
    let username = username.to_string();
    st.db
        .write(move |tx| {
            tx.execute(
                "INSERT INTO admins (username, password_hash, created_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT (username) DO UPDATE SET password_hash = excluded.password_hash",
                params![username, hash, now_s()],
            )?;
            tx.execute("DELETE FROM sessions WHERE admin_id = (SELECT id FROM admins WHERE username = ?1)", [&username])
        })
        .await?;
    Ok(())
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ").map(str::trim)
}

fn session_cookie(token: &str, max_age: i64, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"))
        .unwrap_or_else(|_| HeaderValue::from_static(""))
}

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

pub async fn login(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginReq>,
) -> ApiResult<Response> {
    let ip = st.client_ip(&headers, peer);
    if st.limiter.blocked(&ip) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"));
    }
    let username = body.username.trim().to_string();
    let lookup = username.clone();
    let row: Option<(i64, String)> = st
        .db
        .read(move |c| c.query_row("SELECT id, password_hash FROM admins WHERE username = ?1", [lookup], |r| Ok((r.get(0)?, r.get(1)?))).optional())
        .await?;

    // Hash even when the user does not exist, so both cases take the same time.
    let (admin_id, hash) = row.map_or((None, String::new()), |(id, h)| (Some(id), h));
    let password = body.password;
    let ok = tokio::task::spawn_blocking(move || {
        if hash.is_empty() {
            let _ = hash_password(&password);
            false
        } else {
            verify_password(&password, &hash)
        }
    })
    .await
    .unwrap_or(false);

    let Some(admin_id) = admin_id.filter(|_| ok) else {
        st.limiter.fail(&ip);
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid_credentials"));
    };
    st.limiter.clear(&ip);

    let token = random_hex(32);
    let token_hash = sha256_hex(&token);
    st.db
        .write(move |tx| tx.execute("INSERT INTO sessions (token_hash, admin_id, expires_at) VALUES (?1, ?2, ?3)", params![token_hash, admin_id, now_s() + SESSION_TTL_S]))
        .await?;

    let mut res = Json(json!({ "ok": true, "username": username })).into_response();
    res.headers_mut().insert(header::SET_COOKIE, session_cookie(&token, SESSION_TTL_S, st.is_https(&headers)));
    Ok(res)
}

pub async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = cookie(&headers, COOKIE) {
        let hash = sha256_hex(&token);
        st.db.write(move |tx| tx.execute("DELETE FROM sessions WHERE token_hash = ?1", [hash])).await?;
    }
    let mut res = Json(json!({ "ok": true })).into_response();
    res.headers_mut().insert(header::SET_COOKIE, session_cookie("", 0, st.is_https(&headers)));
    Ok(res)
}

pub async fn me(State(st): State<Arc<AppState>>, Extension(admin): Extension<Admin>) -> Json<serde_json::Value> {
    Json(json!({ "username": admin.username, "role": admin.role, "access": st.access_json(admin.id) }))
}

/// Whether `password` is the signed-in administrator's. Asked again before
/// the one action that reaches every computer: releasing a new agent.
pub async fn check_password(st: &AppState, admin_id: i64, password: String) -> anyhow::Result<bool> {
    let hash: Option<String> = st.db.read(move |c| c.query_row("SELECT password_hash FROM admins WHERE id = ?1", [admin_id], |r| r.get(0)).optional()).await?;
    let Some(hash) = hash else { return Ok(false) };
    Ok(tokio::task::spawn_blocking(move || verify_password(&password, &hash)).await.unwrap_or(false))
}

#[derive(Deserialize)]
pub struct PasswordReq {
    current: String,
    new: String,
}

pub async fn change_password(
    State(st): State<Arc<AppState>>,
    Extension(admin): Extension<Admin>,
    headers: HeaderMap,
    Json(body): Json<PasswordReq>,
) -> ApiResult<Json<serde_json::Value>> {
    if body.new.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::bad("password_too_short"));
    }
    let id = admin.id;
    let hash: String = st.db.read(move |c| c.query_row("SELECT password_hash FROM admins WHERE id = ?1", [id], |r| r.get(0))).await?;
    let (current, new) = (body.current, body.new);
    let new_hash = tokio::task::spawn_blocking(move || verify_password(&current, &hash).then(|| hash_password(&new)))
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let Some(new_hash) = new_hash else {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "wrong_current_password"));
    };
    let new_hash = new_hash?;

    // Sign out every other session; keep the one that made the change.
    let keep = cookie(&headers, COOKIE).map(|t| sha256_hex(&t)).unwrap_or_default();
    st.db
        .write(move |tx| {
            tx.execute("UPDATE admins SET password_hash = ?1 WHERE id = ?2", params![new_hash, id])?;
            tx.execute("DELETE FROM sessions WHERE admin_id = ?1 AND token_hash <> ?2", params![id, keep])
        })
        .await?;
    Ok(Json(json!({ "ok": true })))
}

/// Guards every admin route. Browsers authenticate with the session cookie.
/// Scripts may send `Authorization: Bearer <api key>`, which only ever
/// grants read access to the reports of the organisation the key was made for.
pub async fn require_auth(State(st): State<Arc<AppState>>, mut req: Request, next: Next) -> Response {
    if let Some(token) = cookie(req.headers(), COOKIE) {
        let hash = sha256_hex(&token);
        let found = st
            .db
            .read(move |c| {
                c.query_row(
                    "SELECT a.id, a.username, a.role FROM sessions s JOIN admins a ON a.id = s.admin_id
                     WHERE s.token_hash = ?1 AND s.expires_at > ?2",
                    params![hash, now_s()],
                    |r| Ok(Admin { id: r.get(0)?, username: r.get(1)?, role: r.get(2)? }),
                )
                .optional()
            })
            .await;
        match found {
            Ok(Some(admin)) => {
                req.extensions_mut().insert(admin);
                return next.run(req).await;
            }
            Ok(None) => {}
            Err(e) => return ApiError::from(e).into_response(),
        }
    }

    if req.method() == Method::GET && is_report_path(req.uri().path()) {
        // Keys are long and random and are looked up by their hash, so nothing about a wrong guess leaks.
        if let Some(org) = bearer(req.headers()).and_then(|key| st.org_by_api_key(key)) {
            req.extensions_mut().insert(Admin { id: 0, username: "api-key".into(), role: "api-key".into() });
            req.extensions_mut().insert(KeyOrg(org));
            return next.run(req).await;
        }
    }
    ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}

/// What a route needs: any signed-in user, an owner, or a permission within
/// the organisation the request names.
enum Need {
    AnyUser,
    Owner,
    Org(&'static str),
}

/// The requirement for one request, from its method and path.
fn required(method: &Method, path: &str) -> Need {
    use Need::*;
    let is_get = method == Method::GET;
    if path == "/api/me" || path == "/api/password" {
        return AnyUser;
    }
    // Owner-only: managing users, organisations, and the shared agent program.
    if path == "/api/users" || path.starts_with("/api/users/") || path == "/api/agent-program" {
        return Owner;
    }
    if path == "/api/orgs" {
        return if is_get { AnyUser } else { Owner };
    }
    if path.starts_with("/api/orgs/") {
        return Owner;
    }
    // Downloading an installer carries the organisation's key, so it is its own permission.
    if path.starts_with("/api/download/") {
        return Org("installer");
    }
    if is_get {
        return Org("view");
    }
    // Writes, by area.
    if path == "/api/activity" || path.starts_with("/api/settings") {
        return Org("settings");
    }
    if path.starts_with("/api/blocked-domains") || path.starts_with("/api/blacklist-words") || path.starts_with("/api/categories") {
        return Org("blocking");
    }
    if path.starts_with("/api/machines/") && path.ends_with("/command") {
        return Org("control");
    }
    if path.starts_with("/api/machines/") {
        // Removing a computer is "control"; editing its label is a viewer's edit.
        return if method == Method::DELETE { Org("control") } else { Org("view") };
    }
    Org("control")
}

/// The organisation a request names, the same way [`OrgId`] finds it.
fn request_org(headers: &HeaderMap, uri: &Uri) -> Option<i64> {
    headers
        .get(ORG_HEADER)
        .and_then(|v| v.to_str().ok())
        .or_else(|| query_value(uri.query().unwrap_or(""), "org"))
        .and_then(|v| v.trim().parse().ok())
}

/// Runs after [`require_auth`] and enforces what the signed-in user may do.
/// Owners pass everything; a report API key is already limited to report
/// reads; a member is held to their granted organisations and permissions.
pub async fn authorize(State(st): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let Some(admin) = req.extensions().get::<Admin>().cloned() else {
        return ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };
    if admin.id == 0 || admin.role == "owner" {
        return next.run(req).await;
    }
    match required(req.method(), req.uri().path()) {
        Need::AnyUser => next.run(req).await,
        Need::Owner => ApiError::new(StatusCode::FORBIDDEN, "forbidden").into_response(),
        Need::Org(perm) => match request_org(req.headers(), req.uri()) {
            // Named an organisation and allowed there: proceed.
            Some(org) if st.can(admin.id, org, perm) => next.run(req).await,
            Some(_) => ApiError::new(StatusCode::FORBIDDEN, "forbidden").into_response(),
            // No organisation named: let the handler answer (it returns 400).
            None => next.run(req).await,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_requirements_are_classified() {
        use Need::*;
        let get = |p| required(&Method::GET, p);
        let post = |p| required(&Method::POST, p);
        assert!(matches!(get("/api/me"), AnyUser));
        assert!(matches!(get("/api/orgs"), AnyUser));
        assert!(matches!(post("/api/orgs"), Owner));
        assert!(matches!(post("/api/users"), Owner));
        assert!(matches!(required(&Method::DELETE, "/api/orgs/3"), Owner));
        assert!(matches!(post("/api/agent-program"), Owner));
        assert!(matches!(get("/api/visits"), Org("view")));
        assert!(matches!(get("/api/machines"), Org("view")));
        assert!(matches!(post("/api/blocked-domains"), Org("blocking")));
        assert!(matches!(required(&Method::DELETE, "/api/blacklist-words/5"), Org("blocking")));
        assert!(matches!(required(&Method::PUT, "/api/settings"), Org("settings")));
        assert!(matches!(required(&Method::DELETE, "/api/activity"), Org("settings")));
        assert!(matches!(get("/api/download/agent-installer"), Org("installer")));
        assert!(matches!(post("/api/machines/PC/command"), Org("control")));
        assert!(matches!(required(&Method::DELETE, "/api/machines/PC"), Org("control")));
        assert!(matches!(required(&Method::PATCH, "/api/machines/PC"), Org("view")));
    }

    #[test]
    fn password_hashes_verify_and_are_salted() {
        let a = hash_password("correct horse").unwrap();
        let b = hash_password("correct horse").unwrap();
        assert_ne!(a, b, "each hash gets its own salt");
        assert!(a.starts_with("$argon2id$"));
        assert!(verify_password("correct horse", &a));
        assert!(!verify_password("wrong horse", &a));
        assert!(!verify_password("anything", "not-a-hash"));
    }

    #[test]
    fn cookies_and_bearer_tokens_are_parsed() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("theme=dark; ems_session=abc123; x=y"));
        assert_eq!(cookie(&h, COOKIE).as_deref(), Some("abc123"));
        assert_eq!(cookie(&h, "missing"), None);
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer ems_key"));
        assert_eq!(bearer(&h), Some("ems_key"));
        let c = session_cookie("t", 60, true);
        assert_eq!(c.to_str().unwrap(), "ems_session=t; Path=/; HttpOnly; SameSite=Strict; Max-Age=60; Secure");
    }

    #[test]
    fn a_report_key_reaches_reports_and_nothing_else() {
        for ok in ["/api/overview", "/api/visits", "/api/visits/summary", "/api/visits/report/suspicious", "/api/app-usage/titles", "/api/block-events", "/api/blacklist-words/hits", "/api/machines"] {
            assert!(is_report_path(ok), "{ok}");
        }
        for no in ["/api/orgs", "/api/settings", "/api/download/agent-installer", "/api/download/agent-setup", "/api/blacklist-words", "/api/blocked-domains", "/api/visitsx", "/api/me"] {
            assert!(!is_report_path(no), "{no}");
        }
    }

    async fn org_from(st: &std::sync::Arc<AppState>, uri: &str, header_value: Option<&str>, key_org: Option<i64>) -> Result<i64, StatusCode> {
        let mut builder = axum::http::Request::builder().uri(uri);
        if let Some(v) = header_value {
            builder = builder.header(ORG_HEADER, v);
        }
        let (mut parts, _) = builder.body(()).unwrap().into_parts();
        if let Some(id) = key_org {
            parts.extensions.insert(KeyOrg(id));
        }
        match OrgId::from_request_parts(&mut parts, st).await {
            Ok(OrgId(id)) => Ok(id),
            Err(e) => Err(e.into_response().status()),
        }
    }

    #[tokio::test]
    async fn every_request_must_name_an_organisation_that_exists() {
        let (st, dir) = crate::state::tests::state();
        let st = std::sync::Arc::new(st);
        let acme = st.create_org("Acme").await.unwrap().id;
        let globex = st.create_org("Globex").await.unwrap().id;

        assert_eq!(org_from(&st, "/api/machines", Some(&acme.to_string()), None).await, Ok(acme));
        assert_eq!(org_from(&st, &format!("/api/download/agent-installer?server=x&org={globex}"), None, None).await, Ok(globex));
        assert_eq!(org_from(&st, "/api/machines", None, None).await, Err(StatusCode::BAD_REQUEST));
        assert_eq!(org_from(&st, "/api/machines", Some("abc"), None).await, Err(StatusCode::BAD_REQUEST));
        assert_eq!(org_from(&st, "/api/machines", Some("9999"), None).await, Err(StatusCode::NOT_FOUND));
        // A report key cannot be pointed at another organisation.
        assert_eq!(org_from(&st, &format!("/api/visits?org={globex}"), Some(&globex.to_string()), Some(acme)).await, Ok(acme));
        std::fs::remove_dir_all(dir).ok();
    }
}
