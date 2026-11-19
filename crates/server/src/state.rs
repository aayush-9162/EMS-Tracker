//! Process-wide state and configuration.

use crate::db::Db;
use crate::hub::Hub;
use crate::policy::{PolicyStore, Settings};
use crate::util::{now_s, random_hex, sha256_hex};
use anyhow::Context;
use axum::body::Bytes;
use axum::http::HeaderMap;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    /// Trust `X-Forwarded-For` / `X-Forwarded-Proto` from a reverse proxy.
    pub trust_proxy: bool,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        let bind = std::env::var("EMS_BIND").unwrap_or_else(|_| "0.0.0.0:2021".into());
        Ok(Config {
            bind: bind.parse().with_context(|| format!("EMS_BIND={bind:?} is not an address like 0.0.0.0:2021"))?,
            data_dir: std::env::var("EMS_DATA_DIR").unwrap_or_else(|_| "data".into()).into(),
            trust_proxy: matches!(std::env::var("EMS_TRUST_PROXY").as_deref(), Ok("1" | "true" | "yes")),
        })
    }
}

/// Loads `KEY=VALUE` lines from `.env` in the working directory, without
/// overriding variables that are already set.
pub fn load_dotenv() {
    let Ok(text) = std::fs::read_to_string(".env") else { return };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim(), v.trim().trim_matches('"'));
            if !k.is_empty() && std::env::var_os(k).is_none() {
                std::env::set_var(k, v);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Organisations
// ---------------------------------------------------------------------------

/// A client company. Its computers, blocks, words, categories, settings
/// and reports are its own.
#[derive(Debug, Clone, PartialEq)]
pub struct Org {
    pub id: i64,
    pub name: String,
    /// Carried by every installer made for this organisation. It is how a
    /// computer says whose it is, so it is created once and never changes.
    pub agent_key: String,
    pub api_key_hash: Option<String>,
    pub created_at: i64,
}

/// A user's role and the organisations a member may reach, with the extra
/// permissions granted in each.
#[derive(Clone)]
pub struct UserAccess {
    pub owner: bool,
    pub orgs: HashMap<i64, HashSet<String>>,
}

/// Permissions a member can be granted per organisation, beyond plain viewing.
pub const PERMISSIONS: [&str; 4] = ["blocking", "settings", "control", "installer"];

#[derive(Debug)]
pub enum UserError {
    BadName,
    NameTaken,
    WeakPassword,
    NotFound,
    NotSelf,
    LastOwner,
    OwnerFixed,
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for UserError {
    fn from(e: anyhow::Error) -> Self {
        UserError::Failed(e)
    }
}

#[derive(Default)]
struct Orgs {
    by_id: HashMap<i64, Org>,
    by_agent_key: HashMap<String, i64>,
    by_api_hash: HashMap<String, i64>,
}

impl Orgs {
    fn from(list: Vec<Org>) -> Orgs {
        let mut orgs = Orgs::default();
        for org in list {
            orgs.by_agent_key.insert(org.agent_key.clone(), org.id);
            if let Some(hash) = &org.api_key_hash {
                orgs.by_api_hash.insert(hash.clone(), org.id);
            }
            orgs.by_id.insert(org.id, org);
        }
        orgs
    }
}

#[derive(Debug)]
pub enum OrgError {
    /// The name is empty, a single character, or too long.
    BadName,
    /// Another organisation already has this name.
    NameTaken,
    NotFound,
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for OrgError {
    fn from(e: anyhow::Error) -> Self {
        OrgError::Failed(e)
    }
}

/// Tidies a name as typed: surrounding and repeated spaces removed.
/// Returns `None` for a name that cannot be used.
pub fn clean_org_name(raw: &str) -> Option<String> {
    let name = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let n = name.chars().count();
    ((2..=60).contains(&n) && !name.chars().any(char::is_control)).then_some(name)
}

/// Two names are the same organisation if they differ only in letter case.
fn name_key(name: &str) -> String {
    name.to_lowercase()
}

// ---------------------------------------------------------------------------
// The agent program the server hands out
// ---------------------------------------------------------------------------

/// Name of the Windows agent kept in the server's data directory.
pub const AGENT_FILE: &str = "ems-agent.exe";
/// A file changed this recently may still be being copied; it is looked at again on the next round.
const SETTLE: Duration = Duration::from_secs(5);

/// The agent program, read once and kept in memory. It is the base of every
/// installer, and what installed agents update themselves to.
pub struct AgentBuild {
    /// The program without any settings attached.
    pub bytes: Bytes,
    /// [`ems_proto::exe_fingerprint`] of the program.
    pub sha256: String,
    pub version: Option<String>,
}

type FileStamp = (u64, SystemTime);

// ---------------------------------------------------------------------------
// Sign-in attempts
// ---------------------------------------------------------------------------

/// Slows down password guessing: a handful of failures locks an address out for a while.
#[derive(Default)]
pub struct Limiter {
    fails: Mutex<HashMap<String, (u32, i64)>>,
}

impl Limiter {
    const MAX_FAILS: u32 = 8;
    const WINDOW_S: i64 = 900;

    pub fn blocked(&self, ip: &str) -> bool {
        let map = self.fails.lock().unwrap_or_else(|p| p.into_inner());
        map.get(ip).is_some_and(|(n, since)| *n >= Self::MAX_FAILS && now_s() - since < Self::WINDOW_S)
    }

    pub fn fail(&self, ip: &str) {
        let now = now_s();
        let mut map = self.fails.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() > 10_000 {
            map.retain(|_, (_, since)| now - *since < Self::WINDOW_S);
        }
        let e = map.entry(ip.to_string()).or_insert((0, now));
        if now - e.1 >= Self::WINDOW_S {
            *e = (0, now);
        }
        e.0 += 1;
    }

    pub fn clear(&self, ip: &str) {
        self.fails.lock().unwrap_or_else(|p| p.into_inner()).remove(ip);
    }
}

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub policy: PolicyStore,
    pub hub: Hub,
    orgs: RwLock<Orgs>,
    agent: RwLock<Option<Arc<AgentBuild>>>,
    /// Size and time of the agent file as last looked at, readable or not.
    agent_stamp: Mutex<Option<FileStamp>>,
    /// Restart/shutdown instructions waiting to be handed to each computer,
    /// keyed by machine id. The database is the lasting record; this is the
    /// fast path, so an ordinary check-in never touches the database for one.
    commands: Mutex<HashMap<i64, VecDeque<ems_proto::AgentCommand>>>,
    /// Each user's role and which organisations they may reach, kept in
    /// memory so a permission check never hits the database.
    users: RwLock<HashMap<i64, UserAccess>>,
    pub limiter: Limiter,
    pub started_s: i64,
}

impl AppState {
    pub fn new(cfg: Config, db: Db) -> AppState {
        AppState {
            cfg,
            db,
            policy: PolicyStore::new(),
            hub: Hub::default(),
            orgs: Default::default(),
            agent: Default::default(),
            agent_stamp: Default::default(),
            commands: Default::default(),
            users: Default::default(),
            limiter: Default::default(),
            started_s: now_s(),
        }
    }

    // -- organisations ------------------------------------------------------

    /// Every organisation, by name.
    pub fn orgs(&self) -> Vec<Org> {
        let mut list: Vec<Org> = self.orgs.read().unwrap_or_else(|p| p.into_inner()).by_id.values().cloned().collect();
        list.sort_by(|a, b| name_key(&a.name).cmp(&name_key(&b.name)).then(a.id.cmp(&b.id)));
        list
    }

    pub fn org(&self, id: i64) -> Option<Org> {
        self.orgs.read().unwrap_or_else(|p| p.into_inner()).by_id.get(&id).cloned()
    }

    /// The organisation an agent belongs to, going by the key it presented.
    pub fn org_by_agent_key(&self, key: &str) -> Option<i64> {
        if key.is_empty() {
            return None;
        }
        self.orgs.read().unwrap_or_else(|p| p.into_inner()).by_agent_key.get(key).copied()
    }

    /// The organisation a report API key was created for.
    pub fn org_by_api_key(&self, key: &str) -> Option<i64> {
        if key.is_empty() {
            return None;
        }
        self.orgs.read().unwrap_or_else(|p| p.into_inner()).by_api_hash.get(&sha256_hex(key)).copied()
    }

    /// Re-reads organisations, and with them every organisation's policy.
    pub async fn reload_orgs(&self) -> anyhow::Result<()> {
        let list = self
            .db
            .read(|c| {
                let mut st = c.prepare("SELECT id, name, agent_key, api_key_hash, created_at FROM orgs")?;
                let rows = st.query_map([], |r| Ok(Org { id: r.get(0)?, name: r.get(1)?, agent_key: r.get(2)?, api_key_hash: r.get(3)?, created_at: r.get(4)? }))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .await?;
        *self.orgs.write().unwrap_or_else(|p| p.into_inner()) = Orgs::from(list);
        self.reload_commands().await?;
        self.policy.reload(&self.db).await
    }

    /// Creates an organisation with a key of its own.
    pub async fn create_org(&self, name: &str) -> Result<Org, OrgError> {
        let name = clean_org_name(name).ok_or(OrgError::BadName)?;
        let (stored, key, agent_key) = (name.clone(), name_key(&name), random_hex(16));
        let id: Option<i64> = self
            .db
            .write(move |tx| {
                if tx.query_row("SELECT 1 FROM orgs WHERE name_key = ?1", [&key], |_| Ok(())).optional()?.is_some() {
                    return Ok(None);
                }
                tx.query_row(
                    "INSERT INTO orgs (name, name_key, agent_key, created_at) VALUES (?1, ?2, ?3, ?4) RETURNING id",
                    params![stored, key, agent_key, now_s()],
                    |r| r.get(0),
                )
                .map(Some)
            })
            .await?;
        let id = id.ok_or(OrgError::NameTaken)?;
        self.reload_orgs().await?;
        self.org(id).ok_or(OrgError::NotFound)
    }

    pub async fn rename_org(&self, id: i64, name: &str) -> Result<Org, OrgError> {
        let name = clean_org_name(name).ok_or(OrgError::BadName)?;
        let (stored, key) = (name.clone(), name_key(&name));
        // Some(true) renamed, Some(false) name in use elsewhere, None no such organisation.
        let outcome: Option<bool> = self
            .db
            .write(move |tx| {
                if tx.query_row("SELECT 1 FROM orgs WHERE id = ?1", [id], |_| Ok(())).optional()?.is_none() {
                    return Ok(None);
                }
                if tx.query_row("SELECT 1 FROM orgs WHERE name_key = ?1 AND id <> ?2", params![key, id], |_| Ok(())).optional()?.is_some() {
                    return Ok(Some(false));
                }
                tx.execute("UPDATE orgs SET name = ?1, name_key = ?2 WHERE id = ?3", params![stored, key, id])?;
                Ok(Some(true))
            })
            .await?;
        match outcome {
            None => Err(OrgError::NotFound),
            Some(false) => Err(OrgError::NameTaken),
            Some(true) => {
                self.reload_orgs().await?;
                self.org(id).ok_or(OrgError::NotFound)
            }
        }
    }

    /// Removes an organisation, its computers and everything recorded for
    /// them. Its agents are turned away from the first moment.
    pub async fn delete_org(&self, id: i64) -> Result<(), OrgError> {
        {
            let mut orgs = self.orgs.write().unwrap_or_else(|p| p.into_inner());
            let Some(org) = orgs.by_id.remove(&id) else { return Err(OrgError::NotFound) };
            orgs.by_agent_key.remove(&org.agent_key);
            if let Some(hash) = &org.api_key_hash {
                orgs.by_api_hash.remove(hash);
            }
        }
        self.hub.forget_org(id);
        self.commands.lock().unwrap_or_else(|p| p.into_inner()).clear();
        let result = crate::db::delete_org(&self.db, id).await;
        // Whatever happened, memory must match the database again.
        self.reload_orgs().await?;
        Ok(result?)
    }

    pub async fn save_settings(&self, org: i64, settings: &Settings) -> anyhow::Result<()> {
        let json = serde_json::to_string(settings)?;
        self.db.write(move |tx| tx.execute("UPDATE orgs SET settings = ?1 WHERE id = ?2", params![json, org])).await?;
        self.policy.reload(&self.db).await
    }

    /// Creates (or with `enable` false, revokes) an organisation's read-only report key.
    pub async fn set_api_key(&self, org: i64, enable: bool) -> anyhow::Result<Option<String>> {
        let key = enable.then(|| format!("ems_{}", random_hex(24)));
        let hash = key.as_deref().map(sha256_hex);
        self.db.write(move |tx| tx.execute("UPDATE orgs SET api_key_hash = ?1 WHERE id = ?2", params![hash, org])).await?;
        self.reload_orgs().await?;
        Ok(key)
    }

    // -- users and permissions ----------------------------------------------

    fn users(&self) -> std::sync::RwLockReadGuard<'_, HashMap<i64, UserAccess>> {
        self.users.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Reloads every user's role and organisation access into memory.
    pub async fn reload_users(&self) -> anyhow::Result<()> {
        let (roles, grants) = self
            .db
            .read(|c| {
                let mut s = c.prepare("SELECT id, role FROM admins")?;
                let roles = s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
                let mut s = c.prepare("SELECT admin_id, org_id, perms FROM user_orgs")?;
                let grants = s
                    .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok((roles, grants))
            })
            .await?;
        let mut map: HashMap<i64, UserAccess> = roles
            .into_iter()
            .map(|(id, role)| (id, UserAccess { owner: role == "owner", orgs: HashMap::new() }))
            .collect();
        for (admin_id, org_id, perms) in grants {
            if let Some(u) = map.get_mut(&admin_id) {
                let set: HashSet<String> = perms.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
                u.orgs.insert(org_id, set);
            }
        }
        *self.users.write().unwrap_or_else(|p| p.into_inner()) = map;
        Ok(())
    }

    pub fn is_owner(&self, admin_id: i64) -> bool {
        self.users().get(&admin_id).is_some_and(|u| u.owner)
    }

    /// A member's organisation→permissions map, for the console. `{}` for an
    /// owner (the console treats an owner as having everything).
    pub fn access_json(&self, admin_id: i64) -> Value {
        let users = self.users();
        let Some(u) = users.get(&admin_id).filter(|u| !u.owner) else { return json!({}) };
        let map: serde_json::Map<String, Value> = u.orgs.iter().map(|(org, perms)| (org.to_string(), json!(perms.iter().collect::<Vec<_>>()))).collect();
        Value::Object(map)
    }

    /// Whether `admin_id` may do `perm` in `org`. Owners may do anything;
    /// a member needs the organisation granted, and the permission within it
    /// (every member with the organisation granted can at least "view").
    pub fn can(&self, admin_id: i64, org: i64, perm: &str) -> bool {
        let users = self.users();
        let Some(u) = users.get(&admin_id) else { return false };
        if u.owner {
            return true;
        }
        match u.orgs.get(&org) {
            Some(perms) => perm == "view" || perms.contains(perm),
            None => false,
        }
    }

    /// The organisations a user may reach. `None` means all of them (an owner).
    pub fn accessible_orgs(&self, admin_id: i64) -> Option<HashSet<i64>> {
        let users = self.users();
        let u = users.get(&admin_id)?;
        if u.owner {
            None
        } else {
            Some(u.orgs.keys().copied().collect())
        }
    }

    /// Everyone who can sign in, for the owner's users page.
    pub async fn list_users(&self) -> anyhow::Result<Vec<Value>> {
        let rows = self
            .db
            .read(|c| {
                let mut s = c.prepare("SELECT id, username, role, created_at FROM admins ORDER BY role, username")?;
                let rows = s
                    .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await?;
        let users = self.users();
        Ok(rows
            .into_iter()
            .map(|(id, username, role, created_at)| {
                let access: Vec<Value> = users
                    .get(&id)
                    .map(|u| {
                        let mut list: Vec<(&i64, &HashSet<String>)> = u.orgs.iter().collect();
                        list.sort_by_key(|(oid, _)| **oid);
                        list.into_iter().map(|(oid, perms)| json!({ "org_id": oid, "perms": perms.iter().collect::<Vec<_>>() })).collect()
                    })
                    .unwrap_or_default();
                json!({ "id": id, "username": username, "role": role, "created_at": created_at, "access": access })
            })
            .collect())
    }

    /// Creates a user. `owner` users see everything and manage users and
    /// organisations; a member starts with no access until some is granted.
    pub async fn create_user(&self, username: &str, password: &str, owner: bool) -> Result<i64, UserError> {
        let username = username.trim().to_string();
        if !(2..=64).contains(&username.chars().count()) || username.chars().any(|c| c.is_control()) {
            return Err(UserError::BadName);
        }
        if password.chars().count() < 8 {
            return Err(UserError::WeakPassword);
        }
        let hash = crate::auth::hash_password(password).map_err(UserError::Failed)?;
        let role = if owner { "owner" } else { "member" };
        let (name, r) = (username.clone(), role.to_string());
        let id: Option<i64> = self
            .db
            .write(move |tx| {
                if tx.query_row("SELECT 1 FROM admins WHERE username = ?1", [&name], |_| Ok(())).optional()?.is_some() {
                    return Ok(None);
                }
                tx.query_row("INSERT INTO admins (username, password_hash, role, created_at) VALUES (?1, ?2, ?3, ?4) RETURNING id", params![name, hash, r, now_s()], |row| row.get(0)).map(Some)
            })
            .await?;
        let id = id.ok_or(UserError::NameTaken)?;
        self.reload_users().await?;
        Ok(id)
    }

    pub async fn delete_user(&self, id: i64, acting: i64) -> Result<(), UserError> {
        if id == acting {
            return Err(UserError::NotSelf);
        }
        let owners: i64 = self.db.read(|c| c.query_row("SELECT COUNT(*) FROM admins WHERE role = 'owner'", [], |r| r.get(0))).await?;
        let is_owner = self.is_owner(id);
        if is_owner && owners <= 1 {
            return Err(UserError::LastOwner);
        }
        let removed = self
            .db
            .write(move |tx| {
                tx.execute("DELETE FROM user_orgs WHERE admin_id = ?1", [id])?;
                tx.execute("DELETE FROM sessions WHERE admin_id = ?1", [id])?;
                tx.execute("DELETE FROM admins WHERE id = ?1", [id])
            })
            .await?;
        if removed == 0 {
            return Err(UserError::NotFound);
        }
        self.reload_users().await?;
        Ok(())
    }

    /// An owner resets another user's password; every session of that user ends.
    pub async fn set_user_password(&self, id: i64, password: &str) -> Result<(), UserError> {
        if password.chars().count() < 8 {
            return Err(UserError::WeakPassword);
        }
        let hash = crate::auth::hash_password(password).map_err(UserError::Failed)?;
        let n = self
            .db
            .write(move |tx| {
                tx.execute("DELETE FROM sessions WHERE admin_id = ?1", [id])?;
                tx.execute("UPDATE admins SET password_hash = ?1 WHERE id = ?2", params![hash, id])
            })
            .await?;
        if n == 0 {
            return Err(UserError::NotFound);
        }
        Ok(())
    }

    /// Replaces which organisations a member may reach and the permissions
    /// there. `grants` is (org_id, perms). Unknown permissions are dropped.
    pub async fn set_user_access(&self, id: i64, grants: Vec<(i64, Vec<String>)>) -> Result<(), UserError> {
        if self.is_owner(id) {
            return Err(UserError::OwnerFixed);
        }
        let known: HashSet<i64> = self.orgs().iter().map(|o| o.id).collect();
        let clean: Vec<(i64, String)> = grants
            .into_iter()
            .filter(|(org, _)| known.contains(org))
            .map(|(org, perms)| {
                let p: Vec<&str> = PERMISSIONS.into_iter().filter(|k| perms.iter().any(|g| g == k)).collect();
                (org, p.join(","))
            })
            .collect();
        let exists: bool = self.db.read(move |c| c.query_row("SELECT 1 FROM admins WHERE id = ?1", [id], |_| Ok(())).optional().map(|o| o.is_some())).await?;
        if !exists {
            return Err(UserError::NotFound);
        }
        self.db
            .write(move |tx| {
                tx.execute("DELETE FROM user_orgs WHERE admin_id = ?1", [id])?;
                for (org, perms) in &clean {
                    tx.execute("INSERT INTO user_orgs (admin_id, org_id, perms) VALUES (?1, ?2, ?3)", params![id, org, perms])?;
                }
                Ok(())
            })
            .await?;
        self.reload_users().await?;
        Ok(())
    }

    // -- restart / shutdown -------------------------------------------------

    fn commands(&self) -> std::sync::MutexGuard<'_, HashMap<i64, VecDeque<ems_proto::AgentCommand>>> {
        self.commands.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Loads the commands not yet handed over into memory. Called at startup.
    pub async fn reload_commands(&self) -> anyhow::Result<()> {
        let rows = self
            .db
            .read(|c| {
                let mut s = c.prepare("SELECT id, machine_id, kind, delay_s, message FROM commands WHERE sent_at IS NULL ORDER BY id")?;
                let rows = s
                    .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, u32>(3)?, r.get::<_, Option<String>>(4)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await?;
        let mut map: HashMap<i64, VecDeque<ems_proto::AgentCommand>> = HashMap::new();
        for (id, machine_id, kind, delay_s, message) in rows {
            if let Some(kind) = ems_proto::CommandKind::parse(&kind) {
                map.entry(machine_id).or_default().push_back(ems_proto::AgentCommand { id, kind, delay_s, message });
            }
        }
        *self.commands() = map;
        Ok(())
    }

    /// Queues a restart or shutdown for one computer. It is handed over at the
    /// computer's next check-in.
    pub async fn queue_command(&self, machine_id: i64, kind: ems_proto::CommandKind, delay_s: u32, message: Option<String>, by: &str) -> anyhow::Result<()> {
        let (k, msg, who, now) = (kind.as_str(), message.clone(), by.to_string(), now_s());
        let id: i64 = self
            .db
            .write(move |tx| {
                tx.query_row(
                    "INSERT INTO commands (machine_id, kind, delay_s, message, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING id",
                    params![machine_id, k, delay_s, msg, who, now],
                    |r| r.get(0),
                )
            })
            .await?;
        self.commands().entry(machine_id).or_default().push_back(ems_proto::AgentCommand { id, kind, delay_s, message });
        Ok(())
    }

    /// The instruction waiting for a computer, if any, taken for delivery and
    /// marked as handed over so it is never sent twice. Cheap when none waits.
    pub async fn take_command(&self, machine_id: i64) -> Option<ems_proto::AgentCommand> {
        let cmd = {
            let mut map = self.commands();
            let queue = map.get_mut(&machine_id)?;
            let cmd = queue.pop_front();
            if queue.is_empty() {
                map.remove(&machine_id);
            }
            cmd
        }?;
        // Recorded as sent even if this write fails: a restart must never be handed over twice.
        let id = cmd.id;
        let _ = self.db.write(move |tx| tx.execute("UPDATE commands SET sent_at = ?1 WHERE id = ?2", params![now_s(), id])).await;
        Some(cmd)
    }

    /// Every computer with an instruction still waiting, for the computers list.
    pub fn pending_commands(&self) -> HashMap<i64, &'static str> {
        self.commands().iter().filter_map(|(id, q)| q.front().map(|c| (*id, c.kind.as_str()))).collect()
    }

    /// Cancels the instructions queued for a computer that have not been handed
    /// over yet. Returns how many were cancelled.
    pub async fn cancel_commands(&self, machine_id: i64) -> anyhow::Result<usize> {
        let n = self.commands().remove(&machine_id).map(|q| q.len()).unwrap_or(0);
        self.db.write(move |tx| tx.execute("DELETE FROM commands WHERE machine_id = ?1 AND sent_at IS NULL", [machine_id])).await?;
        Ok(n)
    }

    /// Forgets a removed computer's queued commands (its rows are deleted elsewhere).
    pub fn forget_commands(&self, machine_id: i64) {
        self.commands().remove(&machine_id);
    }

    // -- who is online ------------------------------------------------------

    /// A computer counts as online if it checked in within two and a half
    /// of its organisation's check-in intervals, so one missed check-in
    /// does not show it offline.
    pub fn online_window_s(&self, org: i64) -> i64 {
        (i64::from(self.policy.settings(org).upload_interval_s) * 5 / 2).max(90)
    }

    pub fn online_ids(&self, org: i64) -> std::collections::HashSet<i64> {
        self.hub.online(org, now_s(), self.online_window_s(org))
    }

    pub fn online_count(&self, org: i64) -> usize {
        self.online_ids(org).len()
    }

    // -- the agent program --------------------------------------------------

    pub fn agent_build(&self) -> Option<Arc<AgentBuild>> {
        self.agent.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Reads the agent program from the data directory if the file has
    /// changed since it was last looked at. Reads the disk: call it off the
    /// async threads. `at_start` skips the wait for a file to settle.
    pub fn refresh_agent_build(&self, at_start: bool) {
        let path = self.cfg.data_dir.join(AGENT_FILE);
        let stamp: Option<FileStamp> = std::fs::metadata(&path).ok().filter(|m| m.is_file()).map(|m| (m.len(), m.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
        let mut seen = self.agent_stamp.lock().unwrap_or_else(|p| p.into_inner());
        if *seen == stamp {
            return;
        }
        let Some((len, modified)) = stamp else {
            *seen = None;
            *self.agent.write().unwrap_or_else(|p| p.into_inner()) = None;
            crate::logln!("{} is no longer in the data directory: installers and agent updates are unavailable", AGENT_FILE);
            return;
        };
        if !at_start && modified.elapsed().is_ok_and(|age| age < SETTLE) {
            return;
        }
        let Ok(file) = std::fs::read(&path) else { return };
        if file.len() as u64 != len {
            return;
        }
        *seen = stamp;
        let exe = ems_proto::exe_part(&file);
        if !ems_proto::is_windows_program(exe) {
            *self.agent.write().unwrap_or_else(|p| p.into_inner()) = None;
            crate::logln!("{} in the data directory is not a Windows program; ignoring it", AGENT_FILE);
            return;
        }
        let build = AgentBuild { sha256: ems_proto::sha256_hex(exe), version: ems_proto::find_version_tag(exe), bytes: Bytes::copy_from_slice(exe) };
        crate::logln!("agent program loaded: version {}, {} KB, fingerprint {}", build.version.as_deref().unwrap_or("unknown"), build.bytes.len() / 1024, &build.sha256[..12]);
        *self.agent.write().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(build));
    }

    /// Makes `exe` the agent program the server holds: written next to the
    /// old file and renamed into place, so a half-written file is never
    /// read, then loaded. Reads and writes the disk: call it off the async threads.
    pub fn store_agent_program(&self, exe: &[u8]) -> anyhow::Result<()> {
        let path = self.cfg.data_dir.join(AGENT_FILE);
        let tmp = self.cfg.data_dir.join(format!("{AGENT_FILE}.new"));
        std::fs::write(&tmp, exe).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
        self.refresh_agent_build(true);
        Ok(())
    }

    // -- requests -----------------------------------------------------------

    /// The caller's address, taking a trusted reverse proxy into account.
    pub fn client_ip(&self, headers: &HeaderMap, peer: SocketAddr) -> String {
        if self.cfg.trust_proxy {
            if let Some(first) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|v| v.split(',').next()) {
                let first = first.trim();
                if !first.is_empty() && first.len() <= 64 {
                    return first.to_string();
                }
            }
        }
        peer.ip().to_string()
    }

    pub fn is_https(&self, headers: &HeaderMap) -> bool {
        self.cfg.trust_proxy && headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("https"))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Bytes laid out like an agent program of the given version, for tests.
    pub fn fake_agent(version: &str, len: usize, fill: u8) -> Vec<u8> {
        let mut b = vec![fill; len.max(1024)];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let tag = format!("{}{version};", ems_proto::VERSION_TAG);
        b[0x100..0x100 + tag.len()].copy_from_slice(tag.as_bytes());
        b
    }

    /// A server state on a database of its own, in a fresh temporary folder.
    pub fn state() -> (AppState, PathBuf) {
        let dir = std::env::temp_dir().join(format!("ems-state-{}", random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = Config { bind: "127.0.0.1:0".parse().unwrap(), data_dir: dir.clone(), trust_proxy: false };
        let db = Db::open(&dir.join("ems.db")).unwrap();
        (AppState::new(cfg, db), dir)
    }

    #[tokio::test]
    async fn each_organisation_gets_a_unique_name_and_its_own_key() {
        let (st, dir) = state();
        st.reload_orgs().await.unwrap();
        assert!(st.orgs().is_empty(), "a new server has no organisation until one is created");

        let acme = st.create_org("  Acme   Traders ").await.unwrap();
        assert_eq!(acme.name, "Acme Traders");
        assert_eq!(acme.agent_key.len(), 32);
        let globex = st.create_org("Globex").await.unwrap();
        assert_ne!(acme.agent_key, globex.agent_key);
        assert_ne!(acme.id, globex.id);

        // The name must be unique, whatever the letter case or spacing.
        for taken in ["Acme Traders", "ACME TRADERS", " acme  traders "] {
            assert!(matches!(st.create_org(taken).await, Err(OrgError::NameTaken)), "{taken:?}");
        }
        for bad in ["", " ", "A", &"x".repeat(61)] {
            assert!(matches!(st.create_org(bad).await, Err(OrgError::BadName)), "{bad:?}");
        }

        // The key says which organisation a computer belongs to.
        assert_eq!(st.org_by_agent_key(&acme.agent_key), Some(acme.id));
        assert_eq!(st.org_by_agent_key(&globex.agent_key), Some(globex.id));
        assert_eq!(st.org_by_agent_key("not-a-key"), None);
        assert_eq!(st.org_by_agent_key(""), None);

        // A restart changes nothing: installed computers go on working.
        st.reload_orgs().await.unwrap();
        assert_eq!(st.org(acme.id), Some(acme.clone()));
        assert_eq!(st.orgs().iter().map(|o| o.name.as_str()).collect::<Vec<_>>(), ["Acme Traders", "Globex"]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn renaming_keeps_the_key_and_removing_turns_agents_away() {
        let (st, dir) = state();
        let acme = st.create_org("Acme").await.unwrap();
        let globex = st.create_org("Globex").await.unwrap();

        assert!(matches!(st.rename_org(acme.id, "globex").await, Err(OrgError::NameTaken)));
        assert!(matches!(st.rename_org(999, "Other").await, Err(OrgError::NotFound)));
        // Changing only the letter case of its own name is allowed.
        assert_eq!(st.rename_org(acme.id, "ACME").await.unwrap().name, "ACME");
        let renamed = st.rename_org(acme.id, "Acme Holdings").await.unwrap();
        assert_eq!(renamed.agent_key, acme.agent_key, "installed computers must not notice a rename");
        assert_eq!(st.policy.effective(acme.id, "PC").org, "Acme Holdings");
        // The old name is free again.
        let reused = st.create_org("Acme").await.unwrap();
        assert_ne!(reused.id, acme.id);

        st.delete_org(acme.id).await.unwrap();
        assert_eq!(st.org_by_agent_key(&acme.agent_key), None);
        assert_eq!(st.org_by_agent_key(&globex.agent_key), Some(globex.id));
        assert!(matches!(st.delete_org(acme.id).await, Err(OrgError::NotFound)));
        // Ids are never reused, so nothing can point at the wrong organisation later.
        let later = st.create_org("Initech").await.unwrap();
        assert!(later.id > reused.id);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn settings_and_report_keys_belong_to_one_organisation() {
        let (st, dir) = state();
        let acme = st.create_org("Acme").await.unwrap();
        let globex = st.create_org("Globex").await.unwrap();

        st.save_settings(acme.id, &Settings { upload_interval_s: 60, ..Settings::default() }).await.unwrap();
        assert_eq!((st.policy.settings(acme.id).upload_interval_s, st.policy.settings(globex.id).upload_interval_s), (60, 300));
        assert_eq!((st.online_window_s(acme.id), st.online_window_s(globex.id)), (150, 750));

        let key = st.set_api_key(acme.id, true).await.unwrap().unwrap();
        assert_eq!(st.org_by_api_key(&key), Some(acme.id));
        assert_eq!(st.org_by_api_key("ems_wrong"), None);
        st.set_api_key(acme.id, false).await.unwrap();
        assert_eq!(st.org_by_api_key(&key), None);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_agent_program_is_read_from_the_data_directory() {
        let (st, dir) = state();
        st.refresh_agent_build(true);
        assert!(st.agent_build().is_none());

        // A program with one organisation's settings attached: the settings are not part of it.
        let program = fake_agent("9.8.7", 8000, 0x90);
        let mut file = program.clone();
        ems_proto::append_setup(&mut file, &ems_proto::SetupFile { server: "https://ems.example.com".into(), key: Some("k".into()), org: None });
        std::fs::write(dir.join(AGENT_FILE), &file).unwrap();
        st.refresh_agent_build(true);
        let build = st.agent_build().expect("loaded");
        assert_eq!(&build.bytes[..], &program[..]);
        assert_eq!(build.sha256, ems_proto::sha256_hex(&program));
        assert_eq!(build.version.as_deref(), Some("9.8.7"));

        // Something that is not a program is not handed out.
        std::fs::write(dir.join(AGENT_FILE), b"<html>not found</html>").unwrap();
        st.refresh_agent_build(true);
        assert!(st.agent_build().is_none());

        // An upload replaces the file and is in use at once.
        let newer = fake_agent("9.9.0", 9000, 0x91);
        st.store_agent_program(&newer).unwrap();
        assert_eq!(st.agent_build().expect("loaded").version.as_deref(), Some("9.9.0"));
        assert_eq!(std::fs::read(dir.join(AGENT_FILE)).unwrap(), newer);
        assert!(!dir.join(format!("{AGENT_FILE}.new")).exists());
        std::fs::remove_file(dir.join(AGENT_FILE)).unwrap();
        st.refresh_agent_build(true);
        assert!(st.agent_build().is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn limiter_locks_out_after_repeated_failures() {
        let l = Limiter::default();
        for _ in 0..Limiter::MAX_FAILS - 1 {
            l.fail("1.2.3.4");
        }
        assert!(!l.blocked("1.2.3.4"));
        l.fail("1.2.3.4");
        assert!(l.blocked("1.2.3.4"));
        assert!(!l.blocked("5.6.7.8"));
        l.clear("1.2.3.4");
        assert!(!l.blocked("1.2.3.4"));
    }
}
