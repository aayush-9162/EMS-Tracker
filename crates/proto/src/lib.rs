//! Wire protocol between the EMS agent and the EMS server, plus the small
//! pieces of domain logic both sides must agree on (how a URL becomes a
//! host, what "blocked" means, how blacklist words are matched).
//!
//! Transport: plain HTTPS. Every so often each computer makes one request,
//! `POST /api/agent/sync`, carrying a [`SyncRequest`]. That single request
//! says "I am here", uploads whatever activity is waiting, and gets back a
//! [`SyncResponse`] that includes the policy only if it has changed.
//!
//! A computer is identified by its name, and the key its installer carries
//! says which organisation it belongs to. There is nothing to enroll.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u32 = 2;
/// Path of the one endpoint agents use.
pub const SYNC_PATH: &str = "/api/agent/sync";
/// Where an agent fetches a newer copy of itself when a check-in offers one.
pub const UPDATE_PATH: &str = "/api/agent/update";
/// Header carrying the organisation's agent key.
pub const KEY_HEADER: &str = "x-ems-key";

/// Hard caps shared by both ends so neither can be made to hold unbounded data.
pub const MAX_BATCH_ROWS: usize = 5_000;
pub const MAX_URL_LEN: usize = 2_000;
pub const MAX_TITLE_LEN: usize = 500;

// ---------------------------------------------------------------------------
// Agent -> server
// ---------------------------------------------------------------------------

/// One check-in from a computer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncRequest {
    pub v: u32,
    /// The computer's name. This is its identity on the server.
    pub hostname: String,
    /// The computer's address on its own network, for display.
    #[serde(default)]
    pub local_ip: String,
    #[serde(default)]
    pub os_version: String,
    #[serde(default)]
    pub agent_version: String,
    /// Fingerprint of the agent program that is running (see
    /// [`exe_fingerprint`]). The server compares it with the copy it holds
    /// and offers an update when they differ.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent_sha: String,
    /// Hash of the policy the agent already holds. The server only sends
    /// the policy back when this differs from the current one.
    #[serde(default)]
    pub policy_hash: String,
    /// Activity waiting to be stored, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<Batch>,
    /// A fresh snapshot of the computer (system summary and installed
    /// programs). Sent only when it differs from the last one the agent
    /// uploaded, so most check-ins carry nothing here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<Inventory>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncResponse {
    pub ok: bool,
    /// Sequence number of the batch that is now safely stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<u64>,
    /// Present only when the agent's `policy_hash` is out of date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
    /// Present when the server holds a different agent program than the one
    /// that checked in, and the organisation lets agents update themselves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<AgentUpdate>,
    /// A one-off instruction for the computer: restart or shut down. Carried
    /// on the check-in reply, acted on once, then never sent again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<AgentCommand>,
    #[serde(default)]
    pub server_ms: i64,
}

/// What the administrator asked a computer to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    Restart,
    Shutdown,
    /// Lock the screen, so the signed-in person must sign in again.
    Lock,
}

impl CommandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CommandKind::Restart => "restart",
            CommandKind::Shutdown => "shutdown",
            CommandKind::Lock => "lock",
        }
    }
    pub fn parse(s: &str) -> Option<CommandKind> {
        match s {
            "restart" => Some(CommandKind::Restart),
            "shutdown" => Some(CommandKind::Shutdown),
            "lock" => Some(CommandKind::Lock),
            _ => None,
        }
    }
}

/// A restart or shutdown the server wants a computer to carry out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCommand {
    /// The server's id for this instruction, so the same one is recognised if it arrives twice.
    pub id: i64,
    pub kind: CommandKind,
    /// Seconds to warn the person at the keyboard before it happens.
    #[serde(default)]
    pub delay_s: u32,
    /// A short note shown to that person while the warning counts down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// The agent program the server wants a computer to run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentUpdate {
    /// [`exe_fingerprint`] of the program served at [`UPDATE_PATH`].
    pub sha256: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// A slow-changing picture of one computer: what it is, how up to date
/// Windows is, and every program installed on it. Collected by the agent
/// now and then and uploaded only when it changes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub system: SystemInfo,
    #[serde(default)]
    pub apps: Vec<InstalledApp>,
    /// The last lines of the agent's own log, for viewing in the console.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log_tail: Vec<String>,
}

impl Inventory {
    /// Stable fingerprint: the agent keeps the last one it sent and uploads
    /// again only when this changes.
    pub fn fingerprint(&self) -> String {
        sha256_hex(serde_json::to_string(self).unwrap_or_default().as_bytes())
    }
}

/// A summary of the machine itself.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemInfo {
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub cpu: String,
    #[serde(default)]
    pub ram_mb: u64,
    #[serde(default)]
    pub disk_total_gb: u64,
    #[serde(default)]
    pub disk_free_gb: u64,
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub model: String,
    /// Seconds since the computer last started.
    #[serde(default)]
    pub uptime_s: u64,
    /// When this Windows build was installed, i.e. the last feature update
    /// (`YYYY-MM-DD`). Always present on a healthy machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_installed: Option<String>,
    /// When Windows last recorded finishing an update install
    /// (`YYYY-MM-DD HH:MM:SS`, UTC). Often empty on consumer Windows 11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update: Option<String>,
    /// A Windows update is installed but the computer needs a restart to finish it.
    #[serde(default)]
    pub reboot_pending: bool,
    /// This computer's address on its own network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    /// The address the server saw the check-in come from. Filled in by the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    /// The hardware address of the network adapter in use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// How the computer is connected: "Wi-Fi", "Ethernet" or similar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_type: Option<String>,
    /// Printers the computer can print to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub printers: Vec<String>,
}

/// One installed program, as it appears in "Installed apps".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InstalledApp {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    /// Install date as Windows records it (often `YYYYMMDD`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_on: Option<String>,
}

/// Settings an installer carries with it: where the server is, the key of
/// the organisation it was made for, and that organisation's name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SetupFile {
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Shown to the person installing, so they can see whose installer it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// Marks the start of a [`SetupFile`] appended to the end of the agent
/// executable. Windows ignores bytes after the end of a program, so the
/// server can hand out one ready-to-run file that already knows its server.
pub const SETUP_MARKER: &str = "\n--EMS-AGENT-SETUP--\n";

/// Appends `setup` to the bytes of an agent executable.
pub fn append_setup(exe: &mut Vec<u8>, setup: &SetupFile) {
    exe.extend_from_slice(SETUP_MARKER.as_bytes());
    exe.extend_from_slice(serde_json::to_string(setup).unwrap_or_default().as_bytes());
    exe.push(b'\n');
}

/// How far from the end of a file attached settings are looked for.
pub const SETUP_TAIL: usize = 4096;

/// Finds settings appended by [`append_setup`]: where they start in `tail`, and what they say.
fn setup_at(tail: &[u8]) -> Option<(usize, SetupFile)> {
    let marker = SETUP_MARKER.as_bytes();
    let at = tail.windows(marker.len()).rposition(|w| w == marker)?;
    let setup: SetupFile = serde_json::from_slice(&tail[at + marker.len()..]).ok()?;
    (!setup.server.trim().is_empty()).then_some((at, setup))
}

/// Reads settings appended by [`append_setup`] from the tail of a file.
pub fn read_setup(tail: &[u8]) -> Option<SetupFile> {
    setup_at(tail).map(|(_, setup)| setup)
}

/// The program itself, without any settings attached to its end. The
/// marker text also occurs inside the program, so only an attachment that
/// actually reads as settings is cut off.
pub fn exe_part(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    loop {
        let from = end.saturating_sub(SETUP_TAIL);
        match setup_at(&bytes[from..end]) {
            Some((at, _)) => end = from + at,
            None => return &bytes[..end],
        }
    }
}

/// True for bytes laid out as a Windows program: the `MZ` start and the
/// `PE` header it points to. Enough to turn away a web page, a text file or
/// a download that was cut short at the very beginning.
pub fn is_windows_program(bytes: &[u8]) -> bool {
    if bytes.len() < 1024 || !bytes.starts_with(b"MZ") {
        return false;
    }
    let at = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    at.checked_add(4).and_then(|end| bytes.get(at..end)) == Some(b"PE\0\0".as_slice())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Identifies an agent program regardless of which organisation's settings
/// are attached to it: the SHA-256 of [`exe_part`].
pub fn exe_fingerprint(bytes: &[u8]) -> String {
    sha256_hex(exe_part(bytes))
}

/// Text every agent program contains, followed by its version and a `;`.
/// It lets the server tell which version it is holding without running it.
pub const VERSION_TAG: &str = "EMS-AGENT-VERSION=";

/// Reads the version out of an agent program (see [`VERSION_TAG`]).
pub fn find_version_tag(bytes: &[u8]) -> Option<String> {
    let tag = VERSION_TAG.as_bytes();
    let mut from = 0;
    while let Some(at) = bytes[from..].windows(tag.len()).position(|w| w == tag) {
        let start = from + at + tag.len();
        let rest = &bytes[start..bytes.len().min(start + 40)];
        if let Some(len) = rest.iter().position(|b| *b == b';') {
            let version = &rest[..len];
            if !version.is_empty() && version.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+')) {
                return Some(String::from_utf8_lossy(version).into_owned());
            }
        }
        from = start;
    }
    None
}

/// True for a usable computer name: letters, digits, `-`, `_` and `.`.
pub fn valid_hostname(name: &str) -> bool {
    (1..=63).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A group of rows. `seq` is chosen by the agent and is stable across
/// retries of the same batch, which lets the server acknowledge a batch it
/// has already stored without storing it twice.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Batch {
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visits: Vec<Visit>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<AppUse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
}

impl Batch {
    pub fn len(&self) -> usize {
        self.visits.len() + self.apps.len() + self.events.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Time spent on one URL in a browser.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Visit {
    #[serde(default)]
    pub user: String,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    pub start_ms: i64,
    pub dur_s: u32,
}

/// Time spent with one application window in the foreground.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppUse {
    #[serde(default)]
    pub user: String,
    pub app: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    pub start_ms: i64,
    pub dur_s: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// The user tried to open a blocked site.
    Blocked,
    /// A blacklist word appeared in a URL.
    Word,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub user: String,
    pub kind: EventKind,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub word: Option<String>,
    pub at_ms: i64,
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlMode {
    /// Store the full URL including the query string.
    #[default]
    Full,
    /// Drop `?query` and `#fragment` before storing.
    StripQuery,
    /// Store the domain only.
    DomainOnly,
}

/// Everything an agent needs to know, already resolved for that machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Blocked domains. Each entry also covers every subdomain.
    #[serde(default)]
    pub blocked: Vec<String>,
    /// Concrete subdomain hostnames known to exist under a blocked domain.
    /// Only the hosts-file layer needs these, because it cannot wildcard.
    #[serde(default)]
    pub extra_hosts: Vec<String>,
    /// Blacklist words, lowercase.
    #[serde(default)]
    pub words: Vec<String>,
    pub upload_interval_s: u32,
    pub idle_threshold_s: u32,
    #[serde(default)]
    pub url_mode: UrlMode,
    pub close_blocked_tabs: bool,
    pub notify_user: bool,
    /// Also give browsers their own managed block list. Off unless an
    /// administrator turns it on: an open browser takes up to 15 minutes
    /// to pick up or drop a change to that list.
    #[serde(default)]
    pub browser_policy: bool,
    pub track_web: bool,
    pub track_apps: bool,
    /// Name of the organisation this computer belongs to, for display.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub org: String,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            blocked: Vec::new(),
            extra_hosts: Vec::new(),
            words: Vec::new(),
            // Five minutes: activity waits on the computer and is sent in one request.
            upload_interval_s: 300,
            idle_threshold_s: 300,
            url_mode: UrlMode::Full,
            close_blocked_tabs: true,
            // Blocked tabs are closed without a word unless an administrator asks for a notice.
            notify_user: false,
            browser_policy: false,
            track_web: true,
            track_apps: true,
            org: String::new(),
        }
    }
}

impl Policy {
    /// Stable fingerprint used to skip resending an unchanged policy.
    /// Not a security boundary, so a fast non-cryptographic hash is enough.
    pub fn hash(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in json.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{h:016x}")
    }
}

// ---------------------------------------------------------------------------
// Shared domain logic
// ---------------------------------------------------------------------------

/// Splits `scheme://rest`. Returns `None` when there is no `://` scheme.
fn split_scheme(s: &str) -> Option<(&str, &str)> {
    let idx = s.find("://")?;
    let scheme = &s[..idx];
    let mut chars = scheme.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')) {
        return None;
    }
    Some((scheme, &s[idx + 3..]))
}

fn is_web_scheme(scheme: &str) -> bool {
    scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
}

/// True for a syntactically plausible public host: either a dotted IPv4
/// address or a DNS name whose last label looks like a TLD.
///
/// Requiring a TLD-shaped last label is what keeps stray numbers such as
/// `4592.19` (a spreadsheet cell, a price) from being mistaken for a site.
pub fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.contains('.') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    for l in &labels {
        if l.is_empty() || l.len() > 63 {
            return false;
        }
        if !l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return false;
        }
        if l.starts_with('-') || l.ends_with('-') {
            return false;
        }
    }
    if labels.iter().all(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return labels.len() == 4 && labels.iter().all(|l| l.len() <= 3 && l.parse::<u16>().map_or(false, |n| n <= 255));
    }
    let last = labels[labels.len() - 1];
    last.starts_with("xn--") || (last.len() >= 2 && last.bytes().all(|b| b.is_ascii_lowercase()))
}

/// Extracts the host from a URL or from address-bar text that has no scheme
/// (`example.com/path`). Lowercased, `www.` removed, port and credentials
/// removed. Returns `None` for anything that is not an http(s) location.
pub fn host_of(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 8192 || s.contains(char::is_whitespace) {
        return None;
    }
    let rest = match split_scheme(s) {
        Some((scheme, rest)) => {
            if !is_web_scheme(scheme) {
                return None;
            }
            rest
        }
        None => s,
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let mut host = &rest[..end];
    if let Some(i) = host.rfind('@') {
        host = &host[i + 1..];
    }
    if let Some(i) = host.rfind(':') {
        if host[i + 1..].bytes().all(|b| b.is_ascii_digit()) {
            host = &host[..i];
        }
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
    valid_host(&host).then_some(host)
}

/// Normalises what an administrator typed into a "block this" box.
pub fn normalize_block_entry(raw: &str) -> Option<String> {
    host_of(raw.trim().trim_start_matches("*."))
}

/// True when `host` is `domain` itself or any subdomain of it.
pub fn domain_covers(domain: &str, host: &str) -> bool {
    if host == domain {
        return true;
    }
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// Returns the blocked entry that covers `host`, if any.
pub fn find_blocked<'a>(host: &str, blocked: &'a [String]) -> Option<&'a str> {
    blocked.iter().map(String::as_str).find(|d| domain_covers(d, host))
}

/// Prepares a URL for blacklist-word matching: lowercase, `+` as space and
/// percent-escapes decoded, so `?q=bad+word` and `?q=bad%20word` both
/// contain the phrase `bad word`.
pub fn word_match_text(url: &str) -> String {
    let lower = url.to_lowercase().replace('+', " ");
    let bytes = lower.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_lowercase()
}

/// Returns the first blacklist word contained in `text` (see [`word_match_text`]).
pub fn find_word<'a>(text: &str, words: &'a [String]) -> Option<&'a str> {
    words.iter().map(String::as_str).find(|w| !w.is_empty() && text.contains(w))
}

/// Normalises a blacklist word the way the admin API stores it.
pub fn normalize_word(raw: &str) -> Option<String> {
    let s = raw.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let n = s.chars().count();
    (2..=255).contains(&n).then_some(s)
}

/// Turns address-bar text into the URL that gets stored, honouring the
/// privacy mode. Returns `None` when nothing should be stored.
pub fn clean_url(raw: &str, mode: UrlMode) -> Option<String> {
    if mode == UrlMode::DomainOnly {
        return None;
    }
    let s = raw.trim();
    let mut url = match split_scheme(s) {
        Some((scheme, _)) if is_web_scheme(scheme) => s.to_string(),
        Some(_) => return None,
        None => format!("https://{s}"),
    };
    if mode == UrlMode::StripQuery {
        if let Some(i) = url.find(['?', '#']) {
            url.truncate(i);
        }
    }
    Some(truncate(&url, MAX_URL_LEN))
}

/// Truncates to at most `max` characters without splitting a code point.
pub fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("https://www.Example.com/a?b#c").as_deref(), Some("example.com"));
        assert_eq!(host_of("example.com/path").as_deref(), Some("example.com"));
        assert_eq!(host_of("http://user:pw@sub.example.co.uk:8080/x").as_deref(), Some("sub.example.co.uk"));
        assert_eq!(host_of("192.168.1.10:2021/admin").as_deref(), Some("192.168.1.10"));
        assert_eq!(host_of("m.facebook.com").as_deref(), Some("m.facebook.com"));
        assert_eq!(host_of("xn--bcher-kva.xn--p1ai").as_deref(), Some("xn--bcher-kva.xn--p1ai"));
    }

    #[test]
    fn rejects_things_that_are_not_sites() {
        for bad in [
            "", "4592.19", "877.00", "123", "1.2.3", "999.1.1.1", "localhost", "localhost:3000",
            "how to cook rice", "node.js tutorial", "chrome://settings", "about:blank",
            "file:///C:/x.html", "edge://newtab", "chrome-extension://abc/page.html",
            "-bad.com", "bad-.com", "a..com", "report.1",
        ] {
            assert_eq!(host_of(bad), None, "{bad:?} should not be a host");
        }
    }

    #[test]
    fn block_matching_covers_subdomains_only() {
        assert!(domain_covers("facebook.com", "facebook.com"));
        assert!(domain_covers("facebook.com", "m.facebook.com"));
        assert!(domain_covers("facebook.com", "a.b.facebook.com"));
        assert!(!domain_covers("facebook.com", "notfacebook.com"));
        assert!(!domain_covers("facebook.com", "facebook.com.evil.org"));
        assert!(!domain_covers("m.facebook.com", "facebook.com"));
        let list = vec!["youtube.com".to_string(), "x.com".to_string()];
        assert_eq!(find_blocked("music.youtube.com", &list), Some("youtube.com"));
        assert_eq!(find_blocked("netflix.com", &list), None);
        assert_eq!(find_blocked("max.com", &list), None);
    }

    #[test]
    fn block_entry_normalisation() {
        assert_eq!(normalize_block_entry(" https://WWW.YouTube.com/watch?v=1 ").as_deref(), Some("youtube.com"));
        assert_eq!(normalize_block_entry("*.tiktok.com").as_deref(), Some("tiktok.com"));
        assert_eq!(normalize_block_entry("not a domain"), None);
    }

    #[test]
    fn word_matching_decodes_search_terms() {
        let words = vec!["bad word".to_string(), "casino".to_string()];
        assert_eq!(find_word(&word_match_text("https://g.com/search?q=Bad+Word"), &words), Some("bad word"));
        assert_eq!(find_word(&word_match_text("https://g.com/search?q=bad%20word"), &words), Some("bad word"));
        assert_eq!(find_word(&word_match_text("https://best-CASINO.example/x"), &words), Some("casino"));
        assert_eq!(find_word(&word_match_text("https://g.com/search?q=good"), &words), None);
        // Malformed escapes must not panic or swallow characters.
        assert_eq!(word_match_text("a%zzb%2"), "a%zzb%2");
        assert_eq!(word_match_text("100%"), "100%");
    }

    #[test]
    fn url_cleaning_respects_privacy_mode() {
        assert_eq!(clean_url("example.com/a?t=1#x", UrlMode::Full).as_deref(), Some("https://example.com/a?t=1#x"));
        assert_eq!(clean_url("http://example.com/a?t=1#x", UrlMode::StripQuery).as_deref(), Some("http://example.com/a"));
        assert_eq!(clean_url("https://example.com/a", UrlMode::DomainOnly), None);
        assert_eq!(clean_url("chrome://settings", UrlMode::Full), None);
        assert_eq!(clean_url(&format!("https://e.com/{}", "a".repeat(5000)), UrlMode::Full).unwrap().len(), MAX_URL_LEN);
    }

    #[test]
    fn policy_hash_tracks_content() {
        let a = Policy::default();
        let mut b = Policy::default();
        assert_eq!(a.hash(), b.hash());
        b.blocked.push("x.com".into());
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn sync_messages_round_trip() {
        let batch = Batch {
            seq: 7,
            visits: vec![Visit { user: "u".into(), domain: "e.com".into(), url: None, title: None, browser: None, start_ms: 1, dur_s: 2 }],
            ..Default::default()
        };
        let req = SyncRequest { v: PROTOCOL_VERSION, hostname: "PC-01".into(), batch: Some(batch), ..Default::default() };
        let back: SyncRequest = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        let b = back.batch.unwrap();
        assert_eq!((back.hostname.as_str(), b.seq, b.visits.len(), b.apps.len()), ("PC-01", 7, 1, 0));

        // A check-in with nothing to upload stays small, and a reply with nothing to say stays small.
        let idle = serde_json::to_string(&SyncRequest { v: 2, hostname: "PC-01".into(), ..Default::default() }).unwrap();
        assert!(!idle.contains("batch"));
        let reply = serde_json::to_string(&SyncResponse { ok: true, ack: Some(9), policy: None, update: None, command: None, server_ms: 5 }).unwrap();
        assert_eq!(reply, "{\"ok\":true,\"ack\":9,\"server_ms\":5}");
    }

    #[test]
    fn setup_travels_at_the_end_of_the_executable() {
        let mut exe = vec![0x4d, 0x5a, 0x90, 0x00, 0xff, 0x00, 0x7b, 0x22];
        assert_eq!(read_setup(&exe), None, "a plain executable carries no settings");
        let setup = SetupFile { server: "https://ems.example.com".into(), key: Some("k1".into()), org: Some("Acme Traders".into()) };
        append_setup(&mut exe, &setup);
        assert_eq!(read_setup(&exe), Some(setup));
        // Only the tail is needed, and a second append wins.
        let newer = SetupFile { server: "http://10.0.0.5:2021".into(), key: None, org: None };
        append_setup(&mut exe, &newer);
        assert_eq!(read_setup(&exe[exe.len() - 80..]), Some(newer));
        assert_eq!(read_setup(SETUP_MARKER.as_bytes()), None, "a marker with nothing after it is ignored");
    }

    #[test]
    fn an_inventory_fingerprint_changes_only_with_its_contents() {
        let mut inv = Inventory {
            system: SystemInfo { os: "Windows 11".into(), ram_mb: 16384, reboot_pending: false, ..Default::default() },
            apps: vec![InstalledApp { name: "Google Chrome".into(), version: Some("120.0".into()), ..Default::default() }], log_tail: vec![],
        };
        let base = inv.fingerprint();
        assert_eq!(base.len(), 64);
        assert_eq!(base, inv.clone().fingerprint(), "the same contents give the same fingerprint");
        inv.system.reboot_pending = true;
        assert_ne!(inv.fingerprint(), base, "a changed system fact changes it");
        let mut with_app = inv.clone();
        with_app.apps.push(InstalledApp { name: "7-Zip".into(), ..Default::default() });
        assert_ne!(with_app.fingerprint(), inv.fingerprint(), "a new program changes it");
        // It survives a round trip on the wire.
        let req = SyncRequest { v: PROTOCOL_VERSION, hostname: "PC".into(), inventory: Some(inv.clone()), ..Default::default() };
        let back: SyncRequest = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back.inventory.unwrap().fingerprint(), inv.fingerprint());
    }

    #[test]
    fn a_program_has_one_fingerprint_whatever_is_attached_to_it() {
        // Like the real agent, this stand-in contains the marker text itself.
        let mut program = b"MZ program bytes ".to_vec();
        program.extend_from_slice(SETUP_MARKER.as_bytes());
        program.extend_from_slice(b" more program bytes");
        let plain = exe_fingerprint(&program);
        assert_eq!(exe_part(&program), &program[..], "nothing is attached, so nothing is cut off");
        assert_eq!(plain.len(), 64);

        let mut for_acme = program.clone();
        append_setup(&mut for_acme, &SetupFile { server: "https://ems.example.com".into(), key: Some("key-a".into()), org: Some("Acme".into()) });
        let mut for_globex = program.clone();
        append_setup(&mut for_globex, &SetupFile { server: "https://ems.example.com".into(), key: Some("key-b".into()), org: Some("Globex".into()) });
        assert_ne!(for_acme, for_globex, "each organisation gets its own installer");
        assert_eq!(exe_fingerprint(&for_acme), plain);
        assert_eq!(exe_fingerprint(&for_globex), plain);

        // Settings attached twice are both removed.
        append_setup(&mut for_acme, &SetupFile { server: "https://other.example".into(), key: None, org: None });
        assert_eq!(exe_part(&for_acme), &program[..]);

        let mut other = program.clone();
        other[3] ^= 1;
        assert_ne!(exe_fingerprint(&other), plain, "a different program has a different fingerprint");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn a_windows_program_is_told_from_other_files() {
        let mut program = vec![0u8; 2048];
        program[..2].copy_from_slice(b"MZ");
        program[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        program[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(is_windows_program(&program));

        let mut no_header = program.clone();
        no_header[0x80] = b'X';
        assert!(!is_windows_program(&no_header));
        let mut points_outside = program.clone();
        points_outside[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!is_windows_program(&points_outside), "a header address past the end must not panic");
        assert!(!is_windows_program(b"MZ"));
        assert!(!is_windows_program(&[b'<'; 4096]));
        assert!(!is_windows_program(&[]));
    }

    #[test]
    fn the_version_is_read_out_of_a_program() {
        let mut program = b"\x00junk EMS-AGENT-VERSION= not this one\x00".to_vec();
        program.extend_from_slice(format!("{VERSION_TAG}1.4.2;").as_bytes());
        program.extend_from_slice(b"\x00more");
        assert_eq!(find_version_tag(&program).as_deref(), Some("1.4.2"));
        assert_eq!(find_version_tag(b"no tag here"), None);
        assert_eq!(find_version_tag(VERSION_TAG.as_bytes()), None);
    }

    #[test]
    fn a_command_rides_on_the_reply_and_round_trips() {
        let cmd = AgentCommand { id: 42, kind: CommandKind::Restart, delay_s: 60, message: Some("Saving? You have a minute.".into()) };
        let reply = SyncResponse { ok: true, command: Some(cmd.clone()), ..Default::default() };
        let back: SyncResponse = serde_json::from_str(&serde_json::to_string(&reply).unwrap()).unwrap();
        assert_eq!(back.command, Some(cmd));
        // A reply with no command stays small.
        assert!(!serde_json::to_string(&SyncResponse { ok: true, ..Default::default() }).unwrap().contains("command"));
        assert_eq!(CommandKind::parse("shutdown"), Some(CommandKind::Shutdown));
        assert_eq!(CommandKind::parse("sleep"), None);
        assert_eq!(CommandKind::Shutdown.as_str(), "shutdown");
    }

    #[test]
    fn computer_names_are_validated() {
        for ok in ["DESKTOP-V3M7L2B", "pc_01", "front.desk", "A"] {
            assert!(valid_hostname(ok), "{ok}");
        }
        let too_long = "x".repeat(64);
        for bad in ["", "two words", "a/b", "pc;drop", too_long.as_str()] {
            assert!(!valid_hostname(bad), "{bad:?}");
        }
    }
}
