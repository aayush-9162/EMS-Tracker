//! Hosts-file layer of site blocking.
//!
//! Blocked names are pointed at the unspecified address, so a connection to
//! them fails at once in every browser and every other program, before any
//! page content is requested. The agent owns only the lines between its two
//! markers and leaves the rest of the file byte-for-byte as it found it.

use ems_proto::{domain_covers, Policy};
use std::collections::BTreeSet;
use std::path::Path;

pub const BEGIN: &str = "# >>> EMS managed block: do not edit, changes are overwritten";
pub const END: &str = "# <<< EMS managed block";
/// Beyond this many names the hosts file starts to slow name resolution down.
const MAX_NAMES: usize = 20_000;

fn is_ip_literal(host: &str) -> bool {
    host.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
}

/// The hostnames to sinkhole for a policy. Each blocked domain contributes
/// itself and its `www.` form, plus the concrete subdomains the server has
/// seen. Anything that would cut the agent off from its own server is left out.
pub fn desired_names(policy: &Policy, server_host: Option<&str>) -> Vec<String> {
    let mut names = BTreeSet::new();
    let reaches_server = |name: &str| server_host.is_some_and(|s| domain_covers(name, s) || name == s);
    for d in &policy.blocked {
        if is_ip_literal(d) || reaches_server(d) {
            continue;
        }
        names.insert(d.clone());
        names.insert(format!("www.{d}"));
    }
    for h in &policy.extra_hosts {
        let parent_blocked = policy.blocked.iter().any(|d| domain_covers(d, h) && !reaches_server(d));
        if parent_blocked && !is_ip_literal(h) && !reaches_server(h) {
            names.insert(h.clone());
        }
    }
    names.into_iter().take(MAX_NAMES).collect()
}

/// Hosts files predate UTF-8 and may hold bytes in a legacy code page.
/// Mapping each byte to the same-numbered character and back is lossless,
/// so comments in any encoding survive a rewrite untouched.
fn decode(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), true),
        Err(_) => (bytes.iter().map(|b| *b as char).collect(), false),
    }
}

fn encode(text: &str, utf8: bool) -> Vec<u8> {
    if utf8 {
        text.as_bytes().to_vec()
    } else {
        text.chars().map(|c| c as u32 as u8).collect()
    }
}

/// Names currently inside the managed block.
pub fn current_names(text: &str) -> Vec<String> {
    let mut inside = false;
    let mut names = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line == BEGIN {
            inside = true;
        } else if line == END {
            inside = false;
        } else if inside {
            if let Some(name) = line.split_whitespace().nth(1) {
                names.insert(name.to_string());
            }
        }
    }
    names.into_iter().collect()
}

/// Returns the file content with the managed block replaced by `names`.
/// With no names the block is removed entirely.
pub fn render(existing: &str, names: &[String]) -> String {
    let eol = if existing.contains("\r\n") || existing.is_empty() { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(existing.len() + names.len() * 48);
    let mut inside = false;
    for line in existing.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed == BEGIN {
            inside = true;
        } else if trimmed == END {
            inside = false;
        } else if !inside {
            out.push_str(line);
        }
    }
    // Drop blank lines left at the end so repeated rewrites do not grow the file.
    let kept = out.trim_end_matches(['\r', '\n', ' ', '\t']).len();
    out.truncate(kept);
    if !out.is_empty() {
        out.push_str(eol);
    }
    if !names.is_empty() {
        if !out.is_empty() {
            out.push_str(eol);
        }
        out.push_str(BEGIN);
        out.push_str(eol);
        for n in names {
            out.push_str("0.0.0.0 ");
            out.push_str(n);
            out.push_str(eol);
            out.push_str(":: ");
            out.push_str(n);
            out.push_str(eol);
        }
        out.push_str(END);
        out.push_str(eol);
    }
    out
}

/// Brings the hosts file in line with `names`. Returns whether it was rewritten.
pub fn apply(path: &Path, names: &[String]) -> std::io::Result<bool> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    let (text, utf8) = decode(&bytes);
    if current_names(&text) == names {
        return Ok(false);
    }
    let next = encode(&render(&text, names), utf8);

    // Some security tools mark the file read-only; lift that just for the write.
    let was_readonly = std::fs::metadata(path).map(|m| m.permissions().readonly()).unwrap_or(false);
    if was_readonly {
        set_readonly(path, false);
    }
    let result = std::fs::write(path, next);
    if was_readonly {
        set_readonly(path, true);
    }
    result.map(|()| true)
}

fn set_readonly(path: &Path, readonly: bool) {
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(readonly);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(blocked: &[&str], extra: &[&str]) -> Policy {
        Policy { blocked: blocked.iter().map(|s| s.to_string()).collect(), extra_hosts: extra.iter().map(|s| s.to_string()).collect(), ..Policy::default() }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn each_domain_gets_its_www_form_and_known_subdomains() {
        let p = policy(&["facebook.com", "192.168.1.9"], &["m.facebook.com", "stray.example.org"]);
        assert_eq!(desired_names(&p, None), names(&["facebook.com", "m.facebook.com", "www.facebook.com"]));
    }

    #[test]
    fn the_agents_own_server_is_never_sinkholed() {
        let p = policy(&["example.com", "other.com"], &["ems.example.com", "x.other.com"]);
        let got = desired_names(&p, Some("ems.example.com"));
        assert_eq!(got, names(&["other.com", "www.other.com", "x.other.com"]));
        // Blocking the exact server host is ignored too.
        assert!(desired_names(&policy(&["ems.example.com"], &[]), Some("ems.example.com")).is_empty());
    }

    #[test]
    fn user_content_is_preserved_and_the_block_is_replaced() {
        let original = "# my hosts\r\n127.0.0.1 localhost\r\n\r\n10.0.0.5 intranet\r\n";
        let first = render(original, &names(&["a.com"]));
        assert!(first.starts_with(original.trim_end()));
        assert!(first.contains("0.0.0.0 a.com\r\n:: a.com\r\n"));
        assert_eq!(current_names(&first), names(&["a.com"]));

        let second = render(&first, &names(&["b.com", "c.com"]));
        assert!(!second.contains("a.com"));
        assert_eq!(current_names(&second), names(&["b.com", "c.com"]));
        assert_eq!(second.matches(BEGIN).count(), 1);

        // Removing every name restores the user's file exactly.
        assert_eq!(render(&second, &[]), original.trim_end().to_string() + "\r\n");
    }

    #[test]
    fn rewriting_is_stable_and_keeps_line_endings() {
        let unix = "127.0.0.1 localhost\n";
        let once = render(unix, &names(&["a.com"]));
        assert!(!once.contains('\r'));
        assert_eq!(render(&once, &names(&["a.com"])), once, "same input, same file");
        assert_eq!(render("", &names(&["a.com"])), format!("{BEGIN}\r\n0.0.0.0 a.com\r\n:: a.com\r\n{END}\r\n"));
        assert_eq!(render("", &[]), "");
    }

    #[test]
    fn legacy_encoded_bytes_round_trip() {
        // 0xE9 is "é" in Windows-1252 and invalid on its own in UTF-8.
        let bytes = b"# caf\xE9\r\n127.0.0.1 localhost\r\n".to_vec();
        let (text, utf8) = decode(&bytes);
        assert!(!utf8);
        let out = encode(&render(&text, &names(&["a.com"])), utf8);
        assert!(out.starts_with(b"# caf\xE9\r\n127.0.0.1 localhost\r\n"));
        assert_eq!(encode(&render(&decode(&out).0, &[]), false), bytes);
    }

    #[test]
    fn apply_only_writes_when_something_changed() {
        let dir = crate::config::temp_dir("hosts");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\r\n").unwrap();

        assert!(apply(&path, &names(&["a.com"])).unwrap());
        assert!(!apply(&path, &names(&["a.com"])).unwrap(), "already in place");
        assert!(apply(&path, &[]).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "127.0.0.1 localhost\r\n");
        assert!(!apply(&path, &[]).unwrap());
        std::fs::remove_dir_all(dir).ok();
    }
}
