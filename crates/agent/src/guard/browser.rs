//! Browser-policy layer of site blocking.
//!
//! Chromium-family browsers and Firefox read a managed block list from the
//! registry (the same mechanism Group Policy uses). A browser that has it
//! refuses the navigation itself: no DNS lookup, no request, no page, and it
//! shows its own "blocked by your organization" notice. Entries cover every
//! subdomain, which the hosts file cannot do. A running browser picks up a
//! change at its next policy reload (Chromium: within 15 minutes) or restart.
//!
//! The agent writes only value names in a reserved numeric range, so block
//! lists that an administrator manages by other means are left alone.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use winreg::enums::{KEY_READ, KEY_WRITE};
use winreg::RegKey;

pub struct Target {
    pub browser: &'static str,
    pub key: &'static str,
    firefox: bool,
}

pub const TARGETS: &[Target] = &[
    Target { browser: "Chrome", key: r"SOFTWARE\Policies\Google\Chrome\URLBlocklist", firefox: false },
    Target { browser: "Edge", key: r"SOFTWARE\Policies\Microsoft\Edge\URLBlocklist", firefox: false },
    Target { browser: "Brave", key: r"SOFTWARE\Policies\BraveSoftware\Brave\URLBlocklist", firefox: false },
    Target { browser: "Chromium", key: r"SOFTWARE\Policies\Chromium\URLBlocklist", firefox: false },
    Target { browser: "Vivaldi", key: r"SOFTWARE\Policies\Vivaldi\URLBlocklist", firefox: false },
    Target { browser: "Firefox", key: r"SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block", firefox: true },
];

/// Value names the agent owns. Browsers accept at most 1000 entries per list.
const FIRST: u32 = 91_000;
const LAST: u32 = 91_999;
/// Never remove keys at or above this one, even when empty.
const KEEP_FROM: &str = r"SOFTWARE\Policies";

fn is_ip_literal(host: &str) -> bool {
    host.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
}

fn pattern(target: &Target, domain: &str) -> String {
    if !target.firefox {
        // Chromium: a bare host matches it and all of its subdomains, on any scheme.
        domain.to_string()
    } else if is_ip_literal(domain) {
        format!("*://{domain}/*")
    } else {
        // Firefox match pattern: `*.` matches the domain itself as well as subdomains.
        format!("*://*.{domain}/*")
    }
}

fn owned(name: &str) -> Option<u32> {
    name.parse::<u32>().ok().filter(|n| (FIRST..=LAST).contains(n))
}

/// Deletes `path` and then each parent, for as long as they are empty.
fn prune_empty(root: &RegKey, path: &str) {
    let mut path = path.to_string();
    while path.len() > KEEP_FROM.len() && path.to_ascii_uppercase().starts_with(&KEEP_FROM.to_ascii_uppercase()) {
        let empty = root.open_subkey_with_flags(&path, KEY_READ).and_then(|k| k.query_info()).is_ok_and(|i| i.sub_keys == 0 && i.values == 0);
        if !empty || root.delete_subkey(&path).is_err() {
            break;
        }
        match path.rfind('\\') {
            Some(i) => path.truncate(i),
            None => break,
        }
    }
}

fn apply_one(root: &RegKey, target: &Target, domains: &[String]) -> io::Result<bool> {
    let desired: BTreeSet<String> = domains.iter().take((LAST - FIRST + 1) as usize).map(|d| pattern(target, d)).collect();

    let mut ours: BTreeMap<u32, String> = BTreeMap::new();
    let existing = match root.open_subkey_with_flags(target.key, KEY_READ | KEY_WRITE) {
        Ok(key) => {
            for (name, _) in key.enum_values().flatten() {
                if let Some(n) = owned(&name) {
                    ours.insert(n, key.get_value::<String, _>(&name).unwrap_or_default());
                }
            }
            Some(key)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };

    let current: BTreeSet<&String> = ours.values().collect();
    if current.len() == ours.len() && current.iter().copied().eq(desired.iter()) {
        return Ok(false);
    }

    if desired.is_empty() {
        if let Some(key) = existing {
            for n in ours.keys() {
                key.delete_value(n.to_string())?;
            }
            drop(key);
            prune_empty(root, target.key);
        }
        return Ok(true);
    }

    let key = match existing {
        Some(key) => key,
        None => root.create_subkey_with_flags(target.key, KEY_READ | KEY_WRITE)?.0,
    };
    for n in ours.keys() {
        key.delete_value(n.to_string())?;
    }
    for (i, pat) in desired.iter().enumerate() {
        key.set_value((FIRST + i as u32).to_string(), pat)?;
    }
    Ok(true)
}

pub struct Applied {
    pub changed: bool,
    pub errors: Vec<String>,
}

/// Brings every browser's managed block list in line with `domains`.
pub fn apply(root: &RegKey, domains: &[String]) -> Applied {
    let mut out = Applied { changed: false, errors: Vec::new() };
    for target in TARGETS {
        match apply_one(root, target, domains) {
            Ok(changed) => out.changed |= changed,
            Err(e) => out.errors.push(format!("{}: {e}", target.browser)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg::enums::HKEY_CURRENT_USER;

    /// A throwaway key under HKCU standing in for the registry root.
    struct Sandbox {
        path: String,
        root: RegKey,
    }

    impl Sandbox {
        fn new() -> Sandbox {
            let path = format!(r"Software\EMS-Test\{}", crate::config::random_tag());
            let (root, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(&path).unwrap();
            Sandbox { path, root }
        }
        fn values(&self, key: &str) -> BTreeMap<String, String> {
            let Ok(k) = self.root.open_subkey(key) else { return BTreeMap::new() };
            k.enum_values().flatten().map(|(n, _)| (n.clone(), k.get_value::<String, _>(&n).unwrap())).collect()
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let _ = hkcu.delete_subkey_all(&self.path);
            // Remove the shared parent too once the last sandbox is gone.
            let _ = hkcu.delete_subkey(r"Software\EMS-Test");
        }
    }

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    const CHROME: &str = r"SOFTWARE\Policies\Google\Chrome\URLBlocklist";
    const FIREFOX: &str = r"SOFTWARE\Policies\Mozilla\Firefox\WebsiteFilter\Block";

    #[test]
    fn writes_each_browsers_own_format() {
        let sb = Sandbox::new();
        let r = apply(&sb.root, &list(&["facebook.com", "10.0.0.7"]));
        assert!(r.changed && r.errors.is_empty(), "{:?}", r.errors);
        let chrome: Vec<String> = sb.values(CHROME).into_values().collect();
        assert_eq!(chrome, ["10.0.0.7", "facebook.com"]);
        let firefox: Vec<String> = sb.values(FIREFOX).into_values().collect();
        assert_eq!(firefox, ["*://*.facebook.com/*", "*://10.0.0.7/*"]);
        assert!(sb.values(CHROME).keys().all(|n| owned(n).is_some()));
    }

    #[test]
    fn a_second_identical_apply_changes_nothing() {
        let sb = Sandbox::new();
        assert!(apply(&sb.root, &list(&["a.com", "b.com"])).changed);
        assert!(!apply(&sb.root, &list(&["b.com", "a.com"])).changed, "order must not matter");
        assert!(apply(&sb.root, &list(&["a.com"])).changed);
        assert_eq!(sb.values(CHROME).len(), 1);
    }

    #[test]
    fn entries_managed_by_someone_else_are_left_alone() {
        let sb = Sandbox::new();
        let (key, _) = sb.root.create_subkey(CHROME).unwrap();
        key.set_value("1", &"corp-blocked.example").unwrap();

        apply(&sb.root, &list(&["a.com"]));
        assert_eq!(sb.values(CHROME).get("1").map(String::as_str), Some("corp-blocked.example"));
        assert_eq!(sb.values(CHROME).len(), 2);

        // Clearing our entries keeps theirs, and keeps the key because it is not empty.
        assert!(apply(&sb.root, &[]).changed);
        assert_eq!(sb.values(CHROME).into_iter().collect::<Vec<_>>(), [("1".to_string(), "corp-blocked.example".to_string())]);
    }

    #[test]
    fn clearing_removes_the_keys_the_agent_created() {
        let sb = Sandbox::new();
        apply(&sb.root, &list(&["a.com"]));
        assert!(sb.root.open_subkey(CHROME).is_ok());
        assert!(apply(&sb.root, &[]).changed);
        assert!(sb.root.open_subkey(CHROME).is_err(), "empty list key is removed");
        assert!(sb.root.open_subkey(r"SOFTWARE\Policies\Google").is_err(), "and so are its empty parents");
        assert!(sb.root.open_subkey(r"SOFTWARE\Policies").is_ok(), "but never the Policies key itself");
        assert!(!apply(&sb.root, &[]).changed, "nothing left to do");
    }
}
