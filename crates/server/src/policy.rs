//! The policy every agent enforces, held in memory, one per organisation.
//!
//! Agents never query the database for their policy. It is loaded once and
//! reloaded when an administrator changes something; each check-in compares
//! a hash against this in-memory copy and gets the policy back only when it
//! has changed.

use crate::db::Db;
use ems_proto::{Policy, UrlMode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::RwLock;

pub const GLOBAL: &str = "*";
/// Most concrete subdomains pushed per blocked domain.
const MAX_EXTRA_PER_DOMAIN: usize = 64;

/// Administrator-tunable behaviour of one organisation, stored as one JSON document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub upload_interval_s: u32,
    pub idle_threshold_s: u32,
    pub url_mode: UrlMode,
    pub close_blocked_tabs: bool,
    pub notify_user: bool,
    pub browser_policy: bool,
    pub track_web: bool,
    pub track_apps: bool,
    /// Let computers replace their agent with the one the server holds.
    pub auto_update: bool,
    /// Activity older than this is deleted. 0 keeps everything.
    pub retention_days: u32,
    /// Minutes east of UTC used for calendar-day boundaries in reports.
    pub tz_offset_min: i32,
}

impl Default for Settings {
    fn default() -> Self {
        let p = Policy::default();
        Settings {
            upload_interval_s: p.upload_interval_s,
            idle_threshold_s: p.idle_threshold_s,
            url_mode: p.url_mode,
            close_blocked_tabs: p.close_blocked_tabs,
            notify_user: p.notify_user,
            browser_policy: p.browser_policy,
            track_web: p.track_web,
            track_apps: p.track_apps,
            auto_update: true,
            retention_days: 90,
            tz_offset_min: 0,
        }
    }
}

impl Settings {
    /// Clamps every field to a range the agents can honour.
    pub fn sanitized(mut self) -> Settings {
        self.upload_interval_s = self.upload_interval_s.clamp(15, 3600);
        self.idle_threshold_s = self.idle_threshold_s.clamp(60, 3600);
        self.retention_days = self.retention_days.min(3650);
        self.tz_offset_min = self.tz_offset_min.clamp(-720, 840);
        self
    }
}

/// One organisation's blocks, words and settings.
#[derive(Default)]
struct OrgPolicy {
    name: String,
    global: BTreeSet<String>,
    per_machine: HashMap<String, BTreeSet<String>>,
    words: Vec<String>,
    settings: Settings,
    /// Blocked domain -> known concrete subdomains of it.
    extra: HashMap<String, BTreeSet<String>>,
}

impl OrgPolicy {
    fn is_blocked_anywhere(&self, domain: &str) -> bool {
        self.global.contains(domain) || self.per_machine.values().any(|s| s.contains(domain))
    }

    /// Files `host` under every blocked ancestor domain. Returns true if anything changed.
    fn learn(&mut self, host: &str) -> bool {
        let mut changed = false;
        let mut rest = host;
        while let Some(i) = rest.find('.') {
            rest = &rest[i + 1..];
            if rest.contains('.') && self.is_blocked_anywhere(rest) {
                let set = self.extra.entry(rest.to_string()).or_default();
                if set.len() < MAX_EXTRA_PER_DOMAIN && set.insert(host.to_string()) {
                    changed = true;
                }
            }
        }
        changed
    }
}

pub struct PolicyStore {
    orgs: RwLock<HashMap<i64, OrgPolicy>>,
}

impl PolicyStore {
    pub fn new() -> PolicyStore {
        PolicyStore { orgs: RwLock::new(HashMap::new()) }
    }

    /// An organisation's settings; the defaults for one that is not known.
    pub fn settings(&self, org: i64) -> Settings {
        self.orgs.read().unwrap_or_else(|p| p.into_inner()).get(&org).map(|o| o.settings.clone()).unwrap_or_default()
    }

    /// Re-reads organisations, blocks, words and settings from the database.
    pub async fn reload(&self, db: &Db) -> anyhow::Result<()> {
        let (orgs, blocks, words) = db
            .read(|c| {
                let mut st = c.prepare("SELECT id, name, settings FROM orgs")?;
                let orgs = st
                    .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let mut st = c.prepare("SELECT org_id, domain, machine_uuid FROM blocked_domains")?;
                let blocks = st
                    .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let mut st = c.prepare("SELECT org_id, word FROM blacklist_words ORDER BY word")?;
                let words = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
                Ok((orgs, blocks, words))
            })
            .await?;

        let mut next: HashMap<i64, OrgPolicy> = orgs
            .into_iter()
            .map(|(id, name, settings)| {
                let settings = settings.and_then(|s| serde_json::from_str::<Settings>(&s).ok()).unwrap_or_default().sanitized();
                (id, OrgPolicy { name, settings, ..OrgPolicy::default() })
            })
            .collect();
        for (org, domain, machine) in blocks {
            let Some(policy) = next.get_mut(&org) else { continue };
            if machine == GLOBAL {
                policy.global.insert(domain);
            } else {
                policy.per_machine.entry(machine).or_default().insert(domain);
            }
        }
        for (org, word) in words {
            if let Some(policy) = next.get_mut(&org) {
                policy.words.push(word);
            }
        }
        {
            let known = db.known_hosts();
            let known = known.read().unwrap_or_else(|p| p.into_inner());
            for policy in next.values_mut().filter(|p| !p.global.is_empty() || !p.per_machine.is_empty()) {
                for host in known.iter() {
                    policy.learn(host);
                }
            }
        }
        *self.orgs.write().unwrap_or_else(|p| p.into_inner()) = next;
        Ok(())
    }

    /// Called with site names seen for the first time. Returns true if one
    /// of them sits under a domain some organisation blocks, which changes
    /// that organisation's policy.
    pub fn learn_hosts(&self, hosts: &[String]) -> bool {
        if hosts.is_empty() {
            return false;
        }
        let mut orgs = self.orgs.write().unwrap_or_else(|p| p.into_inner());
        let mut changed = false;
        for policy in orgs.values_mut() {
            for h in hosts {
                changed |= policy.learn(h);
            }
        }
        changed
    }

    /// The policy as it applies to one computer: its organisation's blocks
    /// for everyone, plus the computer's own.
    pub fn effective(&self, org: i64, machine_uuid: &str) -> Policy {
        let orgs = self.orgs.read().unwrap_or_else(|p| p.into_inner());
        let Some(inner) = orgs.get(&org) else { return Policy::default() };
        let mut blocked: BTreeSet<&String> = inner.global.iter().collect();
        if let Some(own) = inner.per_machine.get(machine_uuid) {
            blocked.extend(own.iter());
        }
        let covered: HashSet<&str> = blocked.iter().map(|s| s.as_str()).collect();
        let mut extra: BTreeSet<&String> = BTreeSet::new();
        for d in &blocked {
            if let Some(hosts) = inner.extra.get(d.as_str()) {
                extra.extend(hosts.iter().filter(|h| !covered.contains(h.as_str())));
            }
        }
        let s = &inner.settings;
        Policy {
            blocked: blocked.into_iter().cloned().collect(),
            extra_hosts: extra.into_iter().cloned().collect(),
            words: inner.words.clone(),
            upload_interval_s: s.upload_interval_s,
            idle_threshold_s: s.idle_threshold_s,
            url_mode: s.url_mode,
            close_blocked_tabs: s.close_blocked_tabs,
            notify_user: s.notify_user,
            browser_policy: s.browser_policy,
            track_web: s.track_web,
            track_apps: s.track_apps,
            org: inner.name.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One organisation (id 1) with the given blocks.
    fn store(global: &[&str], machine: &[(&str, &str)]) -> PolicyStore {
        let s = PolicyStore::new();
        add_org(&s, 1, "Acme", global, machine);
        s
    }

    fn add_org(s: &PolicyStore, id: i64, name: &str, global: &[&str], machine: &[(&str, &str)]) {
        let mut policy = OrgPolicy { name: name.into(), global: global.iter().map(|d| d.to_string()).collect(), ..OrgPolicy::default() };
        for (m, d) in machine {
            policy.per_machine.entry(m.to_string()).or_default().insert(d.to_string());
        }
        s.orgs.write().unwrap().insert(id, policy);
    }

    #[test]
    fn machine_gets_global_plus_its_own_blocks() {
        let s = store(&["facebook.com"], &[("pc-1", "youtube.com")]);
        assert_eq!(s.effective(1, "pc-1").blocked, ["facebook.com", "youtube.com"]);
        assert_eq!(s.effective(1, "pc-2").blocked, ["facebook.com"]);
    }

    #[test]
    fn each_organisation_has_its_own_blocks_words_and_settings() {
        let s = store(&["facebook.com"], &[("pc-1", "youtube.com")]);
        add_org(&s, 2, "Globex", &["netflix.com"], &[]);
        {
            let mut orgs = s.orgs.write().unwrap();
            orgs.get_mut(&1).unwrap().words = vec!["casino".into()];
            orgs.get_mut(&2).unwrap().settings.upload_interval_s = 60;
        }
        // The same computer name in the other organisation shares nothing.
        let acme = s.effective(1, "pc-1");
        let globex = s.effective(2, "pc-1");
        assert_eq!(acme.blocked, ["facebook.com", "youtube.com"]);
        assert_eq!(globex.blocked, ["netflix.com"]);
        assert_eq!((acme.words.len(), globex.words.len()), (1, 0));
        assert_eq!((acme.upload_interval_s, globex.upload_interval_s), (300, 60));
        assert_eq!((acme.org.as_str(), globex.org.as_str()), ("Acme", "Globex"));
        assert_eq!((s.settings(2).upload_interval_s, s.settings(99).upload_interval_s), (60, 300));
        assert!(s.effective(99, "pc-1").blocked.is_empty(), "an unknown organisation blocks nothing");

        // A subdomain seen anywhere is filed only where its parent is blocked.
        assert!(s.learn_hosts(&["m.facebook.com".into(), "www2.netflix.com".into()]));
        assert_eq!(s.effective(1, "pc-9").extra_hosts, ["m.facebook.com"]);
        assert_eq!(s.effective(2, "pc-9").extra_hosts, ["www2.netflix.com"]);
    }

    #[test]
    fn learned_subdomains_reach_only_machines_that_block_the_parent() {
        let s = store(&["facebook.com"], &[("pc-1", "youtube.com")]);
        let before = s.effective(1, "pc-1").hash();
        assert!(s.learn_hosts(&["m.facebook.com".into(), "music.youtube.com".into(), "docs.google.com".into()]));
        assert_ne!(s.effective(1, "pc-1").hash(), before, "the policy hash changes, so agents fetch it at their next check-in");
        assert_eq!(s.effective(1, "pc-1").extra_hosts, ["m.facebook.com", "music.youtube.com"]);
        assert_eq!(s.effective(1, "pc-2").extra_hosts, ["m.facebook.com"]);

        let settled = s.effective(1, "pc-1").hash();
        assert!(!s.learn_hosts(&["docs.google.com".into(), "m.facebook.com".into()]), "nothing new");
        assert_eq!(s.effective(1, "pc-1").hash(), settled);
    }

    #[test]
    fn deep_hosts_file_under_the_blocked_ancestor() {
        let s = store(&["example.co.uk"], &[]);
        s.learn_hosts(&["a.b.example.co.uk".into(), "co.uk".into(), "other.co.uk".into()]);
        assert_eq!(s.effective(1, "x").extra_hosts, ["a.b.example.co.uk"]);
    }

    #[test]
    fn settings_are_clamped_and_updates_are_on_unless_turned_off() {
        let s = Settings { upload_interval_s: 1, idle_threshold_s: 99_999, retention_days: 99_999, tz_offset_min: 5000, ..Settings::default() }.sanitized();
        assert_eq!((s.upload_interval_s, s.idle_threshold_s, s.retention_days, s.tz_offset_min), (15, 3600, 3650, 840));
        // Settings saved before the option existed keep updating.
        assert!(serde_json::from_str::<Settings>("{\"upload_interval_s\":120}").unwrap().auto_update);
        assert!(!serde_json::from_str::<Settings>("{\"auto_update\":false}").unwrap().auto_update);
    }
}
