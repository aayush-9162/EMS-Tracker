//! Applies the blocking policy to this computer.
//!
//! Two layers do the work, and both take effect, and are undone, at once:
//!   1. hosts file (here): the blocked name stops resolving for every
//!      program as soon as the file is rewritten;
//!   2. tab closer (in the tray helper): a tab showing a blocked page is
//!      closed within a fraction of a second, which covers pages that were
//!      already open, subdomains the hosts file does not list, and
//!      connections the browser still had cached.
//!
//! A third layer is optional and off by default:
//!   3. browser policy (here): the browser itself refuses the address and
//!      every subdomain. Browsers read policy at start-up and re-read it on
//!      their own schedule (Chromium: every 15 minutes), and Windows offers
//!      no supported way to hurry a running browser on a computer that is
//!      not domain-joined. So a browser that is open keeps blocking a site
//!      for up to 15 minutes after it was unblocked or the agent was
//!      removed, which is why this layer has to be asked for.
//!
//! Blocking by IP address in the Windows firewall is deliberately not used:
//! large sites share addresses with unrelated ones behind the same CDN, so
//! an address rule for one site would break others.

pub mod browser;
pub mod hosts;

use crate::paths::{Ctx, PolicyHive};
use ems_proto::{domain_covers, Policy};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::RegKey;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct Guard {
    enforce: bool,
    hosts_path: PathBuf,
    hive: PolicyHive,
    server_host: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub summary: String,
    pub changed: bool,
    pub ok: bool,
}

impl Guard {
    pub fn new(ctx: &Ctx, server_host: Option<String>) -> Guard {
        Guard { enforce: ctx.enforce, hosts_path: ctx.hosts_path.clone(), hive: ctx.policy_hive, server_host }
    }

    fn root(&self) -> RegKey {
        RegKey::predef(match self.hive {
            PolicyHive::Machine => HKEY_LOCAL_MACHINE,
            PolicyHive::User => HKEY_CURRENT_USER,
        })
    }

    /// Idempotent: compares the desired state with what is on the machine
    /// and writes only what differs, so it is cheap to call repeatedly.
    pub fn apply(&self, policy: &Policy) -> Outcome {
        if !self.enforce {
            return Outcome { summary: "blocking is not applied on this run".into(), changed: false, ok: true };
        }
        let server = self.server_host.as_deref();
        let domains: Vec<String> = policy.blocked.iter().filter(|d| !server.is_some_and(|s| domain_covers(d, s))).cloned().collect();
        let names = hosts::desired_names(policy, server);

        let mut problems = Vec::new();
        let hosts_changed = match hosts::apply(&self.hosts_path, &names) {
            Ok(changed) => changed,
            Err(e) => {
                problems.push(format!("hosts file: {e}"));
                false
            }
        };
        let browsers = browser::apply(&self.root(), browser_domains(policy, &domains));
        problems.extend(browsers.errors);

        // Windows only reads the real hosts file; a stand-in used for a trial run needs no flush.
        if hosts_changed && self.hosts_path == crate::paths::system_hosts_file() {
            flush_dns_cache();
        }

        let summary = if problems.is_empty() {
            format!("{} site(s) blocked", domains.len())
        } else {
            format!("{} site(s) blocked, with problems: {}", domains.len(), problems.join("; "))
        };
        Outcome { summary, changed: hosts_changed || browsers.changed, ok: problems.is_empty() }
    }

    /// Removes everything the agent put in place. Used when uninstalling.
    pub fn clear(&self) -> Outcome {
        self.apply(&Policy { blocked: Vec::new(), extra_hosts: Vec::new(), ..Policy::default() })
    }
}

/// What goes into the browsers' own block lists: the blocked domains when
/// the option is on, and nothing when it is off. "Nothing" matters: it makes
/// the agent take out entries it wrote while the option was on.
fn browser_domains<'a>(policy: &Policy, domains: &'a [String]) -> &'a [String] {
    if policy.browser_policy {
        domains
    } else {
        &[]
    }
}

/// Drops cached lookups so a newly blocked name stops resolving immediately.
fn flush_dns_cache() {
    let system = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let exe = PathBuf::from(system).join("System32").join("ipconfig.exe");
    let _ = std::process::Command::new(exe)
        .arg("/flushdns")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browsers_get_a_block_list_only_when_asked() {
        let domains = vec!["youtube.com".to_string(), "facebook.com".to_string()];
        let off = Policy { blocked: domains.clone(), ..Policy::default() };
        assert!(!off.browser_policy, "off unless an administrator turns it on");
        assert!(browser_domains(&off, &domains).is_empty(), "an empty list makes the agent remove entries it wrote earlier");
        let on = Policy { browser_policy: true, ..off };
        assert_eq!(browser_domains(&on, &domains), &domains[..]);
    }

    #[test]
    fn a_run_without_enforcement_touches_nothing() {
        let dir = crate::config::temp_dir("guard");
        let hosts = dir.join("hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\r\n").unwrap();
        let ctx = Ctx { data_dir: dir.clone(), pipe_name: String::new(), enforce: false, hosts_path: hosts.clone(), policy_hive: PolicyHive::User, launch_sessions: false, update: crate::paths::UpdateMode::Off };
        let outcome = Guard::new(&ctx, None).apply(&Policy { blocked: vec!["youtube.com".into()], browser_policy: true, ..Policy::default() });
        assert!(outcome.ok && !outcome.changed);
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "127.0.0.1 localhost\r\n");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn with_the_browser_list_off_blocking_is_the_hosts_file_alone() {
        let dir = crate::config::temp_dir("guard");
        let hosts = dir.join("hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\r\n").unwrap();
        // Enforcing, with the browser list off: nothing is written to the registry, so no rights are needed.
        let ctx = Ctx { data_dir: dir.clone(), pipe_name: String::new(), enforce: true, hosts_path: hosts.clone(), policy_hive: PolicyHive::User, launch_sessions: false, update: crate::paths::UpdateMode::Off };
        let guard = Guard::new(&ctx, None);
        let blocked = guard.apply(&Policy { blocked: vec!["youtube.com".into()], ..Policy::default() });
        assert!(blocked.ok, "{}", blocked.summary);
        assert!(std::fs::read_to_string(&hosts).unwrap().contains("0.0.0.0 www.youtube.com"));

        // Unblocking, or uninstalling, puts the file back exactly as it was.
        let cleared = guard.clear();
        assert!(cleared.ok && cleared.changed);
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "127.0.0.1 localhost\r\n");
        std::fs::remove_dir_all(dir).ok();
    }
}
