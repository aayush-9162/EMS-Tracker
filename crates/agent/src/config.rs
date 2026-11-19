//! Where the server is, and how an installer finds that out by itself.

use anyhow::{bail, Context};
use ems_proto::{Policy, SetupFile, SYNC_PATH};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// What the installed agent keeps on disk. There is no per-computer secret:
/// a computer is known to the server by its name, within the organisation
/// its installer was made for.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Base address of the server, e.g. `https://ems.example.com`.
    pub server_url: String,
    /// The organisation's agent key. It tells the server whose computer this is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The organisation's name as the installer carried it, for display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// File looked for next to the executable, holding a [`SetupFile`].
pub const SETUP_FILE_NAME: &str = "ems-agent.json";
/// Address compiled into the executable, if `EMS_SERVER` was set when it was built.
const BUILT_IN_SERVER: Option<&str> = option_env!("EMS_SERVER");
const BUILT_IN_KEY: Option<&str> = option_env!("EMS_KEY");

/// Accepts what a person is likely to type (`https://host`, `host`,
/// `host:2021`, `http://10.0.0.5:2021/`) and returns the base address.
pub fn normalize_server_url(raw: &str) -> anyhow::Result<String> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("the server address is empty");
    }
    let (scheme, rest) = match s.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = match scheme.to_ascii_lowercase().as_str() {
                "https" => "https",
                "http" => "http",
                other => bail!("unsupported scheme {other:?}; use https:// or http://"),
            };
            (scheme, rest)
        }
        // A bare name is assumed to be behind TLS; a bare name:port is assumed to be a LAN server.
        None => (if s.contains(':') { "http" } else { "https" }, s),
    };
    let rest = rest.trim_end_matches('/');
    let authority = rest.split('/').next().unwrap_or("");
    let plausible = authority.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    if authority.is_empty() || !plausible || !authority.chars().any(|c| c.is_ascii_alphanumeric()) || rest.contains(char::is_whitespace) {
        bail!("{raw:?} is not a server address");
    }
    Ok(format!("{scheme}://{rest}"))
}

pub fn sync_url(server_url: &str) -> String {
    format!("{server_url}{SYNC_PATH}")
}

/// Host part of the server address, used to make sure the agent never blocks its own server.
pub fn server_host(server_url: &str) -> Option<String> {
    let rest = server_url.split_once("://").map_or(server_url, |(_, r)| r);
    let authority = rest.split('/').next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    };
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn server_port(server_url: &str) -> u16 {
    let default = if server_url.starts_with("http://") { 80 } else { 443 };
    let rest = server_url.split_once("://").map_or(server_url, |(_, r)| r);
    let authority = rest.split('/').next().unwrap_or("");
    authority.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(default)
}

/// This computer's address on the network it uses to reach the server.
/// Nothing is sent: connecting a UDP socket only asks the system which
/// local address it would use.
pub fn local_ip(server_url: &str) -> String {
    let Some(host) = server_host(server_url) else { return String::new() };
    let probe = || -> std::io::Result<String> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.connect((host.as_str(), server_port(server_url)))?;
        Ok(socket.local_addr()?.ip().to_string())
    };
    probe().unwrap_or_default()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

impl AgentConfig {
    pub fn load(path: &Path) -> anyhow::Result<AgentConfig> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(text.trim_start_matches('\u{feff}')).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        write_atomic(path, serde_json::to_string_pretty(self)?.as_bytes())
    }
}

/// Settings attached to the end of the executable by the server's "Download installer".
fn attached_setup(exe: &Path) -> Option<SetupFile> {
    let mut file = std::fs::File::open(exe).ok()?;
    let len = file.metadata().ok()?.len();
    let take = len.min(4096);
    file.seek(SeekFrom::Start(len - take)).ok()?;
    let mut tail = Vec::with_capacity(take as usize);
    file.read_to_end(&mut tail).ok()?;
    ems_proto::read_setup(&tail)
}

fn setup_beside(exe: &Path) -> Option<SetupFile> {
    let text = std::fs::read_to_string(exe.parent()?.join(SETUP_FILE_NAME)).ok()?;
    serde_json::from_str::<SetupFile>(text.trim_start_matches('\u{feff}')).ok().filter(|s| !s.server.trim().is_empty())
}

/// Works out which server to use, without asking anyone. First match wins:
///   1. `--server` given on the command line;
///   2. settings attached to this executable (the server's downloadable installer);
///   3. `ems-agent.json` in the same folder as this executable;
///   4. an address compiled in when the executable was built;
///   5. what an earlier installation on this computer used (an upgrade).
/// Returns the settings and a short description of where they came from.
pub fn discover_setup(cli_server: Option<&str>, cli_key: Option<&str>, exe: &Path, installed: Option<AgentConfig>) -> anyhow::Result<(AgentConfig, &'static str)> {
    let (setup, source) = if let Some(server) = cli_server {
        (SetupFile { server: server.to_string(), key: cli_key.map(str::to_string), org: None }, "the command line")
    } else if let Some(setup) = attached_setup(exe) {
        (setup, "this installer")
    } else if let Some(setup) = setup_beside(exe) {
        (setup, "ems-agent.json next to the installer")
    } else if let Some(server) = BUILT_IN_SERVER.filter(|s| !s.trim().is_empty()) {
        (SetupFile { server: server.to_string(), key: BUILT_IN_KEY.map(str::to_string), org: None }, "the address built into this program")
    } else if let Some(cfg) = installed {
        return Ok((cfg, "the existing installation"));
    } else {
        bail!(
            "This installer does not know which server to report to.\n\n\
             Download your organisation's installer from the EMS console, or save the {SETUP_FILE_NAME} file offered there next to this program."
        );
    };
    let key = setup.key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty());
    let org = setup.org.map(|o| o.trim().to_string()).filter(|o| !o.is_empty());
    Ok((AgentConfig { server_url: normalize_server_url(&setup.server)?, key, org }, source))
}

/// The last policy received, kept on disk so blocking and tracking settings
/// still apply after a restart with no network.
pub fn load_policy(path: &Path) -> Option<Policy> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

pub fn save_policy(path: &Path, policy: &Policy) -> anyhow::Result<()> {
    write_atomic(path, serde_json::to_string(policy)?.as_bytes())
}

#[cfg(test)]
pub fn random_tag() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("random source");
    format!("{:016x}", u64::from_le_bytes(b))
}

#[cfg(test)]
pub fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ems-{tag}-{}", random_tag()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses_are_normalised() {
        for (input, want) in [
            ("https://ems.example.com", "https://ems.example.com"),
            ("https://ems.example.com/", "https://ems.example.com"),
            ("http://192.168.1.10:2021", "http://192.168.1.10:2021"),
            ("192.168.1.10:2021", "http://192.168.1.10:2021"),
            ("ems.example.com", "https://ems.example.com"),
            ("https://example.com/ems/", "https://example.com/ems"),
            ("  HTTP://localhost:2021  ", "http://localhost:2021"),
        ] {
            assert_eq!(normalize_server_url(input).unwrap(), want, "{input}");
        }
        for bad in ["", "ftp://x", "https://", "http://a b", "wss://x"] {
            assert!(normalize_server_url(bad).is_err(), "{bad:?}");
        }
        assert_eq!(sync_url("https://ems.example.com"), "https://ems.example.com/api/agent/sync");
    }

    #[test]
    fn server_host_and_port_are_extracted() {
        assert_eq!(server_host("https://EMS.Example.com").as_deref(), Some("ems.example.com"));
        assert_eq!(server_host("http://192.168.1.10:2021").as_deref(), Some("192.168.1.10"));
        assert_eq!(server_host("http://[::1]:2021").as_deref(), Some("::1"));
        assert_eq!((server_port("https://a.com"), server_port("http://a.com"), server_port("http://a.com:2021/x")), (443, 80, 2021));
    }

    #[test]
    fn the_local_address_is_found_without_a_server() {
        // Loopback is always routable, whatever network the test machine is on.
        assert_eq!(local_ip("http://127.0.0.1:2021"), "127.0.0.1");
    }

    #[test]
    fn config_survives_a_round_trip() {
        let dir = temp_dir("cfg");
        let path = dir.join("agent.json");
        let cfg = AgentConfig { server_url: "https://x".into(), key: Some("k".into()), org: Some("Acme".into()) };
        cfg.save(&path).unwrap();
        assert_eq!(AgentConfig::load(&path).unwrap(), cfg);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_installer_finds_its_settings_in_priority_order() {
        let dir = temp_dir("setup");
        let exe = dir.join("ems-agent-setup.exe");
        std::fs::write(&exe, b"MZ fake program bytes").unwrap();
        let old = AgentConfig { server_url: "https://old.example".into(), key: None, org: None };

        // Nothing anywhere: a clear error rather than a guess.
        if BUILT_IN_SERVER.is_none() {
            let err = discover_setup(None, None, &exe, None).unwrap_err().to_string();
            assert!(err.contains(SETUP_FILE_NAME), "{err}");
            // An upgrade keeps reporting where it did before.
            assert_eq!(discover_setup(None, None, &exe, Some(old.clone())).unwrap(), (old.clone(), "the existing installation"));
        }

        // A file next to the installer beats the previous installation.
        std::fs::write(dir.join(SETUP_FILE_NAME), r#"{ "server": "ems.example.com" }"#).unwrap();
        let (cfg, source) = discover_setup(None, None, &exe, Some(old.clone())).unwrap();
        assert_eq!((cfg.server_url.as_str(), cfg.key, source), ("https://ems.example.com", None, "ems-agent.json next to the installer"));

        // Settings attached to the installer itself beat the file.
        let mut bytes = std::fs::read(&exe).unwrap();
        ems_proto::append_setup(&mut bytes, &SetupFile { server: "https://attached.example".into(), key: Some(" k9 ".into()), org: Some("Acme Traders".into()) });
        std::fs::write(&exe, bytes).unwrap();
        let (cfg, source) = discover_setup(None, None, &exe, Some(old.clone())).unwrap();
        assert_eq!((cfg.server_url.as_str(), cfg.key.as_deref(), source), ("https://attached.example", Some("k9"), "this installer"));
        assert_eq!(cfg.org.as_deref(), Some("Acme Traders"), "the installer says which organisation it was made for");

        // And the command line beats everything.
        let (cfg, source) = discover_setup(Some("10.0.0.5:2021"), None, &exe, Some(old)).unwrap();
        assert_eq!((cfg.server_url.as_str(), source), ("http://10.0.0.5:2021", "the command line"));
        std::fs::remove_dir_all(dir).ok();
    }
}
