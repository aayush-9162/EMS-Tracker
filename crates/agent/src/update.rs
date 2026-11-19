//! Keeping the agent up to date without anyone visiting the computer.
//!
//! At each check-in the agent tells the server which program it is running.
//! When the server holds a different one, the reply says so, and the agent:
//!   1. downloads it into its own folder;
//!   2. checks that it is exactly the program the server described;
//!   3. runs it once (`version`) to see that it starts on this computer;
//!   4. starts that new copy with `apply-update`. The new copy stops the
//!      agent, swaps the files, starts the agent again, and puts the old
//!      program back if the new one does not stay up.
//!
//! An update is only taken over HTTPS (or from this same computer, which is
//! how it is tested): the program runs with full rights, so it must come
//! from the server whose certificate has been checked. A program that
//! cannot be installed is tried three times and then left alone until the
//! server offers a different one.

use crate::config;
use crate::core::Shared;
use crate::paths::UpdateMode;
use anyhow::{anyhow, bail, Context};
use ems_proto::{AgentUpdate, KEY_HEADER, UPDATE_PATH};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The downloaded program, next to the installed one.
pub const UPDATE_EXE: &str = "ems-agent-update.exe";
/// The program that was running before an update, kept until the new one has proved itself.
pub const OLD_EXE: &str = "ems-agent-old.exe";
const ATTEMPTS_FILE: &str = "update.json";

const MAX_SIZE: u64 = 64 * 1024 * 1024;
const MAX_TRIES: u32 = 3;
const RETRY_AFTER_MS: i64 = 30 * 60 * 1000;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
/// How long the freshly started agent is watched before the update counts as done.
const WATCH: Duration = Duration::from_secs(12);

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// Fingerprint of the program this process was started from, as the server computes it.
pub fn own_fingerprint() -> String {
    std::env::current_exe().and_then(std::fs::read).map(|bytes| ems_proto::exe_fingerprint(&bytes)).unwrap_or_default()
}

/// Which update was last tried, and how often, so that one that cannot be
/// installed is not downloaded again at every check-in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Attempts {
    sha256: String,
    tries: u32,
    last_ms: i64,
}

#[derive(Debug, PartialEq)]
enum Skip {
    /// The last try was a short while ago.
    TooSoon,
    /// Tried as often as allowed; wait for the server to offer something else.
    GaveUp,
}

/// Decides whether to try an offered update now. Returns which try this is.
fn may_try(previous: Option<&Attempts>, offered: &str, now_ms: i64) -> Result<u32, Skip> {
    match previous {
        Some(p) if p.sha256 == offered => {
            if p.tries >= MAX_TRIES {
                Err(Skip::GaveUp)
            } else if now_ms - p.last_ms < RETRY_AFTER_MS && now_ms >= p.last_ms {
                Err(Skip::TooSoon)
            } else {
                Ok(p.tries + 1)
            }
        }
        _ => Ok(1),
    }
}

/// An update is accepted only from a server reached over HTTPS, or from this computer itself.
fn trusted_source(server_url: &str) -> bool {
    server_url.starts_with("https://") || matches!(config::server_host(server_url).as_deref(), Some("127.0.0.1" | "localhost" | "::1"))
}

fn download(http: &ureq::Agent, shared: &Shared, to: &Path) -> anyhow::Result<u64> {
    let url = format!("{}{}", shared.cfg.server_url, UPDATE_PATH);
    let mut call = http.get(&url).config().timeout_global(Some(DOWNLOAD_TIMEOUT)).build();
    if let Some(key) = &shared.cfg.key {
        call = call.header(KEY_HEADER, key.as_str());
    }
    let mut response = call.call().map_err(|e| anyhow!("downloading the update: {e}"))?;
    let mut file = std::fs::File::create(to).with_context(|| format!("creating {}", to.display()))?;
    let copied = std::io::copy(&mut response.body_mut().as_reader().take(MAX_SIZE + 1), &mut file).context("downloading the update")?;
    file.sync_all().ok();
    Ok(copied)
}

/// The file must be the very program the server described.
fn verify(file: &Path, offer: &AgentUpdate) -> anyhow::Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    if bytes.len() as u64 != offer.size {
        bail!("the download is {} bytes, the server said {}", bytes.len(), offer.size);
    }
    if !bytes.starts_with(b"MZ") {
        bail!("the download is not a Windows program");
    }
    if !ems_proto::sha256_hex(&bytes).eq_ignore_ascii_case(&offer.sha256) {
        bail!("the download does not match the fingerprint the server gave");
    }
    Ok(())
}

/// Runs `<program> version` and expects it to answer like an agent.
fn try_run(program: &Path) -> anyhow::Result<String> {
    let mut child = Command::new(program)
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .with_context(|| format!("starting {}", program.display()))?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            bail!("the new program did not answer");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    let out = out.trim().to_string();
    if !status.success() || !out.starts_with("ems-agent ") {
        bail!("the new program does not run on this computer (it said {out:?})");
    }
    Ok(out)
}

fn load_attempts(path: &Path) -> Option<Attempts> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Downloads and checks the offered program, then hands over to it.
/// Returns true when the hand-over has started.
fn take(http: &ureq::Agent, shared: &Shared, offer: &AgentUpdate) -> anyhow::Result<bool> {
    if !trusted_source(&shared.cfg.server_url) {
        return Ok(false);
    }
    if offer.size == 0 || offer.size > MAX_SIZE || offer.sha256.len() != 64 || offer.sha256.eq_ignore_ascii_case(&shared.exe_sha) {
        return Ok(false);
    }
    let attempts_path = shared.ctx.data_dir.join(ATTEMPTS_FILE);
    let now = crate::logger::now_ms();
    let tries = match may_try(load_attempts(&attempts_path).as_ref(), &offer.sha256, now) {
        Ok(n) => n,
        Err(_) => return Ok(false),
    };
    // Written before anything else, so that an update which breaks the agent is still counted.
    let record = Attempts { sha256: offer.sha256.clone(), tries, last_ms: now };
    std::fs::write(&attempts_path, serde_json::to_string(&record)?).with_context(|| format!("writing {}", attempts_path.display()))?;
    let name = offer.version.as_deref().unwrap_or("a new version");
    crate::log!("update: the server offers {name}; downloading (try {tries} of {MAX_TRIES})");

    let exe = std::env::current_exe()?;
    let fresh = exe.with_file_name(UPDATE_EXE);
    let outcome = (|| -> anyhow::Result<()> {
        download(http, shared, &fresh)?;
        verify(&fresh, offer)?;
        let said = try_run(&fresh)?;
        crate::log!("update: {said} is downloaded and checked; restarting on it");
        start_applier(&fresh, &exe, shared)
    })();
    if let Err(e) = &outcome {
        // Whatever was downloaded is not going to be used.
        let _ = std::fs::remove_file(&fresh);
        if tries >= MAX_TRIES {
            crate::log!("update: this version will not be tried again; a different one from the server will be");
        }
        return Err(anyhow!("{e:#}"));
    }
    Ok(true)
}

fn start_applier(fresh: &Path, target: &Path, shared: &Shared) -> anyhow::Result<()> {
    let mut cmd = Command::new(fresh);
    cmd.arg("apply-update").arg("--target").arg(target).arg("--log").arg(shared.ctx.log_path());
    match shared.ctx.update {
        UpdateMode::Service => {
            cmd.arg("--service");
        }
        // A development run is not a service: the new copy waits for this
        // process to end and then starts the same command line again.
        UpdateMode::Process | UpdateMode::Off => {
            cmd.arg("--wait-pid").arg(std::process::id().to_string()).arg("--").args(std::env::args().skip(1));
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .with_context(|| format!("starting {}", fresh.display()))?;
    Ok(())
}

/// Called after a check-in whose reply offered an update.
pub async fn offered(http: &ureq::Agent, shared: &Arc<Shared>, offer: AgentUpdate) {
    if shared.ctx.update == UpdateMode::Off {
        return;
    }
    let (http, worker) = (http.clone(), shared.clone());
    match tokio::task::spawn_blocking(move || take(&http, &worker, &offer)).await {
        Ok(Ok(true)) => {
            if shared.ctx.update == UpdateMode::Process {
                shared.quit.notify_one();
            }
        }
        Ok(Ok(false)) => {}
        Ok(Err(e)) => crate::log!("update: not installed: {e:#}"),
        Err(_) => {}
    }
}

/// Removes what an update leaves behind. Called once the agent has been
/// running for a while, when no update can still be in progress.
pub fn tidy(shared: &Shared) {
    let Ok(exe) = std::env::current_exe() else { return };
    for name in [UPDATE_EXE, OLD_EXE] {
        let path = exe.with_file_name(name);
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }
    // The update that was being tried is the one now running: nothing left to remember.
    let attempts = shared.ctx.data_dir.join(ATTEMPTS_FILE);
    if load_attempts(&attempts).is_some_and(|a| a.sha256.eq_ignore_ascii_case(&shared.exe_sha)) {
        let _ = std::fs::remove_file(attempts);
    }
}

// ---------------------------------------------------------------------------
// The hand-over, run from the downloaded copy (`apply-update`)
// ---------------------------------------------------------------------------

/// A file can stay locked for a moment after the process using it has ended.
fn retrying<T>(mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let mut tries = 0;
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(_) if tries < 40 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Puts `new` in the place of `target`, keeping what was there as `old`.
/// If the new program cannot be put in place, the old one stays where it was.
fn swap(new: &Path, target: &Path, old: &Path) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(old);
    retrying(|| std::fs::rename(target, old)).with_context(|| format!("moving {} aside", target.display()))?;
    if let Err(e) = retrying(|| std::fs::copy(new, target)) {
        let _ = std::fs::remove_file(target);
        std::fs::rename(old, target).with_context(|| format!("putting {} back", target.display()))?;
        return Err(e).with_context(|| format!("copying the new program to {}", target.display()));
    }
    Ok(())
}

/// Undoes [`swap`].
fn restore(target: &Path, old: &Path) -> anyhow::Result<()> {
    let _ = retrying(|| std::fs::remove_file(target));
    retrying(|| std::fs::rename(old, target)).with_context(|| format!("putting {} back", target.display()))?;
    Ok(())
}

fn wait_for_exit(pid: u32, limit: Duration) -> anyhow::Result<()> {
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};
    unsafe {
        // Not there any more: nothing to wait for.
        let Ok(process) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) else { return Ok(()) };
        let waited = WaitForSingleObject(process, limit.as_millis() as u32);
        let _ = CloseHandle(process);
        if waited != WAIT_OBJECT_0 {
            bail!("the running agent (process {pid}) did not stop");
        }
    }
    Ok(())
}

/// Whether the installed service is answering on its local pipe.
fn agent_answers() -> bool {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return false };
    rt.block_on(async { tokio::time::timeout(Duration::from_secs(2), crate::pipe::query(crate::paths::DEFAULT_PIPE)).await }).is_ok_and(|r| r.is_ok())
}

fn apply_to_service(new: &Path, target: &Path, old: &Path) -> anyhow::Result<()> {
    use crate::install;
    install::stop_agent_service()?;
    install::stop_installed_instances();
    if let Err(e) = swap(new, target, old) {
        let _ = install::start_agent_service();
        return Err(e);
    }

    // The new agent must start, stay up, and answer.
    let started = install::start_agent_service();
    let deadline = Instant::now() + WATCH;
    let mut healthy = started.is_ok();
    let mut answered = false;
    while healthy && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        healthy = install::agent_service_running();
        answered = answered || agent_answers();
    }
    if healthy && answered {
        let _ = std::fs::remove_file(old);
        return Ok(());
    }

    crate::log!("update: the new agent did not stay running; putting the previous one back");
    let _ = install::stop_agent_service();
    install::stop_installed_instances();
    restore(target, old)?;
    install::start_agent_service().context("starting the previous agent again")?;
    bail!("the new agent did not stay running, so the previous one was put back")
}

fn apply_to_process(new: &Path, target: &Path, old: &Path, pid: u32, restart_with: &[String]) -> anyhow::Result<()> {
    wait_for_exit(pid, Duration::from_secs(30))?;
    swap(new, target, old)?;
    Command::new(target)
        .args(restart_with)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .with_context(|| format!("starting {}", target.display()))?;
    let _ = std::fs::remove_file(old);
    Ok(())
}

/// `ems-agent-update.exe apply-update --target <installed exe> --log <file> (--service | --wait-pid <n> -- <args>)`
pub fn apply(args: &[String]) -> anyhow::Result<()> {
    let opt = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let target = PathBuf::from(opt("--target").context("--target is required")?);
    if let Some(log) = opt("--log") {
        crate::logger::init(Path::new(&log), false);
    }
    let new = std::env::current_exe()?;
    let old = target.with_file_name(OLD_EXE);
    let result = if args.iter().any(|a| a == "--service") {
        apply_to_service(&new, &target, &old)
    } else {
        let pid: u32 = opt("--wait-pid").and_then(|p| p.parse().ok()).context("--wait-pid is required")?;
        let rest = args.iter().position(|a| a == "--").map(|i| &args[i + 1..]).unwrap_or(&[]);
        apply_to_process(&new, &target, &old, pid, rest)
    };
    match &result {
        Ok(()) => crate::log!("update: now running agent {}", crate::version()),
        Err(e) => crate::log!("update: failed: {e:#}"),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_update_that_fails_is_retried_a_few_times_and_then_left_alone() {
        let hour = 3_600_000;
        assert_eq!(may_try(None, "aaa", 0), Ok(1));
        let first = Attempts { sha256: "aaa".into(), tries: 1, last_ms: 10 * hour };
        assert_eq!(may_try(Some(&first), "aaa", 10 * hour + 60_000), Err(Skip::TooSoon), "not at every check-in");
        assert_eq!(may_try(Some(&first), "aaa", 11 * hour), Ok(2));
        let last = Attempts { tries: MAX_TRIES, ..first.clone() };
        assert_eq!(may_try(Some(&last), "aaa", 100 * hour), Err(Skip::GaveUp));
        // A different program from the server starts afresh, at once.
        assert_eq!(may_try(Some(&last), "bbb", 10 * hour + 1), Ok(1));
        // A clock set back must not stall updates for ever.
        assert_eq!(may_try(Some(&first), "aaa", 0), Ok(2));
    }

    #[test]
    fn updates_are_only_taken_over_https_or_from_this_computer() {
        for ok in ["https://ems.example.com", "http://127.0.0.1:2021", "http://localhost:2021", "http://[::1]:2021"] {
            assert!(trusted_source(ok), "{ok}");
        }
        for no in ["http://ems.example.com", "http://192.168.1.10:2021", "http://localhost.evil.example"] {
            assert!(!trusted_source(no), "{no}");
        }
    }

    #[test]
    fn a_download_must_be_exactly_what_the_server_described() {
        let dir = config::temp_dir("update");
        let file = dir.join(UPDATE_EXE);
        let program = b"MZ this stands in for a program".to_vec();
        std::fs::write(&file, &program).unwrap();
        let offer = AgentUpdate { sha256: ems_proto::sha256_hex(&program), size: program.len() as u64, version: None };
        verify(&file, &offer).unwrap();
        verify(&file, &AgentUpdate { sha256: offer.sha256.to_uppercase(), ..offer.clone() }).unwrap();

        assert!(verify(&file, &AgentUpdate { size: offer.size + 1, ..offer.clone() }).is_err(), "wrong size");
        assert!(verify(&file, &AgentUpdate { sha256: "0".repeat(64), ..offer.clone() }).is_err(), "wrong fingerprint");
        // One changed byte, same length.
        let mut tampered = program.clone();
        tampered[10] ^= 1;
        std::fs::write(&file, &tampered).unwrap();
        assert!(verify(&file, &offer).is_err(), "tampered");
        // Right fingerprint, but not a program at all.
        let page = b"<html>error</html>".to_vec();
        std::fs::write(&file, &page).unwrap();
        assert!(verify(&file, &AgentUpdate { sha256: ems_proto::sha256_hex(&page), size: page.len() as u64, version: None }).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn swapping_keeps_the_old_program_until_told_and_can_be_undone() {
        let dir = config::temp_dir("swap");
        let (new, target, old) = (dir.join(UPDATE_EXE), dir.join("ems-agent.exe"), dir.join(OLD_EXE));
        std::fs::write(&target, b"version one").unwrap();
        std::fs::write(&new, b"version two").unwrap();
        std::fs::write(&old, b"left over from an earlier update").unwrap();

        swap(&new, &target, &old).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"version two");
        assert_eq!(std::fs::read(&old).unwrap(), b"version one");

        // The new one did not stay up: the previous program is back, exactly.
        restore(&target, &old).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"version one");
        assert!(!old.exists());

        // The new program cannot be read: the installed one must still be there afterwards.
        std::fs::remove_file(&new).unwrap();
        assert!(swap(&new, &target, &old).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"version one");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_running_program_reports_its_own_fingerprint_and_version() {
        let sha = own_fingerprint();
        assert_eq!(sha.len(), 64);
        // The server reads the version out of the program file; it must be findable there.
        assert_eq!(ems_proto::find_version_tag(crate::VERSION_TAG.as_bytes()).as_deref(), Some(env!("CARGO_PKG_VERSION")));
        assert_eq!(crate::version(), env!("CARGO_PKG_VERSION"));
        // A program that is not an agent is turned down before anything is swapped.
        let cmd = PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32").join("where.exe");
        assert!(try_run(&cmd).is_err());
    }
}
