//! Installing and removing the agent.
//!
//! The normal way in is to double-click the installer: it finds its own
//! settings, asks Windows for administrator rights, installs, starts and
//! reports the result in a message box. The same steps are available as
//! commands for deployment tools.

use crate::config::{self, AgentConfig};
use crate::guard::Guard;
use crate::paths::{self, Ctx, DISPLAY_NAME, EXE_NAME, RUN_VALUE, SERVICE_DESCRIPTION, SERVICE_NAME};
use anyhow::{bail, Context};
use std::ffi::OsString;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
use windows::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MB_SETFOREGROUND, SW_SHOWNORMAL};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
    ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
use winreg::RegKey;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;
const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
/// Makes the agent appear under "Installed apps", with a working Uninstall button.
const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\EMSAgent";

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

fn require_admin() -> anyhow::Result<()> {
    if is_admin() {
        Ok(())
    } else {
        bail!("administrator rights are needed (run from an elevated prompt, or double-click the installer)")
    }
}

pub fn message_box(text: &str, error: bool) {
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(None, PCWSTR(wide.as_ptr()), w!("EMS Agent"), MB_OK | MB_SETFOREGROUND | if error { MB_ICONERROR } else { MB_ICONINFORMATION });
    }
}

/// Starts this program again with administrator rights. Windows shows its
/// own consent prompt; the new copy carries on from there.
pub fn relaunch_elevated(arguments: &str) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let result = unsafe { ShellExecuteW(None, w!("runas"), &HSTRING::from(exe.as_os_str()), &HSTRING::from(arguments), None, SW_SHOWNORMAL) };
    // By the API's contract, values of 32 or less are errors (5 means the prompt was declined).
    if result.0 as isize <= 32 {
        bail!("administrator rights were not granted");
    }
    Ok(())
}

/// Exit code of an elevated install that worked but could not reach the server yet.
pub const EXIT_NOT_CONNECTED: i32 = 3;

/// Runs this program again with administrator rights and waits for it to
/// finish. Returns its exit code. The caller stays un-elevated, in the
/// signed-in user's own session, which is what the tray helper needs.
pub fn run_elevated(arguments: &str) -> anyhow::Result<u32> {
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    let exe = HSTRING::from(std::env::current_exe()?.as_os_str());
    let args = HSTRING::from(arguments);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(exe.as_ptr()),
        lpParameters: PCWSTR(args.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    unsafe {
        ShellExecuteExW(&mut info).map_err(|_| anyhow::anyhow!("administrator rights were not granted"))?;
        if info.hProcess.is_invalid() {
            bail!("the elevated installer could not be started");
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1u32;
        let _ = GetExitCodeProcess(info.hProcess, &mut code);
        let _ = CloseHandle(info.hProcess);
        Ok(code)
    }
}

/// Starts the tray helper for the person at the keyboard. Called from the
/// un-elevated installer, so the helper runs as that user. A helper that
/// is already running makes this a no-op: it allows one copy per session.
pub fn start_tray_helper() {
    let _ = std::process::Command::new(paths::install_dir().join(EXE_NAME)).arg("session").spawn();
}

fn system32(exe: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32").join(exe)
}

/// Ends every other process named `ems-agent.exe` (the tray helpers), so
/// the installed executable can be replaced or removed.
pub fn stop_installed_instances() {
    let me = std::process::id();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return };
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut more = Process32FirstW(snapshot, &mut entry).is_ok();
        while more {
            let len = entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            if name.eq_ignore_ascii_case(EXE_NAME) && entry.th32ProcessID != me {
                if let Ok(process) = OpenProcess(PROCESS_TERMINATE, false, entry.th32ProcessID) {
                    let _ = TerminateProcess(process, 0);
                    let _ = CloseHandle(process);
                }
            }
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
    }
}

fn stop_service(manager: &ServiceManager) -> anyhow::Result<bool> {
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP) else {
        return Ok(false);
    };
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        let deadline = Instant::now() + Duration::from_secs(20);
        while service.query_status()?.current_state != ServiceState::Stopped {
            if Instant::now() > deadline {
                bail!("the {SERVICE_NAME} service did not stop in time");
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    Ok(true)
}

/// Stops the installed service and waits for it. Used by an update, which
/// runs as the service's own account.
pub fn stop_agent_service() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    stop_service(&manager)?;
    Ok(())
}

pub fn start_agent_service() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
    if service.query_status()?.current_state == ServiceState::Stopped {
        service.start::<&str>(&[]).context("starting the service")?;
    }
    Ok(())
}

pub fn agent_service_running() -> bool {
    let state = || -> anyhow::Result<ServiceState> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        Ok(manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)?.query_status()?.current_state)
    };
    matches!(state(), Ok(ServiceState::Running | ServiceState::StartPending))
}

/// Keeps the version shown under "Installed apps" in step with the program
/// that is actually running, which an update changes without an install.
pub fn record_installed_version() {
    if let Ok(entry) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(UNINSTALL_KEY, KEY_SET_VALUE) {
        let _ = entry.set_value("DisplayVersion", &crate::version());
    }
}

/// Makes the data directory readable by SYSTEM and Administrators only.
fn lock_down(dir: &Path) {
    let _ = std::process::Command::new(system32("icacls.exe"))
        .arg(dir)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Whether this copy of the program is the installed one.
pub fn running_installed() -> bool {
    std::env::current_exe().is_ok_and(|exe| same_file(&exe, &paths::install_dir().join(EXE_NAME)))
}

/// The settings of the agent already installed on this computer, if any.
pub fn installed_config() -> Option<AgentConfig> {
    AgentConfig::load(&Ctx::installed().config_path()).ok()
}

pub struct Installed {
    pub server_url: String,
    pub hostname: String,
    /// The organisation the installer was made for, when it says.
    pub org: Option<String>,
    /// The freshly started agent reached the server within a few seconds.
    pub connected: bool,
}

impl Installed {
    pub fn summary(&self) -> String {
        let whose = self.org.as_deref().map(|o| format!(" for {o}")).unwrap_or_default();
        if self.connected {
            format!("EMS Agent is installed and working.\n\nThis computer ({}) is now reporting{whose} to\n{}", self.hostname, self.server_url)
        } else {
            format!(
                "EMS Agent is installed on {}{whose}, but the server has not answered yet:\n{}\n\n\
                 It keeps trying by itself. If the computer does not appear in the console, check the address and that the server is running.",
                self.hostname, self.server_url
            )
        }
    }
}

/// Waits briefly for the service to report a successful check-in.
fn wait_until_connected(limit: Duration) -> bool {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return false };
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        let status = rt.block_on(async { tokio::time::timeout(Duration::from_secs(2), crate::pipe::query(paths::DEFAULT_PIPE)).await });
        if matches!(status, Ok(Ok((_, s))) if s.connected) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// Installs or upgrades the agent and starts it. Needs administrator rights.
pub fn install(server: Option<&str>, key: Option<&str>) -> anyhow::Result<Installed> {
    let source = std::env::current_exe()?;
    let ctx = Ctx::installed();
    let (cfg, found_in) = config::discover_setup(server, key, &source, installed_config())?;
    require_admin()?;
    crate::log!("installing: server {} (from {found_in})", cfg.server_url);

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    // An upgrade replaces a running agent: stop it first.
    stop_service(&manager)?;
    let dir = paths::install_dir();
    let target = dir.join(EXE_NAME);
    if !same_file(&source, &target) {
        stop_installed_instances();
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut tries = 0;
        loop {
            match std::fs::copy(&source, &target) {
                Ok(_) => break,
                // The old copy can stay locked for a moment after its process ends.
                Err(_) if tries < 20 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(250));
                }
                Err(e) => return Err(e).with_context(|| format!("copying the agent to {}", target.display())),
            }
        }
    }

    std::fs::create_dir_all(&ctx.data_dir)?;
    lock_down(&ctx.data_dir);
    cfg.save(&ctx.config_path())?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: target.clone(),
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(existing) => {
            existing.change_config(&info)?;
            existing
        }
        Err(_) => manager.create_service(&info, access).context("creating the service")?,
    };
    service.set_description(SERVICE_DESCRIPTION)?;
    // Restart after a crash, as any long-running service should.
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(120) },
        ]),
    })?;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // The tray helper starts with each user's sign-in.
    let (run, _) = hklm.create_subkey(RUN_KEY)?;
    run.set_value(RUN_VALUE, &format!("\"{}\" session", target.display()))?;
    // Listed under "Installed apps" so it can be removed the usual way.
    let (entry, _) = hklm.create_subkey(UNINSTALL_KEY)?;
    entry.set_value("DisplayName", &DISPLAY_NAME)?;
    entry.set_value("DisplayVersion", &crate::version())?;
    entry.set_value("Publisher", &"EMS")?;
    entry.set_value("InstallLocation", &dir.display().to_string())?;
    entry.set_value("DisplayIcon", &target.display().to_string())?;
    entry.set_value("UninstallString", &format!("\"{}\" uninstall --gui", target.display()))?;
    entry.set_value("NoModify", &1u32)?;
    entry.set_value("NoRepair", &1u32)?;

    service.start::<&str>(&[]).context("starting the service")?;
    let connected = wait_until_connected(Duration::from_secs(12));
    Ok(Installed { server_url: cfg.server_url, hostname: crate::core::computer_name(), org: cfg.org, connected })
}

pub struct Removed {
    /// Folder to delete once this process has exited (it holds the running executable).
    pub leftover_dir: Option<PathBuf>,
    pub notes: Vec<String>,
}

/// Stops and removes the agent and lifts all blocking. Needs administrator rights.
pub fn uninstall(purge: bool) -> anyhow::Result<Removed> {
    require_admin()?;
    let ctx = Ctx::installed();
    let mut notes = Vec::new();
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    if stop_service(&manager)? {
        manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?.delete()?;
    }
    stop_installed_instances();

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(run) = hklm.open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE) {
        let _ = run.delete_value(RUN_VALUE);
    }
    let _ = hklm.delete_subkey_all(UNINSTALL_KEY);

    // Lift every block the agent put in place.
    let outcome = Guard::new(&ctx, None).clear();
    if !outcome.ok {
        notes.push(format!("site blocking could not be fully removed: {}", outcome.summary));
    }

    // Records that were never uploaded are of no use without the agent, so the data folder goes too
    // unless the caller wants to keep the queue for a reinstall.
    if purge {
        if let Err(e) = std::fs::remove_dir_all(&ctx.data_dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                notes.push(format!("could not remove {}: {e}", ctx.data_dir.display()));
            }
        }
    }

    let dir = paths::install_dir();
    let leftover_dir = if std::env::current_exe().is_ok_and(|exe| exe.starts_with(&dir)) {
        Some(dir)
    } else {
        if dir.exists() {
            std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
        }
        None
    };
    Ok(Removed { leftover_dir, notes })
}

/// A running executable cannot delete itself; a short-lived shell does it
/// once this process has exited. Call as the very last step.
pub fn remove_dir_after_exit(dir: &Path) {
    // Passed to cmd.exe exactly as written. Letting the standard library
    // quote it would escape the inner quotes in a way cmd does not
    // understand, and the folder (whose path contains a space) would stay.
    let script = format!("\"ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{}\"\"", dir.display());
    let _ = std::process::Command::new(system32("cmd.exe"))
        .raw_arg("/d /c")
        .raw_arg(script)
        .current_dir(system32(""))
        .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_install_message_says_whose_installer_it_was() {
        let done = Installed { server_url: "https://ems.example.com".into(), hostname: "PC-1".into(), org: Some("Acme Traders".into()), connected: true };
        assert!(done.summary().contains("reporting for Acme Traders to\nhttps://ems.example.com"), "{}", done.summary());
        let waiting = Installed { connected: false, ..done };
        assert!(waiting.summary().contains("installed on PC-1 for Acme Traders, but"), "{}", waiting.summary());
        let plain = Installed { server_url: "https://x".into(), hostname: "PC-1".into(), org: None, connected: true };
        assert!(plain.summary().contains("is now reporting to\n"), "{}", plain.summary());
    }

    #[test]
    fn the_install_folder_is_really_removed_after_exit() {
        // A folder with a space in its name, like "Program Files\EMS Agent", holding a file.
        let parent = crate::config::temp_dir("uninstall");
        let dir = parent.join("EMS Agent test");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("ems-agent.exe"), b"stand-in").unwrap();
        std::fs::write(dir.join("sub").join("more.txt"), b"x").unwrap();

        remove_dir_after_exit(&dir);
        assert!(dir.exists(), "removal is delayed so the running program can exit first");
        let deadline = Instant::now() + Duration::from_secs(15);
        while dir.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(!dir.exists(), "the folder must be gone a few seconds later");
        std::fs::remove_dir_all(parent).ok();
    }
}
