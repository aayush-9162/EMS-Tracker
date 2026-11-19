//! Carrying out a restart or shutdown the administrator asked for.
//!
//! This runs inside the service (LocalSystem), which holds the shutdown
//! right; the right only has to be switched on in the process token first.
//! The person at the keyboard gets a short warning with a message, then
//! Windows restarts or shuts the computer down, closing programs itself.

use ems_proto::{AgentCommand, CommandKind};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Shutdown::{InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_OTHER, SHTDN_REASON_MINOR_OTHER};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The longest warning we will show; the admin cannot ask for a very long delay.
const MAX_DELAY_S: u32 = 600;

/// Switches on the shutdown right in this process. LocalSystem has it, but
/// like every privilege it starts disabled and must be enabled to be used.
fn enable_shutdown_privilege() -> anyhow::Result<()> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)?;
        let mut luid = LUID::default();
        let result = LookupPrivilegeValueW(PCWSTR::null(), windows::core::w!("SeShutdownPrivilege"), &mut luid);
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        let adjusted = result.and_then(|_| AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None));
        let _ = CloseHandle(token);
        adjusted.map_err(|e| anyhow::anyhow!("could not enable the shutdown right: {e}"))
    }
}

/// Starts the restart or shutdown. Returns once Windows has accepted it; the
/// computer goes down after the warning has counted down.
pub fn execute(cmd: &AgentCommand) -> anyhow::Result<()> {
    enable_shutdown_privilege()?;
    let reboot = matches!(cmd.kind, CommandKind::Restart);
    let delay = cmd.delay_s.min(MAX_DELAY_S);
    let default_msg = if reboot {
        "Your organization is restarting this computer. Please save your work."
    } else {
        "Your organization is shutting this computer down. Please save your work."
    };
    let message = HSTRING::from(cmd.message.as_deref().filter(|m| !m.trim().is_empty()).unwrap_or(default_msg));
    let reason = SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED;
    unsafe {
        // No machine name = this computer; force programs closed after the warning.
        InitiateSystemShutdownExW(PCWSTR::null(), PCWSTR(message.as_ptr()), delay, true, reboot, reason)
            .map_err(|e| anyhow::anyhow!("Windows refused the {} request: {e}", cmd.kind.as_str()))?;
    }
    crate::log!("{} requested by the server: in {} s", cmd.kind.as_str(), delay);
    Ok(())
}
