//! Starts the tray helper inside each signed-in user's desktop session.
//!
//! A service runs in an isolated session and cannot see what is on screen,
//! so the part of the agent that watches the foreground window has to run
//! as the user. The Run key starts it at sign-in; this module covers the
//! cases the Run key cannot: right after installation, and when the helper
//! has exited. It only works when running as the service (LocalSystem).

use crate::core::{lock, Shared};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW};
use windows::Win32::System::Threading::{CreateProcessAsUserW, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW};

/// Do not start a helper for the same session more often than this.
const RETRY_AFTER: Duration = Duration::from_secs(120);

/// Ids of sessions with a user at the keyboard or connected remotely.
fn active_sessions() -> Vec<u32> {
    let mut out = Vec::new();
    unsafe {
        let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut info, &mut count).is_ok() && !info.is_null() {
            for s in std::slice::from_raw_parts(info, count as usize) {
                if s.State == WTSActive && s.SessionId != 0 {
                    out.push(s.SessionId);
                }
            }
            WTSFreeMemory(info as *mut _);
        }
    }
    out
}

/// Starts the tray helper (`"<this exe>" session`) in the given session.
fn launch(session_id: u32) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    launch_cmd(session_id, &format!("\"{}\" session", exe.display()))
}

/// Locks the screen of every signed-in desktop session. Called by the
/// service, which is the only thing that can start a process in another
/// session; from anywhere else it simply does nothing.
pub fn lock_active_sessions() -> anyhow::Result<()> {
    let rundll = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32\\rundll32.exe");
    let command = format!("\"{}\" user32.dll,LockWorkStation", rundll.display());
    let sessions = active_sessions();
    if sessions.is_empty() {
        anyhow::bail!("no one is signed in to lock");
    }
    let mut last_err = None;
    for id in sessions {
        if let Err(e) = launch_cmd(id, &command) {
            last_err = Some(e);
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Starts `command_line` as the user who owns `session_id`.
fn launch_cmd(session_id: u32, command_line: &str) -> anyhow::Result<()> {
    let mut cmd: Vec<u16> = command_line.encode_utf16().chain(std::iter::once(0)).collect();
    let mut desktop: Vec<u16> = "winsta0\\default".encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut token = HANDLE::default();
        WTSQueryUserToken(session_id, &mut token)?;
        let mut env: *mut std::ffi::c_void = std::ptr::null_mut();
        let have_env = CreateEnvironmentBlock(&mut env, Some(token), false).is_ok();

        let startup = STARTUPINFOW { cb: std::mem::size_of::<STARTUPINFOW>() as u32, lpDesktop: PWSTR(desktop.as_mut_ptr()), ..Default::default() };
        let mut process = PROCESS_INFORMATION::default();
        let created = CreateProcessAsUserW(
            Some(token),
            None,
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            if have_env { Some(env as *const _) } else { None },
            None,
            &startup,
            &mut process,
        );
        if have_env {
            let _ = DestroyEnvironmentBlock(env);
        }
        let _ = CloseHandle(token);
        created?;
        let _ = CloseHandle(process.hThread);
        let _ = CloseHandle(process.hProcess);
    }
    Ok(())
}

pub async fn run(shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let mut last_try: HashMap<u32, Instant> = HashMap::new();
    // Let helpers started by the Run key connect first.
    let mut wait = Duration::from_secs(8);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => return,
        }
        wait = Duration::from_secs(30);

        let sessions = tokio::task::spawn_blocking(active_sessions).await.unwrap_or_default();
        last_try.retain(|id, _| sessions.contains(id));
        for id in sessions {
            if lock(&shared.sessions).contains_key(&id) {
                continue;
            }
            if last_try.get(&id).is_some_and(|t| t.elapsed() < RETRY_AFTER) {
                continue;
            }
            last_try.insert(id, Instant::now());
            match tokio::task::spawn_blocking(move || launch(id)).await {
                Ok(Ok(())) => crate::log!("started the tray helper in session {id}"),
                Ok(Err(e)) => crate::log!("could not start the tray helper in session {id}: {e:#}"),
                Err(_) => {}
            }
        }
    }
}
