//! The notification-area icon and the window behind it.
//!
//! The icon is shown while the agent is running; clicking it opens a small
//! neutral status window (connection and version). It does not announce
//! monitoring or blocking: notice to staff is given by the organisation
//! that deploys it, not by this program. This thread also hosts the system
//! event hooks that tell the tracker the moment the foreground window or
//! its title changes.

use super::{State, Wake};
use crate::ipc::ToCore;
use std::cell::RefCell;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::Graphics::Gdi::{CreateBitmap, DeleteObject};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::RemoteDesktop::{WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION};
use windows::Win32::UI::Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK};
use windows::Win32::UI::Shell::{Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_WARNING, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIconIndirect, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW, GetCursorPos,
    GetForegroundWindow, GetMessageW, GetWindowThreadProcessId, MessageBoxW, PostMessageW, PostQuitMessage, RegisterClassW, RegisterWindowMessageW,
    SetForegroundWindow, TrackPopupMenu, TranslateMessage, EVENT_OBJECT_NAMECHANGE, EVENT_SYSTEM_FOREGROUND, HICON, ICONINFO, MB_ICONINFORMATION, MB_OK,
    MB_SETFOREGROUND, MF_DISABLED, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG, OBJID_WINDOW, TPM_BOTTOMALIGN, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON,
    WINDOW_EX_STYLE, WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS, WM_APP, WM_DESTROY, WM_ENDSESSION, WM_LBUTTONUP, WM_POWERBROADCAST, WM_QUERYENDSESSION,
    WM_RBUTTONUP, WM_WTSSESSION_CHANGE, WNDCLASSW, WS_OVERLAPPED,
};

const WM_TRAY: u32 = WM_APP + 1;
pub const WM_REFRESH: u32 = WM_APP + 2;
pub const WM_BALLOON: u32 = WM_APP + 3;
const ID_STATUS: usize = 1;
const ID_SYNC: usize = 2;
const TRAY_ID: u32 = 1;

// Session-change and power codes (wParam values).
const WTS_CONSOLE_CONNECT: usize = 1;
const WTS_CONSOLE_DISCONNECT: usize = 2;
const WTS_REMOTE_CONNECT: usize = 3;
const WTS_REMOTE_DISCONNECT: usize = 4;
const WTS_SESSION_LOCK: usize = 7;
const WTS_SESSION_UNLOCK: usize = 8;
const PBT_APMSUSPEND: usize = 4;
const PBT_APMRESUMESUSPEND: usize = 7;
const PBT_APMRESUMEAUTOMATIC: usize = 18;

struct Ui {
    state: Arc<State>,
    wake: Sender<Wake>,
    out: UnboundedSender<ToCore>,
    online: HICON,
    offline: HICON,
    taskbar_created: u32,
    dialog_open: bool,
}

thread_local! {
    static UI: RefCell<Option<Ui>> = const { RefCell::new(None) };
}

/// Title-change hook for the foreground process only; replaced on every focus change.
static NAME_HOOK: AtomicIsize = AtomicIsize::new(0);
static WAKE: std::sync::OnceLock<Sender<Wake>> = std::sync::OnceLock::new();

fn wake_tracker() {
    if let Some(tx) = WAKE.get() {
        let _ = tx.send(Wake::Probe);
    }
}

/// Draws a filled circle as a 32x32 icon.
fn dot_icon(rgb: (u8, u8, u8)) -> HICON {
    const N: i32 = 32;
    let mut pixels = vec![0u32; (N * N) as usize];
    let (c, r) = ((N as f32 - 1.0) / 2.0, 11.5f32);
    for y in 0..N {
        for x in 0..N {
            let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
            // One pixel of soft edge so the dot is not jagged.
            let alpha = ((r + 0.5 - d).clamp(0.0, 1.0) * 255.0) as u32;
            let mul = |v: u8| u32::from(v) * alpha / 255;
            pixels[(y * N + x) as usize] = (alpha << 24) | (mul(rgb.0) << 16) | (mul(rgb.1) << 8) | mul(rgb.2);
        }
    }
    unsafe {
        let color = CreateBitmap(N, N, 1, 32, Some(pixels.as_ptr() as *const _));
        let mask = CreateBitmap(N, N, 1, 1, None);
        let info = ICONINFO { fIcon: true.into(), xHotspot: 0, yHotspot: 0, hbmMask: mask, hbmColor: color };
        let icon = CreateIconIndirect(&info).unwrap_or_default();
        let _ = DeleteObject(color.into());
        let _ = DeleteObject(mask.into());
        icon
    }
}

fn copy_into(dst: &mut [u16], text: &str) {
    let max = dst.len() - 1;
    let units: Vec<u16> = text.encode_utf16().take(max).collect();
    dst[..units.len()].copy_from_slice(&units);
    dst[units.len()] = 0;
}

fn icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW { cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32, hWnd: hwnd, uID: TRAY_ID, ..Default::default() }
}

fn show_icon(hwnd: HWND, ui: &Ui, add: bool) {
    let status = ui.state.status();
    let linked = ui.state.service_linked();
    let mut data = icon_data(hwnd);
    data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    data.uCallbackMessage = WM_TRAY;
    data.hIcon = if linked && status.connected { ui.online } else { ui.offline };
    let tip = if !linked {
        "EMS Agent (starting)"
    } else if status.connected {
        "EMS Agent"
    } else {
        "EMS Agent (offline)"
    };
    copy_into(&mut data.szTip, tip);
    unsafe {
        let _ = Shell_NotifyIconW(if add { NIM_ADD } else { NIM_MODIFY }, &data);
    }
}

fn show_balloon(hwnd: HWND, text: &str) {
    let mut data = icon_data(hwnd);
    data.uFlags = NIF_INFO;
    data.dwInfoFlags = NIIF_WARNING;
    copy_into(&mut data.szInfoTitle, "EMS Agent");
    copy_into(&mut data.szInfo, text);
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &data);
    }
}

/// The text of the status window the user sees on clicking the tray icon.
/// Kept to plain operational facts: it does not mention recording or
/// blocking. The full picture (blocked sites, records waiting) stays in the
/// `ems-agent status` command, for whoever administers the computer.
fn status_text(state: &State) -> String {
    let s = state.status();
    let link = if !state.service_linked() {
        "starting".to_string()
    } else if s.connected {
        "connected".to_string()
    } else {
        "offline (will retry)".to_string()
    };
    let last = match s.last_sync_ms {
        Some(ms) => {
            let ago = ((crate::logger::now_ms() - ms) / 1000).max(0);
            if ago < 90 { "just now".to_string() } else { format!("{} min ago", ago / 60) }
        }
        None => "not yet".to_string(),
    };
    format!(
        "EMS Agent\n\n\
         Organisation:\t{}\n\
         Computer:\t{}\n\
         User:\t\t{}\n\
         Status:\t\t{}\n\
         Last contact:\t{}\n\
         Version:\t\t{}",
        if s.org.is_empty() { "not known yet" } else { s.org.as_str() },
        s.hostname,
        state.user,
        link,
        last,
        crate::version(),
    )
}

fn show_status(hwnd: HWND) {
    let text = UI.with(|ui| {
        let mut ui = ui.borrow_mut();
        let ui = ui.as_mut()?;
        if ui.dialog_open {
            return None;
        }
        ui.dialog_open = true;
        Some(status_text(&ui.state))
    });
    let Some(text) = text else { return };
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        MessageBoxW(Some(hwnd), PCWSTR(wide.as_ptr()), w!("EMS Agent"), MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
    }
    UI.with(|ui| {
        if let Some(ui) = ui.borrow_mut().as_mut() {
            ui.dialog_open = false;
        }
    });
}

fn show_menu(hwnd: HWND) {
    unsafe {
        let Ok(menu) = CreatePopupMenu() else { return };
        let _ = AppendMenuW(menu, MF_STRING | MF_DISABLED | MF_GRAYED, 0, w!("EMS Agent"));
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(menu, MF_STRING, ID_STATUS, w!("Status..."));
        let _ = AppendMenuW(menu, MF_STRING, ID_SYNC, w!("Sync now"));
        let mut pt = POINT::default();
        let _ = GetCursorPos(&mut pt);
        // Required so the menu closes when the user clicks elsewhere.
        let _ = SetForegroundWindow(hwnd);
        let chosen = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, None, hwnd, None);
        let _ = DestroyMenu(menu);
        match chosen.0 as usize {
            ID_STATUS => show_status(hwnd),
            ID_SYNC => UI.with(|ui| {
                if let Some(ui) = ui.borrow().as_ref() {
                    let _ = ui.out.send(ToCore::SyncNow);
                }
            }),
            _ => {}
        }
    }
}

unsafe extern "system" fn on_win_event(_hook: HWINEVENTHOOK, event: u32, hwnd: HWND, id_object: i32, id_child: i32, _thread: u32, _time: u32) {
    if event == EVENT_SYSTEM_FOREGROUND {
        // Follow title changes of whichever process is now in front, and only that one.
        let old = NAME_HOOK.swap(0, Ordering::Relaxed);
        if old != 0 {
            let _ = UnhookWinEvent(HWINEVENTHOOK(old as *mut _));
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid != 0 && pid != std::process::id() {
            let hook = SetWinEventHook(EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE, None, Some(on_win_event), pid, 0, WINEVENT_OUTOFCONTEXT);
            NAME_HOOK.store(hook.0 as isize, Ordering::Relaxed);
        }
        wake_tracker();
    } else if event == EVENT_OBJECT_NAMECHANGE && id_object == OBJID_WINDOW.0 && id_child == 0 && hwnd == GetForegroundWindow() {
        wake_tracker();
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let taskbar_created = UI.with(|ui| ui.borrow().as_ref().map_or(0, |u| u.taskbar_created));
    match msg {
        WM_TRAY => {
            match lparam.0 as u32 {
                WM_RBUTTONUP => show_menu(hwnd),
                WM_LBUTTONUP => show_status(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        WM_REFRESH => {
            UI.with(|ui| {
                if let Some(ui) = ui.borrow().as_ref() {
                    show_icon(hwnd, ui, false);
                }
            });
            LRESULT(0)
        }
        WM_BALLOON => {
            let text = UI.with(|ui| ui.borrow().as_ref().and_then(|u| u.state.take_notice()));
            if let Some(text) = text {
                show_balloon(hwnd, &text);
            }
            LRESULT(0)
        }
        WM_WTSSESSION_CHANGE => {
            let away = match wparam.0 {
                WTS_SESSION_LOCK | WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT => Some(true),
                WTS_SESSION_UNLOCK | WTS_CONSOLE_CONNECT | WTS_REMOTE_CONNECT => Some(false),
                _ => None,
            };
            if let (Some(away), Some(tx)) = (away, WAKE.get()) {
                let _ = tx.send(Wake::Away(away));
            }
            LRESULT(0)
        }
        WM_POWERBROADCAST => {
            let away = match wparam.0 {
                PBT_APMSUSPEND => Some(true),
                PBT_APMRESUMESUSPEND | PBT_APMRESUMEAUTOMATIC => Some(false),
                _ => None,
            };
            if let (Some(away), Some(tx)) = (away, WAKE.get()) {
                let _ = tx.send(Wake::Away(away));
            }
            LRESULT(1)
        }
        WM_QUERYENDSESSION => LRESULT(1),
        WM_ENDSESSION => {
            if wparam.0 != 0 {
                // Signing out or shutting down: hand over what is in progress before the process is ended.
                if let Some(tx) = WAKE.get() {
                    let _ = tx.send(Wake::Quit);
                }
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            let _ = Shell_NotifyIconW(NIM_DELETE, &icon_data(hwnd));
            let _ = WTSUnRegisterSessionNotification(hwnd);
            PostQuitMessage(0);
            LRESULT(0)
        }
        m if m == taskbar_created && m != 0 => {
            // Explorer restarted: the icon has to be added again.
            UI.with(|ui| {
                if let Some(ui) = ui.borrow().as_ref() {
                    show_icon(hwnd, ui, true);
                }
            });
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Asks the UI thread to act; safe to call from any thread.
pub fn post(state: &State, msg: u32) {
    let hwnd = state.ui_window.load(Ordering::Relaxed);
    if hwnd != 0 {
        unsafe {
            let _ = PostMessageW(Some(HWND(hwnd as *mut _)), msg, WPARAM(0), LPARAM(0));
        }
    }
}

/// Creates the icon and runs the message loop until the session ends.
pub fn run(state: Arc<State>, wake: Sender<Wake>, out: UnboundedSender<ToCore>) -> anyhow::Result<()> {
    let _ = WAKE.set(wake.clone());
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class = w!("EMSAgentTray");
        let wc = WNDCLASSW { lpfnWndProc: Some(wndproc), hInstance: instance.into(), lpszClassName: class, ..Default::default() };
        if RegisterClassW(&wc) == 0 {
            anyhow::bail!("could not register the window class");
        }
        let hwnd = CreateWindowExW(WINDOW_EX_STYLE(0), class, w!("EMS Agent"), WS_OVERLAPPED, 0, 0, 0, 0, None, None, Some(instance.into()), None)?;

        let ui = Ui {
            state: state.clone(),
            wake,
            out,
            online: dot_icon((0x22, 0xc5, 0x5e)),
            offline: dot_icon((0xf5, 0x9e, 0x0b)),
            taskbar_created: RegisterWindowMessageW(w!("TaskbarCreated")),
            dialog_open: false,
        };
        show_icon(hwnd, &ui, true);
        UI.with(|slot| *slot.borrow_mut() = Some(ui));
        state.ui_window.store(hwnd.0 as isize, Ordering::Relaxed);

        let _ = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
        let foreground_hook =
            SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, None, Some(on_win_event), 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
        // Start following the window that is already in front.
        on_win_event(foreground_hook, EVENT_SYSTEM_FOREGROUND, GetForegroundWindow(), 0, 0, 0, 0);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        let _ = UnhookWinEvent(foreground_hook);
        let name_hook = NAME_HOOK.swap(0, Ordering::Relaxed);
        if name_hook != 0 {
            let _ = UnhookWinEvent(HWINEVENTHOOK(name_hook as *mut _));
        }
        let _ = DestroyWindow(hwnd);
    }
    UI.with(|slot| {
        if let Some(ui) = slot.borrow_mut().take() {
            let _ = ui.wake.send(Wake::Quit);
        }
    });
    Ok(())
}
