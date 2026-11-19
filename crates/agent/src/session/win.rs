//! Thin wrappers over the Win32 calls the tray helper needs.

use std::collections::HashMap;
use windows::core::{BOOL, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM};
use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, GetLastInputInfo, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP, LASTINPUTINFO, VIRTUAL_KEY,
    VK_CONTROL, VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT,
};
use windows::Win32::UI::WindowsAndMessaging::{EnumChildWindows, GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId};

#[derive(Debug, Clone)]
pub struct Window {
    pub hwnd: isize,
    pub pid: u32,
    /// Full path of the executable; empty when Windows will not reveal it.
    pub exe_path: String,
    /// File name of the executable, lowercase.
    pub exe_name: String,
    pub title: String,
}

fn process_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).is_ok();
        let _ = CloseHandle(handle);
        ok.then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

fn file_name_lower(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_lowercase()
}

/// Store apps are hosted by ApplicationFrameHost; the real app is a child window owned by another process.
fn hosted_app_pid(frame: HWND, frame_pid: u32) -> Option<u32> {
    struct Search {
        frame_pid: u32,
        found: u32,
    }
    unsafe extern "system" fn visit(child: HWND, lparam: LPARAM) -> BOOL {
        let search = &mut *(lparam.0 as *mut Search);
        let mut pid = 0u32;
        GetWindowThreadProcessId(child, Some(&mut pid));
        if pid != 0 && pid != search.frame_pid {
            search.found = pid;
            return false.into();
        }
        true.into()
    }
    let mut search = Search { frame_pid, found: 0 };
    unsafe {
        let _ = EnumChildWindows(Some(frame), Some(visit), LPARAM(&mut search as *mut Search as isize));
    }
    (search.found != 0).then_some(search.found)
}

/// The window the user is working in, if any.
pub fn foreground() -> Option<Window> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0.is_null() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return None;
        }
        let mut exe_path = process_path(pid).unwrap_or_default();
        if file_name_lower(&exe_path) == "applicationframehost.exe" {
            if let Some(real) = hosted_app_pid(hwnd, pid).and_then(process_path) {
                exe_path = real;
            }
        }
        let mut buf = [0u16; 600];
        let n = GetWindowTextW(hwnd, &mut buf).max(0) as usize;
        Some(Window { hwnd: hwnd.0 as isize, pid, exe_name: file_name_lower(&exe_path), exe_path, title: String::from_utf16_lossy(&buf[..n]) })
    }
}

pub fn is_foreground(hwnd: isize) -> bool {
    unsafe { GetForegroundWindow().0 as isize == hwnd }
}

/// Milliseconds since the last keyboard or mouse input in this session.
pub fn idle_ms() -> u64 {
    unsafe {
        let mut info = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
        if !GetLastInputInfo(&mut info).as_bool() {
            return 0;
        }
        u64::from(GetTickCount().wrapping_sub(info.dwTime))
    }
}

/// True while some program asks Windows to keep the display on, which is
/// what video players and calls do. Without this, an hour of watching a
/// video with hands off the mouse would look like an hour away.
pub fn display_kept_awake() -> bool {
    #[link(name = "powrprof")]
    extern "system" {
        fn CallNtPowerInformation(level: i32, input: *const core::ffi::c_void, input_len: u32, output: *mut core::ffi::c_void, output_len: u32) -> i32;
    }
    const SYSTEM_EXECUTION_STATE: i32 = 16;
    const ES_DISPLAY_REQUIRED: u32 = 0x2;
    let mut state = 0u32;
    let status = unsafe { CallNtPowerInformation(SYSTEM_EXECUTION_STATE, std::ptr::null(), 0, &mut state as *mut u32 as *mut _, 4) };
    status == 0 && state & ES_DISPLAY_REQUIRED != 0
}

/// Friendly application names ("Google Chrome"), read from each executable's
/// version resource once and remembered.
#[derive(Default)]
pub struct AppNames {
    cache: HashMap<String, String>,
}

impl AppNames {
    pub fn name(&mut self, exe_path: &str, exe_name: &str) -> String {
        if exe_path.is_empty() {
            return "Unknown".into();
        }
        if let Some(n) = self.cache.get(exe_path) {
            return n.clone();
        }
        let name = file_description(exe_path).unwrap_or_else(|| exe_name.trim_end_matches(".exe").to_string());
        if self.cache.len() > 500 {
            self.cache.clear();
        }
        self.cache.insert(exe_path.to_string(), name.clone());
        name
    }
}

fn file_description(path: &str) -> Option<String> {
    unsafe {
        let wide = HSTRING::from(path);
        let size = GetFileVersionInfoSizeW(&wide, None);
        if size == 0 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        GetFileVersionInfoW(&wide, None, size, data.as_mut_ptr() as *mut _).ok()?;

        let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        let translation = HSTRING::from("\\VarFileInfo\\Translation");
        if !VerQueryValueW(data.as_ptr() as *const _, &translation, &mut ptr, &mut len).as_bool() || len < 4 || ptr.is_null() {
            return None;
        }
        let pair = std::slice::from_raw_parts(ptr as *const u16, 2);
        let query = HSTRING::from(format!("\\StringFileInfo\\{:04x}{:04x}\\FileDescription", pair[0], pair[1]));
        let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        if !VerQueryValueW(data.as_ptr() as *const _, PCWSTR(query.as_ptr()), &mut ptr, &mut len).as_bool() || len == 0 || ptr.is_null() {
            return None;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(ptr as *const u16, len as usize));
        let text = text.trim_end_matches('\0').trim().to_string();
        (!text.is_empty()).then_some(text)
    }
}

fn key_down(vk: VIRTUAL_KEY) -> bool {
    unsafe { (GetAsyncKeyState(i32::from(vk.0)) as u16) & 0x8000 != 0 }
}

fn key_event(vk: VIRTUAL_KEY, up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: 0, dwFlags: if up { KEYEVENTF_KEYUP } else { KEYBD_EVENT_FLAGS(0) }, time: 0, dwExtraInfo: 0 } },
    }
}

/// Closes the active tab of `hwnd` by sending Ctrl+W, the one shortcut
/// every browser shares. Returns false, doing nothing, unless it is safe:
/// the window must still be in front, and Shift, Alt and Win must be up,
/// because combined with them the shortcut means something else entirely
/// (Ctrl+Shift+W closes the whole window).
pub fn close_active_tab(hwnd: isize) -> bool {
    if !is_foreground(hwnd) || [VK_SHIFT, VK_MENU, VK_LWIN, VK_RWIN].into_iter().any(key_down) {
        return false;
    }
    const VK_W: VIRTUAL_KEY = VIRTUAL_KEY(0x57);
    let ctrl_held = key_down(VK_CONTROL);
    let mut inputs = Vec::with_capacity(4);
    if !ctrl_held {
        inputs.push(key_event(VK_CONTROL, false));
    }
    inputs.push(key_event(VK_W, false));
    inputs.push(key_event(VK_W, true));
    if !ctrl_held {
        inputs.push(key_event(VK_CONTROL, true));
    }
    unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) as usize == inputs.len() }
}
