//! The per-user half of the agent. Runs inside each signed-in user's
//! session, shows the tray icon, watches the foreground window and reports
//! what it sees to the service over the local pipe.

pub mod engine;
mod tray;
mod uia;
mod win;

use crate::ipc::{Status, ToCore, ToSession};
use engine::{Action, Engine, Foreground, Observation, Web};
use ems_proto::Policy;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use windows::core::HSTRING;
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::CreateMutexW;

/// Rows kept in memory while the service cannot be reached.
const BACKLOG_MAX: usize = 20_000;

pub enum Wake {
    /// Something changed on screen; look now instead of at the next tick.
    Probe,
    /// The session was locked/unlocked or the computer is suspending/resuming.
    Away(bool),
    Quit,
}

/// State shared between the tray, tracker and pipe threads.
pub struct State {
    pub user: String,
    policy: RwLock<Policy>,
    status: RwLock<Status>,
    linked: AtomicBool,
    notice: Mutex<Option<String>>,
    pub ui_window: AtomicIsize,
}

impl State {
    pub fn policy(&self) -> Policy {
        self.policy.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
    pub fn status(&self) -> Status {
        self.status.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
    /// Whether the pipe to the service is up.
    pub fn service_linked(&self) -> bool {
        self.linked.load(Ordering::Relaxed)
    }
    pub fn take_notice(&self) -> Option<String> {
        self.notice.lock().unwrap_or_else(|p| p.into_inner()).take()
    }
    fn notify_user(&self, text: String) {
        *self.notice.lock().unwrap_or_else(|p| p.into_inner()) = Some(text);
        tray::post(self, tray::WM_BALLOON);
    }
}

/// Looks at the screen once and describes it for the engine.
fn observe(uia: &mut Option<uia::Uia>, names: &mut win::AppNames, away: bool) -> Observation {
    let now_ms = crate::logger::now_ms();
    let idle_ms = if win::display_kept_awake() { 0 } else { win::idle_ms() };
    let foreground = win::foreground().filter(|w| w.pid != std::process::id() && w.exe_name != "lockapp.exe").map(|w| {
        let app = names.name(&w.exe_path, &w.exe_name);
        let web = if !uia::is_browser(&w.exe_name) {
            Web::NotBrowser
        } else {
            let full_url = |s: &str| s.starts_with("http://") || s.starts_with("https://");
            match uia.as_mut().and_then(|u| u.address_bar(w.hwnd)) {
                // With the caret in the address bar its text may be half-typed and
                // says nothing reliable about the page underneath. Ask the page itself.
                Some(bar) if bar.focused && !full_url(&bar.text) => match uia.as_ref().and_then(|u| u.document_url(w.hwnd)) {
                    Some(url) if full_url(&url) && ems_proto::host_of(&url).is_some() => Web::Page { raw: url, browser: app.clone() },
                    _ => Web::Unknown { typing: true },
                },
                Some(bar) if ems_proto::host_of(&bar.text).is_some() => Web::Page { raw: bar.text, browser: app.clone() },
                _ => Web::Unknown { typing: false },
            }
        };
        Foreground { window: w.hwnd, app, title: w.title, exe: w.exe_path, web }
    });
    Observation { now_ms, idle_ms, away, foreground }
}

fn tracker_loop(state: Arc<State>, wake: Receiver<Wake>, out: UnboundedSender<ToCore>) {
    let mut uia = uia::Uia::new();
    if uia.is_none() {
        crate::log!("UI Automation is unavailable: websites will not be recorded");
    }
    let mut names = win::AppNames::default();
    let mut engine = Engine::default();
    let (mut rows, mut actions) = (Vec::new(), Vec::new());
    let mut away = false;
    // After an on-screen change, look again shortly: browsers update the
    // address bar a moment after the window title.
    let mut follow_up = false;

    loop {
        let timeout = if follow_up { Duration::from_millis(250) } else { Duration::from_millis(1000) };
        follow_up = false;
        let mut quit = false;
        let mut handle = |w: Wake, follow_up: &mut bool| match w {
            Wake::Probe => *follow_up = true,
            Wake::Away(a) => away = a,
            Wake::Quit => quit = true,
        };
        match wake.recv_timeout(timeout) {
            Ok(w) => {
                handle(w, &mut follow_up);
                while let Ok(w) = wake.try_recv() {
                    handle(w, &mut follow_up);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => quit = true,
        }
        if quit {
            engine.flush(crate::logger::now_ms(), &mut rows);
            for r in rows.drain(..) {
                let _ = out.send(r);
            }
            return;
        }

        let policy = state.policy();
        engine.step(observe(&mut uia, &mut names, away), &policy, &mut rows, &mut actions);
        for r in rows.drain(..) {
            let _ = out.send(r);
        }
        for a in actions.drain(..) {
            match a {
                Action::CloseTab { window } => {
                    // Press the tab's own close button; fall back to the keyboard shortcut
                    // only for browsers whose tab strip cannot be read.
                    let how = if uia.as_ref().is_some_and(|u| u.close_selected_tab(window)) {
                        "closed the tab"
                    } else if win::close_active_tab(window) {
                        "sent the close-tab shortcut"
                    } else {
                        "close postponed (window not in front or a modifier key is held)"
                    };
                    crate::log!("blocked page in front: {how}");
                    follow_up = true;
                }
                Action::Notify { text } => state.notify_user(text),
            }
        }
    }
}

async fn write_msg<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, msg: &ToCore) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(msg)?;
    line.push(b'\n');
    w.write_all(&line).await
}

/// One connection to the service. Returns when the pipe breaks.
async fn linked(pipe: tokio::net::windows::named_pipe::NamedPipeClient, state: &State, session: u32, out: &mut UnboundedReceiver<ToCore>, backlog: &mut VecDeque<ToCore>, wake: &Sender<Wake>) {
    let (read, mut write) = tokio::io::split(pipe);
    if write_msg(&mut write, &ToCore::Hello { user: state.user.clone(), session }).await.is_err() {
        return;
    }
    while let Some(msg) = backlog.pop_front() {
        if write_msg(&mut write, &msg).await.is_err() {
            backlog.push_front(msg);
            return;
        }
    }
    state.linked.store(true, Ordering::Relaxed);
    tray::post(state, tray::WM_REFRESH);

    let mut reader = BufReader::new(read);
    let mut buf = Vec::new();
    loop {
        tokio::select! {
            line = crate::pipe::read_capped_line(&mut reader, &mut buf) => {
                if !matches!(line, Ok(true)) {
                    return;
                }
                match serde_json::from_slice::<ToSession>(&buf) {
                    Ok(ToSession::Policy { policy }) => {
                        *state.policy.write().unwrap_or_else(|p| p.into_inner()) = policy;
                        // A new block may apply to the page that is open right now.
                        let _ = wake.send(Wake::Probe);
                    }
                    Ok(ToSession::Status { status }) => {
                        *state.status.write().unwrap_or_else(|p| p.into_inner()) = status;
                        tray::post(state, tray::WM_REFRESH);
                    }
                    Err(_) => {}
                }
            }
            msg = out.recv() => {
                let Some(msg) = msg else { return };
                if write_msg(&mut write, &msg).await.is_err() {
                    backlog.push_back(msg);
                    return;
                }
            }
        }
    }
}

async fn pipe_loop(pipe_name: String, state: Arc<State>, session: u32, mut out: UnboundedReceiver<ToCore>, wake: Sender<Wake>) {
    let mut backlog: VecDeque<ToCore> = VecDeque::new();
    loop {
        if let Ok(pipe) = crate::pipe::connect(&pipe_name) {
            linked(pipe, &state, session, &mut out, &mut backlog, &wake).await;
            state.linked.store(false, Ordering::Relaxed);
            tray::post(&state, tray::WM_REFRESH);
        }
        // Not connected: keep collecting, within bounds, and try again shortly.
        let retry = tokio::time::sleep(Duration::from_secs(3));
        tokio::pin!(retry);
        loop {
            tokio::select! {
                _ = &mut retry => break,
                msg = out.recv() => match msg {
                    Some(msg) => {
                        if backlog.len() >= BACKLOG_MAX {
                            backlog.pop_front();
                        }
                        backlog.push_back(msg);
                    }
                    None => return,
                },
            }
        }
    }
}

fn user_name() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
}

fn session_id() -> u32 {
    let mut id = 0u32;
    unsafe {
        let _ = ProcessIdToSessionId(std::process::id(), &mut id);
    }
    id
}

/// Development aid: reports what the agent can read from browser window
/// `hwnd` and optionally closes its selected tab. Works on a window that is
/// not in front, so it can be tried without interrupting anyone.
pub fn dev_browser(hwnd: isize, close: bool) -> String {
    let Some(mut uia) = uia::Uia::new() else { return "UI Automation is unavailable".into() };
    let started = std::time::Instant::now();
    let bar = uia.address_bar(hwnd);
    let first_ms = started.elapsed().as_millis();
    let started = std::time::Instant::now();
    let again = uia.address_bar(hwnd);
    let repeat_us = started.elapsed().as_micros();
    let started = std::time::Instant::now();
    let doc = uia.document_url(hwnd);
    let doc_ms = started.elapsed().as_millis();
    let mut out = format!("address bar : {bar:?} (found in {first_ms} ms; repeat read {repeat_us} us, same={})", bar == again);
    out.push_str(&format!("\ndocument url: {doc:?} ({doc_ms} ms)"));
    if close {
        let started = std::time::Instant::now();
        let closed = uia.close_selected_tab(hwnd);
        out.push_str(&format!("\nclose tab   : {closed} ({} ms)", started.elapsed().as_millis()));
    }
    out
}

/// Entry point of `ems-agent session`. Returns the process exit code.
pub fn run(pipe_name: &str) -> i32 {
    // One helper per user session (per pipe, so a development run can coexist with an installed agent).
    let tag: String = pipe_name.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let mutex_name = HSTRING::from(format!("Local\\EMSAgentSession-{tag}"));
    unsafe {
        let mutex = CreateMutexW(None, true, &mutex_name);
        if mutex.is_err() || GetLastError() == ERROR_ALREADY_EXISTS {
            return 0;
        }
        // Held for the life of the process.
        std::mem::forget(mutex);
    }

    let log_dir = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir).join("EMS");
    crate::logger::init(&log_dir.join("session.log"), false);
    crate::log!("tray helper starting for {} (session {})", user_name(), session_id());

    let state = Arc::new(State {
        user: user_name(),
        policy: RwLock::new(Policy::default()),
        status: RwLock::new(Status::default()),
        linked: AtomicBool::new(false),
        notice: Mutex::new(None),
        ui_window: AtomicIsize::new(0),
    });
    let (wake_tx, wake_rx) = std::sync::mpsc::channel::<Wake>();
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel::<ToCore>();

    {
        let (state, wake, pipe_name, session) = (state.clone(), wake_tx.clone(), pipe_name.to_string(), session_id());
        std::thread::Builder::new()
            .name("pipe".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
                rt.block_on(pipe_loop(pipe_name, state, session, out_rx, wake));
            })
            .expect("pipe thread");
    }
    let tracker = {
        let (state, out) = (state.clone(), out_tx.clone());
        std::thread::Builder::new().name("tracker".into()).spawn(move || tracker_loop(state, wake_rx, out)).expect("tracker thread")
    };

    let result = tray::run(state, wake_tx, out_tx);
    if let Err(e) = &result {
        crate::log!("tray failed: {e:#}");
    }
    let _ = tracker.join();
    // Let the pipe thread pass the final rows to the service.
    std::thread::sleep(Duration::from_millis(300));
    i32::from(result.is_err())
}
