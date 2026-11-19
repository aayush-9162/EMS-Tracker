//! Reads the address bar of the foreground browser through UI Automation,
//! the accessibility interface screen readers use.
//!
//! The address bar is located once per browser window by walking only the
//! browser's own toolbar tree (page content is never entered) and is then
//! remembered, so the per-second read is a single cheap call.

use std::collections::{HashMap, VecDeque};
use windows::core::Interface;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, CUIAutomation8, IUIAutomation, IUIAutomation2, IUIAutomationElement, IUIAutomationInvokePattern, IUIAutomationSelectionItemPattern,
    IUIAutomationTreeWalker, IUIAutomationValuePattern, UIA_ButtonControlTypeId, UIA_DataGridControlTypeId, UIA_DocumentControlTypeId, UIA_EditControlTypeId,
    UIA_InvokePatternId, UIA_ListControlTypeId, UIA_MenuBarControlTypeId, UIA_MenuControlTypeId, UIA_SelectionItemPatternId, UIA_TabControlTypeId,
    UIA_TabItemControlTypeId, UIA_TableControlTypeId, UIA_TreeControlTypeId, UIA_ValuePatternId,
};
use windows::Win32::UI::WindowsAndMessaging::IsWindow;

/// Executables treated as web browsers.
const BROWSERS: &[&str] = &[
    "chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "opera.exe", "opera_gx.exe", "vivaldi.exe", "arc.exe", "chromium.exe", "thorium.exe",
    "librewolf.exe", "waterfox.exe", "zen.exe", "browser.exe", "iexplore.exe", "floorp.exe", "duckduckgo.exe", "whale.exe", "maxthon.exe",
];

pub fn is_browser(exe_name: &str) -> bool {
    BROWSERS.contains(&exe_name)
}

/// How many toolbar elements to look at before giving up on a window.
const MAX_NODES: usize = 900;
const MAX_DEPTH: usize = 16;
/// A hung browser must not hang the agent.
const CALL_TIMEOUT_MS: u32 = 2_000;

#[derive(Debug, Clone, PartialEq)]
pub struct AddressBar {
    pub text: String,
    /// The user has the caret in the address bar.
    pub focused: bool,
}

pub struct Uia {
    automation: IUIAutomation,
    walker: IUIAutomationTreeWalker,
    known: HashMap<isize, IUIAutomationElement>,
}

fn value_of(el: &IUIAutomationElement) -> Option<String> {
    unsafe {
        let pattern: IUIAutomationValuePattern = el.GetCurrentPatternAs(UIA_ValuePatternId).ok()?;
        Some(pattern.CurrentValue().ok()?.to_string())
    }
}

impl Uia {
    /// Must be called on the thread that will use it.
    pub fn new() -> Option<Uia> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            let automation: IUIAutomation =
                CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER).or_else(|_| CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)).ok()?;
            if let Ok(v2) = automation.cast::<IUIAutomation2>() {
                let _ = v2.SetConnectionTimeout(CALL_TIMEOUT_MS);
                let _ = v2.SetTransactionTimeout(CALL_TIMEOUT_MS);
            }
            let walker = automation.ControlViewWalker().ok()?;
            Some(Uia { automation, walker, known: HashMap::new() })
        }
    }

    /// Breadth-first search of the browser's own controls for the address bar.
    fn find_address_bar(&self, hwnd: isize) -> Option<IUIAutomationElement> {
        unsafe {
            let root = self.automation.ElementFromHandle(HWND(hwnd as *mut _)).ok()?;
            let mut queue: VecDeque<(IUIAutomationElement, usize)> = VecDeque::new();
            queue.push_back((root, 0));
            let mut fallback: Option<IUIAutomationElement> = None;
            let mut seen = 0usize;

            while let Some((el, depth)) = queue.pop_front() {
                seen += 1;
                if seen > MAX_NODES {
                    break;
                }
                let kind = el.CurrentControlType().unwrap_or_default();
                if kind == UIA_EditControlTypeId {
                    let class = el.CurrentClassName().map(|s| s.to_string()).unwrap_or_default();
                    let id = el.CurrentAutomationId().map(|s| s.to_string()).unwrap_or_default();
                    // Chromium-family browsers and Firefox name their address bar reliably.
                    if class == "OmniboxViewViews" || id == "urlbar-input" {
                        return Some(el);
                    }
                    // Anything else: accept an edit box only if it currently holds a web address.
                    if fallback.is_none() && value_of(&el).is_some_and(|v| ems_proto::host_of(&v).is_some()) {
                        fallback = Some(el.clone());
                    }
                    continue;
                }
                // Page content, tab strips and lists never contain the address bar and can be huge.
                let skip = [
                    UIA_DocumentControlTypeId,
                    UIA_TabControlTypeId,
                    UIA_TabItemControlTypeId,
                    UIA_MenuBarControlTypeId,
                    UIA_MenuControlTypeId,
                    UIA_TreeControlTypeId,
                    UIA_ListControlTypeId,
                    UIA_DataGridControlTypeId,
                    UIA_TableControlTypeId,
                ];
                if depth >= MAX_DEPTH || (depth > 0 && skip.contains(&kind)) {
                    continue;
                }
                let mut child = self.walker.GetFirstChildElement(&el).ok();
                while let Some(c) = child {
                    child = self.walker.GetNextSiblingElement(&c).ok();
                    queue.push_back((c, depth + 1));
                }
            }
            fallback
        }
    }

    /// The address of the page actually being shown in browser window `hwnd`,
    /// read from the page's document element rather than the address bar.
    /// Browsers expose the committed URL there, so it is right even while
    /// the address bar holds half-typed text. It is the costlier read, so
    /// it is used only when the address bar cannot be trusted.
    pub fn document_url(&self, hwnd: isize) -> Option<String> {
        unsafe {
            let root = self.automation.ElementFromHandle(HWND(hwnd as *mut _)).ok()?;
            let mut queue: VecDeque<(IUIAutomationElement, usize)> = VecDeque::new();
            queue.push_back((root, 0));
            let mut seen = 0usize;
            while let Some((el, depth)) = queue.pop_front() {
                seen += 1;
                if seen > MAX_NODES {
                    break;
                }
                let kind = el.CurrentControlType().unwrap_or_default();
                if depth > 0 && kind == UIA_DocumentControlTypeId {
                    // Only the visible tab's document is attached to the window.
                    return value_of(&el).filter(|v| !v.is_empty());
                }
                let skip = [UIA_EditControlTypeId, UIA_TabControlTypeId, UIA_TabItemControlTypeId, UIA_MenuBarControlTypeId, UIA_MenuControlTypeId, UIA_TreeControlTypeId, UIA_ListControlTypeId];
                if depth >= MAX_DEPTH || (depth > 0 && skip.contains(&kind)) {
                    continue;
                }
                let mut child = self.walker.GetFirstChildElement(&el).ok();
                while let Some(c) = child {
                    child = self.walker.GetNextSiblingElement(&c).ok();
                    queue.push_back((c, depth + 1));
                }
            }
            None
        }
    }

    /// First button underneath `el`, looking a few levels down.
    fn button_under(&self, el: &IUIAutomationElement) -> Option<IUIAutomationElement> {
        unsafe {
            let mut queue: VecDeque<(IUIAutomationElement, usize)> = VecDeque::new();
            queue.push_back((el.clone(), 0));
            let mut seen = 0usize;
            while let Some((node, depth)) = queue.pop_front() {
                seen += 1;
                if seen > 40 {
                    break;
                }
                if depth > 0 && node.CurrentControlType().unwrap_or_default() == UIA_ButtonControlTypeId {
                    return Some(node);
                }
                if depth >= 3 {
                    continue;
                }
                let mut child = self.walker.GetFirstChildElement(&node).ok();
                while let Some(c) = child {
                    child = self.walker.GetNextSiblingElement(&c).ok();
                    queue.push_back((c, depth + 1));
                }
            }
            None
        }
    }

    /// Closes the selected tab of browser window `hwnd` by pressing that
    /// tab's own close button. Unlike a keyboard shortcut this cannot land
    /// in another window, does not depend on where the keyboard focus is,
    /// and is unaffected by keys the user happens to be holding.
    /// Returns false when the tab or its close button cannot be found.
    pub fn close_selected_tab(&self, hwnd: isize) -> bool {
        unsafe {
            let Ok(root) = self.automation.ElementFromHandle(HWND(hwnd as *mut _)) else { return false };
            let mut queue: VecDeque<(IUIAutomationElement, usize)> = VecDeque::new();
            queue.push_back((root, 0));
            let mut seen = 0usize;
            while let Some((el, depth)) = queue.pop_front() {
                seen += 1;
                if seen > MAX_NODES {
                    break;
                }
                let kind = el.CurrentControlType().unwrap_or_default();
                if depth > 0 && kind == UIA_TabItemControlTypeId {
                    let selected = el
                        .GetCurrentPatternAs::<IUIAutomationSelectionItemPattern>(UIA_SelectionItemPatternId)
                        .and_then(|p| p.CurrentIsSelected())
                        .is_ok_and(|b| b.as_bool());
                    if selected {
                        let Some(button) = self.button_under(&el) else { return false };
                        return button.GetCurrentPatternAs::<IUIAutomationInvokePattern>(UIA_InvokePatternId).and_then(|p| p.Invoke()).is_ok();
                    }
                    continue;
                }
                let skip = [UIA_DocumentControlTypeId, UIA_EditControlTypeId, UIA_MenuBarControlTypeId, UIA_MenuControlTypeId, UIA_TreeControlTypeId, UIA_DataGridControlTypeId, UIA_TableControlTypeId];
                if depth >= MAX_DEPTH || (depth > 0 && skip.contains(&kind)) {
                    continue;
                }
                let mut child = self.walker.GetFirstChildElement(&el).ok();
                while let Some(c) = child {
                    child = self.walker.GetNextSiblingElement(&c).ok();
                    queue.push_back((c, depth + 1));
                }
            }
            false
        }
    }

    /// Text of the address bar of browser window `hwnd`, if it can be read.
    pub fn address_bar(&mut self, hwnd: isize) -> Option<AddressBar> {
        if self.known.len() > 64 {
            self.known.retain(|h, _| unsafe { IsWindow(Some(HWND(*h as *mut _))).as_bool() });
        }
        // First try the element remembered for this window.
        if let Some(el) = self.known.get(&hwnd) {
            if let Some(text) = value_of(el) {
                let focused = unsafe { el.CurrentHasKeyboardFocus().map(|b| b.as_bool()).unwrap_or(false) };
                return Some(AddressBar { text, focused });
            }
            self.known.remove(&hwnd);
        }
        let el = self.find_address_bar(hwnd)?;
        let text = value_of(&el)?;
        let focused = unsafe { el.CurrentHasKeyboardFocus().map(|b| b.as_bool()).unwrap_or(false) };
        self.known.insert(hwnd, el);
        Some(AddressBar { text, focused })
    }
}
