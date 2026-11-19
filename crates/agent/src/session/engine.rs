//! Turns a stream of "what is in the foreground right now" observations
//! into activity rows and blocking actions. Pure logic with no Windows
//! calls, so every rule here is covered by tests.

use crate::ipc::ToCore;
use ems_proto::{clean_url, find_blocked, find_word, host_of, truncate, word_match_text, AppUse, Event, EventKind, Policy, UrlMode, Visit, MAX_TITLE_LEN};
use std::collections::HashMap;

/// A stretch of unbroken activity is cut into rows no longer than this, so a
/// crash loses little and long sessions still land in the right hour.
const SPLIT_MS: i64 = 300_000;
/// Steps normally arrive every second. A much longer gap means the computer
/// slept or froze, and that time must not be counted.
const GAP_MS: i64 = 15_000;
/// Window titles and URLs that change faster than this update the current
/// row instead of starting a new one (think of a title showing a timer, or
/// a map whose URL follows every pan).
const CHURN_MS: i64 = 15_000;
const EVENT_REPEAT_MS: i64 = 20_000;
const CLOSE_REPEAT_MS: i64 = 1_500;
const NOTIFY_REPEAT_MS: i64 = 8_000;

#[derive(Debug, Clone, PartialEq)]
pub enum Web {
    /// The foreground window is not a browser.
    NotBrowser,
    /// A browser, but no page address could be read. `typing` means the
    /// address bar is being edited, so the page underneath is unchanged.
    Unknown { typing: bool },
    /// A browser showing a page. `raw` is the address-bar text.
    Page { raw: String, browser: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Foreground {
    pub window: isize,
    pub app: String,
    pub title: String,
    pub exe: String,
    pub web: Web,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub now_ms: i64,
    /// Time since the last keyboard or mouse input.
    pub idle_ms: u64,
    /// Screen locked, session disconnected or computer suspending.
    pub away: bool,
    pub foreground: Option<Foreground>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    CloseTab { window: isize },
    Notify { text: String },
}

struct AppSeg {
    app: String,
    title: String,
    exe: String,
    start_ms: i64,
}

struct VisitSeg {
    domain: String,
    url: Option<String>,
    title: String,
    browser: String,
    start_ms: i64,
}

#[derive(Default)]
pub struct Engine {
    app: Option<AppSeg>,
    visit: Option<VisitSeg>,
    last_now: i64,
    recent_events: HashMap<String, i64>,
    last_close: Option<(isize, i64)>,
    last_notify: i64,
}

fn secs(start_ms: i64, end_ms: i64) -> u32 {
    (((end_ms - start_ms).max(0) + 500) / 1000) as u32
}

fn opt(s: &str, max: usize) -> Option<String> {
    let t = truncate(s.trim(), max);
    (!t.is_empty()).then_some(t)
}

impl Engine {
    fn end_app(&mut self, end_ms: i64, out: &mut Vec<ToCore>) {
        if let Some(a) = self.app.take() {
            let dur_s = secs(a.start_ms, end_ms);
            if dur_s >= 1 {
                out.push(ToCore::App(AppUse { user: String::new(), app: a.app, title: opt(&a.title, MAX_TITLE_LEN), exe: opt(&a.exe, 500), start_ms: a.start_ms, dur_s }));
            }
        }
    }

    fn end_visit(&mut self, end_ms: i64, out: &mut Vec<ToCore>) {
        if let Some(v) = self.visit.take() {
            let dur_s = secs(v.start_ms, end_ms);
            if dur_s >= 1 {
                out.push(ToCore::Visit(Visit {
                    user: String::new(),
                    domain: v.domain,
                    url: v.url,
                    title: opt(&v.title, MAX_TITLE_LEN),
                    browser: opt(&v.browser, 64),
                    start_ms: v.start_ms,
                    dur_s,
                }));
            }
        }
    }

    /// Ends everything in progress, for shutdown or sign-out.
    pub fn flush(&mut self, now_ms: i64, out: &mut Vec<ToCore>) {
        self.end_app(now_ms, out);
        self.end_visit(now_ms, out);
    }

    /// `last_input` is when the keyboard or mouse was last touched. A long
    /// stretch in the same window is cut there rather than "now": if the
    /// user turns out to have walked away, the row already sent must not
    /// include minutes nobody was present for.
    fn track_app(&mut self, now: i64, last_input: i64, fg: &Foreground, out: &mut Vec<ToCore>) {
        let mut start = now;
        match self.app.as_mut() {
            Some(a) if a.app == fg.app => {
                if a.title != fg.title {
                    if now - a.start_ms < CHURN_MS {
                        a.title.clone_from(&fg.title);
                        return;
                    }
                } else if now - a.start_ms < SPLIT_MS || last_input <= a.start_ms {
                    return;
                } else {
                    start = last_input;
                }
            }
            _ => {}
        }
        self.end_app(start, out);
        self.app = Some(AppSeg { app: fg.app.clone(), title: fg.title.clone(), exe: fg.exe.clone(), start_ms: start });
    }

    #[allow(clippy::too_many_arguments)]
    fn track_visit(&mut self, now: i64, last_input: i64, domain: String, url: Option<String>, fg: &Foreground, browser: &str, out: &mut Vec<ToCore>) {
        let mut start = now;
        match self.visit.as_mut() {
            Some(v) if v.domain == domain => {
                if v.url != url {
                    if now - v.start_ms < CHURN_MS {
                        v.url = url;
                        v.title.clone_from(&fg.title);
                        return;
                    }
                } else if now - v.start_ms < SPLIT_MS || last_input <= v.start_ms {
                    v.title.clone_from(&fg.title);
                    return;
                } else {
                    start = last_input;
                }
            }
            _ => {}
        }
        self.end_visit(start, out);
        self.visit = Some(VisitSeg { domain, url, title: fg.title.clone(), browser: browser.to_string(), start_ms: start });
    }

    /// Reports an event unless the same one was reported moments ago.
    fn report(&mut self, key: String, event: Event, out: &mut Vec<ToCore>) {
        let now = event.at_ms;
        if self.recent_events.len() > 256 {
            self.recent_events.retain(|_, t| now - *t < EVENT_REPEAT_MS);
        }
        if self.recent_events.get(&key).is_some_and(|t| now - *t < EVENT_REPEAT_MS) {
            return;
        }
        self.recent_events.insert(key, now);
        out.push(ToCore::Event(event));
    }

    fn stop_page(&mut self, now: i64, window: isize, message: String, policy: &Policy, actions: &mut Vec<Action>) {
        if policy.close_blocked_tabs && !self.last_close.is_some_and(|(w, t)| w == window && now - t < CLOSE_REPEAT_MS) {
            self.last_close = Some((window, now));
            actions.push(Action::CloseTab { window });
        }
        if policy.notify_user && now - self.last_notify >= NOTIFY_REPEAT_MS {
            self.last_notify = now;
            actions.push(Action::Notify { text: message });
        }
    }

    pub fn step(&mut self, obs: Observation, policy: &Policy, out: &mut Vec<ToCore>, actions: &mut Vec<Action>) {
        let now = obs.now_ms;
        if self.last_now != 0 && (now - self.last_now > GAP_MS || now < self.last_now) {
            // Slept, froze or the clock was set back: close at the last moment known to be real.
            let end = self.last_now;
            self.flush(end, out);
        }
        self.last_now = now;

        let idle_limit = u64::from(policy.idle_threshold_s) * 1000;
        let fg = match obs.foreground {
            Some(fg) if !obs.away && obs.idle_ms < idle_limit => fg,
            _ => {
                // Count time only up to the last real input, not the minutes spent deciding the user had left.
                let end = if obs.away { now } else { now - (obs.idle_ms.min(i64::MAX as u64) as i64) };
                self.flush(end, out);
                return;
            }
        };

        let last_input = now - (obs.idle_ms.min(idle_limit) as i64);
        if policy.track_apps {
            self.track_app(now, last_input, &fg, out);
        } else {
            self.end_app(now, out);
        }

        let (raw, browser) = match &fg.web {
            Web::Page { raw, browser } => (raw.as_str(), browser.as_str()),
            // While the address bar is being edited the page underneath is still the one being viewed.
            Web::Unknown { typing: true } => return,
            Web::Unknown { typing: false } | Web::NotBrowser => {
                self.end_visit(now, out);
                return;
            }
        };
        let Some(host) = host_of(raw) else {
            self.end_visit(now, out);
            return;
        };

        if find_blocked(&host, &policy.blocked).is_some() {
            self.end_visit(now, out);
            let event = Event { user: String::new(), kind: EventKind::Blocked, domain: host.clone(), url: clean_url(raw, policy.url_mode), word: None, at_ms: now };
            self.report(format!("b|{host}"), event, out);
            self.stop_page(now, fg.window, format!("{host} is blocked by your organization."), policy, actions);
            return;
        }

        if !policy.words.is_empty() {
            let text = word_match_text(raw);
            if let Some(word) = find_word(&text, &policy.words) {
                self.end_visit(now, out);
                let event = Event {
                    user: String::new(),
                    kind: EventKind::Word,
                    domain: host.clone(),
                    url: clean_url(raw, UrlMode::Full),
                    word: Some(word.to_string()),
                    at_ms: now,
                };
                self.report(format!("w|{word}|{host}"), event, out);
                self.stop_page(now, fg.window, "This page was closed: it matches a term restricted by your organization.".into(), policy, actions);
                return;
            }
        }

        if policy.track_web {
            self.track_visit(now, last_input, host, clean_url(raw, policy.url_mode), &fg, browser, out);
        } else {
            self.end_visit(now, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000_000;

    fn app(name: &str, title: &str) -> Foreground {
        Foreground { window: 1, app: name.into(), title: title.into(), exe: format!("C:\\{name}.exe"), web: Web::NotBrowser }
    }

    fn page(url: &str) -> Foreground {
        Foreground { window: 7, app: "Chrome".into(), title: "A page".into(), exe: "C:\\chrome.exe".into(), web: Web::Page { raw: url.into(), browser: "Chrome".into() } }
    }

    struct Run {
        engine: Engine,
        policy: Policy,
        rows: Vec<ToCore>,
        actions: Vec<Action>,
    }

    impl Run {
        fn new(policy: Policy) -> Run {
            Run { engine: Engine::default(), policy, rows: Vec::new(), actions: Vec::new() }
        }
        fn at(&mut self, offset_s: i64, fg: Option<Foreground>) -> &mut Run {
            self.obs(offset_s, 0, false, fg)
        }
        fn obs(&mut self, offset_s: i64, idle_s: u64, away: bool, fg: Option<Foreground>) -> &mut Run {
            let obs = Observation { now_ms: T0 + offset_s * 1000, idle_ms: idle_s * 1000, away, foreground: fg };
            self.engine.step(obs, &self.policy, &mut self.rows, &mut self.actions);
            self
        }
        /// Feeds the same foreground once a second, as the real loop does.
        fn hold(&mut self, from_s: i64, to_s: i64, fg: &Foreground) -> &mut Run {
            for s in from_s..=to_s {
                self.at(s, Some(fg.clone()));
            }
            self
        }
        fn apps(&self) -> Vec<(String, u32)> {
            self.rows.iter().filter_map(|r| if let ToCore::App(a) = r { Some((a.app.clone(), a.dur_s)) } else { None }).collect()
        }
        fn visits(&self) -> Vec<(String, Option<String>, u32)> {
            self.rows.iter().filter_map(|r| if let ToCore::Visit(v) = r { Some((v.domain.clone(), v.url.clone(), v.dur_s)) } else { None }).collect()
        }
        fn events(&self) -> Vec<(EventKind, String)> {
            self.rows.iter().filter_map(|r| if let ToCore::Event(e) = r { Some((e.kind, e.domain.clone())) } else { None }).collect()
        }
        fn closes(&self) -> usize {
            self.actions.iter().filter(|a| matches!(a, Action::CloseTab { .. })).count()
        }
    }

    #[test]
    fn switching_apps_records_time_on_the_one_left() {
        let mut r = Run::new(Policy::default());
        r.hold(0, 40, &app("Excel", "Budget")).hold(41, 50, &app("Word", "Letter"));
        r.engine.flush(T0 + 50_000, &mut r.rows);
        assert_eq!(r.apps(), [("Excel".to_string(), 41), ("Word".to_string(), 9)]);
    }

    #[test]
    fn long_activity_is_cut_every_five_minutes_with_no_time_lost() {
        let mut r = Run::new(Policy::default());
        r.hold(0, 720, &app("Excel", "Budget"));
        r.engine.flush(T0 + 720_000, &mut r.rows);
        assert_eq!(r.apps().iter().map(|(_, d)| *d).collect::<Vec<_>>(), [300, 300, 120]);
    }

    #[test]
    fn going_idle_counts_time_only_up_to_the_last_input() {
        let mut r = Run::new(Policy::default());
        r.hold(0, 60, &app("Excel", "Budget"));
        // No input from t=60 on. The threshold (300s) is crossed at t=360.
        for s in 61..=360 {
            r.obs(s, (s - 60) as u64, false, Some(app("Excel", "Budget")));
        }
        assert_eq!(r.apps(), [("Excel".to_string(), 60)], "the five idle minutes are not credited");
        // Back at the keyboard: a fresh row starts.
        r.hold(400, 410, &app("Excel", "Budget"));
        r.engine.flush(T0 + 410_000, &mut r.rows);
        assert_eq!(r.apps()[1], ("Excel".to_string(), 10));
    }

    #[test]
    fn sleep_or_lock_is_not_counted() {
        let mut r = Run::new(Policy::default());
        r.hold(0, 30, &app("Excel", "Budget"));
        // The machine sleeps for an hour: no steps at all, then it wakes.
        r.hold(3630, 3640, &app("Excel", "Budget"));
        assert_eq!(r.apps(), [("Excel".to_string(), 30)]);

        let mut r = Run::new(Policy::default());
        r.hold(0, 20, &app("Excel", "Budget"));
        r.obs(21, 0, true, Some(app("Excel", "Budget")));
        assert_eq!(r.apps(), [("Excel".to_string(), 21)], "locking ends the row at once");
    }

    #[test]
    fn a_ticking_title_does_not_flood_rows() {
        let mut r = Run::new(Policy::default());
        for s in 0..=120 {
            r.at(s, Some(app("Player", &format!("Song - {s}s"))));
        }
        r.engine.flush(T0 + 120_000, &mut r.rows);
        let apps = r.apps();
        assert!(apps.len() <= 9, "one row per churn window at most, got {}", apps.len());
        assert_eq!(apps.iter().map(|(_, d)| *d).sum::<u32>(), 120, "and every second is still accounted for");
    }

    #[test]
    fn visits_follow_the_page_and_stop_when_the_browser_loses_focus() {
        let mut r = Run::new(Policy::default());
        r.hold(0, 30, &page("example.com/a")).hold(31, 50, &page("https://www.other.org/x?y=1")).hold(51, 60, &app("Excel", "Budget"));
        assert_eq!(
            r.visits(),
            [("example.com".to_string(), Some("https://example.com/a".to_string()), 31), ("other.org".to_string(), Some("https://www.other.org/x?y=1".to_string()), 20)]
        );
    }

    #[test]
    fn typing_in_the_address_bar_keeps_the_current_visit() {
        let mut r = Run::new(Policy::default());
        let typing = Foreground { web: Web::Unknown { typing: true }, ..page("ignored") };
        r.hold(0, 10, &page("example.com/a")).hold(11, 20, &typing).hold(21, 30, &page("example.com/a"));
        r.engine.flush(T0 + 30_000, &mut r.rows);
        assert_eq!(r.visits(), [("example.com".to_string(), Some("https://example.com/a".to_string()), 30)]);
    }

    #[test]
    fn privacy_modes_change_what_is_stored() {
        for (mode, want) in [(UrlMode::StripQuery, Some("https://example.com/a".to_string())), (UrlMode::DomainOnly, None)] {
            let mut r = Run::new(Policy { url_mode: mode, ..Policy::default() });
            r.hold(0, 10, &page("example.com/a?token=secret"));
            r.engine.flush(T0 + 10_000, &mut r.rows);
            assert_eq!(r.visits(), [("example.com".to_string(), want, 10)]);
        }
    }

    #[test]
    fn a_blocked_page_is_closed_reported_once_and_never_recorded_as_a_visit() {
        let mut r = Run::new(Policy { blocked: vec!["facebook.com".into()], notify_user: true, ..Policy::default() });
        r.hold(0, 5, &page("example.com")).hold(6, 9, &page("m.facebook.com/home"));
        assert_eq!(r.visits(), [("example.com".to_string(), Some("https://example.com".to_string()), 6)]);
        assert_eq!(r.events(), [(EventKind::Blocked, "m.facebook.com".to_string())], "one report, not one per second");
        assert_eq!(r.closes(), 2, "the close is retried if the tab is still there after 1.5s");
        assert_eq!(r.actions.iter().filter(|a| matches!(a, Action::Notify { .. })).count(), 1);
        assert!(r.visits().iter().all(|(d, _, _)| !d.contains("facebook")));
    }

    #[test]
    fn by_default_a_blocked_tab_is_closed_without_any_notice() {
        let mut r = Run::new(Policy { blocked: vec!["facebook.com".into()], words: vec!["casino".into()], ..Policy::default() });
        r.hold(0, 4, &page("facebook.com")).hold(5, 9, &page("https://example.com/?q=casino"));
        assert!(r.closes() >= 2, "both pages are closed");
        assert!(r.actions.iter().all(|a| matches!(a, Action::CloseTab { .. })), "and nothing is shown to the user");
        assert_eq!(r.events().len(), 2, "while both are still reported to the console");
    }

    #[test]
    fn blocking_can_be_silent_and_leave_the_tab_alone() {
        let policy = Policy { blocked: vec!["facebook.com".into()], close_blocked_tabs: false, notify_user: false, ..Policy::default() };
        let mut r = Run::new(policy);
        r.hold(0, 5, &page("facebook.com"));
        assert!(r.actions.is_empty());
        assert_eq!(r.events().len(), 1);
    }

    #[test]
    fn a_blacklist_word_in_a_search_closes_the_tab() {
        let mut r = Run::new(Policy { words: vec!["bad word".into()], ..Policy::default() });
        r.hold(0, 3, &page("https://www.google.com/search?q=bad+word"));
        assert_eq!(r.events(), [(EventKind::Word, "google.com".to_string())]);
        assert!(r.closes() >= 1);
        assert!(r.visits().is_empty());
        // The same site without the word is fine.
        r.hold(4, 10, &page("https://www.google.com/search?q=good"));
        r.engine.flush(T0 + 10_000, &mut r.rows);
        assert_eq!(r.visits().len(), 1);
    }

    #[test]
    fn tracking_switches_are_respected() {
        let mut r = Run::new(Policy { track_apps: false, track_web: false, blocked: vec!["x.com".into()], ..Policy::default() });
        r.hold(0, 10, &page("example.com")).hold(11, 12, &page("x.com"));
        r.engine.flush(T0 + 12_000, &mut r.rows);
        assert!(r.apps().is_empty() && r.visits().is_empty());
        assert_eq!(r.events().len(), 1, "blocking still works with tracking off");
    }
}
