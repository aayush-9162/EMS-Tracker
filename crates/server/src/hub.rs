//! What the server knows about each computer right now, kept in memory.
//!
//! A check-in from a known computer whose details have not changed touches
//! only this map: no database read, no database write. "Last seen" times
//! are written to disk by a background task every couple of minutes.
//!
//! A computer is known by its organisation and its name together, so two
//! organisations can each have a `RECEPTION` without meeting.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

const RECENT_SEQS: usize = 8;

struct Entry {
    org: i64,
    host: String,
    last_seen: i64,
    /// Address, system and agent as last reported; a change means the database row needs updating.
    details: String,
    /// Fingerprint of the agent program the computer is running.
    agent_sha: String,
    /// The last few batch sequences stored for this computer, to recognise
    /// a batch that is sent again. Matched exactly rather than by "highest
    /// so far", so a computer whose clock jumps backwards can never have
    /// new data mistaken for old.
    recent_seq: VecDeque<u64>,
}

#[derive(Default)]
struct Inner {
    ids: HashMap<(i64, String), i64>,
    entries: HashMap<i64, Entry>,
    dirty: HashSet<i64>,
}

#[derive(Default)]
pub struct Hub {
    inner: Mutex<Inner>,
}

impl Hub {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Records a check-in. Returns the computer's id if it is already known
    /// with these exact details; `None` means the caller must create or
    /// update its database row and then call [`Hub::remember`].
    pub fn check_in(&self, org: i64, host: &str, details: &str, now_s: i64) -> Option<i64> {
        let mut inner = self.lock();
        let id = *inner.ids.get(&(org, host.to_string()))?;
        let entry = inner.entries.get_mut(&id)?;
        if entry.details != details {
            return None;
        }
        entry.last_seen = now_s;
        inner.dirty.insert(id);
        Some(id)
    }

    pub fn remember(&self, org: i64, host: &str, id: i64, details: &str, agent_sha: &str, now_s: i64) {
        let mut inner = self.lock();
        inner.ids.insert((org, host.to_string()), id);
        let recent_seq = inner.entries.remove(&id).map(|e| e.recent_seq).unwrap_or_default();
        inner.entries.insert(id, Entry { org, host: host.to_string(), last_seen: now_s, details: details.to_string(), agent_sha: agent_sha.to_string(), recent_seq });
        inner.dirty.insert(id);
    }

    /// Drops everything known about a computer, when it is removed by an administrator.
    pub fn forget(&self, id: i64) {
        let mut inner = self.lock();
        if let Some(entry) = inner.entries.remove(&id) {
            inner.ids.remove(&(entry.org, entry.host));
        }
        inner.dirty.remove(&id);
    }

    /// Drops every computer of an organisation that is being removed.
    pub fn forget_org(&self, org: i64) {
        let mut inner = self.lock();
        let gone: Vec<i64> = inner.entries.iter().filter(|(_, e)| e.org == org).map(|(id, _)| *id).collect();
        for id in gone {
            inner.entries.remove(&id);
            inner.dirty.remove(&id);
        }
        inner.ids.retain(|(o, _), _| *o != org);
    }

    pub fn known(&self) -> usize {
        self.lock().entries.len()
    }

    /// Ids of one organisation's computers that checked in within the last `window_s` seconds.
    pub fn online(&self, org: i64, now_s: i64, window_s: i64) -> HashSet<i64> {
        self.lock().entries.iter().filter(|(_, e)| e.org == org && now_s - e.last_seen <= window_s).map(|(id, _)| *id).collect()
    }

    pub fn last_seen(&self) -> HashMap<i64, i64> {
        self.lock().entries.iter().map(|(id, e)| (*id, e.last_seen)).collect()
    }

    /// Which agent program each computer of an organisation reported, for those that reported one.
    pub fn agent_shas(&self, org: i64) -> HashMap<i64, String> {
        self.lock().entries.iter().filter(|(_, e)| e.org == org && !e.agent_sha.is_empty()).map(|(id, e)| (*id, e.agent_sha.clone())).collect()
    }

    /// Check-in times changed since the last call, for writing to disk.
    pub fn take_dirty(&self) -> Vec<(i64, i64)> {
        let mut inner = self.lock();
        let ids: Vec<i64> = inner.dirty.drain().collect();
        ids.into_iter().filter_map(|id| inner.entries.get(&id).map(|e| (id, e.last_seen))).collect()
    }

    pub fn already_stored(&self, id: i64, seq: u64) -> bool {
        self.lock().entries.get(&id).is_some_and(|e| e.recent_seq.contains(&seq))
    }

    pub fn mark_stored(&self, id: i64, seq: u64) {
        let mut inner = self.lock();
        if let Some(entry) = inner.entries.get_mut(&id) {
            if !entry.recent_seq.contains(&seq) {
                if entry.recent_seq.len() >= RECENT_SEQS {
                    entry.recent_seq.pop_front();
                }
                entry.recent_seq.push_back(seq);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_computer_checks_in_without_touching_the_database() {
        let hub = Hub::default();
        assert_eq!(hub.check_in(1, "PC-1", "10.0.0.5|win11|1.0", 100), None, "unknown: the caller creates the row");
        hub.remember(1, "PC-1", 7, "10.0.0.5|win11|1.0", "", 100);
        assert_eq!(hub.check_in(1, "PC-1", "10.0.0.5|win11|1.0", 160), Some(7));
        assert_eq!(hub.last_seen()[&7], 160);
        // New address: the row must be refreshed.
        assert_eq!(hub.check_in(1, "PC-1", "10.0.0.9|win11|1.0", 220), None);
        hub.remember(1, "PC-1", 7, "10.0.0.9|win11|1.0", "", 220);
        assert_eq!(hub.check_in(1, "PC-1", "10.0.0.9|win11|1.0", 280), Some(7));
        assert_eq!(hub.known(), 1);
    }

    #[test]
    fn the_same_name_in_two_organisations_is_two_computers() {
        let hub = Hub::default();
        hub.remember(1, "RECEPTION", 10, "d", "sha-a", 100);
        assert_eq!(hub.check_in(2, "RECEPTION", "d", 100), None, "the other organisation has not seen this name yet");
        hub.remember(2, "RECEPTION", 20, "d", "sha-b", 100);
        assert_eq!(hub.check_in(1, "RECEPTION", "d", 150), Some(10));
        assert_eq!(hub.check_in(2, "RECEPTION", "d", 150), Some(20));
        assert_eq!(hub.online(1, 150, 60), HashSet::from([10]));
        assert_eq!(hub.online(2, 150, 60), HashSet::from([20]));
        assert_eq!(hub.agent_shas(1), HashMap::from([(10, "sha-a".to_string())]));

        hub.forget_org(1);
        assert_eq!(hub.check_in(1, "RECEPTION", "d", 200), None);
        assert_eq!(hub.check_in(2, "RECEPTION", "d", 200), Some(20), "removing one organisation leaves the other alone");
        assert_eq!(hub.known(), 1);
    }

    #[test]
    fn online_means_checked_in_recently() {
        let hub = Hub::default();
        hub.remember(1, "A", 1, "", "", 1000);
        hub.remember(1, "B", 2, "", "", 900);
        assert_eq!(hub.online(1, 1000, 150), HashSet::from([1, 2]));
        assert_eq!(hub.online(1, 1100, 150), HashSet::from([1]));
        assert!(hub.online(1, 2000, 150).is_empty());
        hub.forget(1);
        assert_eq!(hub.check_in(1, "A", "", 2000), None);
    }

    #[test]
    fn dirty_times_are_handed_out_once() {
        let hub = Hub::default();
        hub.remember(1, "A", 7, "", "", 100);
        hub.check_in(1, "A", "", 101);
        assert_eq!(hub.take_dirty(), [(7, 101)]);
        assert!(hub.take_dirty().is_empty());
    }

    #[test]
    fn replayed_batches_are_recognised_and_survive_a_details_change() {
        let hub = Hub::default();
        hub.remember(1, "A", 1, "v1", "", 0);
        assert!(!hub.already_stored(1, 5));
        hub.mark_stored(1, 5);
        assert!(hub.already_stored(1, 5));
        assert!(!hub.already_stored(1, 4), "an older, never-seen sequence is new data");
        hub.remember(1, "A", 1, "v2", "", 10);
        assert!(hub.already_stored(1, 5), "updating details keeps the replay memory");
        for seq in 6..6 + RECENT_SEQS as u64 {
            hub.mark_stored(1, seq);
        }
        assert!(!hub.already_stored(1, 5), "only the most recent few are remembered");
    }
}
