//! Messages between the per-user tray helper and the background service,
//! sent as JSON lines over a local named pipe.
//!
//! The helper sees what the user is doing (only a process in the user's
//! session can); the service talks to the server and owns the upload queue.
//! Activity flows helper -> service; policy and status flow back.

use ems_proto::{AppUse, Event, Policy, Visit};
use serde::{Deserialize, Serialize};

/// Longest accepted line. A helper that sends more is disconnected.
pub const MAX_LINE: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ToCore {
    Hello { user: String, session: u32 },
    Visit(Visit),
    App(AppUse),
    Event(Event),
    SyncNow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ToSession {
    Policy { policy: Policy },
    Status { status: Status },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Status {
    /// The last check-in with the server succeeded.
    pub connected: bool,
    pub server: String,
    /// Name of the organisation this computer belongs to, when known.
    #[serde(default)]
    pub org: String,
    pub hostname: String,
    pub pending: u64,
    #[serde(default)]
    pub last_sync_ms: Option<i64>,
    /// One-line summary of what the blocking layer last did.
    #[serde(default)]
    pub enforcement: String,
    pub version: String,
}
