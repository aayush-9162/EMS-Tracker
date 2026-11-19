//! Local named pipe between the service and the per-user tray helpers.

use crate::core::{lock, Shared};
use crate::ipc::{ToCore, ToSession, MAX_LINE};
use crate::spool::Row;
use anyhow::Context;
use std::ffi::c_void;
use std::os::windows::io::RawHandle;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use tokio::sync::watch;
use windows::core::{w, HSTRING};
use windows::Win32::Foundation::{ERROR_PIPE_BUSY, GENERIC_READ, HANDLE};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};

/// Who may use the pipe:
///   SYSTEM, Administrators and the pipe's owner: full control;
///   interactive users: read and write data only.
/// Interactive users are deliberately not given the right to create new
/// instances of the pipe, so no other program can pose as the service.
const PIPE_SDDL: windows::core::PCWSTR = w!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12019b;;;IU)");

struct PipeSecurity {
    attrs: SECURITY_ATTRIBUTES,
}
// The descriptor is allocated once and never freed or mutated.
unsafe impl Send for PipeSecurity {}
unsafe impl Sync for PipeSecurity {}

fn pipe_security() -> anyhow::Result<PipeSecurity> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PIPE_SDDL, SDDL_REVISION_1, &mut sd, None).context("building the pipe security descriptor")?;
    }
    Ok(PipeSecurity {
        attrs: SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() },
    })
}

fn create_instance(name: &str, first: bool, sec: &PipeSecurity) -> std::io::Result<NamedPipeServer> {
    let mut attrs = sec.attrs;
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(64)
            .create_with_security_attributes_raw(name, &mut attrs as *mut SECURITY_ATTRIBUTES as *mut c_void)
    }
}

/// Accepts tray helpers until shutdown.
pub async fn serve(shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let name = shared.ctx.pipe_name.clone();
    let sec = match pipe_security() {
        Ok(s) => s,
        Err(e) => {
            crate::log!("local pipe unavailable: {e:#}");
            return;
        }
    };
    let mut server = match create_instance(&name, true, &sec) {
        Ok(s) => s,
        Err(e) => {
            crate::log!("could not create {name}: {e}. Is another copy of the agent running?");
            return;
        }
    };
    loop {
        tokio::select! {
            connected = server.connect() => {
                if let Err(e) = connected {
                    crate::log!("pipe accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                let next = match create_instance(&name, false, &sec) {
                    Ok(s) => s,
                    Err(e) => {
                        crate::log!("could not create the next pipe instance: {e}");
                        return;
                    }
                };
                let client = std::mem::replace(&mut server, next);
                tokio::spawn(handle_client(client, shared.clone(), shutdown.clone()));
            }
            _ = shutdown.changed() => return,
        }
    }
}

async fn write_line<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, msg: &ToSession) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(msg)?;
    line.push(b'\n');
    w.write_all(&line).await
}

async fn handle_client(pipe: NamedPipeServer, shared: Arc<Shared>, mut shutdown: watch::Receiver<bool>) {
    let (read, mut write) = tokio::io::split(pipe);
    let mut reader = BufReader::new(read);
    let mut policy_rx = shared.policy.subscribe();
    let mut status_rx = shared.status.subscribe();
    let mut user = String::new();
    let mut session: Option<u32> = None;
    let mut buf = Vec::new();

    let initial_policy = policy_rx.borrow_and_update().clone();
    let initial_status = status_rx.borrow_and_update().clone();
    if write_line(&mut write, &ToSession::Policy { policy: initial_policy }).await.is_err()
        || write_line(&mut write, &ToSession::Status { status: initial_status }).await.is_err()
    {
        return;
    }

    loop {
        tokio::select! {
            read = read_capped_line(&mut reader, &mut buf) => {
                match read {
                    Ok(true) => {}
                    _ => break,
                }
                let Ok(msg) = serde_json::from_slice::<ToCore>(&buf) else { continue };
                match msg {
                    ToCore::Hello { user: u, session: s } => {
                        user = ems_proto::truncate(u.trim(), 255);
                        if session.is_none() {
                            *lock(&shared.sessions).entry(s).or_insert(0) += 1;
                            session = Some(s);
                            crate::log!("tray helper connected: user {user}, session {s}");
                        }
                    }
                    // Rows are attributed to whoever said hello, not to what each row claims.
                    ToCore::Visit(mut v) => { v.user = user.clone(); shared.push_row(&Row::Visit(v)); }
                    ToCore::App(mut a) => { a.user = user.clone(); shared.push_row(&Row::App(a)); }
                    ToCore::Event(mut e) => { e.user = user.clone(); shared.push_row(&Row::Event(e)); }
                    ToCore::SyncNow => shared.sync_now.notify_one(),
                }
            }
            changed = policy_rx.changed() => {
                if changed.is_err() { break; }
                let policy = policy_rx.borrow_and_update().clone();
                if write_line(&mut write, &ToSession::Policy { policy }).await.is_err() { break; }
            }
            changed = status_rx.changed() => {
                if changed.is_err() { break; }
                let status = status_rx.borrow_and_update().clone();
                if write_line(&mut write, &ToSession::Status { status }).await.is_err() { break; }
            }
            _ = shutdown.changed() => break,
        }
    }

    if let Some(s) = session {
        let mut sessions = lock(&shared.sessions);
        if let Some(n) = sessions.get_mut(&s) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                sessions.remove(&s);
            }
        }
        crate::log!("tray helper disconnected: session {s}");
    }
}

/// Reads one line into `buf` (without the newline). `Ok(false)` at end of
/// stream. Errors if the line exceeds [`MAX_LINE`], which ends the client.
pub async fn read_capped_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<bool> {
    buf.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(false);
        }
        let (take, done) = match available.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (available.len(), false),
        };
        buf.extend_from_slice(&available[..take]);
        reader.consume(take);
        if buf.len() > MAX_LINE {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
        }
        if done {
            while matches!(buf.last(), Some(b'\n' | b'\r')) {
                buf.pop();
            }
            return Ok(true);
        }
    }
}

/// Connects as a client and returns the service's current policy and status.
pub async fn query(name: &str) -> anyhow::Result<(ems_proto::Policy, crate::ipc::Status)> {
    let pipe = connect(name)?;
    let mut reader = BufReader::new(pipe);
    let mut buf = Vec::new();
    let (mut policy, mut status) = (None, None);
    while policy.is_none() || status.is_none() {
        if !read_capped_line(&mut reader, &mut buf).await? {
            anyhow::bail!("the service closed the connection");
        }
        match serde_json::from_slice::<ToSession>(&buf) {
            Ok(ToSession::Policy { policy: p }) => policy = Some(p),
            Ok(ToSession::Status { status: s }) => status = Some(s),
            Err(_) => {}
        }
    }
    Ok((policy.expect("set above"), status.expect("set above")))
}

/// Opens the client end of the pipe, asking for exactly the access the
/// service grants to interactive users.
pub fn connect(name: &str) -> std::io::Result<NamedPipeClient> {
    let handle: HANDLE = unsafe {
        CreateFileW(
            &HSTRING::from(name),
            GENERIC_READ.0 | FILE_WRITE_DATA.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            // Lets the service identify, but never act as, the connecting user.
            FILE_FLAG_OVERLAPPED | FILE_FLAGS_AND_ATTRIBUTES(SECURITY_SQOS_PRESENT.0 | SECURITY_IDENTIFICATION.0),
            None,
        )
    }
    .map_err(|e| {
        if e.code() == ERROR_PIPE_BUSY.to_hresult() {
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "pipe busy")
        } else {
            std::io::Error::from_raw_os_error(e.code().0 & 0xffff)
        }
    })?;
    unsafe { NamedPipeClient::from_raw_handle(handle.0 as RawHandle) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lines_are_split_and_long_ones_rejected() {
        let data = b"{\"a\":1}\r\nsecond\n".to_vec();
        let mut reader = BufReader::with_capacity(4, &data[..]);
        let mut buf = Vec::new();
        assert!(read_capped_line(&mut reader, &mut buf).await.unwrap());
        assert_eq!(buf, b"{\"a\":1}");
        assert!(read_capped_line(&mut reader, &mut buf).await.unwrap());
        assert_eq!(buf, b"second");
        assert!(!read_capped_line(&mut reader, &mut buf).await.unwrap());

        let huge = vec![b'x'; MAX_LINE + 10];
        let mut reader = BufReader::new(&huge[..]);
        assert!(read_capped_line(&mut reader, &mut buf).await.is_err());
    }
}
