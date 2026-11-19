//! A slow-changing snapshot of the computer: a system summary (what it is,
//! how up to date Windows is, how it is on the network, what it can print
//! to), the list of installed programs, and the tail of the agent's own log.
//!
//! Everything here is read from the registry and a few system calls, so it
//! is cheap and needs no extra service. It is gathered by the background
//! service once a day and uploaded only when it has changed.

use ems_proto::{InstalledApp, Inventory, SystemInfo};
use std::collections::BTreeMap;
use std::path::Path;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows::Win32::Graphics::Printing::{EnumPrintersW, PRINTER_ENUM_CONNECTIONS, PRINTER_ENUM_LOCAL, PRINTER_INFO_4W};
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH};
use windows::Win32::Networking::WinSock::AF_UNSPEC;
use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows::Win32::System::SystemInformation::{GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX};
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS};
use winreg::{RegKey, HKEY};

/// Caps so one strange machine cannot send an unbounded payload.
const MAX_APPS: usize = 2000;
const MAX_PRINTERS: usize = 200;
const MAX_LOG_LINES: usize = 150;
const GB: u64 = 1024 * 1024 * 1024;

fn reg_str(root: HKEY, path: &str, name: &str) -> Option<String> {
    let value: String = RegKey::predef(root).open_subkey(path).ok()?.get_value(name).ok()?;
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn total_ram_mb() -> u64 {
    let mut m = MEMORYSTATUSEX { dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32, ..Default::default() };
    unsafe {
        if GlobalMemoryStatusEx(&mut m).is_ok() {
            return m.ullTotalPhys / 1024 / 1024;
        }
    }
    0
}

/// Total and free space of the system drive, in whole gigabytes.
fn system_drive() -> (u64, u64) {
    let root = HSTRING::from(format!("{}\\", std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())));
    let (mut total, mut free) = (0u64, 0u64);
    unsafe {
        if GetDiskFreeSpaceExW(PCWSTR(root.as_ptr()), None, Some(&mut total), Some(&mut free)).is_ok() {
            return (total / GB, free / GB);
        }
    }
    (0, 0)
}

/// A Windows update is installed but the computer has not restarted to finish it.
fn reboot_pending() -> bool {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    ]
    .iter()
    .any(|path| hklm.open_subkey(path).is_ok())
}

fn last_windows_update() -> Option<String> {
    reg_str(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install", "LastSuccessTime")
}

/// `YYYY-MM-DD` (UTC) for a Unix timestamp, by Howard Hinnant's day algorithm.
fn epoch_to_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// When this Windows build was installed (the last feature update).
fn os_installed() -> Option<String> {
    let secs: u32 = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").ok()?.get_value("InstallDate").ok()?;
    (secs > 0).then(|| epoch_to_date(u64::from(secs)))
}

/// The hardware address and kind (Wi-Fi/Ethernet) of the adapter the computer
/// is actually using — the one that is up and has a gateway, preferred.
fn net_adapter() -> (Option<String>, Option<String>) {
    unsafe {
        let flags = GET_ADAPTERS_ADDRESSES_FLAGS(0);
        let mut size: u32 = 15 * 1024;
        let mut buf = vec![0u8; size as usize];
        let mut ret = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH), &mut size);
        if ret == ERROR_BUFFER_OVERFLOW.0 {
            buf = vec![0u8; size as usize];
            ret = GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH), &mut size);
        }
        if ret != ERROR_SUCCESS.0 {
            return (None, None);
        }
        // (mac, kind, has_gateway) of the best adapter seen so far.
        let mut best: Option<(String, String, bool)> = None;
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = &*cur;
            let up = a.OperStatus.0 == 1; // IfOperStatusUp
            let is_loopback = a.IfType == 24; // IF_TYPE_SOFTWARE_LOOPBACK
            if up && !is_loopback && a.PhysicalAddressLength >= 6 {
                let mac = a.PhysicalAddress[..6].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
                let kind = match a.IfType {
                    6 => "Ethernet",
                    71 => "Wi-Fi",
                    131 => "Tunnel",
                    _ => "Other",
                }
                .to_string();
                let has_gw = !a.FirstGatewayAddress.is_null();
                let better = best.as_ref().map_or(true, |(_, _, prev_gw)| has_gw && !prev_gw);
                if better {
                    best = Some((mac, kind, has_gw));
                }
            }
            cur = a.Next;
        }
        match best {
            Some((mac, kind, _)) => (Some(mac), Some(kind)),
            None => (None, None),
        }
    }
}

/// The printers the computer can print to (local and network connections).
fn printers() -> Vec<String> {
    let flags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS;
    unsafe {
        let (mut needed, mut count) = (0u32, 0u32);
        // First call learns the size; it returns an error, which is expected.
        let _ = EnumPrintersW(flags, PCWSTR::null(), 4, None, &mut needed, &mut count);
        if needed == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; needed as usize];
        if EnumPrintersW(flags, PCWSTR::null(), 4, Some(&mut buf), &mut needed, &mut count).is_err() {
            return Vec::new();
        }
        let infos = std::slice::from_raw_parts(buf.as_ptr() as *const PRINTER_INFO_4W, count as usize);
        let mut out: Vec<String> = infos
            .iter()
            .filter_map(|p| p.pPrinterName.to_string().ok())
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect();
        out.sort();
        out.dedup();
        out.truncate(MAX_PRINTERS);
        out
    }
}

/// The last lines of the agent's own log, each trimmed to a sane length.
fn read_log_tail(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    let mut lines: Vec<String> = text.lines().rev().take(MAX_LOG_LINES).map(|l| ems_proto::truncate(l, 500)).collect();
    lines.reverse();
    lines
}

pub fn system_info(server_url: &str) -> SystemInfo {
    let (disk_total_gb, disk_free_gb) = system_drive();
    let (mac, net_type) = net_adapter();
    let local_ip = crate::config::local_ip(server_url);
    SystemInfo {
        os: crate::core::os_version(),
        cpu: reg_str(HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString").unwrap_or_default(),
        ram_mb: total_ram_mb(),
        disk_total_gb,
        disk_free_gb,
        manufacturer: reg_str(HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer").unwrap_or_default(),
        model: reg_str(HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName").unwrap_or_default(),
        uptime_s: unsafe { GetTickCount64() } / 1000,
        os_installed: os_installed(),
        last_update: last_windows_update(),
        reboot_pending: reboot_pending(),
        local_ip: (!local_ip.is_empty()).then_some(local_ip),
        public_ip: None, // the server fills this in from the address it sees
        mac,
        net_type,
        printers: printers(),
    }
}

/// Reads one "Uninstall" key and adds each real program to `out`, keyed by
/// name and version so the same program seen twice is listed once.
fn collect_uninstall(key: &RegKey, out: &mut BTreeMap<(String, String), InstalledApp>) {
    for sub_name in key.enum_keys().flatten() {
        let Ok(sub) = key.open_subkey(&sub_name) else { continue };
        let name = match sub.get_value::<String, _>("DisplayName") {
            Ok(n) if !n.trim().is_empty() => n.trim().to_string(),
            _ => continue,
        };
        if sub.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1 {
            continue;
        }
        if sub.get_value::<String, _>("ParentKeyName").is_ok() || sub.get_value::<String, _>("ReleaseType").is_ok_and(|t| t.contains("Update")) {
            continue;
        }
        let opt = |v: &str| sub.get_value::<String, _>(v).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let version = opt("DisplayVersion");
        out.entry((name.to_lowercase(), version.clone().unwrap_or_default())).or_insert(InstalledApp {
            name,
            version,
            publisher: opt("Publisher"),
            installed_on: opt("InstallDate"),
        });
    }
}

pub fn installed_apps() -> Vec<InstalledApp> {
    let mut found = BTreeMap::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for path in [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"] {
        if let Ok(key) = hklm.open_subkey(path) {
            collect_uninstall(&key, &mut found);
        }
    }
    let hku = RegKey::predef(HKEY_USERS);
    for sid in hku.enum_keys().flatten() {
        if !sid.starts_with("S-1-5-21") || sid.ends_with("_Classes") {
            continue;
        }
        for suffix in [r"Software\Microsoft\Windows\CurrentVersion\Uninstall", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"] {
            if let Ok(key) = hku.open_subkey(format!("{sid}\\{suffix}")) {
                collect_uninstall(&key, &mut found);
            }
        }
    }
    let mut apps: Vec<InstalledApp> = found.into_values().collect();
    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(a.version.cmp(&b.version)));
    apps.truncate(MAX_APPS);
    apps
}

pub fn collect(server_url: &str, log_path: &Path) -> Inventory {
    Inventory { system: system_info(server_url), apps: installed_apps(), log_tail: read_log_tail(log_path) }
}
