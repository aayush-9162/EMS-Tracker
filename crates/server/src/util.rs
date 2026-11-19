//! Small helpers: time, randomness, hashing, logging.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn now_s() -> i64 {
    now_ms() / 1000
}

/// `bytes` random bytes, hex encoded (so the result is twice as long).
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("operating system random source unavailable");
    hex(&buf)
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

pub fn sha256_hex(input: &str) -> String {
    hex(&Sha256::digest(input.as_bytes()))
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Parses `YYYY-MM-DD` into the Unix-ms instant at which that day starts in
/// a zone `tz_offset_min` minutes east of UTC.
pub fn day_start_ms(date: &str, tz_offset_min: i32) -> Option<i64> {
    let b = date.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let y: i64 = date[0..4].parse().ok()?;
    let m: i64 = date[5..7].parse().ok()?;
    let d: i64 = date[8..10].parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d) * 86_400_000 - i64::from(tz_offset_min) * 60_000)
}

/// Formats a Unix-ms instant as `YYYY-MM-DD HH:MM:SS` in the given zone.
pub fn fmt_local(ms: i64, tz_offset_min: i32) -> String {
    let local = ms + i64::from(tz_offset_min) * 60_000;
    let days = local.div_euclid(86_400_000);
    let secs = local.rem_euclid(86_400_000) / 1000;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// Timestamped line on stderr. Under systemd or Docker this lands in the journal.
#[macro_export]
macro_rules! logln {
    ($($arg:tt)*) => {
        eprintln!("{} {}", $crate::util::fmt_local($crate::util::now_ms(), 0), format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        for z in [-800_000, -1, 0, 1, 59, 60, 11_016, 11_017, 19_000, 20_770, 800_000] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
        assert_eq!(civil_from_days(20_770), (2026, 11, 13));
    }

    #[test]
    fn day_boundaries_follow_the_zone() {
        let utc = day_start_ms("2026-11-13", 0).unwrap();
        assert_eq!(utc, 20_770 * 86_400_000);
        // India is UTC+05:30, so its day starts 5.5 hours earlier in UTC.
        assert_eq!(day_start_ms("2026-11-13", 330).unwrap(), utc - 330 * 60_000);
        assert_eq!(fmt_local(utc, 0), "2026-11-13 00:00:00");
        assert_eq!(fmt_local(utc - 330 * 60_000, 330), "2026-11-13 00:00:00");
        assert_eq!(fmt_local(utc + 3_723_000, 0), "2026-11-13 01:02:03");
        for bad in ["2026-13-01", "2026-1-01", "20261113", "", "abcd-ef-gh", "2026-11-32"] {
            assert_eq!(day_start_ms(bad, 0), None, "{bad}");
        }
    }

    #[test]
    fn random_values_and_hashes() {
        assert_eq!(random_hex(16).len(), 32);
        assert_ne!(random_hex(16), random_hex(16));
        assert_eq!(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
