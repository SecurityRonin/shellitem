//! FAT (MS-DOS) date/time → Unix epoch seconds conversion.
//!
//! Shell-item file entries and the `0xbeef0004` extension block store
//! timestamps as a 32-bit packed FAT date/time in UTC (libfwsi, *Windows Shell
//! Item format*). The low 16 bits are the time, the high 16 bits the date:
//!
//! - time: bits 0–4 = seconds / 2, bits 5–10 = minutes, bits 11–15 = hours
//! - date: bits 0–4 = day (1–31), bits 5–8 = month (1–12), bits 9–15 = years
//!   since 1980
//!
//! A FAT date of `0` (the common "no timestamp" sentinel) yields `None`.
//! Conversion is overflow-safe and self-contained — no `chrono`/`time`
//! dependency, matching the zero-dep posture of a parser primitive.

/// Number of days in each month for a non-leap year, indexed `month - 1`.
const DAYS_IN_MONTH: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Convert a packed 32-bit FAT date/time (UTC) to Unix epoch seconds.
///
/// Returns `None` when the value is `0` (no timestamp) or when the packed
/// fields are out of range (month `0`/`>12`, day `0`/`>31`) — a malformed
/// field never yields a bogus timestamp, it yields `None`.
#[must_use]
pub(crate) fn fat_to_epoch(value: u32) -> Option<i64> {
    if value == 0 {
        return None;
    }
    let time = (value & 0xFFFF) as u32;
    let date = (value >> 16) as u32;

    let second = ((time & 0x1F) * 2) as u64;
    let minute = ((time >> 5) & 0x3F) as u64;
    let hour = ((time >> 11) & 0x1F) as u64;

    let day = (date & 0x1F) as u64;
    let month = ((date >> 5) & 0x0F) as u64;
    let year = 1980 + ((date >> 9) & 0x7F) as u64;

    if month < 1 || month > 12 || day < 1 || day > 31 {
        return None;
    }

    // Days from the Unix epoch (1970-01-01) to the start of `year`.
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    // Days from the start of `year` to the start of `month`.
    for m in 1..month {
        days += DAYS_IN_MONTH[(m - 1) as usize];
        if m == 2 && is_leap(year) {
            days += 1;
        }
    }
    days += day - 1;

    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    i64::try_from(secs).ok()
}

/// Whether `year` is a Gregorian leap year.
fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Convert a 64-bit Windows `FILETIME` (100-ns intervals since 1601-01-01 UTC)
/// to Unix epoch seconds. Used by the newer `0xbeef0026`-style full-FILETIME
/// timestamps. Returns `None` for a `0` value (no timestamp).
#[must_use]
pub(crate) fn filetime_to_epoch(value: u64) -> Option<i64> {
    if value == 0 {
        return None;
    }
    // 11_644_473_600 = seconds between 1601-01-01 and 1970-01-01.
    let secs_since_1601 = value / 10_000_000;
    let epoch = i64::try_from(secs_since_1601).ok()? - 11_644_473_600;
    Some(epoch)
}
