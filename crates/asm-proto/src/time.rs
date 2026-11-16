//! RFC 3339 UTC timestamps without external dependencies.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Format as RFC 3339 UTC with second precision, e.g. `2026-11-16T12:34:56Z`.
pub fn fmt_rfc3339(t: SystemTime) -> String {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs_f64().ceil() as i64),
    };
    fmt_unix(secs)
}

/// Format Unix seconds as RFC 3339 UTC, e.g. `2026-11-16T12:34:56Z`.
pub fn fmt_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        sod / 60 % 60,
        sod % 60
    )
}

/// Current time as RFC 3339 UTC.
pub fn now_rfc3339() -> String {
    fmt_rfc3339(SystemTime::now())
}

/// Parse RFC 3339 (`YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`) to Unix seconds (fraction truncated).
pub fn parse_unix(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let p = b.get(r)?;
        if !p.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(p.iter().fold(0i64, |a, c| a * 10 + (c - b'0') as i64))
    };
    if b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut i = 19;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    let offset = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 3600 + om * 60;
            if *sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se.min(59) - offset)
}

/// Parse RFC 3339 to a `SystemTime`.
pub fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    let secs = parse_unix(s)?;
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's civil-date algorithms.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_and_parse() {
        assert_eq!(fmt_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(fmt_unix(1_795_437_296), "2026-11-23T12:34:56Z");
        assert_eq!(fmt_unix(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(parse_unix("2026-11-23T12:34:56Z"), Some(1_795_437_296));
        assert_eq!(parse_unix("2026-11-23T13:34:56.123+01:00"), Some(1_795_437_296));
        assert_eq!(parse_unix("1969-12-31T23:59:59Z"), Some(-1));
        assert_eq!(parse_unix("2026-02-29T00:00:00Z"), None);
        assert_eq!(parse_unix("2026-11-23T08:34:56"), None);
        assert_eq!(parse_unix("2026-11-23T08:34:56Zx"), None);
        let now = SystemTime::now();
        let s = fmt_rfc3339(now);
        let back = parse_rfc3339(&s).unwrap();
        assert!(now.duration_since(back).unwrap() < Duration::from_secs(1));
    }
}
