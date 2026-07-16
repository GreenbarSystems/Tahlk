//! Rust-side ISO-8601 UTC timestamps for audit rows.
//!
//! Computed server-side (never trusted from JS) so an audit trail's "when"
//! can't be backdated or spoofed by a compromised WebView. Every audit table
//! that stamps its own `created_at` — `llm_audit` (via `notes.rs`) and
//! `patient_audit` — sources it from here.
//!
//! This module exists because `notes.rs` and `patient_audit.rs` each carried a
//! byte-identical private copy of the function below; `notes.rs`'s own comment
//! nominated the promotion ("if a second caller shows up, promote it to
//! `errors` or a `time` util"), and `patient_audit.rs` was that second caller.
//!
//! Deliberately kept a pure, side-effect-free formatter with no dependencies —
//! it is not a security control itself, only an input to ones.

/// ISO-8601 UTC timestamp, second precision (`2026-07-16T14:22:11Z`).
///
/// Audit rows don't need millisecond precision, and std has no ISO-8601
/// formatter, so this is pieced together from `SystemTime`.
pub(crate) fn utc_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Days-from-epoch → (y,m,d) via the civil-from-days algorithm; hours,
    // minutes, seconds fall out of the remainder. This is enough for the
    // audit-log timestamp — we're not doing calendar math anywhere else.
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Howard Hinnant "civil_from_days" (public domain).
    let z = days + 719_468;
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, minute, second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Relocated verbatim from notes.rs's test module alongside the function it
    // covers. Assertions are unchanged.
    #[test]
    fn utc_now_iso_shape() {
        let s = utc_now_iso();
        // Format: YYYY-MM-DDTHH:MM:SSZ (20 chars). We can't assert exact
        // values without freezing time — shape + a floor year keeps this
        // meaningful without turning into a change-detector test.
        assert_eq!(s.len(), 20, "unexpected timestamp: {:?}", s);
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[13..14], ":");
        assert_eq!(&s[16..17], ":");
        assert_eq!(&s[19..20], "Z");
        let year: i32 = s[..4].parse().unwrap();
        assert!(year >= 2026, "timestamp year suspiciously old: {}", year);
    }

    // Net-new: the shape test above would still pass on a garbage timestamp
    // like 2026-13-45T25:99:99Z, so an off-by-era regression in the
    // civil-from-days math could slip through it. This pins the components to
    // real calendar/clock ranges without freezing time.
    #[test]
    fn components_are_within_real_calendar_and_clock_ranges() {
        let s = utc_now_iso();
        let month: u32 = s[5..7].parse().expect("month should parse");
        let day: u32 = s[8..10].parse().expect("day should parse");
        let hour: u32 = s[11..13].parse().expect("hour should parse");
        let minute: u32 = s[14..16].parse().expect("minute should parse");
        let second: u32 = s[17..19].parse().expect("second should parse");

        assert!((1..=12).contains(&month), "month out of range: {month}");
        assert!((1..=31).contains(&day), "day out of range: {day}");
        assert!(hour < 24, "hour out of range: {hour}");
        assert!(minute < 60, "minute out of range: {minute}");
        assert!(second < 60, "second out of range: {second}");
    }
}
