//! Record retention policy — HIPAA §164.530(j) expiration enforcement.
//!
//! Covered entities must retain records for at least 6 years from creation
//! or last effective date; many state rules require 7 or 10 years. This
//! module lets a provider configure their retention window and destroy
//! encounter records that have aged past it:
//!
//!   - Retention window (years) is stored in the `kv` table.
//!   - Litigation hold flag is also stored in `kv` and suspends automated
//!     destruction when legal matters require preserving records beyond the
//!     normal window.
//!   - `retention_list_candidates` surfaces encounters whose `encounter_date`
//!     predates the cutoff — the provider reviews before committing.
//!   - `retention_destroy_eligible` runs the actual destruction, delegating
//!     to `encounters::delete_encounter_row` so every destruction is logged
//!     to `destruction_log` with `legal_basis = "retention_expired"`.
//!
//! Storage: two rows in the existing `kv` table; no new tables.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use tauri::{AppHandle, State};

use crate::errors::AppError;
use crate::DbState;

/// Whether a litigation hold is currently active.
///
/// Fails CLOSED: a read error propagates instead of being flattened to
/// `false`. This reverses the original decision, which returned `false` on any
/// DB fault so a transient error could not block deletions. That reasoning is
/// right for an availability-sensitive check and wrong for this one — a hold is
/// a legal preservation obligation, and destroying records under one is
/// spoliation. A blocked deletion is recoverable by retrying; a spoliated
/// record is not. When the hold state cannot be determined, callers must
/// refuse to destroy.
pub(crate) fn litigation_hold_is_active(conn: &Connection) -> Result<bool, AppError> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_LITIGATION_HOLD],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| {
            AppError::Storage(format!(
                "could not determine litigation-hold state, refusing to destroy records: {e}"
            ))
        })?;
    Ok(raw.as_deref() == Some("true"))
}

/// Guard for every PHI-destruction path: returns `Err` when a hold is active
/// (or cannot be read). `subject` names what is being destroyed and is
/// interpolated into the message the provider sees, e.g. "encounter records".
///
/// Lives here, but is invoked from inside `encounters::delete_encounter_in_tx`
/// rather than at each call site. The original C5 fix guarded the two outer
/// wrappers (`delete_encounter_row`, `delete_patient_conn`) and missed
/// `destroy_patient_records`, which reaches the inner function directly — so
/// the app's most destructive command ran freely under an active hold. Putting
/// the check on the inner function makes it structurally impossible for a new
/// caller to skip it.
pub(crate) fn litigation_hold_check(conn: &Connection, subject: &str) -> Result<(), AppError> {
    if litigation_hold_is_active(conn)? {
        // Precondition, not a frontend bug: the provider set this hold and
        // needs to be told it is why the deletion refused.
        return Err(AppError::precondition(format!(
            "Litigation hold is active — {subject} cannot be deleted until the hold is lifted."
        )));
    }
    Ok(())
}

// Actor is derived server-side via `kv_ops::provider_id` — this module used to
// carry its own copy of that read.

// pub(crate) so `secrets::WRITE_ONLY_PROTECTED_KEYS` can name them directly
// rather than repeating the literals — the guard and the reader must never
// drift apart. Both are write-blocked on the generic KV API: they gate PHI
// destruction, and the dedicated commands below are the only sanctioned
// write path (they validate, and they write a config_audit row).
pub(crate) const KV_RETENTION_YEARS: &str = "note_settings_v1::retention_years";
pub(crate) const KV_LITIGATION_HOLD: &str = "note_settings_v1::litigation_hold";
const DEFAULT_RETENTION_YEARS: i64 = 7;
const MIN_RETENTION_YEARS: i64 = 1;
const MAX_RETENTION_YEARS: i64 = 30;

/// The configured retention window, always clamped to [MIN, MAX].
///
/// The single reader for this value. `retention_set_years` validates its input
/// against 1..=30, but that guard only covers the sanctioned write path —
/// `retention_get_years` clamped on read while `retention_list_candidates` and
/// `retention_destroy_eligible` parsed the raw row with no clamp at all. A
/// value written around the command (previously possible via generic `kv_set`,
/// now blocked; still possible via direct DB access) therefore reached the
/// destroy path unbounded: `"0"` yields a cutoff of today and makes every
/// signed encounter eligible for destruction.
///
/// Clamping on READ rather than trusting the write path means the invariant
/// holds regardless of how the row got there.
fn retention_years(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT value FROM kv WHERE key = ?1",
        params![KV_RETENTION_YEARS],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| s.parse::<i64>().ok())
    .unwrap_or(DEFAULT_RETENTION_YEARS)
    .clamp(MIN_RETENTION_YEARS, MAX_RETENTION_YEARS)
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Shift a `YYYY-MM-DD` date by `delta` years (negative = into the past).
///
/// Returns `YYYY-MM-DD`. ISO date strings sort lexicographically, so the result
/// can be compared directly against `encounter_date` for "older/newer than"
/// filters.
///
/// Feb 29 is the one case plain year arithmetic gets wrong: it maps onto a
/// non-existent date whenever the target year is not a leap year (e.g.
/// 2028-02-29 minus 7 years is "2021-02-29", which does not exist). Left
/// verbatim, lexicographic comparison then treats `"2021-02-28" < "2021-02-29"`
/// as true and a record dated 2021-02-28 expires one day EARLY.
///
/// We always roll FORWARD to Mar 1 rather than back to Feb 28. In the
/// retention-cutoff direction that means one day of over-retention; in the
/// minor-floor direction (below) it means the protected window ends one day
/// later. Both err toward keeping records longer, which is the safe side:
/// retaining slightly too long is a recoverable policy deviation, destroying
/// early is not.
fn shift_years(date: &str, delta: i64) -> Option<String> {
    // `get` rather than direct slicing: a multi-byte character would make
    // byte-index slicing panic, and this parses caller-adjacent data.
    let year: i64 = date.get(0..4)?.parse().ok()?;
    let month: u32 = date.get(5..7)?.parse().ok()?;
    let day: u32 = date.get(8..10)?.parse().ok()?;
    if date.get(4..5) != Some("-") || date.get(7..8) != Some("-") {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let target = year + delta;
    if month == 2 && day == 29 && !is_leap_year(target) {
        return Some(format!("{target:04}-03-01"));
    }
    Some(format!("{target:04}-{month:02}-{day:02}"))
}

/// Compute the retention cutoff date by subtracting `years` from `today`.
/// A record whose `encounter_date` is strictly less than this cutoff has aged
/// past the standard window. Thin wrapper over `shift_years` (see there for the
/// leap-day handling this depends on).
fn cutoff_date(today: &str, years: i64) -> Option<String> {
    shift_years(today, -years)
}

/// Number of years to keep a minor's record *after* they reach majority (18).
///
/// Arizona minor-record retention: A.R.S. §12-2297 requires medical records of
/// a minor be retained until age 21 (3 years past 18), and the physician board
/// rule A.R.S. §32-2936 sets a 7-year adult floor. Rather than hard-code either
/// statutory constant, we model the common, conservative reading — "the ordinary
/// retention clock does not start until the patient turns 18" — by reusing the
/// provider's configured adult window as the post-majority tail. With the
/// default 7-year window that yields a floor of DOB + 18 + 7 = age 25, which
/// comfortably exceeds the §12-2297 age-21 statutory minimum, so the estimate is
/// deliberately on the conservative (longer-retention) side per this ticket's
/// guidance. The existing 7-year default already carries margin, so erring long
/// here costs nothing and never destroys a minor's record early.
///
/// This is a defensive enhancement, not a precisely-mandated formula: DOB is
/// optional, so when it is absent (the common case) the standard adult clock
/// governs unchanged.
fn minor_post_majority_tail(retention_years: i64) -> i64 {
    retention_years
}

const AGE_OF_MAJORITY: i64 = 18;

/// Decide whether a minor-record extension requires keeping an
/// otherwise-expired encounter longer.
///
/// Called only for encounters that have ALREADY aged past the standard cutoff,
/// so it can only ADD retention, never remove it. Returns `true` when the
/// record must still be retained (i.e. excluded from destruction) because the
/// patient was a minor at encounter time and the post-majority floor has not
/// yet been reached.
///
/// The floor is the LATER of the standard window (which the caller has already
/// applied) and `DOB + 18 + tail`. Behaves as a no-op — returns `false` — when
/// DOB is unknown, malformed, or the patient was already an adult at the
/// encounter, so retention for those cases is byte-for-byte the legacy behavior.
fn minor_extension_retains(
    encounter_date: &str,
    dob: Option<&str>,
    today: &str,
    retention_years: i64,
) -> bool {
    let Some(dob) = dob else { return false };

    // Was the patient a minor at encounter time? Minor iff the encounter
    // predates their 18th birthday.
    let Some(eighteenth) = shift_years(dob, AGE_OF_MAJORITY) else { return false };
    if encounter_date >= eighteenth.as_str() {
        return false; // adult at encounter — standard window already governs
    }

    // Minor floor: start the adult retention clock at majority.
    let tail = minor_post_majority_tail(retention_years);
    let Some(minor_floor) = shift_years(dob, AGE_OF_MAJORITY + tail) else { return false };

    // Retain while today has not yet reached the floor.
    today < minor_floor.as_str()
}

/// A signed encounter that has aged past the standard retention window and
/// survived the minor-extension filter, so it is eligible for destruction.
struct EligibleEncounter {
    id: String,
    encounter_date: String,
    patient_alias: Option<String>,
    status: String,
}

/// Shared candidate query for both the list and destroy paths, so the two can
/// never disagree about what "eligible" means. Selects signed encounters older
/// than the standard cutoff, LEFT JOINs the patient roster for an optional DOB,
/// and drops any whose minor-record floor has not yet been reached.
///
/// The LEFT JOIN keys on `encounters.patient_id`; legacy alias-only encounters
/// (no `patient_id`) get a NULL DOB and therefore the unchanged standard
/// behavior — consistent with DOB being optional.
fn collect_eligible(
    conn: &Connection,
    cutoff: &str,
    today: &str,
    years: i64,
) -> Result<Vec<EligibleEncounter>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT e.id, e.encounter_date, e.patient_alias, e.status, p.dob \
         FROM encounters e LEFT JOIN patients p ON e.patient_id = p.id \
         WHERE e.encounter_date < ?1 AND e.status = 'signed' \
         ORDER BY e.encounter_date ASC",
    )?;
    let rows = stmt.query_map(params![cutoff], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<String>>(4)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (id, encounter_date, patient_alias, status, dob) = row?;
        if minor_extension_retains(&encounter_date, dob.as_deref(), today, years) {
            continue; // patient was a minor; post-majority floor not yet reached
        }
        out.push(EligibleEncounter { id, encounter_date, patient_alias, status });
    }
    Ok(out)
}

/// Read the configured record-retention window. Defaults to 7 years when the
/// provider has not explicitly configured it.
#[tauri::command]
pub(crate) fn retention_get_years(state: State<'_, DbState>) -> Result<i64, AppError> {
    let conn = state.conn()?;
    Ok(retention_years(&conn))
}

/// Set the record-retention window in years. Accepted range: 1–30.
#[tauri::command]
pub(crate) fn retention_set_years(
    state: State<'_, DbState>,
    years: i64,
) -> Result<(), AppError> {
    if !(MIN_RETENTION_YEARS..=MAX_RETENTION_YEARS).contains(&years) {
        return Err(AppError::invalid(format!(
            "retention_years must be between {MIN_RETENTION_YEARS} and {MAX_RETENTION_YEARS}"
        )));
    }
    let mut conn = state.conn()?;
    set_policy_value(
        &mut conn,
        KV_RETENTION_YEARS,
        &years.to_string(),
        "retention_years_changed",
    )
}

/// Write one policy value and its audit row as a single atomic unit.
///
/// Both settings this module owns gate PHI destruction, so "changed but not
/// logged" is a state neither may enter. A bare pooled connection autocommits,
/// so the original code made the change durable and only THEN attempted the
/// audit append: if the append failed the setting had already moved, silently
/// and permanently, while the caller was told the operation failed. For the
/// litigation hold that means the provider believes records are preserved
/// while the hold is actually off and destruction is permitted.
///
/// Takes `&mut Connection` rather than living inside the `#[tauri::command]`
/// so the rollback is unit-testable without a Tauri State harness — the same
/// split `patients` and `encounters` use.
pub(crate) fn set_policy_value(
    conn: &mut Connection,
    key: &str,
    new_value: &str,
    action: &str,
) -> Result<(), AppError> {
    let tx = conn.transaction()?;
    let old: Option<String> = tx
        .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .optional()?;
    let actor = crate::kv_ops::provider_id(&tx);
    crate::kv_ops::upsert_json(&tx, key, new_value)?;
    crate::config_audit::append(&tx, action, old.as_deref(), new_value, &actor)?;
    tx.commit()?;
    Ok(())
}

/// Read the litigation-hold flag. When `true`, no records are eligible for
/// automated retention-based destruction.
#[tauri::command]
pub(crate) fn retention_hold_get(state: State<'_, DbState>) -> Result<bool, AppError> {
    let conn = state.conn()?;
    litigation_hold_is_active(&conn)
}

/// Set or clear the litigation hold. While active, `retention_list_candidates`
/// returns an empty list and `retention_destroy_eligible` refuses to run.
#[tauri::command]
pub(crate) fn retention_hold_set(
    state: State<'_, DbState>,
    active: bool,
) -> Result<(), AppError> {
    let mut conn = state.conn()?;
    // The more dangerous of the two: under the old non-atomic code a failed
    // audit append left the hold LIFTED while the UI reported failure — the
    // provider believes records are preserved, the trail shows no change was
    // ever made, and retention_destroy_eligible will now run.
    set_policy_value(
        &mut conn,
        KV_LITIGATION_HOLD,
        if active { "true" } else { "false" },
        "litigation_hold_changed",
    )
}

/// List signed encounters whose `encounter_date` predates the retention cutoff.
///
/// The cutoff date is derived server-side (High finding H2 closed: caller
/// cannot supply a future date to trigger premature destruction).
/// Only `status = 'signed'` encounters are returned — draft/in-progress
/// encounters are excluded so only legally attestable records are eligible
/// (Medium finding M2 closed).
/// Returns an empty list when a litigation hold is active.
/// Result is ordered oldest-first so the caller can present records
/// chronologically.
#[tauri::command]
pub(crate) fn retention_list_candidates(
    state: State<'_, DbState>,
) -> Result<Vec<Value>, AppError> {
    let conn = state.conn()?;

    // Listing, not destroying — a hold means "nothing is eligible", not an
    // error. Still routed through the fail-closed reader so an unreadable hold
    // state surfaces rather than silently presenting records as purgeable.
    if litigation_hold_is_active(&conn)? {
        return Ok(vec![]);
    }

    let years = retention_years(&conn);

    let today_iso = crate::time::utc_now_iso();
    let today = &today_iso[..10];
    let cutoff = cutoff_date(today, years)
        .ok_or_else(|| AppError::invalid("internal: utc_now_iso did not produce YYYY-MM-DD"))?;

    let rows: Vec<Value> = collect_eligible(&conn, &cutoff, today, years)?
        .into_iter()
        .map(|e| {
            json!({
                "id":             e.id,
                "encounter_date": e.encounter_date,
                "patient_alias":  e.patient_alias,
                "status":         e.status,
            })
        })
        .collect();
    Ok(rows)
}

/// Permanently destroy all signed encounters past the retention window.
///
/// Closes four ADR-0005 compliance findings:
///   H1 (audio disposal): audio files are removed after the SQL commit.
///   H2 (caller-supplied today): cutoff date derived server-side from
///       `utc_now_iso()` — caller cannot pass a future date to trigger
///       premature destruction.
///   M1 (caller-supplied provider_id): actor derived from KV profile.
///   M2 (non-signed candidates): only `status = 'signed'` encounters
///       are eligible — drafts and in-progress records are excluded.
///
/// Refuses when a litigation hold is active. Each encounter is destroyed via
/// `encounters::delete_encounter_in_tx` inside a single outer transaction so
/// the entire batch is atomic. Audio files are removed after the SQL commit
/// (best-effort; a failure logs an error but does not roll back the SQL).
///
/// Returns `{ destroyed: N }`.
#[tauri::command]
pub(crate) async fn retention_destroy_eligible(
    app: AppHandle,
    state: State<'_, DbState>,
) -> Result<Value, AppError> {
    let mut conn = state.conn()?;

    // Checked up front for a clearer message than the per-encounter guard
    // inside delete_encounter_in_tx would give, and to fail before any work.
    if litigation_hold_is_active(&conn)? {
        return Err(AppError::invalid(
            "litigation hold is active — retention-based destruction is blocked",
        ));
    }

    let provider_id = crate::kv_ops::provider_id(&conn);

    let years = retention_years(&conn);

    let today_iso = crate::time::utc_now_iso();
    let today = &today_iso[..10];
    let cutoff = cutoff_date(today, years)
        .ok_or_else(|| AppError::invalid("internal: utc_now_iso did not produce YYYY-MM-DD"))?;

    // Last line of defence before an irreversible batch delete. `years` is
    // clamped to >= 1 so a cutoff at or after today should be unreachable — if
    // it happens anyway, the window is nonsensical and destroying against it
    // would sweep records that are nowhere near expiry. Refuse rather than
    // proceed; ISO dates compare lexicographically.
    if cutoff.as_str() >= today {
        return Err(AppError::invalid(format!(
            "refusing to destroy: computed retention cutoff {cutoff} is not in the past \
             (today {today}, window {years}y) — retention policy looks corrupt"
        )));
    }

    let ids: Vec<String> = collect_eligible(&conn, &cutoff, today, years)?
        .into_iter()
        .map(|e| e.id)
        .collect();

    // Single outer transaction — all encounter deletions are atomic.
    {
        let tx = conn.transaction()?;
        for id in &ids {
            crate::encounters::delete_encounter_in_tx(&tx, id, &provider_id, "retention_expired")?;
        }
        tx.commit()?;
    }
    drop(conn); // release before async audio cleanup

    // Audio cleanup after the SQL commit. Each unremovable file is recorded as
    // `disposal_incomplete` rather than only logged — see
    // audio::purge_after_destruction.
    let pool = state.pool()?;
    for id in &ids {
        crate::audio::purge_after_destruction(&app, &pool, id, &provider_id).await;
    }

    Ok(json!({ "destroyed": ids.len() as i64 }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutoff_subtracts_years_correctly() {
        assert_eq!(
            cutoff_date("2026-07-20", 7),
            Some("2019-07-20".to_string())
        );
        assert_eq!(
            cutoff_date("2026-01-01", 7),
            Some("2019-01-01".to_string())
        );
    }

    #[test]
    fn cutoff_zero_years_is_today() {
        assert_eq!(
            cutoff_date("2026-07-20", 0),
            Some("2026-07-20".to_string())
        );
    }

    #[test]
    fn cutoff_rejects_bad_input() {
        assert!(cutoff_date("bad", 7).is_none());
        assert!(cutoff_date("", 7).is_none());
        assert!(cutoff_date("26-07", 7).is_none()); // too short
        assert!(cutoff_date("2026/07/20", 7).is_none(), "wrong separators");
        assert!(cutoff_date("2026-13-01", 7).is_none(), "month out of range");
        assert!(cutoff_date("2026-07-00", 7).is_none(), "day out of range");
    }

    #[test]
    fn a_leap_day_cutoff_rolls_forward_never_back() {
        // 2028-02-29 minus 7 years is not a real date. The old code emitted
        // "2021-02-29", and since ISO dates compare lexicographically that
        // made "2021-02-28" eligible — destroying a record one day early.
        assert_eq!(cutoff_date("2028-02-29", 7), Some("2021-03-01".to_string()));
        assert_eq!(cutoff_date("2028-02-29", 1), Some("2027-03-01".to_string()));
        assert_eq!(cutoff_date("2028-02-29", 3), Some("2025-03-01".to_string()));

        // The record the bug would have destroyed early must now survive:
        // it is NOT strictly less than the corrected cutoff... and one dated
        // the day before still is, which is correct.
        let cutoff = cutoff_date("2028-02-29", 7).unwrap();
        assert!(cutoff.as_str() <= "2021-03-01", "boundary day is retained");
        assert!(cutoff.as_str() > "2021-02-28", "genuinely older records still expire");
    }

    #[test]
    fn a_leap_day_landing_on_a_leap_year_is_preserved_exactly() {
        // 2028 and 2024 are both leap years, so Feb 29 is real on both ends
        // and no adjustment should happen.
        assert_eq!(cutoff_date("2028-02-29", 4), Some("2024-02-29".to_string()));
        assert_eq!(cutoff_date("2028-02-29", 8), Some("2020-02-29".to_string()));
    }

    #[test]
    fn leap_year_rule_handles_century_boundaries() {
        assert!(is_leap_year(2024));
        assert!(is_leap_year(2000), "divisible by 400");
        assert!(!is_leap_year(1900), "divisible by 100 but not 400");
        assert!(!is_leap_year(2023));
    }

    // ── Retention window clamping (C-4) ─────────────────────────────────
    //
    // retention_set_years validates 1..=30, but that only covers the
    // sanctioned write path. The destroy path used to parse the raw kv row
    // with no clamp, so a value written around the command reached it
    // unbounded — "0" produces a cutoff of today and makes every signed
    // encounter eligible. Clamping on READ makes the invariant hold no matter
    // how the row got there.

    fn kv_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kv (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at INTEGER NOT NULL
             );",
        )
        .unwrap();
        conn
    }

    fn seed_years(conn: &Connection, raw: &str) {
        conn.execute(
            "INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
            params![KV_RETENTION_YEARS, raw],
        )
        .unwrap();
    }

    #[test]
    fn a_zero_retention_window_cannot_reach_the_destroy_path() {
        // The exact value the kv_set chain used to plant.
        let conn = kv_db();
        seed_years(&conn, "0");
        assert_eq!(
            retention_years(&conn),
            MIN_RETENTION_YEARS,
            "0 must clamp to the minimum, not yield a cutoff of today"
        );
        // And the resulting cutoff is genuinely in the past.
        let cutoff = cutoff_date("2026-07-20", retention_years(&conn)).unwrap();
        assert!(cutoff.as_str() < "2026-07-20");
    }

    #[test]
    fn out_of_range_and_malformed_windows_are_clamped_or_defaulted() {
        let conn = kv_db();

        seed_years(&conn, "-5");
        assert_eq!(retention_years(&conn), MIN_RETENTION_YEARS, "negative clamps up");

        seed_years(&conn, "9999");
        assert_eq!(retention_years(&conn), MAX_RETENTION_YEARS, "huge clamps down");

        seed_years(&conn, "not a number");
        assert_eq!(
            retention_years(&conn),
            DEFAULT_RETENTION_YEARS,
            "unparseable falls back to the default, not to 0"
        );

        seed_years(&conn, "7");
        assert_eq!(retention_years(&conn), 7, "in-range values pass through");
    }

    #[test]
    fn a_missing_window_row_uses_the_default() {
        let conn = kv_db();
        assert_eq!(retention_years(&conn), DEFAULT_RETENTION_YEARS);
    }

    // ── Minor-record retention extension (L3) ───────────────────────────
    //
    // When a patient's optional DOB is known and they were a minor at the
    // encounter, the retention floor is the LATER of the standard window and
    // DOB + 18 + tail (tail == the configured adult window). DOB unset, or
    // patient-adult-at-encounter, must behave byte-for-byte like the legacy
    // encounter-only path — no regression.

    #[test]
    fn shift_years_adds_and_subtracts() {
        assert_eq!(shift_years("2008-06-15", 18).as_deref(), Some("2026-06-15"));
        assert_eq!(shift_years("2026-07-20", -7).as_deref(), Some("2019-07-20"));
    }

    #[test]
    fn shift_years_rolls_leap_day_forward_in_both_directions() {
        // Target year is non-leap → Feb 29 rolls forward to Mar 1, never back.
        assert_eq!(shift_years("2008-02-29", 18).as_deref(), Some("2026-03-01"));
        assert_eq!(shift_years("2028-02-29", -7).as_deref(), Some("2021-03-01"));
        // Target year is a leap year → Feb 29 is preserved exactly.
        assert_eq!(shift_years("2008-02-29", 16).as_deref(), Some("2024-02-29"));
    }

    #[test]
    fn dob_unset_never_extends_retention() {
        // The common case: existing patients and legacy encounters have no DOB,
        // so an already-expired encounter stays eligible exactly as before.
        assert!(!minor_extension_retains("2015-01-01", None, "2026-07-20", 7));
    }

    #[test]
    fn adult_at_encounter_never_extends_retention() {
        // DOB known but the patient was 20 at the encounter — the minor rule
        // does not apply and the standard window governs unchanged.
        let dob = "1995-01-01"; // turned 18 on 2013-01-01
        assert!(!minor_extension_retains("2015-06-01", Some(dob), "2026-07-20", 7));
    }

    #[test]
    fn minor_at_encounter_extends_until_the_post_majority_floor() {
        // Born 2010-05-01, encounter at age 8 (2018). Standard 7y window would
        // free it in 2025, but the patient does not turn 18 until 2028, so the
        // floor is DOB + 18 + 7 = 2035-05-01.
        let dob = "2010-05-01";
        let enc = "2018-09-15";

        // Well before the floor: must be retained even though it is a decade old.
        assert!(minor_extension_retains(enc, Some(dob), "2026-07-20", 7));
        // The day before the floor: still retained.
        assert!(minor_extension_retains(enc, Some(dob), "2035-04-30", 7));
        // On/after the floor: no longer retained by the minor rule.
        assert!(!minor_extension_retains(enc, Some(dob), "2035-05-01", 7));
        assert!(!minor_extension_retains(enc, Some(dob), "2040-01-01", 7));
    }

    #[test]
    fn a_malformed_dob_is_ignored_and_falls_back_to_standard() {
        assert!(!minor_extension_retains("2018-01-01", Some("not-a-date"), "2026-07-20", 7));
        assert!(!minor_extension_retains("2018-01-01", Some(""), "2026-07-20", 7));
    }

    // Integration-level coverage of collect_eligible: proves the DOB join and
    // filter compose correctly with the SQL cutoff on a real fixture.
    fn retention_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE encounters (
                 id             TEXT PRIMARY KEY,
                 provider_id    TEXT NOT NULL,
                 encounter_date TEXT NOT NULL,
                 patient_alias  TEXT,
                 patient_id     TEXT,
                 status         TEXT NOT NULL DEFAULT 'draft'
             );
             CREATE TABLE patients (
                 id  TEXT PRIMARY KEY,
                 dob TEXT
             );",
        )
        .unwrap();
        conn
    }

    fn add_patient(conn: &Connection, id: &str, dob: Option<&str>) {
        conn.execute("INSERT INTO patients (id, dob) VALUES (?1, ?2)", params![id, dob])
            .unwrap();
    }

    fn add_signed_encounter(conn: &Connection, id: &str, date: &str, patient_id: Option<&str>) {
        conn.execute(
            "INSERT INTO encounters (id, provider_id, encounter_date, patient_id, status) \
             VALUES (?1, 'dr', ?2, ?3, 'signed')",
            params![id, date, patient_id],
        )
        .unwrap();
    }

    #[test]
    fn collect_eligible_retains_minors_but_not_adults_or_dobless() {
        let conn = retention_db();
        let today = "2026-07-20";
        let years = 7;
        let cutoff = cutoff_date(today, years).unwrap(); // 2019-07-20

        // All three encounters predate the cutoff, so all are standard-eligible.
        add_patient(&conn, "pt-minor", Some("2010-05-01")); // minor at encounter
        add_signed_encounter(&conn, "enc-minor", "2018-09-15", Some("pt-minor"));

        add_patient(&conn, "pt-adult", Some("1990-01-01")); // adult at encounter
        add_signed_encounter(&conn, "enc-adult", "2015-01-01", Some("pt-adult"));

        // No patient row / no DOB → legacy behavior.
        add_signed_encounter(&conn, "enc-legacy", "2015-01-01", None);

        let ids: Vec<String> = collect_eligible(&conn, &cutoff, today, years)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();

        assert!(!ids.contains(&"enc-minor".to_string()), "minor's record is retained past the standard window");
        assert!(ids.contains(&"enc-adult".to_string()), "adult-at-encounter record stays eligible");
        assert!(ids.contains(&"enc-legacy".to_string()), "DOB-less record behaves exactly as before");
    }

    #[test]
    fn collect_eligible_releases_a_minor_record_once_the_floor_passes() {
        let conn = retention_db();
        // Same minor as above, but "today" is well past DOB + 18 + 7 = 2035-05-01.
        let today = "2036-01-01";
        let years = 7;
        let cutoff = cutoff_date(today, years).unwrap();

        add_patient(&conn, "pt-minor", Some("2010-05-01"));
        add_signed_encounter(&conn, "enc-minor", "2018-09-15", Some("pt-minor"));

        let ids: Vec<String> = collect_eligible(&conn, &cutoff, today, years)
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert!(ids.contains(&"enc-minor".to_string()), "once past the post-majority floor the record is eligible again");
    }

    // ── Policy write / audit atomicity (H-4) ────────────────────────────
    //
    // A bare pooled connection autocommits, so the original code made the
    // setting durable and only THEN appended the audit row. A failed append
    // left the value changed with no record while the caller saw an error.

    fn policy_db() -> Connection {
        let conn = kv_db();
        crate::config_audit::init_schema(&conn).unwrap();
        conn
    }

    fn hold_value(conn: &Connection) -> Option<String> {
        conn.query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_LITIGATION_HOLD],
            |r| r.get(0),
        )
        .optional()
        .unwrap()
    }

    fn audit_count(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM config_audit", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn a_policy_change_and_its_audit_row_land_together() {
        let mut conn = policy_db();
        set_policy_value(&mut conn, KV_LITIGATION_HOLD, "true", "litigation_hold_changed").unwrap();

        assert_eq!(hold_value(&conn).as_deref(), Some("true"));
        assert_eq!(audit_count(&conn), 1);

        // The transition is recorded, not just the new state.
        let (old, new): (Option<String>, String) = conn
            .query_row(
                "SELECT old_value, new_value FROM config_audit ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(old, None, "first-ever change has no prior value");
        assert_eq!(new, "true");
    }

    #[test]
    fn a_failed_audit_append_rolls_the_policy_change_back() {
        // The regression. Drop config_audit so the append fails AFTER the kv
        // write inside the same transaction; the hold must not move.
        let mut conn = policy_db();
        set_policy_value(&mut conn, KV_LITIGATION_HOLD, "true", "litigation_hold_changed").unwrap();
        assert_eq!(hold_value(&conn).as_deref(), Some("true"), "precondition: hold on");

        conn.execute_batch("DROP TABLE config_audit;").unwrap();

        let err = set_policy_value(
            &mut conn,
            KV_LITIGATION_HOLD,
            "false",
            "litigation_hold_changed",
        )
        .unwrap_err();
        assert!(matches!(err, AppError::Storage(_) | AppError::Internal(_)));

        assert_eq!(
            hold_value(&conn).as_deref(),
            Some("true"),
            "a litigation hold must not be lifted by an operation that reported failure"
        );
    }

    #[test]
    fn a_failed_audit_append_rolls_the_retention_window_back_too() {
        let mut conn = policy_db();
        set_policy_value(&mut conn, KV_RETENTION_YEARS, "10", "retention_years_changed").unwrap();
        assert_eq!(retention_years(&conn), 10);

        conn.execute_batch("DROP TABLE config_audit;").unwrap();

        assert!(set_policy_value(
            &mut conn,
            KV_RETENTION_YEARS,
            "1",
            "retention_years_changed"
        )
        .is_err());
        assert_eq!(
            retention_years(&conn),
            10,
            "an unlogged shortening of the retention window would silently expand what is destroyable"
        );
    }
}
