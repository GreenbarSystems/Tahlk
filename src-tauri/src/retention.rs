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

/// True when a litigation hold is active and all record deletions must be
/// blocked. Called from `delete_encounter_row` and `delete_patient_conn` (C5).
///
/// Returns `false` on any read error — a transient DB fault should not
/// accidentally block all deletions (fail-open is the lower-risk choice here).
pub(crate) fn litigation_hold_active(conn: &Connection) -> bool {
    let row: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_LITIGATION_HOLD],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten();
    row.as_deref() == Some("true")
}

fn provider_id_from_kv(conn: &Connection) -> String {
    conn.query_row(
        "SELECT value FROM kv WHERE key = 'note_provider_v1::profile'",
        [],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    .and_then(|v| v["name"].as_str().map(|s| s.to_string()))
    .unwrap_or_else(|| "provider".to_string())
}

const KV_RETENTION_YEARS: &str = "note_settings_v1::retention_years";
const KV_LITIGATION_HOLD: &str = "note_settings_v1::litigation_hold";
const DEFAULT_RETENTION_YEARS: i64 = 7;
const MIN_RETENTION_YEARS: i64 = 1;
const MAX_RETENTION_YEARS: i64 = 30;

/// Compute the retention cutoff date by subtracting `years` from `today`.
///
/// `today` must be in `YYYY-MM-DD` format (the same format used for
/// `encounters.encounter_date`). ISO date strings sort lexicographically, so
/// `encounter_date < cutoff` gives the correct "older than N years" filter.
fn cutoff_date(today: &str, years: i64) -> Option<String> {
    if today.len() < 10 {
        return None;
    }
    let year: i64 = today[..4].parse().ok()?;
    let rest = &today[4..10]; // "-MM-DD"
    Some(format!("{:04}{}", year - years, rest))
}

/// Read the configured record-retention window. Defaults to 7 years when the
/// provider has not explicitly configured it.
#[tauri::command]
pub(crate) fn retention_get_years(state: State<'_, DbState>) -> Result<i64, AppError> {
    let conn = state.0.get()?;
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_RETENTION_YEARS],
            |r| r.get(0),
        )
        .ok();
    Ok(raw
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(DEFAULT_RETENTION_YEARS)
        .clamp(MIN_RETENTION_YEARS, MAX_RETENTION_YEARS))
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
    let conn = state.0.get()?;
    let old: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_RETENTION_YEARS],
            |r| r.get(0),
        )
        .ok();
    let actor = provider_id_from_kv(&conn);
    crate::kv_ops::upsert_json(&conn, KV_RETENTION_YEARS, &years.to_string())?;
    crate::config_audit::append(
        &conn,
        "retention_years_changed",
        old.as_deref(),
        &years.to_string(),
        &actor,
    )?;
    Ok(())
}

/// Read the litigation-hold flag. When `true`, no records are eligible for
/// automated retention-based destruction.
#[tauri::command]
pub(crate) fn retention_hold_get(state: State<'_, DbState>) -> Result<bool, AppError> {
    let conn = state.0.get()?;
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_LITIGATION_HOLD],
            |r| r.get(0),
        )
        .ok();
    Ok(raw.as_deref() == Some("true"))
}

/// Set or clear the litigation hold. While active, `retention_list_candidates`
/// returns an empty list and `retention_destroy_eligible` refuses to run.
#[tauri::command]
pub(crate) fn retention_hold_set(
    state: State<'_, DbState>,
    active: bool,
) -> Result<(), AppError> {
    let conn = state.0.get()?;
    let old: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_LITIGATION_HOLD],
            |r| r.get(0),
        )
        .ok();
    let actor = provider_id_from_kv(&conn);
    let new_value = if active { "true" } else { "false" };
    crate::kv_ops::upsert_json(&conn, KV_LITIGATION_HOLD, new_value)?;
    crate::config_audit::append(
        &conn,
        "litigation_hold_changed",
        old.as_deref(),
        new_value,
        &actor,
    )?;
    Ok(())
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
    let conn = state.0.get()?;

    let hold: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_LITIGATION_HOLD],
            |r| r.get(0),
        )
        .ok();
    if hold.as_deref() == Some("true") {
        return Ok(vec![]);
    }

    let years: i64 = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_RETENTION_YEARS],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_RETENTION_YEARS);

    let today_iso = crate::time::utc_now_iso();
    let cutoff = cutoff_date(&today_iso[..10], years)
        .ok_or_else(|| AppError::invalid("internal: utc_now_iso did not produce YYYY-MM-DD"))?;

    let mut stmt = conn.prepare(
        "SELECT id, encounter_date, patient_alias, status \
         FROM encounters WHERE encounter_date < ?1 AND status = 'signed' \
         ORDER BY encounter_date ASC",
    )?;
    let rows: Vec<Value> = stmt
        .query_map(params![cutoff], |r| {
            Ok(json!({
                "id":             r.get::<_, String>(0)?,
                "encounter_date": r.get::<_, String>(1)?,
                "patient_alias":  r.get::<_, Option<String>>(2)?,
                "status":         r.get::<_, String>(3)?,
            }))
        })?
        .filter_map(|r| r.ok())
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
    let mut conn = state.0.get()?;

    let hold: Option<String> = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_LITIGATION_HOLD],
            |r| r.get(0),
        )
        .ok();
    if hold.as_deref() == Some("true") {
        return Err(AppError::invalid(
            "litigation hold is active — retention-based destruction is blocked",
        ));
    }

    let provider_id = provider_id_from_kv(&conn);

    let years: i64 = conn
        .query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![KV_RETENTION_YEARS],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_RETENTION_YEARS);

    let today_iso = crate::time::utc_now_iso();
    let cutoff = cutoff_date(&today_iso[..10], years)
        .ok_or_else(|| AppError::invalid("internal: utc_now_iso did not produce YYYY-MM-DD"))?;

    let ids: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT id FROM encounters WHERE encounter_date < ?1 AND status = 'signed'",
        )?;
        let result: Vec<String> = stmt.query_map(params![cutoff], |r| r.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        result
    };

    // Single outer transaction — all encounter deletions are atomic.
    {
        let tx = conn.transaction()?;
        for id in &ids {
            crate::encounters::delete_encounter_in_tx(&tx, id, &provider_id, "retention_expired")?;
        }
        tx.commit()?;
    }
    drop(conn); // release before async audio cleanup

    // Best-effort audio cleanup after SQL commit.
    for id in &ids {
        if let Err(e) = crate::audio::delete_session_audio(app.clone(), id.clone()).await {
            log::error!(
                "retention_destroy_eligible: audio cleanup failed for {}: {}",
                id,
                crate::log_safety::cap_len(&e.to_string())
            );
        }
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
    }
}
