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

use rusqlite::params;
use serde_json::{json, Value};
use tauri::State;

use crate::errors::AppError;
use crate::DbState;

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
    crate::kv_ops::upsert_json(&conn, KV_RETENTION_YEARS, &years.to_string())
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
    crate::kv_ops::upsert_json(
        &conn,
        KV_LITIGATION_HOLD,
        if active { "true" } else { "false" },
    )
}

/// List encounters whose `encounter_date` predates the retention cutoff.
/// Returns an empty list when a litigation hold is active.
///
/// `today` must be `YYYY-MM-DD`. The result is ordered oldest-first so the
/// caller can present records chronologically.
#[tauri::command]
pub(crate) fn retention_list_candidates(
    state: State<'_, DbState>,
    today: String,
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

    let cutoff = cutoff_date(&today, years)
        .ok_or_else(|| AppError::invalid("today must be YYYY-MM-DD"))?;

    let mut stmt = conn.prepare(
        "SELECT id, encounter_date, patient_alias, status \
         FROM encounters WHERE encounter_date < ?1 ORDER BY encounter_date ASC",
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

/// Permanently destroy all encounters past the retention window.
///
/// Refuses when a litigation hold is active. Each encounter is destroyed via
/// `encounters::delete_encounter_row` so note_audit is scrubbed, note_history
/// is hard-deleted, and each act is logged to the append-only
/// `destruction_log` with `legal_basis = "retention_expired"`. Audio files
/// are not removed by this command — that is async and must be handled by
/// the caller or a follow-up operation.
///
/// Returns `{ destroyed: N }`.
#[tauri::command]
pub(crate) fn retention_destroy_eligible(
    state: State<'_, DbState>,
    today: String,
    provider_id: String,
) -> Result<Value, AppError> {
    // Collect eligible IDs on a read-only connection, then release it before
    // the write loop so each delete_encounter_row call gets a clean checkout.
    let ids: Vec<String> = {
        let conn = state.0.get()?;

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

        let years: i64 = conn
            .query_row(
                "SELECT value FROM kv WHERE key = ?1",
                params![KV_RETENTION_YEARS],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_RETENTION_YEARS);

        let cutoff = cutoff_date(&today, years)
            .ok_or_else(|| AppError::invalid("today must be YYYY-MM-DD"))?;

        let mut stmt =
            conn.prepare("SELECT id FROM encounters WHERE encounter_date < ?1")?;
        stmt.query_map(params![cutoff], |r| r.get(0))?
            .filter_map(|r| r.ok())
            .collect()
    }; // read connection released here

    let mut destroyed = 0i64;
    for id in &ids {
        let mut conn = state.0.get()?;
        crate::encounters::delete_encounter_row(
            &mut conn,
            id,
            &provider_id,
            "retention_expired",
        )?;
        destroyed += 1;
    }

    Ok(json!({ "destroyed": destroyed }))
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
