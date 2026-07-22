//! Append-only PHI destruction log — HIPAA disposal audit trail.
//!
//! Every deliberate destruction of PHI (encounter delete, patient cascade,
//! retention-expired purge) appends one row here. There is intentionally
//! no delete command for this table — it is the evidence of destruction,
//! not a PHI store. `patient_alias` is captured at destruction time (a
//! truncated display label, not a database identifier) so the log remains
//! meaningful even after the patient roster row is gone.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use tauri::State;

use crate::errors::AppError;
use crate::time::utc_now_iso;
use crate::DbState;

pub(crate) fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS destruction_log (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at        TEXT NOT NULL,
            provider_id       TEXT NOT NULL DEFAULT '',
            entity_type       TEXT NOT NULL,
            entity_id         TEXT NOT NULL,
            patient_alias     TEXT,
            legal_basis       TEXT NOT NULL,
            records_scrubbed  INTEGER NOT NULL DEFAULT 0
        );",
    )
}

/// Append one destruction event inside the caller's transaction.
///
/// Takes `&Connection` so callers can pass a `&Transaction` (which derefs
/// to `Connection`) and make this write atomic with the mutation it records
/// — same pattern as `patient_audit::append`.
///
/// `entity_type`: `"encounter"`, `"patient"`, or `"bulk"`.
/// `legal_basis`: `"provider_request"`, `"patient_request"`, or `"retention_expired"`.
pub(crate) fn append(
    conn: &Connection,
    provider_id: &str,
    entity_type: &str,
    entity_id: &str,
    patient_alias: &str,
    legal_basis: &str,
    records_scrubbed: i64,
) -> Result<(), AppError> {
    conn.execute(
        "INSERT INTO destruction_log \
         (created_at, provider_id, entity_type, entity_id, patient_alias, legal_basis, records_scrubbed) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            utc_now_iso(),
            provider_id,
            entity_type,
            entity_id,
            if patient_alias.is_empty() { None } else { Some(patient_alias) },
            legal_basis,
            records_scrubbed,
        ],
    )?;
    Ok(())
}

/// Record a destruction-log CSV export event.
///
/// Appends a system-level row to destruction_log so the act of exporting
/// the log is itself audited (Low finding L4 closed). Uses entity_type =
/// "system" and entity_id = "destlog_csv_export" to distinguish from PHI
/// destruction events. Actor is derived from the KV provider profile.
#[tauri::command]
pub(crate) fn destruction_log_note_exported(
    state: State<'_, DbState>,
    row_count: i64,
) -> Result<(), AppError> {
    let conn = state.0.get()?;
    let provider_id = crate::kv_ops::provider_id(&conn);
    append(&conn, &provider_id, "system", "destlog_csv_export", "", "export", row_count)
}

/// Returns the last `limit` rows (default 50, max 500), newest first.
/// Read-only — no delete or clear command is registered for this table.
#[tauri::command]
pub(crate) fn destruction_log_list(
    state: State<'_, DbState>,
    limit: Option<i64>,
) -> Result<Vec<Value>, AppError> {
    let conn = state.0.get()?;
    let n = crate::db::clamp_list_limit_to(limit, 50, crate::db::AUDIT_LIST_LIMIT_MAX);
    let mut stmt = conn.prepare(
        "SELECT id, created_at, provider_id, entity_type, entity_id, \
                patient_alias, legal_basis, records_scrubbed \
         FROM destruction_log ORDER BY id DESC LIMIT ?1",
    )?;
    let rows: Vec<Value> = stmt
        .query_map(params![n], |r| {
            Ok(json!({
                "id":               r.get::<_, i64>(0)?,
                "created_at":       r.get::<_, String>(1)?,
                "provider_id":      r.get::<_, String>(2)?,
                "entity_type":      r.get::<_, String>(3)?,
                "entity_id":        r.get::<_, String>(4)?,
                "patient_alias":    r.get::<_, Option<String>>(5)?,
                "legal_basis":      r.get::<_, String>(6)?,
                "records_scrubbed": r.get::<_, i64>(7)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}
