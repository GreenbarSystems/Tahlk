//! Append-only audit log for patient roster CRUD (fixes audit finding H2:
//! "Patient record create/update/delete have no audit logging").
//!
//! 45 CFR §164.312(b) requires audit controls recording activity on ePHI.
//! Before this fix, `patients.rs`'s upsert/delete handlers wrote no trace
//! of who created, edited, or permanently deleted a patient record —
//! the only entity-level lifecycle in the app with zero audit coverage
//! (every other entity — notes, audio, LLM calls — had at least partial
//! logging).
//!
//! Mirrors `llm_audit.rs`'s design (the precedent this finding's own
//! remediation called out) rather than `note_history.rs`/`note_audit.rs`'s
//! hash chain: a flat, append-only table, metadata only. `patient_id`,
//! `provider_id`, and `action` are logged — never `alias`/`dob`/`notes` —
//! so this log doesn't become a second copy of PHI to protect.
//!
//! [`append`] is called from inside `patients::upsert_patient_conn` and
//! `patients::delete_patient_conn`, in the SAME transaction as the actual
//! data mutation — not as a separate, independently-skippable command.
//! That's deliberate: a create/update/delete and its audit row are one
//! atomic unit, so a caller cannot mutate the roster without an audit
//! entry landing, and the create-vs-update distinction is derived from
//! the transaction's own pre-write existence check rather than trusted
//! from the caller.
//!
//! No delete/remove command is exposed to JS for this table, closing the
//! same class of gap finding H1 closed for the encounter-scoped trail.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use tauri::State;

use crate::errors::AppError;
use crate::time::utc_now_iso;
use crate::DbState;

pub(crate) fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS patient_audit (
             id           INTEGER PRIMARY KEY AUTOINCREMENT,
             created_at   TEXT NOT NULL,
             patient_id   TEXT NOT NULL,
             provider_id  TEXT NOT NULL DEFAULT '',
             action       TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS patient_audit_pid_idx
             ON patient_audit (patient_id);
         CREATE INDEX IF NOT EXISTS patient_audit_created_idx
             ON patient_audit (created_at DESC);",
    )
}

/// Valid `action` values. Enforced at the Tauri command boundary so a
/// compromised WebView can't stuff an arbitrary string into a compliance
/// record.
/// `patient_records_destroyed` is written by `destroy_patient_records`
/// (patients.rs) and was missing here, so the debug_assert below PANICKED
/// mid-transaction in every debug build — including `cargo test`. It went
/// unnoticed because no test exercises that command, and in release the
/// assert compiles out and an off-allowlist action reaches the compliance
/// record instead. (Audit H-2.)
pub(crate) const VALID_ACTIONS: &[&str] = &[
    "patient_created",
    "patient_updated",
    "patient_deleted",
    "patient_records_destroyed",
];

/// Appends one audit row. Takes `&Connection` so callers can pass a
/// `&Transaction` (which derefs to `Connection`) to make the write part of
/// the same atomic transaction as the data mutation it's recording.
pub(crate) fn append(conn: &Connection, patient_id: &str, provider_id: &str, action: &str) -> Result<(), AppError> {
    debug_assert!(VALID_ACTIONS.contains(&action), "append called with an unvalidated action: {action}");
    conn.execute(
        "INSERT INTO patient_audit (created_at, patient_id, provider_id, action) VALUES (?1,?2,?3,?4)",
        params![utc_now_iso(), patient_id, provider_id, action],
    )?;
    Ok(())
}

#[tauri::command]
pub(crate) fn patient_audit_list(state: State<DbState>, patient_id: String) -> Result<Vec<Value>, AppError> {
    let conn = state.conn()?;
    let mut stmt = conn.prepare(
        "SELECT created_at, patient_id, provider_id, action \
         FROM patient_audit WHERE patient_id = ?1 ORDER BY id",
    )?;
    let rows = stmt.query_map(params![patient_id], |r| {
        Ok(json!({
            "createdAt":  r.get::<_, String>(0)?,
            "patientId":  r.get::<_, String>(1)?,
            "providerId": r.get::<_, String>(2)?,
            "action":     r.get::<_, String>(3)?,
        }))
    })?
    .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn append_then_list_round_trips() {
        let conn = fresh_db();
        append(&conn, "pt-1", "Dr. Chen", "patient_created").unwrap();
        let rows = list_conn(&conn, "pt-1");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["patientId"], "pt-1");
        assert_eq!(rows[0]["providerId"], "Dr. Chen");
        assert_eq!(rows[0]["action"], "patient_created");
        assert!(rows[0]["createdAt"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn list_only_returns_rows_for_the_requested_patient() {
        let conn = fresh_db();
        append(&conn, "pt-1", "Dr. Chen", "patient_created").unwrap();
        append(&conn, "pt-2", "Dr. Chen", "patient_created").unwrap();
        assert_eq!(list_conn(&conn, "pt-1").len(), 1);
        assert_eq!(list_conn(&conn, "pt-2").len(), 1);
        assert_eq!(list_conn(&conn, "pt-3").len(), 0);
    }

    #[test]
    fn list_preserves_insertion_order() {
        let conn = fresh_db();
        append(&conn, "pt-1", "Dr. Chen", "patient_created").unwrap();
        append(&conn, "pt-1", "Dr. Chen", "patient_updated").unwrap();
        append(&conn, "pt-1", "Dr. Chen", "patient_deleted").unwrap();
        let rows = list_conn(&conn, "pt-1");
        let actions: Vec<&str> = rows.iter().map(|r| r["action"].as_str().unwrap()).collect();
        assert_eq!(actions, vec!["patient_created", "patient_updated", "patient_deleted"]);
    }

    // Mirrors patient_audit_list's query directly against a raw Connection
    // (the #[tauri::command] fn can't be called without a Tauri State
    // harness).
    fn list_conn(conn: &Connection, patient_id: &str) -> Vec<Value> {
        let mut stmt = conn
            .prepare("SELECT created_at, patient_id, provider_id, action FROM patient_audit WHERE patient_id = ?1 ORDER BY id")
            .unwrap();
        stmt.query_map(params![patient_id], |r| {
            Ok(json!({
                "createdAt":  r.get::<_, String>(0)?,
                "patientId":  r.get::<_, String>(1)?,
                "providerId": r.get::<_, String>(2)?,
                "action":     r.get::<_, String>(3)?,
            }))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }
}
