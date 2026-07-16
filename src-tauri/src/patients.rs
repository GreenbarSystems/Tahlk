//! Patient roster CRUD.
//!
//! A lightweight standalone roster: name/alias plus an optional DOB and free
//! notes. Deliberately NOT linked to encounters in this iteration — there is
//! no foreign key and no `encounter.patient_id`. The table is SQLCipher-
//! encrypted at rest like every other table (connections come pre-keyed from
//! the pool), so alias/DOB/notes never hit disk in plaintext.
//!
//! Mirrors `encounters.rs`: `#[tauri::command]` entry points take `DbState`
//! and delegate to pure `&Connection` helpers so the CRUD logic can be unit-
//! tested against an in-memory SQLite fixture without a Tauri State harness.
//!
//! `upsert_patient_conn`/`delete_patient_conn` write a `patient_audit` row
//! (see `patient_audit.rs`) in the SAME transaction as the data mutation —
//! fixes audit finding H2 ("Patient record create/update/delete have no
//! audit logging"). This is deliberately NOT a separate JS-callable command
//! the caller could forget to invoke: create/update/delete and their audit
//! entry are one atomic unit, and create-vs-update is derived here from an
//! existence check inside the transaction, not trusted from the caller.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use tauri::State;

use crate::db::{patient_row_to_json, PATIENT_COLS};
use crate::errors::AppError;
use crate::patient_audit;
use crate::DbState;

/// Clamp a caller-supplied `LIMIT` into a sane range. The ceiling and clamp
/// live in `db::clamp_list_limit`, shared with `encounters` — this wrapper
/// only supplies this module's default page size.
pub(crate) fn clamp_list_limit(limit: Option<i64>) -> i64 {
    crate::db::clamp_list_limit(limit, DEFAULT_LIST_LIMIT)
}

/// Default page size when the caller passes no limit. Larger than
/// `encounters`'s because the roster is browsed whole, not windowed.
const DEFAULT_LIST_LIMIT: i64 = 200;

/// Extract a required, non-empty string field from an incoming patient
/// payload, or return `AppError::InvalidInput` naming the field. Mirrors the
/// boundary validation in `encounters::required_str` so a missing/blank alias
/// fails loudly instead of persisting an empty NOT NULL column.
fn required_str<'a>(incoming: &'a Value, field: &'static str) -> Result<&'a str, AppError> {
    match incoming[field].as_str() {
        Some(s) if !s.trim().is_empty() => Ok(s),
        _ => Err(AppError::invalid(format!(
            "patient.{field} is required and must be a non-empty string"
        ))),
    }
}

#[tauri::command]
pub(crate) fn list_patients(state: State<DbState>, limit: Option<i64>) -> Result<Vec<Value>, AppError> {
    let conn = state.0.get()?;
    list_patients_conn(&conn, limit)
}

/// Pure DB helper for `list_patients`. Ordered by alias so the roster reads
/// alphabetically regardless of insertion order.
pub(crate) fn list_patients_conn(conn: &Connection, limit: Option<i64>) -> Result<Vec<Value>, AppError> {
    let n = clamp_list_limit(limit);
    let sql = format!("SELECT {PATIENT_COLS} FROM patients ORDER BY alias COLLATE NOCASE ASC LIMIT ?1");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![n], patient_row_to_json)?;
    let mut out = Vec::with_capacity(n as usize);
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

#[tauri::command]
pub(crate) fn get_patient(state: State<DbState>, id: String) -> Result<Option<Value>, AppError> {
    let conn = state.0.get()?;
    get_patient_conn(&conn, &id)
}

pub(crate) fn get_patient_conn(conn: &Connection, id: &str) -> Result<Option<Value>, AppError> {
    let sql = format!("SELECT {PATIENT_COLS} FROM patients WHERE id = ?1");
    Ok(conn.query_row(&sql, params![id], patient_row_to_json).optional()?)
}

fn check_provider_id(provider_id: &str) -> Result<(), AppError> {
    if provider_id.len() > crate::MAX_PROVIDER_ID_BYTES {
        return Err(AppError::invalid(format!(
            "provider_id exceeds {} bytes",
            crate::MAX_PROVIDER_ID_BYTES
        )));
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn upsert_patient(state: State<DbState>, patient: Value, provider_id: String) -> Result<(), AppError> {
    check_provider_id(&provider_id)?;
    let mut conn = state.0.get()?;
    upsert_patient_conn(&mut conn, &patient, &provider_id)
}

/// Insert-or-update a patient row. `id`, `alias`, and `created_at` are
/// required; `dob`/`notes` are nullable. On conflict only the caller-owned
/// fields change — `created_at` is preserved from the original INSERT so an
/// edit can't rewrite when the record was first created.
///
/// Whether this is a create or an update is decided HERE, from an existence
/// check inside the same transaction as the write — not from a caller-
/// supplied flag, which a buggy or compromised caller could get wrong.
pub(crate) fn upsert_patient_conn(conn: &mut Connection, patient: &Value, provider_id: &str) -> Result<(), AppError> {
    let id         = required_str(patient, "id")?;
    let alias      = required_str(patient, "alias")?;
    let created_at = required_str(patient, "created_at")?;
    let updated_at = required_str(patient, "updated_at")?;

    let tx = conn.transaction()?;

    let existed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM patients WHERE id = ?1)",
        params![id],
        |r| r.get::<_, i64>(0),
    )? != 0;

    tx.execute(
        "INSERT INTO patients (id, alias, dob, notes, created_at, updated_at) \
         VALUES (?1,?2,?3,?4,?5,?6) \
         ON CONFLICT(id) DO UPDATE SET \
             alias      = excluded.alias, \
             dob        = excluded.dob, \
             notes      = excluded.notes, \
             updated_at = excluded.updated_at",
        params![
            id,
            alias,
            patient["dob"].as_str(),
            patient["notes"].as_str(),
            created_at,
            updated_at,
        ],
    )?;

    let action = if existed { "patient_updated" } else { "patient_created" };
    patient_audit::append(&tx, id, provider_id, action)?;

    tx.commit()?;
    Ok(())
}

#[tauri::command]
pub(crate) fn delete_patient(state: State<DbState>, id: String, provider_id: String) -> Result<(), AppError> {
    check_provider_id(&provider_id)?;
    let mut conn = state.0.get()?;
    delete_patient_conn(&mut conn, &id, &provider_id)
}

pub(crate) fn delete_patient_conn(conn: &mut Connection, id: &str, provider_id: &str) -> Result<(), AppError> {
    let tx = conn.transaction()?;
    let n = tx.execute("DELETE FROM patients WHERE id = ?1", params![id])?;
    if n == 0 {
        // Transaction is dropped without committing — no audit row for a
        // no-op delete against a nonexistent patient.
        return Err(AppError::invalid(format!("patient {id} not found")));
    }
    patient_audit::append(&tx, id, provider_id, "patient_deleted")?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! CRUD coverage driven against a raw in-memory SQLite fixture (no Tauri
    //! State harness), mirroring `encounters.rs`'s test approach.

    use super::*;
    use rusqlite::Connection;
    use serde_json::json;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE patients (
                id         TEXT PRIMARY KEY,
                alias      TEXT NOT NULL,
                dob        TEXT,
                notes      TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )
        .unwrap();
        patient_audit::init_schema(&conn).unwrap();
        conn
    }

    fn sample(id: &str, alias: &str) -> Value {
        json!({
            "id": id,
            "alias": alias,
            "dob": "1990-01-15",
            "notes": "prefers morning appointments",
            "created_at": "2026-07-10T10:00:00Z",
            "updated_at": "2026-07-10T10:00:00Z",
        })
    }

    // Reads patient_audit rows directly, bypassing the #[tauri::command]
    // list fn (which needs a Tauri State harness).
    fn audit_rows(conn: &Connection, patient_id: &str) -> Vec<(String, String)> {
        let mut stmt = conn
            .prepare("SELECT provider_id, action FROM patient_audit WHERE patient_id = ?1 ORDER BY id")
            .unwrap();
        stmt.query_map(params![patient_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn upsert_then_get_roundtrips_all_fields() {
        let mut conn = fresh_db();
        upsert_patient_conn(&mut conn, &sample("pt-1", "A. Nonymous"), "Dr. Chen").unwrap();
        let got = get_patient_conn(&conn, "pt-1").unwrap().unwrap();
        assert_eq!(got["id"], "pt-1");
        assert_eq!(got["alias"], "A. Nonymous");
        assert_eq!(got["dob"], "1990-01-15");
        assert_eq!(got["notes"], "prefers morning appointments");
        assert_eq!(got["created_at"], "2026-07-10T10:00:00Z");
    }

    #[test]
    fn upsert_allows_null_dob_and_notes() {
        let mut conn = fresh_db();
        let p = json!({
            "id": "pt-2",
            "alias": "No Details",
            "dob": null,
            "notes": null,
            "created_at": "2026-07-10T10:00:00Z",
            "updated_at": "2026-07-10T10:00:00Z",
        });
        upsert_patient_conn(&mut conn, &p, "Dr. Chen").unwrap();
        let got = get_patient_conn(&conn, "pt-2").unwrap().unwrap();
        assert!(got["dob"].is_null());
        assert!(got["notes"].is_null());
    }

    #[test]
    fn upsert_updates_existing_and_preserves_created_at() {
        let mut conn = fresh_db();
        upsert_patient_conn(&mut conn, &sample("pt-1", "Original"), "Dr. Chen").unwrap();
        let edited = json!({
            "id": "pt-1",
            "alias": "Edited Name",
            "dob": "2000-12-31",
            "notes": "updated note",
            // A hostile/careless caller sends a different created_at — it must
            // be ignored so the original creation timestamp can't be rewritten.
            "created_at": "1999-01-01T00:00:00Z",
            "updated_at": "2026-07-11T09:00:00Z",
        });
        upsert_patient_conn(&mut conn, &edited, "Dr. Chen").unwrap();
        let got = get_patient_conn(&conn, "pt-1").unwrap().unwrap();
        assert_eq!(got["alias"], "Edited Name");
        assert_eq!(got["dob"], "2000-12-31");
        assert_eq!(got["notes"], "updated note");
        assert_eq!(got["updated_at"], "2026-07-11T09:00:00Z");
        assert_eq!(
            got["created_at"], "2026-07-10T10:00:00Z",
            "created_at must survive an edit unchanged"
        );
    }

    #[test]
    fn upsert_rejects_missing_alias() {
        let mut conn = fresh_db();
        let p = json!({
            "id": "pt-3",
            "alias": "",
            "created_at": "2026-07-10T10:00:00Z",
            "updated_at": "2026-07-10T10:00:00Z",
        });
        let err = upsert_patient_conn(&mut conn, &p, "Dr. Chen").unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        let msg = format!("{err}");
        assert!(msg.contains("alias"), "error should name the field: {msg}");
    }

    #[test]
    fn upsert_rejects_missing_id() {
        let mut conn = fresh_db();
        let p = json!({
            "alias": "Nameless",
            "created_at": "2026-07-10T10:00:00Z",
            "updated_at": "2026-07-10T10:00:00Z",
        });
        assert!(matches!(
            upsert_patient_conn(&mut conn, &p, "Dr. Chen").unwrap_err(),
            AppError::InvalidInput(_)
        ));
    }

    #[test]
    fn get_missing_patient_returns_none() {
        let conn = fresh_db();
        assert!(get_patient_conn(&conn, "nope").unwrap().is_none());
    }

    #[test]
    fn delete_removes_row() {
        let mut conn = fresh_db();
        upsert_patient_conn(&mut conn, &sample("pt-1", "Doomed"), "Dr. Chen").unwrap();
        delete_patient_conn(&mut conn, "pt-1", "Dr. Chen").unwrap();
        assert!(get_patient_conn(&conn, "pt-1").unwrap().is_none());
    }

    #[test]
    fn delete_missing_patient_reports_not_found() {
        let mut conn = fresh_db();
        let err = delete_patient_conn(&mut conn, "ghost", "Dr. Chen").unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        assert!(format!("{err}").contains("not found"));
    }

    #[test]
    fn list_returns_rows_alphabetically_by_alias() {
        let mut conn = fresh_db();
        upsert_patient_conn(&mut conn, &sample("pt-1", "Charlie"), "Dr. Chen").unwrap();
        upsert_patient_conn(&mut conn, &sample("pt-2", "alice"), "Dr. Chen").unwrap();
        upsert_patient_conn(&mut conn, &sample("pt-3", "Bob"), "Dr. Chen").unwrap();
        let rows = list_patients_conn(&conn, None).unwrap();
        let aliases: Vec<&str> = rows.iter().map(|r| r["alias"].as_str().unwrap()).collect();
        // COLLATE NOCASE means 'alice' sorts with the A's, not after Z.
        assert_eq!(aliases, vec!["alice", "Bob", "Charlie"]);
    }

    #[test]
    fn list_empty_db_returns_empty_vec() {
        let conn = fresh_db();
        assert!(list_patients_conn(&conn, None).unwrap().is_empty());
    }

    // ── Audit trail (fixes finding H2) ──────────────────────────────────────

    #[test]
    fn creating_a_new_patient_writes_a_patient_created_row() {
        let mut conn = fresh_db();
        upsert_patient_conn(&mut conn, &sample("pt-1", "New Patient"), "Dr. Chen").unwrap();
        let rows = audit_rows(&conn, "pt-1");
        assert_eq!(rows, vec![("Dr. Chen".to_string(), "patient_created".to_string())]);
    }

    #[test]
    fn editing_an_existing_patient_writes_a_patient_updated_row_not_created() {
        let mut conn = fresh_db();
        upsert_patient_conn(&mut conn, &sample("pt-1", "Original"), "Dr. Chen").unwrap();
        upsert_patient_conn(&mut conn, &sample("pt-1", "Edited"), "Dr. Chen").unwrap();
        let rows = audit_rows(&conn, "pt-1");
        assert_eq!(
            rows,
            vec![
                ("Dr. Chen".to_string(), "patient_created".to_string()),
                ("Dr. Chen".to_string(), "patient_updated".to_string()),
            ]
        );
    }

    #[test]
    fn deleting_a_patient_writes_a_patient_deleted_row() {
        let mut conn = fresh_db();
        upsert_patient_conn(&mut conn, &sample("pt-1", "Doomed"), "Dr. Chen").unwrap();
        delete_patient_conn(&mut conn, "pt-1", "Dr. Chen").unwrap();
        let rows = audit_rows(&conn, "pt-1");
        assert_eq!(rows[1], ("Dr. Chen".to_string(), "patient_deleted".to_string()));
    }

    #[test]
    fn deleting_a_nonexistent_patient_writes_no_audit_row() {
        let mut conn = fresh_db();
        assert!(delete_patient_conn(&mut conn, "ghost", "Dr. Chen").is_err());
        assert!(audit_rows(&conn, "ghost").is_empty());
    }

    #[test]
    fn upsert_reject_paths_write_no_audit_row() {
        let mut conn = fresh_db();
        let bad = json!({
            "id": "pt-bad",
            "alias": "",
            "created_at": "2026-07-10T10:00:00Z",
            "updated_at": "2026-07-10T10:00:00Z",
        });
        assert!(upsert_patient_conn(&mut conn, &bad, "Dr. Chen").is_err());
        assert!(audit_rows(&conn, "pt-bad").is_empty());
    }

    #[test]
    fn different_providers_each_get_their_own_audit_identity_recorded() {
        let mut conn = fresh_db();
        upsert_patient_conn(&mut conn, &sample("pt-1", "Shared Chart"), "Dr. Chen").unwrap();
        upsert_patient_conn(&mut conn, &sample("pt-1", "Shared Chart Edited"), "Dr. Patel").unwrap();
        let rows = audit_rows(&conn, "pt-1");
        assert_eq!(rows[0].0, "Dr. Chen");
        assert_eq!(rows[1].0, "Dr. Patel");
    }

    #[test]
    fn clamp_list_limit_defaults_and_bounds() {
        assert_eq!(clamp_list_limit(None), 200);
        assert_eq!(clamp_list_limit(Some(0)), 1);
        assert_eq!(clamp_list_limit(Some(-5)), 1);
        assert_eq!(clamp_list_limit(Some(50)), 50);
        assert_eq!(clamp_list_limit(Some(i64::MAX)), 1000);
    }
}
