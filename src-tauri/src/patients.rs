//! Patient roster CRUD.
//!
//! A lightweight standalone roster: name/alias plus an optional DOB and free
//! notes. Since ADR-0005 Commit 2, encounters carry an optional `patient_id`
//! foreign reference (no FK constraint) that enables cascade PHI destruction
//! via `destroy_patient_records`. The table is SQLCipher-encrypted at rest
//! like every other table (connections come pre-keyed from the pool), so
//! alias/DOB/notes never hit disk in plaintext.
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
use serde_json::{json, Value};
use tauri::{AppHandle, State};

use crate::db::{patient_row_to_json, PATIENT_COLS};
use crate::errors::AppError;
use crate::patient_audit;
use crate::retention;
use crate::DbState;

/// Derive the acting provider's display name from the KV-stored profile.
// Actor derivation lives in `kv_ops::provider_id` — this module previously
// carried TWO copies of it under different names (`provider_id_from_kv` and
// `read_provider_id`), each with its own doc comment claiming to be the
// server-side derivation.

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
/// payload, or return `AppError::InvalidInput` naming the field. Same rule as
/// `encounters::required_str` — missing, wrong-type, empty, and whitespace-only
/// all fail loudly instead of persisting a blank NOT NULL column. (The two
/// genuinely agree now; until 2026-07-16 this one trimmed and that one didn't,
/// while this comment already claimed they matched.)
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

#[tauri::command]
pub(crate) fn upsert_patient(state: State<DbState>, patient: Value) -> Result<(), AppError> {
    let mut conn = state.0.get()?;
    let provider_id = crate::kv_ops::provider_id(&conn);
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
        "INSERT INTO patients (id, alias, dob, notes, source_id, created_at, updated_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7) \
         ON CONFLICT(id) DO UPDATE SET \
             alias      = excluded.alias, \
             dob        = excluded.dob, \
             notes      = excluded.notes, \
             source_id  = excluded.source_id, \
             updated_at = excluded.updated_at",
        params![
            id,
            alias,
            patient["dob"].as_str(),
            patient["notes"].as_str(),
            patient["source_id"].as_str(),
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
pub(crate) fn delete_patient(state: State<DbState>, id: String) -> Result<(), AppError> {
    let mut conn = state.0.get()?;
    let provider_id = crate::kv_ops::provider_id(&conn);
    delete_patient_conn(&mut conn, &id, &provider_id)
}

pub(crate) fn delete_patient_conn(conn: &mut Connection, id: &str, provider_id: &str) -> Result<(), AppError> {
    // C5: block deletions when a litigation hold is active. Needed explicitly
    // here because a roster delete removes only the patients row — it never
    // reaches delete_encounter_in_tx, where the shared guard lives.
    retention::litigation_hold_check(conn, "patient records")?;
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

/// Permanently destroy all PHI for a patient: cascade-deletes every linked
/// encounter (scrubbing note_audit, hard-deleting note_history, logging each
/// to destruction_log), then removes the patient roster row and appends a
/// summary entry to destruction_log, followed by best-effort audio cleanup.
///
/// Actor identity is derived server-side from `note_provider_v1::profile` —
/// the caller cannot forge provider attribution (Medium finding M1 closed).
///
/// All SQL mutations run inside a single outer transaction — if any encounter
/// deletion fails the entire cascade rolls back (Medium finding M3 closed).
///
/// Audio files for each encounter are removed after the SQL commit
/// (High finding H1 closed). Audio cleanup is best-effort: a failure logs an
/// error but does not roll back the already-committed SQL destruction.
#[tauri::command]
pub(crate) async fn destroy_patient_records(
    app: AppHandle,
    state: State<'_, DbState>,
    patient_id: String,
) -> Result<Value, AppError> {
    let mut conn = state.0.get()?;

    // Explicit hold check, in addition to the one inside delete_encounter_in_tx.
    // Not redundant: a patient with zero linked encounters never enters the
    // cascade loop, so the inner guard would never fire, and the raw
    // `DELETE FROM patients` below would destroy the roster row under an active
    // hold. Checking here also fails before any work rather than mid-cascade.
    retention::litigation_hold_check(&conn, "patient records")?;

    // Derive actor server-side — WebView cannot supply or forge provider_id.
    let provider_id = crate::kv_ops::provider_id(&conn);

    // Read alias first — existence guard and legacy encounter-match fallback.
    let patient_alias: String = conn
        .query_row(
            "SELECT alias FROM patients WHERE id = ?1",
            params![patient_id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| AppError::invalid(format!("patient {patient_id} not found")))?;

    // Collect encounter IDs linked by patient_id OR matching the current alias
    // (legacy fallback for encounters created before ADR-0005 Commit 2).
    // Done before the outer transaction so the collection query is outside the
    // write path (consistent snapshot; no dirty reads from partial deletes).
    let encounter_ids: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT id FROM encounters WHERE patient_id = ?1 OR patient_alias = ?2",
        )?;
        let ids: Vec<String> = stmt.query_map(params![patient_id, patient_alias], |r| r.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        ids
    };

    let encounters_destroyed = encounter_ids.len() as i64;

    // Single outer transaction — all encounter deletions, the patient-row
    // removal, audit, and destruction_log entry are one atomic unit.
    {
        let tx = conn.transaction()?;
        for enc_id in &encounter_ids {
            crate::encounters::delete_encounter_in_tx(&tx, enc_id, &provider_id, "patient_request")?;
        }
        tx.execute("DELETE FROM patients WHERE id = ?1", params![patient_id])?;
        patient_audit::append(&tx, &patient_id, &provider_id, "patient_records_destroyed")?;
        crate::destruction_log::append(
            &tx,
            &provider_id,
            "patient",
            &patient_id,
            &patient_alias,
            "patient_request",
            encounters_destroyed,
        )?;
        tx.commit()?;
    }
    drop(conn); // release DB connection before the async .await calls below

    // Best-effort audio cleanup — after the SQL commit so a file-delete failure
    // never leaves a partially-committed DB state.
    for enc_id in &encounter_ids {
        if let Err(e) = crate::audio::delete_session_audio(app.clone(), enc_id.clone()).await {
            log::error!(
                "destroy_patient_records: audio cleanup failed for {}: {}",
                enc_id,
                crate::log_safety::cap_len(&e.to_string())
            );
        }
    }

    Ok(json!({ "encounters_destroyed": encounters_destroyed }))
}

/// Count encounters linked to a patient (by patient_id or matching alias for
/// legacy rows). Used to preview the impact of `destroy_patient_records` so
/// the provider knows how many records will be permanently destroyed before
/// committing to the irreversible action.
#[tauri::command]
pub(crate) fn count_patient_encounters(
    state: State<DbState>,
    patient_id: String,
) -> Result<i64, AppError> {
    let conn = state.0.get()?;
    let patient_alias: String = conn
        .query_row(
            "SELECT alias FROM patients WHERE id = ?1",
            params![patient_id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default();
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM encounters WHERE patient_id = ?1 OR patient_alias = ?2",
        params![patient_id, patient_alias],
        |r| r.get(0),
    )?;
    Ok(count)
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
                source_id  TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE kv (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )
        .unwrap();
        patient_audit::init_schema(&conn).unwrap();
        conn
    }

    // The litigation-hold flag lives in kv. delete_patient_conn reads it and
    // fails CLOSED, so the table must exist for the delete path to work at all
    // — absence is indistinguishable from an unreadable hold, which is exactly
    // the state the guard is meant to refuse.
    fn set_hold(conn: &Connection, active: bool) {
        conn.execute(
            "INSERT OR REPLACE INTO kv (key, value, updated_at) \
             VALUES ('note_settings_v1::litigation_hold', ?1, 0)",
            params![if active { "true" } else { "false" }],
        )
        .unwrap();
    }

    #[test]
    fn litigation_hold_blocks_roster_deletion() {
        // delete_patient_conn removes only the patients row — it never reaches
        // delete_encounter_in_tx, so it needs its own guard.
        let mut conn = fresh_db();
        upsert_patient_conn(&mut conn, &sample("pt-1", "A. Nonymous"), "Dr. Chen").unwrap();
        set_hold(&conn, true);

        let err = delete_patient_conn(&mut conn, "pt-1", "Dr. Chen").unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        assert!(format!("{err}").contains("litigation hold"));
        assert!(
            get_patient_conn(&conn, "pt-1").unwrap().is_some(),
            "a blocked delete must leave the roster row intact"
        );
    }

    #[test]
    fn roster_deletion_proceeds_once_the_hold_is_lifted() {
        let mut conn = fresh_db();
        upsert_patient_conn(&mut conn, &sample("pt-1", "A. Nonymous"), "Dr. Chen").unwrap();
        set_hold(&conn, true);
        assert!(delete_patient_conn(&mut conn, "pt-1", "Dr. Chen").is_err());

        set_hold(&conn, false);
        delete_patient_conn(&mut conn, "pt-1", "Dr. Chen").unwrap();
        assert!(get_patient_conn(&conn, "pt-1").unwrap().is_none());
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
