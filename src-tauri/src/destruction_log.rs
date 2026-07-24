//! Append-only PHI destruction log — HIPAA disposal audit trail.
//!
//! Every deliberate destruction of PHI (encounter delete, patient cascade,
//! retention-expired purge) appends one row here. There is intentionally
//! no delete command for this table — it is the evidence of destruction,
//! not a PHI store.
//!
//! `patient_alias` is stored as a **one-way SHA-256 blind**, not a readable
//! label: the disposal record must not retain a readable patient identifier
//! indefinitely after the patient's other records are destroyed (privacy
//! review — this record was the one PHI-disposal artifact with no disposal
//! story of its own). Blinding preserves the record's evidentiary purpose —
//! "was patient X's data destroyed?" is answered by blinding X's alias and
//! matching — while removing the readable name. This mirrors the SHA-256
//! `encounter_id` blinding already applied to `note_audit` on destruction.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use tauri::State;

use crate::errors::AppError;
use crate::time::utc_now_iso;
use crate::DbState;

/// One-way SHA-256 blind (lowercase hex) of a patient alias for the disposal
/// record. Empty alias → `None` (system rows carry no alias). Deterministic, so
/// every disposal for the same patient shares a blind — the property that keeps
/// the log correlatable without retaining a readable identifier.
///
/// NOTE: a local `sha256`; the crate-wide hoist of the four copies of this into
/// a shared crypto util is tracked separately (maintainability finding M1).
fn blind_alias(alias: &str) -> Option<String> {
    if alias.is_empty() {
        return None;
    }
    let d = ring::digest::digest(&ring::digest::SHA256, alias.as_bytes());
    Some(crate::hex::to_hex(d.as_ref()))
}

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
    )?;

    // One-time privacy backfill: blind any `patient_alias` still stored in a
    // readable (pre-blinding) form. Idempotent — a SHA-256 hex is exactly 64
    // lowercase-hex chars, so already-blinded rows are filtered out and every
    // startup after the first is a no-op. `destruction_log` carries no hash
    // chain, so this in-place update touches no integrity attestation; it only
    // de-identifies labels already on disk.
    let mut stmt = conn.prepare(
        "SELECT id, patient_alias FROM destruction_log \
         WHERE patient_alias IS NOT NULL \
           AND (length(patient_alias) != 64 OR patient_alias GLOB '*[^0-9a-f]*')",
    )?;
    let stale: Vec<(i64, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);
    for (id, alias) in stale {
        if let Some(blinded) = blind_alias(&alias) {
            conn.execute(
                "UPDATE destruction_log SET patient_alias = ?1 WHERE id = ?2",
                params![blinded, id],
            )?;
        }
    }
    Ok(())
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
            blind_alias(patient_alias),
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
    let conn = state.conn()?;
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
    let conn = state.conn()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    fn alias_of(conn: &Connection, entity_id: &str) -> Option<String> {
        conn.query_row(
            "SELECT patient_alias FROM destruction_log WHERE entity_id = ?1",
            params![entity_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn append_blinds_a_readable_alias() {
        let conn = fresh();
        append(&conn, "prov", "encounter", "enc-1", "Jane Doe", "patient_request", 3).unwrap();
        let stored = alias_of(&conn, "enc-1").unwrap();
        assert_ne!(stored, "Jane Doe", "the readable alias must not be stored");
        assert_eq!(stored.len(), 64, "blind must be a 64-char SHA-256 hex");
        assert!(stored.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn empty_alias_stays_null() {
        let conn = fresh();
        append(&conn, "prov", "system", "destlog_csv_export", "", "export", 0).unwrap();
        assert_eq!(alias_of(&conn, "destlog_csv_export"), None);
    }

    #[test]
    fn blind_is_deterministic_for_correlation() {
        // Same patient destroyed across two encounters → same blind, so a later
        // "was this patient disposed?" query can match by re-blinding the name.
        let conn = fresh();
        append(&conn, "prov", "encounter", "enc-a", "Jane Doe", "patient_request", 1).unwrap();
        append(&conn, "prov", "encounter", "enc-b", "Jane Doe", "patient_request", 1).unwrap();
        assert_eq!(alias_of(&conn, "enc-a"), alias_of(&conn, "enc-b"));
        // And a different patient blinds differently.
        append(&conn, "prov", "encounter", "enc-c", "John Roe", "patient_request", 1).unwrap();
        assert_ne!(alias_of(&conn, "enc-a"), alias_of(&conn, "enc-c"));
    }

    #[test]
    fn backfill_blinds_legacy_plaintext_and_is_idempotent() {
        let conn = fresh();
        // Simulate a pre-blinding row written directly with a readable alias.
        conn.execute(
            "INSERT INTO destruction_log \
             (created_at, provider_id, entity_type, entity_id, patient_alias, legal_basis, records_scrubbed) \
             VALUES ('2026-01-01', 'prov', 'encounter', 'enc-legacy', 'J.D. (fixed typo)', 'provider_request', 2)",
            [],
        )
        .unwrap();

        // Re-run init_schema → backfill blinds the legacy row.
        init_schema(&conn).unwrap();
        let after = alias_of(&conn, "enc-legacy").unwrap();
        assert_eq!(after.len(), 64, "legacy alias must be blinded");
        assert_ne!(after, "J.D. (fixed typo)");

        // Idempotent: a second run must not re-hash the already-blinded value.
        init_schema(&conn).unwrap();
        assert_eq!(alias_of(&conn, "enc-legacy").unwrap(), after);
    }
}
