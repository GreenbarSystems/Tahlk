//! Encounter row CRUD + sign-off + stats.
//!
//! `mark_encounter_signed` and `clear_encounter_audio_path` use targeted
//! UPDATEs so a sign-off (or audio purge) can never clobber sibling columns
//! that the caller didn't intend to touch — critical for the attestation
//! moment, and for keeping audio retention orthogonal to note content.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use tauri::State;

use crate::db::{encounter_row_to_json, ENCOUNTER_COLS};
use crate::errors::AppError;
use crate::DbState;

/// Reject an upsert that would mutate a signed encounter in any way other
/// than a `patient_alias` typo fix.
///
/// The write flow is: JS calls `upsert_encounter` — without this guard, a
/// compromised WebView (or a bad refactor) could send `{ id, status: 'draft',
/// signed_at: null, signed_hash: null }` and demote a signed row back to a
/// draft, then re-sign it against different content. That would silently
/// break the tamper-evident hash chain, because the chain only surfaces on
/// audit — nobody watches it in real time.
///
/// Rules once `status='signed'`:
///   * `status`, `signed_at`, `signed_hash`, `created_at`, `provider_id`,
///     `encounter_date`, `audio_path` all become immutable.
///   * `patient_alias` MAY change (providers correct typos post-sign).
///
/// The check runs inside the same transaction as the write so a concurrent
/// legitimate sign-off between check and write cannot open a race window.
pub(crate) fn enforce_signed_immutability(
    conn: &Connection,
    incoming: &Value,
) -> Result<(), AppError> {
    let id = incoming["id"].as_str().unwrap_or("");
    if id.is_empty() {
        return Ok(()); // upsert will fail on its own; nothing to guard.
    }
    let existing: Option<(String, Option<String>, Option<String>, String, String, String, Option<String>)> = conn
        .query_row(
            "SELECT status, signed_at, signed_hash, created_at, provider_id, encounter_date, audio_path \
             FROM encounters WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
        )
        .optional()?;
    let Some((status, signed_at, signed_hash, created_at, provider_id, encounter_date, audio_path)) = existing else {
        return Ok(()); // brand-new row; nothing to compare against.
    };
    if status != "signed" {
        return Ok(()); // draft rows remain fully mutable by design.
    }

    // Signed row — verify the incoming payload leaves the frozen fields
    // unchanged. `as_str()` returns None for null/missing; comparing against
    // `Option<&str>` handles both shapes uniformly.
    let want_status       = incoming["status"].as_str();
    let want_signed_at    = incoming["signed_at"].as_str();
    let want_signed_hash  = incoming["signed_hash"].as_str();
    let want_created_at   = incoming["created_at"].as_str();
    let want_provider_id  = incoming["provider_id"].as_str();
    let want_enc_date     = incoming["encounter_date"].as_str();
    let want_audio_path   = incoming["audio_path"].as_str();

    let unchanged = want_status == Some(status.as_str())
        && want_signed_at.map(str::to_string) == signed_at
        && want_signed_hash.map(str::to_string) == signed_hash
        && want_created_at == Some(created_at.as_str())
        && want_provider_id == Some(provider_id.as_str())
        && want_enc_date == Some(encounter_date.as_str())
        && want_audio_path.map(str::to_string) == audio_path;

    if !unchanged {
        return Err(AppError::invalid(
            "cannot modify a signed encounter (only patient_alias may change)",
        ));
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn list_encounters(state: State<DbState>, limit: Option<i64>) -> Result<Vec<Value>, AppError> {
    let conn = state.0.lock();
    let n = limit.unwrap_or(50);
    let sql = format!(
        "SELECT {ENCOUNTER_COLS} FROM encounters ORDER BY created_at DESC LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![n], encounter_row_to_json)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

// Flip an encounter to signed, touching ONLY the sign columns. upsert_encounter
// overwrites patient_alias/audio_path from its payload, so using it for sign-off
// (which doesn't resend those) would null them out — corrupting the record at
// the moment of attestation. This targeted update cannot clobber other columns.
#[tauri::command]
pub(crate) fn mark_encounter_signed(
    state: State<DbState>,
    id: String,
    signed_at: String,
    signed_hash: String,
) -> Result<(), AppError> {
    let conn = state.0.lock();
    let n = conn.execute(
        "UPDATE encounters SET status = 'signed', signed_at = ?2, signed_hash = ?3 WHERE id = ?1",
        params![id, signed_at, signed_hash],
    )?;
    if n == 0 {
        return Err(AppError::invalid(format!("encounter {} not found", id)));
    }
    Ok(())
}

// Null out audio_path on a single encounter row without touching any other
// column — mirrors mark_encounter_signed's scoping so an audio-purge cannot
// clobber patient_alias or sign-off fields.
#[tauri::command]
pub(crate) fn clear_encounter_audio_path(state: State<DbState>, id: String) -> Result<(), AppError> {
    let conn = state.0.lock();
    let n = conn.execute(
        "UPDATE encounters SET audio_path = NULL WHERE id = ?1",
        params![id],
    )?;
    if n == 0 {
        return Err(AppError::invalid(format!("encounter {} not found", id)));
    }
    Ok(())
}

// Fetch a single encounter by id — avoids pulling the whole list to open one row.
#[tauri::command]
pub(crate) fn get_encounter(state: State<DbState>, id: String) -> Result<Option<Value>, AppError> {
    let conn = state.0.lock();
    let sql = format!("SELECT {ENCOUNTER_COLS} FROM encounters WHERE id = ?1");
    Ok(conn.query_row(&sql, params![id], encounter_row_to_json).optional()?)
}

// Home-screen counters via indexed COUNT(*) — O(index) instead of shipping rows
// to JS and filtering. `today` is passed in so the comparison matches how
// encounter_date is stored client-side.
#[tauri::command]
pub(crate) fn encounter_stats(state: State<DbState>, today: String) -> Result<Value, AppError> {
    let conn = state.0.lock();
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM encounters", [], |r| r.get(0))?;
    let signed: i64 = conn.query_row(
        "SELECT COUNT(*) FROM encounters WHERE status = 'signed'",
        [],
        |r| r.get(0),
    )?;
    let today_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM encounters WHERE encounter_date = ?1",
        params![today],
        |r| r.get(0),
    )?;
    Ok(json!({ "total": total, "signed": signed, "today": today_count }))
}

#[tauri::command]
pub(crate) fn upsert_encounter(state: State<DbState>, encounter: Value) -> Result<(), AppError> {
    let mut conn = state.0.lock();
    // Wrap the check + write in a single transaction so a legitimate
    // concurrent sign-off between check and write cannot squeeze in and
    // convert this call from "upsert draft" into "demote signed".
    let tx = conn.transaction()?;
    enforce_signed_immutability(&tx, &encounter)?;
    tx.execute(
        "INSERT INTO encounters (id, provider_id, encounter_date, patient_alias, status, \
                                 audio_path, created_at, signed_at, signed_hash) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) \
         ON CONFLICT(id) DO UPDATE SET \
             status       = excluded.status, \
             patient_alias= excluded.patient_alias, \
             audio_path   = excluded.audio_path, \
             signed_at    = excluded.signed_at, \
             signed_hash  = excluded.signed_hash",
        params![
            encounter["id"].as_str().unwrap_or(""),
            encounter["provider_id"].as_str().unwrap_or(""),
            encounter["encounter_date"].as_str().unwrap_or(""),
            encounter["patient_alias"].as_str(),
            encounter["status"].as_str().unwrap_or("draft"),
            encounter["audio_path"].as_str(),
            encounter["created_at"].as_str().unwrap_or(""),
            encounter["signed_at"].as_str(),
            encounter["signed_hash"].as_str(),
        ],
    )?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit-level coverage for the signed-row immutability guard. We drive
    //! `enforce_signed_immutability` directly against a raw in-memory
    //! SQLite so the tests don't need a Tauri State harness.

    use super::*;
    use rusqlite::Connection;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE encounters (
                id             TEXT PRIMARY KEY,
                provider_id    TEXT NOT NULL,
                encounter_date TEXT NOT NULL,
                patient_alias  TEXT,
                status         TEXT NOT NULL DEFAULT 'draft',
                audio_path     TEXT,
                created_at     TEXT NOT NULL,
                signed_at      TEXT,
                signed_hash    TEXT
            );",
        )
        .unwrap();
        conn
    }

    fn insert_signed(conn: &Connection) {
        conn.execute(
            "INSERT INTO encounters (id, provider_id, encounter_date, patient_alias, status, \
                                     audio_path, created_at, signed_at, signed_hash) \
             VALUES ('enc-1','prov-1','2026-07-04','J.D.','signed', \
                     '/tmp/audio.wav','2026-07-04T10:00:00Z', \
                     '2026-07-04T10:30:00Z','deadbeef')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn draft_row_is_freely_mutable() {
        let conn = fresh_db();
        conn.execute(
            "INSERT INTO encounters (id, provider_id, encounter_date, status, created_at) \
             VALUES ('enc-1','prov-1','2026-07-04','draft','2026-07-04T10:00:00Z')",
            [],
        ).unwrap();
        let incoming = json!({
            "id": "enc-1",
            "provider_id": "prov-1",
            "encounter_date": "2026-07-04",
            "status": "draft",
            "created_at": "2026-07-04T10:00:00Z",
            "patient_alias": "changed",
            "audio_path": "/new/path.wav",
            "signed_at": null,
            "signed_hash": null
        });
        assert!(enforce_signed_immutability(&conn, &incoming).is_ok());
    }

    #[test]
    fn brand_new_row_is_allowed() {
        let conn = fresh_db();
        let incoming = json!({
            "id": "enc-new",
            "provider_id": "prov-1",
            "encounter_date": "2026-07-04",
            "status": "draft",
            "created_at": "2026-07-04T10:00:00Z"
        });
        assert!(enforce_signed_immutability(&conn, &incoming).is_ok());
    }

    #[test]
    fn signed_row_rejects_status_demotion() {
        let conn = fresh_db();
        insert_signed(&conn);
        let incoming = json!({
            "id": "enc-1",
            "provider_id": "prov-1",
            "encounter_date": "2026-07-04",
            "status": "draft",              // <-- illegal demotion
            "audio_path": "/tmp/audio.wav",
            "created_at": "2026-07-04T10:00:00Z",
            "signed_at": null,
            "signed_hash": null
        });
        let err = enforce_signed_immutability(&conn, &incoming).unwrap_err();
        // The wire code stays `invalid_input` (per AppError::invalid) so JS
        // can toast the message unchanged. Assert the variant directly since
        // `code()` is private to the errors module.
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    #[test]
    fn signed_row_rejects_hash_swap() {
        let conn = fresh_db();
        insert_signed(&conn);
        let incoming = json!({
            "id": "enc-1",
            "provider_id": "prov-1",
            "encounter_date": "2026-07-04",
            "status": "signed",
            "audio_path": "/tmp/audio.wav",
            "created_at": "2026-07-04T10:00:00Z",
            "signed_at": "2026-07-04T10:30:00Z",
            "signed_hash": "cafef00d"       // <-- swapped hash
        });
        assert!(enforce_signed_immutability(&conn, &incoming).is_err());
    }

    #[test]
    fn signed_row_allows_patient_alias_typo_fix() {
        let conn = fresh_db();
        insert_signed(&conn);
        let incoming = json!({
            "id": "enc-1",
            "provider_id": "prov-1",
            "encounter_date": "2026-07-04",
            "status": "signed",
            "patient_alias": "J.D. (fixed typo)",
            "audio_path": "/tmp/audio.wav",
            "created_at": "2026-07-04T10:00:00Z",
            "signed_at": "2026-07-04T10:30:00Z",
            "signed_hash": "deadbeef"
        });
        assert!(enforce_signed_immutability(&conn, &incoming).is_ok());
    }

    #[test]
    fn signed_row_rejects_audio_path_change() {
        // audio_path is intentionally frozen too — a post-sign audio_path
        // swap could point provenance at a different .wav than the one
        // that was transcribed to produce the signed note.
        let conn = fresh_db();
        insert_signed(&conn);
        let incoming = json!({
            "id": "enc-1",
            "provider_id": "prov-1",
            "encounter_date": "2026-07-04",
            "status": "signed",
            "audio_path": "/malicious/other.wav",
            "created_at": "2026-07-04T10:00:00Z",
            "signed_at": "2026-07-04T10:30:00Z",
            "signed_hash": "deadbeef"
        });
        assert!(enforce_signed_immutability(&conn, &incoming).is_err());
    }
}
