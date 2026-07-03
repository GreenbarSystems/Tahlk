//! Encounter row CRUD + sign-off + stats.
//!
//! `mark_encounter_signed` and `clear_encounter_audio_path` use targeted
//! UPDATEs so a sign-off (or audio purge) can never clobber sibling columns
//! that the caller didn't intend to touch — critical for the attestation
//! moment, and for keeping audio retention orthogonal to note content.

use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use tauri::State;

use crate::db::{encounter_row_to_json, ENCOUNTER_COLS};
use crate::DbState;

#[tauri::command]
pub(crate) fn list_encounters(state: State<DbState>, limit: Option<i64>) -> Result<Vec<Value>, String> {
    let conn = state.0.lock();
    let n = limit.unwrap_or(50);
    let sql = format!(
        "SELECT {ENCOUNTER_COLS} FROM encounters ORDER BY created_at DESC LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![n], encounter_row_to_json)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
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
) -> Result<(), String> {
    let conn = state.0.lock();
    let n = conn
        .execute(
            "UPDATE encounters SET status = 'signed', signed_at = ?2, signed_hash = ?3 WHERE id = ?1",
            params![id, signed_at, signed_hash],
        )
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err(format!("encounter {} not found", id));
    }
    Ok(())
}

// Null out audio_path on a single encounter row without touching any other
// column — mirrors mark_encounter_signed's scoping so an audio-purge cannot
// clobber patient_alias or sign-off fields.
#[tauri::command]
pub(crate) fn clear_encounter_audio_path(state: State<DbState>, id: String) -> Result<(), String> {
    let conn = state.0.lock();
    let n = conn
        .execute(
            "UPDATE encounters SET audio_path = NULL WHERE id = ?1",
            params![id],
        )
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err(format!("encounter {} not found", id));
    }
    Ok(())
}

// Fetch a single encounter by id — avoids pulling the whole list to open one row.
#[tauri::command]
pub(crate) fn get_encounter(state: State<DbState>, id: String) -> Result<Option<Value>, String> {
    let conn = state.0.lock();
    let sql = format!("SELECT {ENCOUNTER_COLS} FROM encounters WHERE id = ?1");
    conn.query_row(&sql, params![id], encounter_row_to_json)
        .optional()
        .map_err(|e| e.to_string())
}

// Home-screen counters via indexed COUNT(*) — O(index) instead of shipping rows
// to JS and filtering. `today` is passed in so the comparison matches how
// encounter_date is stored client-side.
#[tauri::command]
pub(crate) fn encounter_stats(state: State<DbState>, today: String) -> Result<Value, String> {
    let conn = state.0.lock();
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM encounters", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let signed: i64 = conn
        .query_row("SELECT COUNT(*) FROM encounters WHERE status = 'signed'", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let today_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM encounters WHERE encounter_date = ?1", params![today], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    Ok(json!({ "total": total, "signed": signed, "today": today_count }))
}

#[tauri::command]
pub(crate) fn upsert_encounter(state: State<DbState>, encounter: Value) -> Result<(), String> {
    let conn = state.0.lock();
    conn.execute(
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
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
