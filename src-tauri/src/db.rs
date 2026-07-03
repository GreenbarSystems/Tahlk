//! Database bootstrap and shared row helpers.
//!
//! `DbState` (the shared connection wrapper) lives in `lib.rs` at the crate
//! root so every module can name it via `crate::DbState` without cyclic
//! imports. This module owns the schema + connection pragmas and the
//! encounter-row projection used by both list and get queries.

use parking_lot::Mutex;
use rusqlite::Connection;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager};

use crate::DbState;

// Column order shared by list_encounters and get_encounter. Keeping the
// SELECT list identical between the two paths means encounter_row_to_json
// can be reused without positional drift.
pub(crate) const ENCOUNTER_COLS: &str =
    "id, provider_id, encounter_date, patient_alias, status, \
     audio_path, created_at, signed_at, signed_hash";

pub(crate) fn encounter_row_to_json(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "id":             r.get::<_, String>(0)?,
        "provider_id":    r.get::<_, String>(1)?,
        "encounter_date": r.get::<_, String>(2)?,
        "patient_alias":  r.get::<_, Option<String>>(3)?,
        "status":         r.get::<_, String>(4)?,
        "audio_path":     r.get::<_, Option<String>>(5)?,
        "created_at":     r.get::<_, String>(6)?,
        "signed_at":      r.get::<_, Option<String>>(7)?,
        "signed_hash":    r.get::<_, Option<String>>(8)?,
    }))
}

pub(crate) fn open_database(app: &AppHandle) -> rusqlite::Result<Connection> {
    let data_dir = app.path().app_data_dir().expect("could not resolve app_data_dir");
    std::fs::create_dir_all(&data_dir).expect("could not create app data dir");
    let db_path = data_dir.join("tahlk.db");
    let conn = Connection::open(&db_path)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous   = NORMAL;
         PRAGMA foreign_keys  = ON;

         CREATE TABLE IF NOT EXISTS kv (
             key        TEXT PRIMARY KEY,
             value      TEXT NOT NULL,
             updated_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS kv_prefix_idx ON kv (key);

         CREATE TABLE IF NOT EXISTS encounters (
             id             TEXT PRIMARY KEY,
             provider_id    TEXT NOT NULL,
             encounter_date TEXT NOT NULL,
             patient_alias  TEXT,
             status         TEXT NOT NULL DEFAULT 'draft',
             audio_path     TEXT,
             created_at     TEXT NOT NULL,
             signed_at      TEXT,
             signed_hash    TEXT
         );
         CREATE INDEX IF NOT EXISTS enc_date_idx ON encounters (encounter_date DESC);
         CREATE INDEX IF NOT EXISTS enc_status_idx ON encounters (status);
         CREATE INDEX IF NOT EXISTS enc_created_idx ON encounters (created_at DESC);",
    )?;
    Ok(conn)
}

// Convenience wrapper so `run()` in lib.rs doesn't need to know how DbState
// is constructed from a Connection.
pub(crate) fn new_state(conn: Connection) -> DbState {
    DbState(Mutex::new(conn))
}
