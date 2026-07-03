//! Generic key/value store commands.
//!
//! All entry points route through `guard_key` / the `secret_*` LIKE-escape
//! so the `secret_v1::anthropic_api_key` namespace can never be read, written,
//! removed, or enumerated through the JS-facing KV API. Secrets live in the
//! OS keychain (see `secrets.rs`).

use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use tauri::State;

use crate::secrets::guard_key;
use crate::DbState;

#[tauri::command]
pub(crate) fn kv_get(state: State<DbState>, key: String) -> Result<Option<Value>, String> {
    guard_key(&key)?;
    let conn = state.0.lock();
    let row: Option<String> = conn
        .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    match row {
        Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| e.to_string()),
        None => Ok(None),
    }
}

#[tauri::command]
pub(crate) fn kv_set(state: State<DbState>, key: String, value: Value) -> Result<(), String> {
    guard_key(&key)?;
    let conn = state.0.lock();
    let json = serde_json::to_string(&value).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO kv (key, value, updated_at) \
         VALUES (?1, ?2, strftime('%s', 'now')) \
         ON CONFLICT(key) DO UPDATE SET \
             value      = excluded.value, \
             updated_at = excluded.updated_at",
        params![key, json],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub(crate) fn kv_remove(state: State<DbState>, key: String) -> Result<(), String> {
    guard_key(&key)?;
    let conn = state.0.lock();
    conn.execute("DELETE FROM kv WHERE key = ?1", params![key])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub(crate) fn kv_list(state: State<DbState>, prefix: String) -> Result<Vec<(String, Value)>, String> {
    let pattern = if prefix.is_empty() { String::from("%") } else { format!("{}%", prefix) };
    let conn = state.0.lock();
    // Never surface secret_* keys through enumeration.
    let mut stmt = conn
        .prepare("SELECT key, value FROM kv WHERE key LIKE ?1 AND key NOT LIKE 'secret\\_%' ESCAPE '\\' ORDER BY key")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![pattern], |r| {
            let k: String = r.get(0)?;
            let v: String = r.get(1)?;
            Ok((k, v))
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        let (k, v) = row.map_err(|e| e.to_string())?;
        let parsed: Value = serde_json::from_str(&v).map_err(|e| e.to_string())?;
        out.push((k, parsed));
    }
    Ok(out)
}
