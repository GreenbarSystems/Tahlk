//! Tamper-evident note history — proper relational storage.
//!
//! Replaces the legacy `note_history_v1::<id>` KV blob. Each history entry is
//! a row keyed by (encounter_id, seq); `seq` is derived inside the append
//! transaction so two concurrent appends on the same encounter cannot collide
//! on ordering (the old blob path had an O(n) read-modify-write per append).
//!
//! The entry_hash is treated as opaque data: the Rust side never re-computes
//! or validates it. Chaining and verification stay in the JS domain layer
//! (contentHash.js / historyChain.js), so this module is a dumb append-only
//! log — any future actor field or notes change requires ZERO Rust change.
//!
//! Migration from the legacy KV blob happens once in `db::open_database` and
//! is idempotent (see `migrate_from_kv`).
//!
//! Legacy entries in the KV blob may lack `prev_hash` / `entry_hash` (early
//! prototypes wrote a bare `{action, actor, timestamp, contentHash}`). The
//! table column `entry_hash` is NOT NULL to reject NEW inserts without a
//! hash, but the migration path passes empty strings through so the audit
//! trail is preserved verbatim; verifyHistoryChain treats empty entry_hash
//! rows as legacy-skipped, matching the prior semantics.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use tauri::State;

use crate::DbState;

const LEGACY_PREFIX: &str = "note_history_v1::";

pub(crate) fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS note_history (
             id            INTEGER PRIMARY KEY AUTOINCREMENT,
             encounter_id  TEXT NOT NULL,
             seq           INTEGER NOT NULL,
             action        TEXT NOT NULL,
             actor         TEXT NOT NULL,
             timestamp     TEXT NOT NULL,
             content_hash  TEXT NOT NULL,
             notes         TEXT NOT NULL DEFAULT '',
             prev_hash     TEXT,
             entry_hash    TEXT NOT NULL,
             UNIQUE (encounter_id, seq)
         );
         CREATE INDEX IF NOT EXISTS note_history_enc_idx
             ON note_history (encounter_id, seq);",
    )
}

// One-shot migration of note_history_v1::<id> KV blobs into the relational
// table. Called from db::open_database after schema creation. Idempotent:
//
//   • Scans kv WHERE key LIKE 'note_history_v1::%' ESCAPE '\'
//   • For each encounter that has ZERO existing rows in note_history,
//     parses the blob and INSERTs rows preserving array-index order as seq.
//   • DELETEs the KV row only after all INSERTs for that encounter succeed.
//
// Wrapped in a single transaction PER encounter, so a poison-pill blob
// aborts only that encounter's migration and leaves the KV row in place for
// later inspection — the app still starts, and the untouched blob remains
// available to the old code path (which we're deleting anyway).
pub(crate) fn migrate_from_kv(conn: &mut Connection) -> rusqlite::Result<()> {
    // Collect (key, value) pairs up front so we don't hold a prepared stmt
    // while we open per-encounter transactions.
    let rows: Vec<(String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT key, value FROM kv \
             WHERE key LIKE 'note_history\\_v1::%' ESCAPE '\\'",
        )?;
        let iter = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in iter {
            out.push(row?);
        }
        out
    };

    for (key, value) in rows {
        let encounter_id = match key.strip_prefix(LEGACY_PREFIX) {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => continue,
        };

        // Skip encounters that already have rows in the new table — protects
        // against re-running after a partial migration or a manual replay.
        let existing: i64 = conn.query_row(
            "SELECT COUNT(*) FROM note_history WHERE encounter_id = ?1",
            params![encounter_id],
            |r| r.get(0),
        )?;
        if existing > 0 {
            // The old KV row is now redundant — drop it.
            conn.execute("DELETE FROM kv WHERE key = ?1", params![key])?;
            continue;
        }

        // Parse the JSON blob (already stringified by kv_set). The outer
        // value is JSON-serialized, so it's a JSON string containing a JSON
        // array. Handle both encodings defensively.
        let parsed: Value = match serde_json::from_str::<Value>(&value) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("note_history migration: unparseable blob for {}, skipping", encounter_id);
                continue;
            }
        };
        let entries = match parsed.as_array() {
            Some(a) => a.clone(),
            None => {
                eprintln!("note_history migration: blob for {} is not an array, skipping", encounter_id);
                continue;
            }
        };

        // Migrate the encounter atomically so a mid-array failure rolls back.
        let tx = conn.transaction()?;
        let mut ok = true;
        for (idx, entry) in entries.iter().enumerate() {
            let seq = (idx as i64) + 1;
            let action = entry.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let actor = entry.get("actor").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let timestamp = entry.get("timestamp").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let content_hash = entry
                .get("contentHash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let notes = entry.get("notes").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let prev_hash: Option<String> = entry
                .get("prevHash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            // Legacy entries may not have entryHash; store empty string so
            // verifyHistoryChain's legacySkipped counter still works.
            let entry_hash = entry
                .get("entryHash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if let Err(e) = tx.execute(
                "INSERT INTO note_history \
                 (encounter_id, seq, action, actor, timestamp, content_hash, notes, prev_hash, entry_hash) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![encounter_id, seq, action, actor, timestamp, content_hash, notes, prev_hash, entry_hash],
            ) {
                eprintln!(
                    "note_history migration: insert failed for {} seq {}: {}, aborting this encounter",
                    encounter_id, seq, e
                );
                ok = false;
                break;
            }
        }
        if !ok {
            let _ = tx.rollback();
            continue;
        }
        // Delete the KV row inside the same commit so migration + cleanup
        // land atomically.
        tx.execute("DELETE FROM kv WHERE key = ?1", params![key])?;
        tx.commit()?;
    }

    Ok(())
}

fn row_to_json(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    // Keys match the JS shape the domain layer already expects, so callers
    // don't need per-row translation. entryHash is emitted as "" when the
    // stored column is empty (legacy migrated rows).
    Ok(json!({
        "action":      r.get::<_, String>(0)?,
        "actor":       r.get::<_, String>(1)?,
        "timestamp":   r.get::<_, String>(2)?,
        "contentHash": r.get::<_, String>(3)?,
        "notes":       r.get::<_, String>(4)?,
        "prevHash":    r.get::<_, Option<String>>(5)?,
        "entryHash":   r.get::<_, String>(6)?,
    }))
}

#[tauri::command]
pub(crate) fn note_history_list(state: State<DbState>, encounter_id: String) -> Result<Vec<Value>, String> {
    let conn = state.0.lock();
    let mut stmt = conn
        .prepare(
            "SELECT action, actor, timestamp, content_hash, notes, prev_hash, entry_hash \
             FROM note_history WHERE encounter_id = ?1 ORDER BY seq",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![encounter_id], row_to_json)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

#[tauri::command]
pub(crate) fn note_history_append(
    state: State<DbState>,
    encounter_id: String,
    entry: Value,
) -> Result<i64, String> {
    // All fields required except notes/prev_hash. entry_hash is opaque data
    // computed by JS; Rust does not re-derive it. Length caps guard against
    // pathological payloads from a compromised WebView.
    fn take_str(v: &Value, k: &str, max: usize) -> Result<String, String> {
        let s = v
            .get(k)
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("missing string field: {}", k))?;
        if s.len() > max {
            return Err(format!("{} exceeds {} bytes", k, max));
        }
        Ok(s.to_string())
    }
    fn opt_str(v: &Value, k: &str, max: usize) -> Result<Option<String>, String> {
        match v.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => {
                if s.len() > max {
                    return Err(format!("{} exceeds {} bytes", k, max));
                }
                Ok(Some(s.clone()))
            }
            Some(_) => Err(format!("{} must be string or null", k)),
        }
    }

    let action = take_str(&entry, "action", 32)?;
    let actor = take_str(&entry, "actor", 256)?;
    let timestamp = take_str(&entry, "timestamp", 64)?;
    let content_hash = take_str(&entry, "contentHash", 128)?;
    // notes may be missing / empty; default to "".
    let notes = entry
        .get("notes")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if notes.len() > 4096 {
        return Err("notes exceeds 4096 bytes".into());
    }
    let prev_hash = opt_str(&entry, "prevHash", 128)?;
    let entry_hash = take_str(&entry, "entryHash", 128)?;

    let mut conn = state.0.lock();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let next_seq: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM note_history WHERE encounter_id = ?1",
            params![encounter_id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;

    // If the caller sent a prev_hash, it must match the last row's entry_hash
    // for this encounter. Enforcing this in the tx (not just JS) closes the
    // "two panels racing an append" hole: the loser is rejected with a chain
    // mismatch instead of silently producing a diverged branch that would
    // only be caught later by verifyHistoryChain.
    let last_hash: Option<String> = tx
        .query_row(
            "SELECT entry_hash FROM note_history \
             WHERE encounter_id = ?1 AND seq = ?2",
            params![encounter_id, next_seq - 1],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if last_hash.as_deref() != prev_hash.as_deref() {
        return Err(format!(
            "prev_hash chain mismatch (expected {:?}, got {:?})",
            last_hash, prev_hash
        ));
    }

    tx.execute(
        "INSERT INTO note_history \
         (encounter_id, seq, action, actor, timestamp, content_hash, notes, prev_hash, entry_hash) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![encounter_id, next_seq, action, actor, timestamp, content_hash, notes, prev_hash, entry_hash],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    Ok(next_seq)
}
