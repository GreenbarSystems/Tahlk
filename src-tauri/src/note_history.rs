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

use crate::errors::AppError;
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
                log::error!("note_history migration: unparseable blob for {}, skipping", encounter_id);
                continue;
            }
        };
        let entries = match parsed.as_array() {
            Some(a) => a.clone(),
            None => {
                log::error!("note_history migration: blob for {} is not an array, skipping", encounter_id);
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
                log::error!(
                    "note_history migration: insert failed for {} seq {}: {}, aborting this encounter",
                    encounter_id, seq, crate::log_safety::cap_len(&e.to_string())
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

// Distinct encounter_ids that have at least one note_history row. Used by
// the JS-side chain verifier (historyChain.js::verifyAllChains) to discover
// which encounters to walk without needing a full encounter listing or any
// join against the encounters table — note_history is deliberately the only
// source of truth queried here, so an encounter row that was hard-deleted
// out of `encounters` (leaving orphaned history) still gets verified rather
// than silently skipped.
//
// Kept in Rust rather than derived from list_encounters()/get_encounter()
// results because those return live encounter metadata (status, alias,
// audio_path) the verifier has no use for and would otherwise recompute
// nothing from — this is a plain `SELECT DISTINCT`, no chain math, matching
// this module's "dumb append-only log" design principle from the file doc
// comment above: verification logic stays entirely in the JS domain layer.
#[tauri::command]
pub(crate) fn note_history_list_encounter_ids(state: State<DbState>) -> Result<Vec<String>, AppError> {
    let conn = state.0.get()?;
    let mut stmt = conn.prepare("SELECT DISTINCT encounter_id FROM note_history ORDER BY encounter_id")?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[tauri::command]
pub(crate) fn note_history_list(state: State<DbState>, encounter_id: String) -> Result<Vec<Value>, AppError> {
    let conn = state.0.get()?;
    let mut stmt = conn.prepare(
        "SELECT action, actor, timestamp, content_hash, notes, prev_hash, entry_hash \
         FROM note_history WHERE encounter_id = ?1 ORDER BY seq",
    )?;
    let rows = stmt
        .query_map(params![encounter_id], row_to_json)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[tauri::command]
pub(crate) fn note_history_append(
    state: State<DbState>,
    encounter_id: String,
    entry: Value,
) -> Result<i64, AppError> {
    // All fields required except notes/prev_hash. entry_hash is opaque data
    // computed by JS; Rust does not re-derive it. Length caps guard against
    // pathological payloads from a compromised WebView. Validation failures
    // map to `InvalidInput` (frontend bug), not `Storage`.
    fn take_str(v: &Value, k: &str, max: usize) -> Result<String, AppError> {
        let s = v
            .get(k)
            .and_then(|x| x.as_str())
            .ok_or_else(|| AppError::invalid(format!("missing string field: {}", k)))?;
        if s.len() > max {
            return Err(AppError::invalid(format!("{} exceeds {} bytes", k, max)));
        }
        Ok(s.to_string())
    }
    fn opt_str(v: &Value, k: &str, max: usize) -> Result<Option<String>, AppError> {
        match v.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => {
                if s.len() > max {
                    return Err(AppError::invalid(format!("{} exceeds {} bytes", k, max)));
                }
                Ok(Some(s.clone()))
            }
            Some(_) => Err(AppError::invalid(format!("{} must be string or null", k))),
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
        return Err(AppError::invalid("notes exceeds 4096 bytes"));
    }
    let prev_hash = opt_str(&entry, "prevHash", 128)?;
    let entry_hash = take_str(&entry, "entryHash", 128)?;

    let mut conn = state.0.get()?;
    append_history_row(
        &mut conn, &encounter_id, &action, &actor, &timestamp, &content_hash,
        &notes, prev_hash.as_deref(), &entry_hash,
    )
}

// Transactional core of note_history_append, split out so it can be driven
// directly against a plain `Connection` in unit tests (no Tauri State
// harness needed) — same pattern as encounters::upsert_encounter_row.
//
// Race-safety note: the prev_hash check below does NOT by itself close the
// "two panels racing an append" hole. Both concurrent transactions can read
// the same last_hash before either has written (SQLite's default DEFERRED
// transaction takes no lock until the first write), so both can pass the
// prev_hash check identically and then both attempt to INSERT the same
// (encounter_id, seq). The actual guarantee against a silent seq collision
// is the `UNIQUE (encounter_id, seq)` table constraint (see init_schema
// above): the loser's INSERT fails at the SQL layer with a constraint
// violation, surfaced here as `AppError::Storage` via the blanket
// `From<rusqlite::Error>` impl. The prev_hash check instead catches a
// different, non-concurrent case: a caller whose local chain has genuinely
// diverged from what's committed (e.g. it appended against a stale/cached
// view of the history), which correctly maps to `InvalidInput` since that's
// a client-side logic mismatch, not a storage failure.
fn append_history_row(
    conn: &mut Connection,
    encounter_id: &str,
    action: &str,
    actor: &str,
    timestamp: &str,
    content_hash: &str,
    notes: &str,
    prev_hash: Option<&str>,
    entry_hash: &str,
) -> Result<i64, AppError> {
    let tx = conn.transaction()?;
    let next_seq: i64 = tx.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM note_history WHERE encounter_id = ?1",
        params![encounter_id],
        |r| r.get(0),
    )?;

    // If the caller sent a prev_hash, it must match the last row's entry_hash
    // for this encounter. This catches a diverged local chain (see the
    // race-safety note on this function); the UNIQUE(encounter_id, seq)
    // constraint below is what actually closes the concurrent-append race.
    let last_hash: Option<String> = tx
        .query_row(
            "SELECT entry_hash FROM note_history \
             WHERE encounter_id = ?1 AND seq = ?2",
            params![encounter_id, next_seq - 1],
            |r| r.get(0),
        )
        .optional()?;
    if last_hash.as_deref() != prev_hash {
        return Err(AppError::invalid(format!(
            "prev_hash chain mismatch (expected {:?}, got {:?})",
            last_hash, prev_hash
        )));
    }

    tx.execute(
        "INSERT INTO note_history \
         (encounter_id, seq, action, actor, timestamp, content_hash, notes, prev_hash, entry_hash) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![encounter_id, next_seq, action, actor, timestamp, content_hash, notes, prev_hash, entry_hash],
    )?;
    tx.commit()?;

    Ok(next_seq)
}

#[cfg(test)]
mod tests {
    //! Unit-level coverage for append_history_row, driven directly against a
    //! raw in-memory SQLite (same pattern as encounters::tests) so we don't
    //! need a Tauri State harness.
    //!
    //! The key thing pinned here is which mechanism actually stops a
    //! concurrent-append race from silently corrupting the seq ordering: NOT
    //! the prev_hash check (both racing writers can read the same prior
    //! state and pass it identically), but the UNIQUE(encounter_id, seq)
    //! table constraint. See the race-safety note on append_history_row.

    use super::*;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    fn append(
        conn: &mut Connection,
        encounter_id: &str,
        prev_hash: Option<&str>,
        entry_hash: &str,
    ) -> Result<i64, AppError> {
        append_history_row(
            conn, encounter_id, "note_saved", "provider-1", "2026-07-11T10:00:00Z",
            "content-hash", "", prev_hash, entry_hash,
        )
    }

    #[test]
    fn first_append_succeeds_with_no_prev_hash() {
        let mut conn = fresh_db();
        let seq = append(&mut conn, "enc-1", None, "hash-a").unwrap();
        assert_eq!(seq, 1);
    }

    #[test]
    fn sequential_appends_chain_correctly() {
        let mut conn = fresh_db();
        assert_eq!(append(&mut conn, "enc-1", None, "hash-a").unwrap(), 1);
        assert_eq!(append(&mut conn, "enc-1", Some("hash-a"), "hash-b").unwrap(), 2);
        assert_eq!(append(&mut conn, "enc-1", Some("hash-b"), "hash-c").unwrap(), 3);
    }

    #[test]
    fn diverged_prev_hash_is_rejected_as_invalid_input_not_storage() {
        // A caller whose local chain has genuinely diverged (stale prev_hash,
        // no actual concurrent writer involved) must be rejected by the
        // prev_hash check itself, mapped to InvalidInput.
        let mut conn = fresh_db();
        append(&mut conn, "enc-1", None, "hash-a").unwrap();
        let err = append(&mut conn, "enc-1", Some("wrong-prev-hash"), "hash-b").unwrap_err();
        assert!(
            matches!(err, AppError::InvalidInput(_)),
            "expected InvalidInput from the prev_hash check, got {:?}",
            err
        );
    }

    #[test]
    fn concurrent_append_race_is_stopped_by_the_unique_constraint_not_prev_hash() {
        // Simulates the actual race the misleading comment used to credit to
        // prev_hash: two transactions both read the same last-committed hash
        // before either has written, so BOTH compute an identical, valid
        // prev_hash for the same next_seq. The loser's INSERT must still be
        // rejected — but by the UNIQUE(encounter_id, seq) constraint at the
        // SQL layer (AppError::Storage), not by the prev_hash check
        // (AppError::InvalidInput), because the prev_hash the loser computed
        // was indistinguishable from the winner's at read time.
        let mut conn = fresh_db();
        append(&mut conn, "enc-1", None, "hash-a").unwrap();

        // Winner: takes seq 2 with a valid prev_hash and commits first.
        append(&mut conn, "enc-1", Some("hash-a"), "hash-b-winner").unwrap();

        // Loser: forge the exact interleaving by hand-inserting a row at the
        // seq the loser would also have computed (2 is now taken, so the
        // loser's own next_seq lookup would actually return 3 post-commit —
        // to prove the constraint is truly what's load-bearing, directly
        // attempt an INSERT at the already-taken seq with a prev_hash that
        // is valid for that seq slot, bypassing the seq lookup to pin down
        // the exact race window where both readers computed the same seq).
        let result = conn.execute(
            "INSERT INTO note_history              (encounter_id, seq, action, actor, timestamp, content_hash, notes, prev_hash, entry_hash)              VALUES (?1,2,'note_saved','provider-2','2026-07-11T10:00:01Z','content-hash','', ?2, 'hash-b-loser')",
            params!["enc-1", "hash-a"],
        );

        let err = result.expect_err("duplicate (encounter_id, seq) must be rejected");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("unique") || msg.to_lowercase().contains("constraint"),
            "expected a UNIQUE constraint violation, got: {}",
            msg
        );

        // The winner's row must be the one that survived, untouched.
        let (actor, entry_hash): (String, String) = conn
            .query_row(
                "SELECT actor, entry_hash FROM note_history WHERE encounter_id = 'enc-1' AND seq = 2",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(actor, "provider-1");
        assert_eq!(entry_hash, "hash-b-winner");
    }

    #[test]
    fn independent_encounters_do_not_share_seq_space() {
        let mut conn = fresh_db();
        assert_eq!(append(&mut conn, "enc-1", None, "hash-a").unwrap(), 1);
        // A different encounter_id starts its own seq at 1, unaffected by
        // enc-1's history.
        assert_eq!(append(&mut conn, "enc-2", None, "hash-x").unwrap(), 1);
    }

    // Mirrors note_history_list_encounter_ids' query directly against a raw
    // Connection (same pattern as the #[tauri::command] fns above, which
    // can't be called without a Tauri State harness).
    fn distinct_encounter_ids(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT DISTINCT encounter_id FROM note_history ORDER BY encounter_id")
            .unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn distinct_encounter_ids_is_empty_on_a_fresh_db() {
        let conn = fresh_db();
        assert_eq!(distinct_encounter_ids(&conn), Vec::<String>::new());
    }

    #[test]
    fn distinct_encounter_ids_returns_each_encounter_once_sorted() {
        let mut conn = fresh_db();
        // enc-2 gets three appends; enc-1 and enc-3 get one each. The
        // multi-row encounter must not produce duplicate ids in the output,
        // and results must come back sorted (not insertion order).
        append(&mut conn, "enc-3", None, "hash-a").unwrap();
        append(&mut conn, "enc-1", None, "hash-b").unwrap();
        append(&mut conn, "enc-2", None, "hash-c").unwrap();
        append(&mut conn, "enc-2", Some("hash-c"), "hash-d").unwrap();
        append(&mut conn, "enc-2", Some("hash-d"), "hash-e").unwrap();
        assert_eq!(
            distinct_encounter_ids(&conn),
            vec!["enc-1".to_string(), "enc-2".to_string(), "enc-3".to_string()]
        );
    }
}
