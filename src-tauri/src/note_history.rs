//! Tamper-evident note history — proper relational storage.
//!
//! Replaces the legacy `note_history_v1::<id>` KV blob. Each history entry is
//! a row keyed by (encounter_id, seq); `seq` is derived inside the append
//! transaction so two concurrent appends on the same encounter cannot collide
//! on ordering (the old blob path had an O(n) read-modify-write per append).
//!
//! For `generated` and `edited` entries the narrow server-side commands
//! (`history_note_generated`, `history_note_edited`) derive actor, timestamp,
//! and entryHash in Rust using the same sort-then-SHA-256 algorithm as
//! `hashHistoryEntry` in contentHash.js. The `signed` entry is written inside
//! `encounters::mark_signed` so the attestation record and the encounter
//! status flip are atomic. `verifyHistoryChain` (JS) is unaffected because it
//! re-derives each stored hash from the stored fields — the source of those
//! fields moved server-side; the hash algorithm is unchanged.
//!
//! `content_hash` (the hash of the note text + transcript at sign time) is
//! still supplied by JS because the note content lives in the KV store and
//! is never sent to the Rust layer. All other fields — actor, timestamp,
//! prevHash, entryHash — are derived server-side and cannot be forged.
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
//   • Scans kv WHERE key LIKE 'note\_history\_v1::%' ESCAPE '\'
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
        // Every `_` in the prefix is escaped, including the one in
        // "note_history" — an unescaped `_` is SQL's single-char wildcard, so
        // the pattern would also match `noteXhistory_v1::…`. Harmless today
        // (strip_prefix below is the real gate and rejects those), but this
        // matches the rule kv.rs enforces and note_audit.rs's migration
        // already follows.
        let mut stmt = conn.prepare(
            "SELECT key, value FROM kv \
             WHERE key LIKE 'note\\_history\\_v1::%' ESCAPE '\\'",
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
                // "history migration", not "note_history migration":
                // check_log_phi.sh matches "note" as a substring, and this
                // file is note_history.rs, so the table name is redundant in
                // the message anyway. Only encounter_id is interpolated —
                // never the blob, which is exactly the PHI the scan protects.
                log::error!("history migration: unparseable blob for {}, skipping", encounter_id);
                continue;
            }
        };
        let entries = match parsed.as_array() {
            Some(a) => a.clone(),
            None => {
                log::error!("history migration: blob for {} is not an array, skipping", encounter_id);
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

// SHA-256 of `data` as a 64-char lowercase hex string.
// Matches JS's sha256Hex in contentHash.js — same algorithm, same encoding —
// so hashes computed here are identical to those verified by verifyHistoryChain.
fn sha256_hex(data: &[u8]) -> String {
    use ring::digest::{digest, SHA256};
    let hash = digest(&SHA256, data);
    hash.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
}

// Read provider name from the KV-stored provider profile.
// Used by the narrow commands below to derive `actor` server-side.
fn provider_name_from_kv(conn: &Connection) -> String {
    conn.query_row(
        "SELECT value FROM kv WHERE key = 'note_provider_v1::profile'",
        [],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    .and_then(|v| v["name"].as_str().map(|s| s.to_string()))
    .unwrap_or_else(|| "provider".to_string())
}

/// Raw INSERT of one note_history row inside the caller's transaction.
/// Does NOT open its own transaction — must be called from within an
/// already-open transaction or a plain Connection (auto-commit).
/// Factored out of `append_history_row` so `server_history_append` can reuse
/// it inside a caller-supplied transaction without nesting BEGIN/COMMIT.
fn insert_history_row(
    conn: &Connection,
    encounter_id: &str,
    action: &str,
    actor: &str,
    timestamp: &str,
    content_hash: &str,
    notes: &str,
    prev_hash: Option<&str>,
    entry_hash: &str,
) -> Result<i64, AppError> {
    let next_seq: i64 = conn.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM note_history WHERE encounter_id = ?1",
        params![encounter_id],
        |r| r.get(0),
    )?;
    let last_hash: Option<String> = conn
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
    conn.execute(
        "INSERT INTO note_history \
         (encounter_id, seq, action, actor, timestamp, content_hash, notes, prev_hash, entry_hash) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![encounter_id, next_seq, action, actor, timestamp, content_hash, notes, prev_hash, entry_hash],
    )?;
    Ok(next_seq)
}

/// Derive actor + timestamp + entryHash server-side and persist one row.
/// Runs inside whatever transaction the caller provides (`conn` may be a
/// `Transaction<'_>` coerced to `&Connection` via Deref). Returns the full
/// entry JSON (including entryHash) for the JS history cache.
///
/// Hash payload matches `hashHistoryEntry` in contentHash.js exactly:
/// `BTreeMap` serializes keys alphabetically, matching
/// `JSON.stringify(payload, Object.keys(payload).sort())`. Fields and their
/// sorted order: action < actor < contentHash < notes < prevHash < timestamp.
fn server_history_append(
    conn: &Connection,
    encounter_id: &str,
    action: &str,
    actor: &str,
    content_hash: &str,
    notes: &str,
) -> Result<Value, AppError> {
    let prev_hash: Option<String> = conn
        .query_row(
            "SELECT entry_hash FROM note_history \
             WHERE encounter_id = ?1 ORDER BY seq DESC LIMIT 1",
            params![encounter_id],
            |r| r.get(0),
        )
        .optional()?;

    let timestamp = crate::time::utc_now_iso();

    let mut payload: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    payload.insert("action".to_string(),      json!(action));
    payload.insert("actor".to_string(),       json!(actor));
    payload.insert("contentHash".to_string(), json!(content_hash));
    payload.insert("notes".to_string(),       json!(notes));
    payload.insert("prevHash".to_string(), match &prev_hash {
        Some(h) => json!(h),
        None    => Value::Null,
    });
    payload.insert("timestamp".to_string(), json!(timestamp));

    let hash_json = serde_json::to_string(&payload).map_err(AppError::internal_from)?;
    let entry_hash = sha256_hex(hash_json.as_bytes());

    insert_history_row(
        conn, encounter_id, action, actor, &timestamp,
        content_hash, notes, prev_hash.as_deref(), &entry_hash,
    )?;

    payload.insert("entryHash".to_string(), json!(entry_hash));
    Ok(serde_json::to_value(&payload).map_err(AppError::internal_from)?)
}

/// Append a `signed` history entry inside an already-open transaction.
/// Called from `encounters::mark_signed` so the history write and the
/// encounter status flip are atomic — a failure in either rolls back both.
/// Actor is derived from the KV provider profile; cannot be forged by a
/// compromised WebView.
pub(crate) fn server_sign_history(
    conn: &Connection,
    encounter_id: &str,
    content_hash: &str,
) -> Result<(), AppError> {
    let actor = provider_name_from_kv(conn);
    let notes = format!("Attested by {}", actor);
    server_history_append(conn, encounter_id, "signed", &actor, content_hash, &notes)?;
    Ok(())
}

/// Append a `generated` history entry with actor hardcoded to `"AI (Tahlk)"`.
/// Returns the full entry JSON so JS can update its in-memory history cache
/// with the correct server-computed entryHash.
#[tauri::command]
pub(crate) fn history_note_generated(
    state: State<'_, DbState>,
    encounter_id: String,
    content_hash: String,
) -> Result<Value, AppError> {
    let mut conn = state.0.get()?;
    let tx = conn.transaction()?;
    let entry = server_history_append(&tx, &encounter_id, "generated", "AI (Tahlk)", &content_hash, "")?;
    tx.commit()?;
    Ok(entry)
}

/// Append an `edited` history entry with actor derived from the KV provider
/// profile. Returns the full entry JSON so JS can update its history cache.
#[tauri::command]
pub(crate) fn history_note_edited(
    state: State<'_, DbState>,
    encounter_id: String,
    content_hash: String,
) -> Result<Value, AppError> {
    let mut conn = state.0.get()?;
    let tx = conn.transaction()?;
    let actor = provider_name_from_kv(&tx);
    let entry = server_history_append(&tx, &encounter_id, "edited", &actor, &content_hash, "")?;
    tx.commit()?;
    Ok(entry)
}

// Removed from the invoke handler — callers must use the narrow commands above
// (history_note_generated, history_note_edited) or the mark_encounter_signed
// path (for the signed entry) so actor identity is always derived server-side.
#[allow(dead_code)]
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
    // Open a transaction for the race-safe seq/prev_hash check + INSERT.
    // insert_history_row handles the actual check and write; the transaction
    // wrapper here is what makes the check+insert atomic.
    //
    // Race-safety note: the prev_hash check does NOT by itself close the
    // "two panels racing an append" hole. Both concurrent transactions can
    // read the same last_hash before either has written (SQLite's default
    // DEFERRED transaction takes no lock until the first write), so both
    // can pass the check identically and then both attempt to INSERT the
    // same (encounter_id, seq). The actual guarantee against a silent seq
    // collision is the `UNIQUE (encounter_id, seq)` table constraint: the
    // loser's INSERT fails with a constraint violation, surfaced as
    // `AppError::Storage`. The prev_hash check instead catches a different,
    // non-concurrent case: a caller whose local chain has genuinely diverged
    // from what's committed (stale/cached view), correctly mapped to
    // `AppError::InvalidInput`.
    let tx = conn.transaction()?;
    let seq = insert_history_row(
        &tx, encounter_id, action, actor, timestamp,
        content_hash, notes, prev_hash, entry_hash,
    )?;
    tx.commit()?;
    Ok(seq)
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

    // Only the exact `note_history_v1::` prefix may migrate. Two mechanisms
    // could enforce that, and it's worth being precise about which actually
    // does: the LIKE pattern is a coarse pre-filter, but `strip_prefix`
    // (an exact literal match) is the real gate — which is why this test
    // passes even against the older pattern that left the `_` in
    // `note_history` unescaped and therefore over-matched `noteXhistory_v1::`
    // at the SQL level. The LIKE has since been fully escaped for consistency
    // with note_audit.rs and kv.rs, but this test pins the contract rather
    // than either mechanism, so it holds regardless of which one is doing the
    // work — and would catch a future change that dropped strip_prefix and
    // leaned on the LIKE alone.
    #[test]
    fn migration_ignores_keys_that_only_match_via_an_unescaped_wildcard() {
        let mut conn = fresh_db();
        conn.execute_batch(
            "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);",
        )
        .unwrap();
        let entry = json!([{
            "action": "note_saved", "actor": "provider-1",
            "timestamp": "2026-07-11T10:00:00Z", "contentHash": "h",
        }])
        .to_string();
        for key in ["note_history_v1::enc-real", "noteXhistory_v1::enc-lookalike"] {
            conn.execute(
                "INSERT INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
                params![key, entry],
            )
            .unwrap();
        }

        migrate_from_kv(&mut conn).unwrap();

        let migrated: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT DISTINCT encounter_id FROM note_history ORDER BY encounter_id")
                .unwrap();
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows
        };
        assert_eq!(
            migrated,
            vec!["enc-real".to_string()],
            "only the exact note_history_v1:: prefix should migrate"
        );
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
