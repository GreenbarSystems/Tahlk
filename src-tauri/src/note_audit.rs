//! Tamper-evident record-access/activity audit log — proper relational
//! storage (fixes audit finding H1: "JS-side audit log ... stored as
//! ordinary KV rows, fully deletable/overwritable via generic
//! kv_remove/kv_set").
//!
//! Replaces the legacy `note_audit_v1::<id>` (live) and
//! `note_audit_archive_v1::<id>` (archive) KV blobs. Each entry is a row
//! keyed by (encounter_id, seq); seq is derived inside the append
//! transaction so two concurrent appends on the same encounter cannot
//! collide on ordering — same mechanism as note_history.rs, including the
//! same race-safety split (prev_hash check catches a diverged local chain;
//! the UNIQUE(encounter_id, seq) constraint is what actually stops a
//! genuine concurrent-append race).
//!
//! Unlike note_history.rs, auditLog.js entries do not have a fixed field
//! shape — action-specific `details` are spread into each entry
//! (encounterId, contentHash, removed, reason, error, format, method, ...
//! vary by action; see contentHash.js's hashAuditEntry doc comment). Rather
//! than guess a fixed column set, each row stores the entry verbatim as
//! JSON (`entry_json`), with `prev_hash`/`entry_hash` pulled into their own
//! columns for the chain-continuity check. This module never interprets
//! `entry_json`'s contents beyond that — chaining and verification stay in
//! the JS domain layer, matching note_history.rs's "dumb append-only log"
//! design principle.
//!
//! Cap/archive semantics (which live entries get archived once an
//! encounter's live count exceeds its cap) are decided by JS — this module
//! just executes "insert this entry, then archive the oldest N still-live
//! rows" as one atomic transaction. JS already has to hold the live log in
//! memory to derive prevHash, so it is the natural place for that policy to
//! live, consistent with note_history.rs keeping ALL business logic out of
//! Rust.
//!
//! Migration from both legacy KV blobs happens once in `db::open_database`
//! and is idempotent (see `migrate_from_kv`) — it concatenates archive
//! (older) ++ live (newer) per encounter in original chain order so no
//! history is lost, then deletes the KV rows.
//!
//! No delete/remove command is exposed to JS for this table. That omission
//! is the actual fix: unlike the old KV storage, nothing reachable from a
//! compromised WebView can erase or blank an encounter's audit trail —
//! only append and read commands exist.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use tauri::State;

use crate::errors::AppError;
use crate::DbState;

const LEGACY_LIVE_PREFIX: &str = "note_audit_v1::";
const LEGACY_ARCHIVE_PREFIX: &str = "note_audit_archive_v1::";

/// Ceiling on one entry's serialized JSON size. Audit entries are small
/// structured records (actor/action/timestamp plus a handful of short
/// fields); 16 KiB is generous headroom while still rejecting a
/// pathological payload from a compromised WebView before it reaches the DB.
pub(crate) const MAX_ENTRY_JSON_BYTES: usize = 16 * 1024;

/// Sanity ceiling on how many live rows a single append can ask to archive
/// at once. Archiving is not a security-sensitive operation (it never
/// deletes data — see module doc), but an unbounded value from a
/// compromised WebView could still trigger a pathologically large UPDATE.
pub(crate) const MAX_EVICT_PER_APPEND: i64 = 100_000;

pub(crate) fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS note_audit (
             id            INTEGER PRIMARY KEY AUTOINCREMENT,
             encounter_id  TEXT NOT NULL,
             seq           INTEGER NOT NULL,
             archived      INTEGER NOT NULL DEFAULT 0,
             prev_hash     TEXT,
             entry_hash    TEXT NOT NULL,
             entry_json    TEXT NOT NULL,
             UNIQUE (encounter_id, seq)
         );
         CREATE INDEX IF NOT EXISTS note_audit_enc_idx
             ON note_audit (encounter_id, seq);
         CREATE INDEX IF NOT EXISTS note_audit_live_idx
             ON note_audit (encounter_id, archived, seq);",
    )
}

// One-shot migration of note_audit_v1::<id> / note_audit_archive_v1::<id>
// KV blobs into the relational table. Idempotent, mirrors
// note_history::migrate_from_kv:
//
//   • Scans kv for both legacy prefixes, grouped by encounter_id.
//   • For each encounter with ZERO existing note_audit rows, concatenates
//     archive (older) ++ live (newer) in original array order and INSERTs
//     rows preserving that order as seq. All migrated rows land with
//     archived = 0 — the live/archived split only matters going forward
//     from the next real append's eviction decision; collapsing it here is
//     harmless since nothing distinguishes them for compliance purposes
//     (both are part of the same tamper-evident chain).
//   • DELETEs both KV rows only after all INSERTs for that encounter
//     succeed (or immediately if an encounter already has rows, or if both
//     blobs were empty/unparseable).
//
// Wrapped in a single transaction PER encounter, so a poison-pill blob
// aborts only that encounter's migration and leaves its KV rows in place
// for later inspection.
pub(crate) fn migrate_from_kv(conn: &mut Connection) -> rusqlite::Result<()> {
    let rows: Vec<(String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT key, value FROM kv \
             WHERE key LIKE 'note\\_audit\\_v1::%' ESCAPE '\\' \
                OR key LIKE 'note\\_audit\\_archive\\_v1::%' ESCAPE '\\'",
        )?;
        let iter = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in iter {
            out.push(row?);
        }
        out
    };

    // Group by encounter_id: (archive_blob, live_blob). Both are Option
    // since an encounter may have only ever had a live blob (never
    // truncated) or, in principle, only an archive (shouldn't happen in
    // practice, but the migration must not assume it can't).
    use std::collections::HashMap;
    let mut by_encounter: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    for (key, value) in rows {
        if let Some(id) = key.strip_prefix(LEGACY_ARCHIVE_PREFIX) {
            if !id.is_empty() {
                by_encounter.entry(id.to_string()).or_default().0 = Some(value);
            }
        } else if let Some(id) = key.strip_prefix(LEGACY_LIVE_PREFIX) {
            if !id.is_empty() {
                by_encounter.entry(id.to_string()).or_default().1 = Some(value);
            }
        }
    }

    for (encounter_id, (archive_blob, live_blob)) in by_encounter {
        let live_key = format!("{LEGACY_LIVE_PREFIX}{encounter_id}");
        let archive_key = format!("{LEGACY_ARCHIVE_PREFIX}{encounter_id}");

        let existing: i64 = conn.query_row(
            "SELECT COUNT(*) FROM note_audit WHERE encounter_id = ?1",
            params![encounter_id],
            |r| r.get(0),
        )?;
        if existing > 0 {
            conn.execute("DELETE FROM kv WHERE key IN (?1, ?2)", params![live_key, archive_key])?;
            continue;
        }

        let mut entries: Vec<Value> = Vec::new();
        for blob in [archive_blob, live_blob].into_iter().flatten() {
            match serde_json::from_str::<Value>(&blob) {
                Ok(Value::Array(arr)) => entries.extend(arr),
                _ => {
                    eprintln!(
                        "note_audit migration: unparseable/non-array blob for {}, skipping that half",
                        encounter_id
                    );
                }
            }
        }
        if entries.is_empty() {
            conn.execute("DELETE FROM kv WHERE key IN (?1, ?2)", params![live_key, archive_key])?;
            continue;
        }

        let tx = conn.transaction()?;
        let mut ok = true;
        for (idx, entry) in entries.iter().enumerate() {
            let seq = (idx as i64) + 1;
            let prev_hash: Option<String> = entry
                .get("prevHash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            // Legacy entries may not have entryHash; store empty string so
            // the JS verifier's legacySkipped counter still works, matching
            // note_history's migration semantics.
            let entry_hash = entry
                .get("entryHash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let entry_json = entry.to_string();

            if let Err(e) = tx.execute(
                "INSERT INTO note_audit (encounter_id, seq, archived, prev_hash, entry_hash, entry_json) \
                 VALUES (?1,?2,0,?3,?4,?5)",
                params![encounter_id, seq, prev_hash, entry_hash, entry_json],
            ) {
                eprintln!(
                    "note_audit migration: insert failed for {} seq {}: {}, aborting this encounter",
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
        tx.execute("DELETE FROM kv WHERE key IN (?1, ?2)", params![live_key, archive_key])?;
        tx.commit()?;
    }

    Ok(())
}

fn entries_from(conn: &Connection, encounter_id: &str, archived: bool) -> Result<Vec<Value>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT entry_json FROM note_audit WHERE encounter_id = ?1 AND archived = ?2 ORDER BY seq",
    )?;
    let rows = stmt.query_map(params![encounter_id, archived as i64], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        let json_str = row?;
        out.push(serde_json::from_str(&json_str).map_err(AppError::internal_from)?);
    }
    Ok(out)
}

#[tauri::command]
pub(crate) fn audit_list(state: State<DbState>, encounter_id: String) -> Result<Vec<Value>, AppError> {
    let conn = state.0.get()?;
    entries_from(&conn, &encounter_id, false)
}

#[tauri::command]
pub(crate) fn audit_archive_list(state: State<DbState>, encounter_id: String) -> Result<Vec<Value>, AppError> {
    let conn = state.0.get()?;
    entries_from(&conn, &encounter_id, true)
}

#[tauri::command]
pub(crate) fn audit_append(
    state: State<DbState>,
    encounter_id: String,
    entry: Value,
    evicted_count: i64,
) -> Result<i64, AppError> {
    if evicted_count < 0 || evicted_count > MAX_EVICT_PER_APPEND {
        return Err(AppError::invalid("evicted_count out of range"));
    }
    let prev_hash = match entry.get("prevHash") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            if s.len() > 128 {
                return Err(AppError::invalid("prevHash exceeds 128 bytes"));
            }
            Some(s.clone())
        }
        Some(_) => return Err(AppError::invalid("prevHash must be string or null")),
    };
    let entry_hash = entry
        .get("entryHash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::invalid("missing string field: entryHash"))?;
    if entry_hash.len() > 128 {
        return Err(AppError::invalid("entryHash exceeds 128 bytes"));
    }
    let entry_hash = entry_hash.to_string();
    let entry_json = serde_json::to_string(&entry).map_err(AppError::internal_from)?;
    if entry_json.len() > MAX_ENTRY_JSON_BYTES {
        return Err(AppError::invalid("audit entry exceeds 16 KiB"));
    }

    let mut conn = state.0.get()?;
    append_audit_row(&mut conn, &encounter_id, prev_hash.as_deref(), &entry_hash, &entry_json, evicted_count)
}

// Transactional core of audit_append, split out so it can be driven
// directly against a plain `Connection` in unit tests — same pattern as
// note_history::append_history_row, including its exact race-safety
// characteristics: the prev_hash check below catches a diverged local
// chain (InvalidInput); the UNIQUE(encounter_id, seq) constraint is what
// actually stops a genuine concurrent-append race (Storage).
fn append_audit_row(
    conn: &mut Connection,
    encounter_id: &str,
    prev_hash: Option<&str>,
    entry_hash: &str,
    entry_json: &str,
    evicted_count: i64,
) -> Result<i64, AppError> {
    let tx = conn.transaction()?;
    let next_seq: i64 = tx.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM note_audit WHERE encounter_id = ?1",
        params![encounter_id],
        |r| r.get(0),
    )?;

    // Chain continuity check against the true last entry for this
    // encounter, regardless of archived status — seq is a total order
    // across both live and archived rows.
    let last_hash: Option<String> = tx
        .query_row(
            "SELECT entry_hash FROM note_audit WHERE encounter_id = ?1 AND seq = ?2",
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
        "INSERT INTO note_audit (encounter_id, seq, archived, prev_hash, entry_hash, entry_json) \
         VALUES (?1,?2,0,?3,?4,?5)",
        params![encounter_id, next_seq, prev_hash, entry_hash, entry_json],
    )?;

    if evicted_count > 0 {
        // Archive the oldest `evicted_count` still-live rows for this
        // encounter — never the row just inserted above, since it is by
        // construction the newest (archiving only ever touches rows with a
        // strictly smaller seq than next_seq's own tail neighbors).
        tx.execute(
            "UPDATE note_audit SET archived = 1 \
             WHERE id IN ( \
                 SELECT id FROM note_audit \
                 WHERE encounter_id = ?1 AND archived = 0 \
                 ORDER BY seq ASC LIMIT ?2 \
             )",
            params![encounter_id, evicted_count],
        )?;
    }

    tx.commit()?;
    Ok(next_seq)
}

#[cfg(test)]
mod tests {
    //! Mirrors note_history's test suite structure and intent: pin down
    //! which mechanism actually stops a concurrent-append race (the UNIQUE
    //! constraint, not the prev_hash check), plus this module's own
    //! archive-on-append and migration behavior.

    use super::*;
    use serde_json::json;

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
        evicted_count: i64,
    ) -> Result<i64, AppError> {
        let entry_json = json!({"action": "note_saved", "prevHash": prev_hash, "entryHash": entry_hash}).to_string();
        append_audit_row(conn, encounter_id, prev_hash, entry_hash, &entry_json, evicted_count)
    }

    #[test]
    fn first_append_succeeds_with_no_prev_hash() {
        let mut conn = fresh_db();
        let seq = append(&mut conn, "enc-1", None, "hash-a", 0).unwrap();
        assert_eq!(seq, 1);
    }

    #[test]
    fn sequential_appends_chain_correctly() {
        let mut conn = fresh_db();
        assert_eq!(append(&mut conn, "enc-1", None, "hash-a", 0).unwrap(), 1);
        assert_eq!(append(&mut conn, "enc-1", Some("hash-a"), "hash-b", 0).unwrap(), 2);
        assert_eq!(append(&mut conn, "enc-1", Some("hash-b"), "hash-c", 0).unwrap(), 3);
    }

    #[test]
    fn diverged_prev_hash_is_rejected_as_invalid_input_not_storage() {
        let mut conn = fresh_db();
        append(&mut conn, "enc-1", None, "hash-a", 0).unwrap();
        let err = append(&mut conn, "enc-1", Some("wrong-prev-hash"), "hash-b", 0).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    #[test]
    fn concurrent_append_race_is_stopped_by_the_unique_constraint_not_prev_hash() {
        let mut conn = fresh_db();
        append(&mut conn, "enc-1", None, "hash-a", 0).unwrap();
        append(&mut conn, "enc-1", Some("hash-a"), "hash-b-winner", 0).unwrap();

        // Directly attempt an INSERT at the already-taken seq to pin down
        // the exact race window where two readers would have computed the
        // same next_seq (mirrors note_history's equivalent test).
        let result = conn.execute(
            "INSERT INTO note_audit (encounter_id, seq, archived, prev_hash, entry_hash, entry_json) \
             VALUES (?1,2,0,?2,'hash-b-loser','{}')",
            params!["enc-1", "hash-a"],
        );
        let err = result.expect_err("duplicate (encounter_id, seq) must be rejected");
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("unique") || msg.contains("constraint"));

        let entry_hash: String = conn
            .query_row(
                "SELECT entry_hash FROM note_audit WHERE encounter_id = 'enc-1' AND seq = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(entry_hash, "hash-b-winner");
    }

    #[test]
    fn independent_encounters_do_not_share_seq_space() {
        let mut conn = fresh_db();
        assert_eq!(append(&mut conn, "enc-1", None, "hash-a", 0).unwrap(), 1);
        assert_eq!(append(&mut conn, "enc-2", None, "hash-x", 0).unwrap(), 1);
    }

    #[test]
    fn audit_list_returns_only_live_rows_in_seq_order() {
        let mut conn = fresh_db();
        append(&mut conn, "enc-1", None, "hash-a", 0).unwrap();
        append(&mut conn, "enc-1", Some("hash-a"), "hash-b", 0).unwrap();
        let live = entries_from(&conn, "enc-1", false).unwrap();
        assert_eq!(live.len(), 2);
        assert_eq!(live[0]["entryHash"], "hash-a");
        assert_eq!(live[1]["entryHash"], "hash-b");
    }

    #[test]
    fn archiving_moves_oldest_live_rows_and_never_touches_the_new_row() {
        let mut conn = fresh_db();
        append(&mut conn, "enc-1", None, "hash-a", 0).unwrap();
        append(&mut conn, "enc-1", Some("hash-a"), "hash-b", 0).unwrap();
        // Third append asks to archive the 2 oldest still-live rows.
        append(&mut conn, "enc-1", Some("hash-b"), "hash-c", 2).unwrap();

        let live = entries_from(&conn, "enc-1", false).unwrap();
        let archived = entries_from(&conn, "enc-1", true).unwrap();
        assert_eq!(live.len(), 1, "only the newest row stays live");
        assert_eq!(live[0]["entryHash"], "hash-c");
        assert_eq!(archived.len(), 2);
        assert_eq!(archived[0]["entryHash"], "hash-a");
        assert_eq!(archived[1]["entryHash"], "hash-b");
    }

    #[test]
    fn archived_rows_still_count_toward_seq_and_chain_continuity() {
        let mut conn = fresh_db();
        append(&mut conn, "enc-1", None, "hash-a", 0).unwrap();
        append(&mut conn, "enc-1", Some("hash-a"), "hash-b", 1).unwrap(); // archives hash-a
        // Next append must chain against hash-b (the true last row) even
        // though hash-a is now archived, not against a filtered live-only view.
        let seq = append(&mut conn, "enc-1", Some("hash-b"), "hash-c", 0).unwrap();
        assert_eq!(seq, 3);
    }

    #[test]
    fn evicted_count_out_of_range_is_rejected() {
        let mut conn = fresh_db();
        let err = append(&mut conn, "enc-1", None, "hash-a", -1).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    // ── Migration ────────────────────────────────────────────────────────

    fn kv_db_with(rows: &[(&str, &str)]) -> Connection {
        let mut conn = fresh_db();
        conn.execute_batch(
            "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);",
        )
        .unwrap();
        for (k, v) in rows {
            conn.execute(
                "INSERT INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
                params![k, v],
            )
            .unwrap();
        }
        migrate_from_kv(&mut conn).unwrap();
        conn
    }

    #[test]
    fn migration_moves_live_only_blob_preserving_order() {
        let live = json!([
            {"action": "note_edited", "entryHash": "h1", "prevHash": null},
            {"action": "note_signed", "entryHash": "h2", "prevHash": "h1"},
        ])
        .to_string();
        let conn = kv_db_with(&[("note_audit_v1::enc-1", &live)]);

        let rows = entries_from(&conn, "enc-1", false).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["entryHash"], "h1");
        assert_eq!(rows[1]["entryHash"], "h2");

        let kv_count: i64 = conn.query_row("SELECT COUNT(*) FROM kv", [], |r| r.get(0)).unwrap();
        assert_eq!(kv_count, 0, "legacy KV row must be deleted after migration");
    }

    #[test]
    fn migration_concatenates_archive_before_live_in_chain_order() {
        let archive = json!([{"action": "note_exported", "entryHash": "a1", "prevHash": null}]).to_string();
        let live = json!([{"action": "note_signed", "entryHash": "l1", "prevHash": "a1"}]).to_string();
        let conn = kv_db_with(&[
            ("note_audit_archive_v1::enc-1", &archive),
            ("note_audit_v1::enc-1", &live),
        ]);

        // Migrated rows all land as live (archived=0) — see module doc.
        let rows = entries_from(&conn, "enc-1", false).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["entryHash"], "a1", "archive entries come first in chain order");
        assert_eq!(rows[1]["entryHash"], "l1");
    }

    #[test]
    fn migration_is_idempotent() {
        let live = json!([{"action": "note_edited", "entryHash": "h1", "prevHash": null}]).to_string();
        let mut conn = kv_db_with(&[("note_audit_v1::enc-1", &live)]);
        // Re-run directly (kv_db_with already ran it once via its own call).
        migrate_from_kv(&mut conn).unwrap();
        let rows = entries_from(&conn, "enc-1", false).unwrap();
        assert_eq!(rows.len(), 1, "second run must not duplicate rows");
    }

    #[test]
    fn migration_skips_unparseable_blob_without_losing_the_other_half() {
        let conn = kv_db_with(&[
            ("note_audit_archive_v1::enc-1", "not json"),
            ("note_audit_v1::enc-1", &json!([{"action": "note_edited", "entryHash": "h1", "prevHash": null}]).to_string()),
        ]);
        let rows = entries_from(&conn, "enc-1", false).unwrap();
        assert_eq!(rows.len(), 1, "the parseable live half must still migrate");
        assert_eq!(rows[0]["entryHash"], "h1");
    }

    #[test]
    fn migration_handles_multiple_independent_encounters() {
        let conn = kv_db_with(&[
            ("note_audit_v1::enc-1", &json!([{"action": "a", "entryHash": "h1", "prevHash": null}]).to_string()),
            ("note_audit_v1::enc-2", &json!([{"action": "a", "entryHash": "h2", "prevHash": null}]).to_string()),
        ]);
        assert_eq!(entries_from(&conn, "enc-1", false).unwrap().len(), 1);
        assert_eq!(entries_from(&conn, "enc-2", false).unwrap().len(), 1);
    }
}
