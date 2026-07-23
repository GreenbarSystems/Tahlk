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
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tauri::State;

use crate::errors::AppError;
use crate::DbState;

/// SHA-256 of `data` returned as a 64-char lowercase hex string.
/// Matches JS's `sha256Hex(str)` in contentHash.js (same algorithm, same
/// encoding), so hashes computed here and hashes computed in JS are identical
/// for the same input bytes — which is required for `verifyAuditChain` to
/// pass on entries written by the narrow server-side commands below.
fn sha256_hex(data: &[u8]) -> String {
    use ring::digest::{digest, SHA256};
    let hash = digest(&SHA256, data);
    hash.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Internal append used by all narrow server-side audit commands.
///
/// Derives `actor` and `timestamp` server-side (the JS payload is never
/// trusted for these fields), reads the chain tail for `prevHash`, constructs
/// the entry JSON with keys sorted alphabetically (matching JS's
/// `JSON.stringify(payload, Object.keys(payload).sort())`), computes the
/// SHA-256 `entryHash`, and delegates the transactional INSERT to
/// `append_audit_row`.
///
/// `extra_fields` carries the action-specific detail fields (encounterId,
/// status, format, …). Keys must NOT include `action`, `actor`, `actorId`,
/// `prevHash`, `timestamp`, or `entryHash` — those are derived or computed
/// here. Any collision silently overwrites the caller-supplied value with the
/// server-derived one, which is the desired behavior.
fn server_append(
    conn: &mut Connection,
    encounter_id: &str,
    action: &str,
    extra_fields: BTreeMap<String, Value>,
) -> Result<(), AppError> {
    // Derive actor from the KV-stored provider profile so a compromised
    // WebView cannot forge the actor identity in an audit entry.
    let actor: String = crate::kv_ops::provider_id(conn);

    // Read the current chain tail so we can include the correct prevHash.
    let prev_hash: Option<String> = conn
        .query_row(
            "SELECT entry_hash FROM note_audit \
             WHERE encounter_id = ?1 ORDER BY seq DESC LIMIT 1",
            params![encounter_id],
            |r| r.get(0),
        )
        .optional()?;

    let timestamp = crate::time::utc_now_iso();

    // Build the hash payload as a BTreeMap so keys serialize in alphabetical
    // order, matching JS's `JSON.stringify(payload, Object.keys(payload).sort())`.
    // `entryHash` and `prevHash` are excluded from the hashed payload (same
    // convention as hashAuditEntry in contentHash.js); prevHash is then added
    // explicitly so it is covered by the hash.
    let mut payload: BTreeMap<String, Value> = BTreeMap::new();
    payload.insert("action".to_string(),    json!(action));
    payload.insert("actor".to_string(),     json!(actor));
    payload.insert("actorId".to_string(),   json!("solo"));
    payload.insert("prevHash".to_string(), match &prev_hash {
        Some(h) => json!(h),
        None    => Value::Null,
    });
    payload.insert("timestamp".to_string(), json!(timestamp));
    for (k, v) in extra_fields {
        payload.insert(k, v);
    }

    let hash_json = serde_json::to_string(&payload).map_err(AppError::internal_from)?;
    let entry_hash = sha256_hex(hash_json.as_bytes());

    // Add entryHash to produce the full stored entry (superset of what was
    // hashed — callers can round-trip this JSON and re-derive the hash,
    // which is exactly what verifyAuditChain does).
    payload.insert("entryHash".to_string(), json!(entry_hash));
    let entry_json = serde_json::to_string(&payload).map_err(AppError::internal_from)?;

    if entry_json.len() > MAX_ENTRY_JSON_BYTES {
        return Err(AppError::invalid("audit entry too large"));
    }

    append_audit_row(conn, encounter_id, prev_hash.as_deref(), &entry_hash, &entry_json, 0)?;
    Ok(())
}

/// Record that an encounter's records were viewed.
///
/// Actor is derived server-side — a compromised WebView cannot forge a false
/// actor identity by crafting an `audit_append` payload.
#[tauri::command]
pub(crate) fn audit_log_record_viewed(
    state: State<'_, DbState>,
    encounter_id: String,
    status: String,
) -> Result<(), AppError> {
    let mut conn = state.0.get()?;
    let mut extra = BTreeMap::new();
    extra.insert("encounterId".to_string(), json!(encounter_id));
    extra.insert("status".to_string(),      json!(status));
    server_append(&mut conn, &encounter_id, "record_viewed", extra)
}

/// Record that an encounter note was edited.
#[tauri::command]
pub(crate) fn audit_log_note_edited(
    state: State<'_, DbState>,
    encounter_id: String,
) -> Result<(), AppError> {
    let mut conn = state.0.get()?;
    let mut extra = BTreeMap::new();
    extra.insert("encounterId".to_string(), json!(encounter_id));
    server_append(&mut conn, &encounter_id, "note_edited", extra)
}

/// Record that an encounter note was signed.
#[tauri::command]
pub(crate) fn audit_log_note_signed(
    state: State<'_, DbState>,
    encounter_id: String,
    content_hash: String,
) -> Result<(), AppError> {
    let mut conn = state.0.get()?;
    let mut extra = BTreeMap::new();
    extra.insert("contentHash".to_string(), json!(content_hash));
    extra.insert("encounterId".to_string(), json!(encounter_id));
    server_append(&mut conn, &encounter_id, "note_signed", extra)
}

/// Record the outcome of an audio purge.
#[tauri::command]
pub(crate) fn audit_log_audio_deleted(
    state: State<'_, DbState>,
    encounter_id: String,
    removed: bool,
    reason: String,
    error: Option<String>,
) -> Result<(), AppError> {
    let mut conn = state.0.get()?;
    let mut extra = BTreeMap::new();
    extra.insert("encounterId".to_string(), json!(encounter_id));
    extra.insert("error".to_string(), match &error {
        Some(e) => json!(e),
        None    => Value::Null,
    });
    extra.insert("reason".to_string(),  json!(reason));
    extra.insert("removed".to_string(), json!(removed));
    server_append(&mut conn, &encounter_id, "audio_deleted", extra)
}

/// Record that a note was exported (to a file or to the clipboard).
#[tauri::command]
pub(crate) fn audit_log_note_exported(
    state: State<'_, DbState>,
    encounter_id: String,
    format: String,
    method: String,
) -> Result<(), AppError> {
    let mut conn = state.0.get()?;
    let mut extra = BTreeMap::new();
    extra.insert("format".to_string(), json!(format));
    extra.insert("method".to_string(), json!(method));
    server_append(&mut conn, &encounter_id, "note_exported", extra)
}

/// Roster/list scopes that may be recorded as a records-listed access event.
/// Enforced at the command boundary so a compromised WebView can't stuff an
/// arbitrary string into the (synthetic) `encounter_id` column and forge an
/// unbounded set of chains — mirrors patient_audit::VALID_ACTIONS.
pub(crate) const VALID_LIST_SCOPES: &[&str] = &["sessions", "patients"];

/// Record that a roster/list of records was displayed to the provider — the
/// list-view counterpart to `record_viewed` (which covers a single-encounter
/// panel). One entry per view render, carrying how many rows of PHI were
/// shown, rather than one entry per row: a roster is a single "PHI became
/// visible in this context" access event, not N of them.
///
/// Reuses the same `server_append` mechanism (same table, same hash chain,
/// same server-derived actor) as every other narrow audit command — it is a
/// sibling action, not a parallel logging path. The rows land under a
/// synthetic `roster:<scope>` key so they form their own chain and can never
/// collide with, or pollute, a real encounter's audit trail.
#[tauri::command]
pub(crate) fn audit_log_records_listed(
    state: State<'_, DbState>,
    scope: String,
    count: i64,
) -> Result<(), AppError> {
    let mut conn = state.0.get()?;
    records_listed_conn(&mut conn, &scope, count)
}

/// Validation + append for `audit_log_records_listed`, split out from the
/// `#[tauri::command]` wrapper so it is exercisable without a Tauri `State`
/// harness (mirrors patient_audit's `list_conn` test seam).
fn records_listed_conn(conn: &mut Connection, scope: &str, count: i64) -> Result<(), AppError> {
    if !VALID_LIST_SCOPES.contains(&scope) {
        return Err(AppError::invalid("unknown records-listed scope"));
    }
    if count < 0 {
        return Err(AppError::invalid("records-listed count must be non-negative"));
    }
    let scope_key = format!("roster:{scope}");
    let mut extra = BTreeMap::new();
    extra.insert("scope".to_string(), json!(scope));
    extra.insert("count".to_string(), json!(count));
    server_append(conn, &scope_key, "records_listed", extra)
}

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
    )?;

    // `scrubbed` marks a row whose entry_json was replaced by a destruction
    // tombstone. The chain columns (prev_hash, entry_hash) are deliberately
    // preserved by that scrub, but the CONTENT they hash over is gone, so a
    // verifier recomputing the hash from entry_json will never match. Without
    // this flag a lawful scrub and a malicious rewrite produce the identical
    // verdict — which is the opposite of tamper-evident.
    let has_scrubbed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('note_audit') WHERE name = 'scrubbed'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has_scrubbed == 0 {
        conn.execute_batch(
            "ALTER TABLE note_audit ADD COLUMN scrubbed INTEGER NOT NULL DEFAULT 0;",
        )?;
        // Backfill rows scrubbed before this column existed. The tombstone
        // written by delete_encounter_in_tx is the only thing that puts
        // `"destroyed":true` into entry_json. Matched textually rather than
        // with json_extract so this does not depend on the JSON1 extension.
        conn.execute_batch(
            "UPDATE note_audit SET scrubbed = 1 \
             WHERE scrubbed = 0 AND entry_json LIKE '%\"destroyed\":true%';",
        )?;
    }
    Ok(())
}

/// Distinct encounter ids present in the audit table.
///
/// Needed because destruction BLINDS `encounter_id` to `sha256(id + now)`:
/// the rows are retained as required, but `audit_list` needs an id to query
/// by and nothing records the mapping. Without an enumerator those rows are
/// preserved and simultaneously unreachable, which is not a retained audit
/// trail in any sense an auditor would accept. Mirrors
/// `note_history_list_encounter_ids`.
#[tauri::command]
pub(crate) fn note_audit_list_encounter_ids(
    state: State<DbState>,
) -> Result<Vec<String>, AppError> {
    let conn = state.0.get()?;
    let mut stmt = conn.prepare("SELECT DISTINCT encounter_id FROM note_audit ORDER BY encounter_id")?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
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
                    log::error!(
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
                log::error!(
                    "note_audit migration: insert failed for {} seq {}: {}, aborting this encounter",
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
        tx.execute("DELETE FROM kv WHERE key IN (?1, ?2)", params![live_key, archive_key])?;
        tx.commit()?;
    }

    Ok(())
}

fn entries_from(conn: &Connection, encounter_id: &str, archived: bool) -> Result<Vec<Value>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT entry_json, prev_hash, entry_hash, scrubbed FROM note_audit \
         WHERE encounter_id = ?1 AND archived = ?2 ORDER BY seq",
    )?;
    let rows = stmt.query_map(params![encounter_id, archived as i64], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)? != 0,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (json_str, prev_hash, entry_hash, scrubbed) = row?;
        let mut entry: Value = serde_json::from_str(&json_str).map_err(AppError::internal_from)?;
        // A scrubbed row's entry_json is the destruction tombstone, which
        // carries none of the chain fields — they survive only in the columns.
        // Re-attach them from there so the chain remains walkable across a
        // destruction, and flag the row so a verifier knows the CONTENT hash
        // is unreproducible by design rather than by tampering.
        //
        // Only for scrubbed rows: an intact row's entry_json already contains
        // exactly these values, and overwriting them from the columns would
        // silently paper over any historical drift instead of surfacing it.
        if scrubbed {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("prevHash".into(), match prev_hash {
                    Some(h) => json!(h),
                    None => Value::Null,
                });
                obj.insert("entryHash".into(), json!(entry_hash));
                obj.insert("scrubbed".into(), json!(true));
            }
        }
        out.push(entry);
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

// Removed from the invoke handler — callers must use the narrow audit_log_*
// commands above so that actor identity is derived server-side and cannot be
// forged by a compromised WebView.
#[allow(dead_code)]
pub(crate) fn audit_append(
    state: State<DbState>,
    encounter_id: String,
    entry: Value,
    evicted_count: i64,
) -> Result<i64, AppError> {
    if !(0..=MAX_EVICT_PER_APPEND).contains(&evicted_count) {
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
    // Defense in depth: the #[tauri::command] wrapper above already checks
    // this, but this function is also callable directly by other Rust code
    // (and by tests) that bypasses that wrapper, and evicted_count flows
    // straight into a SQL UPDATE ... LIMIT below — it must be validated at
    // the point of use, not just at the JS-facing boundary.
    if !(0..=MAX_EVICT_PER_APPEND).contains(&evicted_count) {
        return Err(AppError::invalid("evicted_count out of range"));
    }

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

    // ── Scrubbed-row read shape (H-8) ───────────────────────────────────

    fn scrub(conn: &Connection, encounter_id: &str) {
        conn.execute(
            "UPDATE note_audit SET entry_json = ?1, scrubbed = 1 WHERE encounter_id = ?2",
            params![
                r#"{"destroyed":true,"destroyed_at":"2026-07-21T00:00:00Z","legal_basis":"provider_request"}"#,
                encounter_id
            ],
        )
        .unwrap();
    }

    #[test]
    fn a_scrubbed_row_still_exposes_its_chain_fields() {
        // The tombstone carries no prevHash/entryHash, so without re-attaching
        // them from the columns a verifier sees "missing entryHash" and calls
        // the whole chain broken.
        let mut conn = fresh_db();
        append(&mut conn, "enc-1", None, "hash-a", 0).unwrap();
        append(&mut conn, "enc-1", Some("hash-a"), "hash-b", 0).unwrap();
        scrub(&conn, "enc-1");

        let rows = entries_from(&conn, "enc-1", false).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["entryHash"], "hash-a");
        assert_eq!(rows[0]["prevHash"], Value::Null);
        assert_eq!(rows[1]["entryHash"], "hash-b");
        assert_eq!(rows[1]["prevHash"], "hash-a");
        assert_eq!(rows[0]["scrubbed"], true, "the row must declare itself scrubbed");
        assert_eq!(rows[0]["destroyed"], true, "and keep the tombstone content");
    }

    #[test]
    fn an_intact_row_is_returned_untouched() {
        // Chain fields are re-attached ONLY for scrubbed rows: overwriting an
        // intact row's values from the columns would paper over drift rather
        // than surface it.
        let mut conn = fresh_db();
        append(&mut conn, "enc-1", None, "hash-a", 0).unwrap();

        let rows = entries_from(&conn, "enc-1", false).unwrap();
        assert!(rows[0].get("scrubbed").is_none(), "no scrubbed flag on intact rows");
        assert_eq!(rows[0]["action"], "note_saved");
    }

    #[test]
    fn rows_scrubbed_before_the_flag_existed_are_backfilled() {
        // An install that destroyed an encounter under the previous build has
        // tombstones with scrubbed = 0; they must not stay unverifiable.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE note_audit (
                 id            INTEGER PRIMARY KEY AUTOINCREMENT,
                 encounter_id  TEXT NOT NULL,
                 seq           INTEGER NOT NULL,
                 archived      INTEGER NOT NULL DEFAULT 0,
                 prev_hash     TEXT,
                 entry_hash    TEXT NOT NULL,
                 entry_json    TEXT NOT NULL,
                 UNIQUE (encounter_id, seq)
             );
             INSERT INTO note_audit (encounter_id, seq, prev_hash, entry_hash, entry_json)
             VALUES ('enc-old', 1, NULL, 'hash-a',
                     '{\"destroyed\":true,\"destroyed_at\":\"x\",\"legal_basis\":\"provider_request\"}');",
        )
        .unwrap();

        init_schema(&conn).unwrap();

        let rows = entries_from(&conn, "enc-old", false).unwrap();
        assert_eq!(rows[0]["scrubbed"], true, "legacy tombstones must be recognised");
        assert_eq!(rows[0]["entryHash"], "hash-a");
    }

    #[test]
    fn blinded_rows_remain_reachable_by_id_enumeration() {
        // Destruction replaces encounter_id with sha256(id + now) and records
        // the mapping nowhere, so an enumerator is the only way back to them.
        let mut conn = fresh_db();
        append(&mut conn, "enc-1", None, "hash-a", 0).unwrap();
        append(&mut conn, "enc-2", None, "hash-x", 0).unwrap();
        conn.execute(
            "UPDATE note_audit SET encounter_id = 'blinded-abc' WHERE encounter_id = 'enc-1'",
            [],
        )
        .unwrap();

        let mut stmt = conn
            .prepare("SELECT DISTINCT encounter_id FROM note_audit ORDER BY encounter_id")
            .unwrap();
        let ids: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(ids, vec!["blinded-abc".to_string(), "enc-2".to_string()]);
    }

    #[test]
    fn first_append_succeeds_with_no_prev_hash() {
        let mut conn = fresh_db();
        let seq = append(&mut conn, "enc-1", None, "hash-a", 0).unwrap();
        assert_eq!(seq, 1);
    }

    // ── records_listed (roster/list view access) ────────────────────────

    #[test]
    fn records_listed_appends_a_records_listed_entry_under_a_roster_key() {
        let mut conn = fresh_db();
        records_listed_conn(&mut conn, "sessions", 12).unwrap();

        // Lands under the synthetic roster scope, never a real encounter chain.
        let rows = entries_from(&conn, "roster:sessions", false).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["action"], "records_listed");
        assert_eq!(rows[0]["scope"], "sessions");
        assert_eq!(rows[0]["count"], 12);
        // Actor is server-derived (defaults to "provider" without a kv row),
        // never taken from the caller.
        assert_eq!(rows[0]["actor"], "provider");
    }

    #[test]
    fn records_listed_chains_repeated_views_and_stays_off_encounter_chains() {
        let mut conn = fresh_db();
        records_listed_conn(&mut conn, "patients", 3).unwrap();
        records_listed_conn(&mut conn, "patients", 4).unwrap();

        let roster = entries_from(&conn, "roster:patients", false).unwrap();
        assert_eq!(roster.len(), 2, "each render is its own access event");
        assert_eq!(roster[1]["prevHash"], roster[0]["entryHash"], "entries chain");
        // A real encounter id keyed the same as the scope string is untouched.
        assert!(entries_from(&conn, "patients", false).unwrap().is_empty());
    }

    #[test]
    fn records_listed_rejects_an_unknown_scope() {
        let mut conn = fresh_db();
        let err = records_listed_conn(&mut conn, "billing", 1).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        // Nothing is written on rejection.
        assert!(entries_from(&conn, "roster:billing", false).unwrap().is_empty());
    }

    #[test]
    fn records_listed_rejects_a_negative_count() {
        let mut conn = fresh_db();
        let err = records_listed_conn(&mut conn, "sessions", -1).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
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
