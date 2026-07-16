//! Encounter row CRUD + sign-off + stats.
//!
//! `mark_encounter_signed` and `clear_encounter_audio_path` use targeted
//! UPDATEs so a sign-off (or audio purge) can never clobber sibling columns
//! that the caller didn't intend to touch — critical for the attestation
//! moment, and for keeping audio retention orthogonal to note content.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use tauri::{AppHandle, State};

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

/// Clamp a caller-supplied `LIMIT` into a sane range.
///
/// The ceiling and clamp live in `db::clamp_list_limit` (shared with
/// `patients`, which previously hardcoded the same `1000` separately). This
/// wrapper only supplies this module's default page size.
pub(crate) fn clamp_list_limit(limit: Option<i64>) -> i64 {
    crate::db::clamp_list_limit(limit, DEFAULT_LIST_LIMIT)
}

/// Default page size when the caller passes no limit. Smaller than
/// `patients`'s because the home screen shows a recent-encounters window, not
/// a full roster.
const DEFAULT_LIST_LIMIT: i64 = 50;

#[tauri::command]
pub(crate) fn list_encounters(state: State<DbState>, limit: Option<i64>) -> Result<Vec<Value>, AppError> {
    let conn = state.0.get()?;
    let n = clamp_list_limit(limit);
    let sql = format!(
        "SELECT {ENCOUNTER_COLS} FROM encounters ORDER BY created_at DESC LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![n], encounter_row_to_json)?;
    // Preallocate to `n` (already clamped to [1, 1000] by clamp_list_limit).
    // The LIMIT clause caps the row count exactly, so this is the tight upper
    // bound and avoids the 4–16 reallocations Vec::new() would do while
    // growing from 0 → 50 (default list size) or 0 → 1000.
    let mut out = Vec::with_capacity(n as usize);
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

// Flip an encounter to signed, touching ONLY the sign columns. upsert_encounter
// overwrites patient_alias/audio_path from its payload, so using it for sign-off
// (which doesn't resend those) would null them out — corrupting the record at
// the moment of attestation. This targeted update cannot clobber other columns.
//
// The `AND status != 'signed'` clause makes re-signing atomically impossible:
// an already-signed row matches the id but not the status, so the UPDATE affects
// 0 rows and never overwrites the original signed_at/signed_hash. This mirrors
// enforce_signed_immutability (which guards the upsert_encounter path) so both
// sign-off routes reject a re-sign with the same AppError::InvalidInput variant
// — audit N2, §164.312(c)(1) integrity. The 0-row case is then disambiguated
// (missing row vs. already signed) with a follow-up read inside the same
// transaction so the diagnostic can't race a concurrent write.
#[tauri::command]
pub(crate) fn mark_encounter_signed(
    state: State<DbState>,
    id: String,
    signed_at: String,
    signed_hash: String,
) -> Result<(), AppError> {
    let mut conn = state.0.get()?;
    mark_signed(&mut conn, &id, &signed_at, &signed_hash)
}

/// Pure DB helper for `mark_encounter_signed` — takes any `rusqlite::Connection`
/// so tests can exercise the re-sign guard against an in-memory fixture without
/// the Tauri State harness (same pattern as `query_encounter_stats`).
pub(crate) fn mark_signed(
    conn: &mut Connection,
    id: &str,
    signed_at: &str,
    signed_hash: &str,
) -> Result<(), AppError> {
    let tx = conn.transaction()?;
    let n = tx.execute(
        "UPDATE encounters SET status = 'signed', signed_at = ?2, signed_hash = ?3 \
         WHERE id = ?1 AND status != 'signed'",
        params![id, signed_at, signed_hash],
    )?;
    if n == 0 {
        // Zero rows could mean the id doesn't exist OR the row is already
        // signed. Read the current status (same tx) to return the right error.
        let existing: Option<String> = tx
            .query_row(
                "SELECT status FROM encounters WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        return match existing {
            Some(_) => Err(AppError::invalid(format!(
                "cannot re-sign encounter {id}: already signed"
            ))),
            None => Err(AppError::invalid(format!("encounter {id} not found"))),
        };
    }
    tx.commit()?;
    Ok(())
}

// Null out audio_path on a single encounter row without touching any other
// column — mirrors mark_encounter_signed's scoping so an audio-purge cannot
// clobber patient_alias or sign-off fields.
#[tauri::command]
pub(crate) fn clear_encounter_audio_path(state: State<DbState>, id: String) -> Result<(), AppError> {
    let conn = state.0.get()?;
    let n = conn.execute(
        "UPDATE encounters SET audio_path = NULL WHERE id = ?1",
        params![id],
    )?;
    if n == 0 {
        return Err(AppError::invalid(format!("encounter {} not found", id)));
    }
    Ok(())
}

/// Permanently delete an encounter (audit finding: "No capability exists to
/// delete a signed note, transcript, or entire encounter record"). Deletes
/// the actual PHI content — the `encounters` row itself, the note text and
/// transcript (which live in the generic `kv` table under
/// `note_content_v1::<id>` / `note_content_v1::transcript::<id>`, see
/// data/keys.js) — and best-effort removes any residual on-disk audio.
///
/// Deliberately does NOT delete `note_history`, `note_audit`, or
/// `llm_audit` rows for this id. None of those tables store PHI content
/// (metadata + hashes only, by their own design — see each module's doc
/// comment), and retaining them after the encounter is gone preserves the
/// compliance value of "this record existed, was accessed by X, and was
/// deleted by Y on this date." This matches `note_history_list_
/// encounter_ids`' own documented expectation that an encounter can be
/// hard-deleted while its history rows remain (orphaned but still
/// verifiable) — this command is simply the first thing to actually
/// exercise that path. The JS caller appends a final `encounter_deleted`
/// entry to note_audit after this returns, so the trail itself records
/// the deletion.
#[tauri::command]
pub(crate) async fn delete_encounter(app: AppHandle, state: State<'_, DbState>, id: String) -> Result<(), AppError> {
    {
        let mut conn = state.0.get()?;
        delete_encounter_row(&mut conn, &id)?;
        // conn dropped here, before the .await below — no DB lock held
        // across await, same discipline notes.rs's read_api_key uses.
    }

    // Best-effort, after the SQL commit: a failure here never leaves a
    // half-deleted encounters row, only an orphaned .wav.enc file on disk,
    // which is a strictly smaller problem than an inconsistent DB state.
    if let Err(e) = crate::audio::delete_session_audio(app, id).await {
        log::error!(
            "delete_encounter: residual audio cleanup failed: {}",
            crate::log_safety::cap_len(&e.to_string())
        );
    }

    Ok(())
}

/// Transactional core of `delete_encounter` — takes any `&mut Connection` so
/// tests can drive it against an in-memory fixture without a Tauri State
/// harness (same pattern as `mark_signed`/`upsert_encounter_row`).
fn delete_encounter_row(conn: &mut Connection, id: &str) -> Result<(), AppError> {
    let tx = conn.transaction()?;
    // note_content_v1::<id> / note_content_v1::transcript::<id> are the only
    // KV rows holding this encounter's actual note text/transcript — kept in
    // sync with data/keys.js's noteContent/noteTranscript key formats by
    // hand, since Rust has no shared import of the JS key constants.
    tx.execute(
        "DELETE FROM kv WHERE key IN (?1, ?2)",
        params![
            format!("note_content_v1::{id}"),
            format!("note_content_v1::transcript::{id}"),
        ],
    )?;
    let n = tx.execute("DELETE FROM encounters WHERE id = ?1", params![id])?;
    if n == 0 {
        return Err(AppError::invalid(format!("encounter {id} not found")));
    }
    tx.commit()?;
    Ok(())
}

// Fetch a single encounter by id — avoids pulling the whole list to open one row.
#[tauri::command]
pub(crate) fn get_encounter(state: State<DbState>, id: String) -> Result<Option<Value>, AppError> {
    let conn = state.0.get()?;
    let sql = format!("SELECT {ENCOUNTER_COLS} FROM encounters WHERE id = ?1");
    Ok(conn.query_row(&sql, params![id], encounter_row_to_json).optional()?)
}

// Home-screen counters via indexed COUNT(*) — O(index) instead of shipping rows
// to JS and filtering. `today` is passed in so the comparison matches how
// encounter_date is stored client-side.
//
// Perf (MP1): the three counters used to be three separate `query_row` calls,
// which meant three prepare/step/reset cycles and — under the single-mutex
// arch (P2) — three back-to-back lock hits. SQLite has supported
// `COUNT(*) FILTER (WHERE …)` since 3.30 (bundled SQLCipher ships far newer),
// so we can fold all three into one full-table scan of the covering index on
// `encounters(status, encounter_date)`. Same result set, one prepare, one
// step, one lock.
#[tauri::command]
pub(crate) fn encounter_stats(state: State<DbState>, today: String) -> Result<Value, AppError> {
    let conn = state.0.get()?;
    let (total, signed, today_count) = query_encounter_stats(&conn, &today)?;
    Ok(json!({ "total": total, "signed": signed, "today": today_count }))
}

/// Pure DB helper for `encounter_stats` — takes any `rusqlite::Connection`
/// so tests can drive it against an in-memory fixture without the Tauri
/// State harness. Returns `(total, signed, today_count)`.
///
/// Uses `COUNT(*) FILTER (WHERE …)` to collapse three passes into one. The
/// planner still walks the same rows it would have for `COUNT(*)`, but the
/// FILTER clauses are evaluated on the same row visit, so we avoid two extra
/// scans and two extra prepared-statement round-trips.
pub(crate) fn query_encounter_stats(
    conn: &rusqlite::Connection,
    today: &str,
) -> Result<(i64, i64, i64), AppError> {
    let row = conn.query_row(
        "SELECT \
            COUNT(*)                                        AS total, \
            COUNT(*) FILTER (WHERE status = 'signed')       AS signed, \
            COUNT(*) FILTER (WHERE encounter_date = ?1)     AS today \
         FROM encounters",
        params![today],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
    )?;
    Ok(row)
}

/// Extract a required string field from an incoming encounter payload,
/// or return `AppError::InvalidInput` naming the missing field.
///
/// Previously the four required fields on `upsert_encounter` used
/// `unwrap_or("")`, which coerced missing values into empty strings and
/// happily persisted them — not exploitable, but it hid bugs behind a
/// misleading NOT NULL success. Failing loudly here surfaces the caller
/// error at the boundary (audit L2).
///
/// Whitespace-only values are rejected for the same reason `""` is: they clear
/// NOT NULL while carrying no information. This matters most for `provider_id`,
/// the audit actor identity stamped on every encounter row. The value itself is
/// returned untrimmed — this is a guard, not a normalizer.
fn required_str<'a>(incoming: &'a Value, field: &'static str) -> Result<&'a str, AppError> {
    match incoming[field].as_str() {
        Some(s) if !s.trim().is_empty() => Ok(s),
        _ => Err(AppError::invalid(format!(
            "encounter.{field} is required and must be a non-empty string"
        ))),
    }
}

/// Encounter lifecycle states the local DB will accept. Mirrors the server's
/// `ALLOWED_STATUS` in `server/src/api.rs` so a compromised JS layer can't
/// write garbage that the UI then can't render or exit — and so the desktop
/// and server never disagree about what shapes are valid.
///
/// Keep in sync: any addition here MUST be paired with the same addition on
/// the server (and vice versa), otherwise sync will reject rows the desktop
/// happily wrote (or the server will accept states the desktop can't render).
/// [audit M4]
pub(crate) const ALLOWED_STATUS: &[&str] = &[
    "recording",
    "recording_done",
    "transcribing",
    "draft",
    "signed",
    "exported",
];

/// Validate an incoming status string against the allowlist. Pure function —
/// no DB — so unit tests can enumerate variants without a Tauri harness.
fn check_status(status: &str) -> Result<(), AppError> {
    if ALLOWED_STATUS.contains(&status) {
        Ok(())
    } else {
        Err(AppError::invalid(format!(
            "unknown encounter status: {status}"
        )))
    }
}

#[tauri::command]
pub(crate) fn upsert_encounter(state: State<DbState>, encounter: Value) -> Result<(), AppError> {
    // Fail loudly on missing required fields BEFORE taking the DB lock so a
    // shape-invalid payload can't tie up the connection. `status` retains a
    // legitimate default of "draft" because callers reasonably omit it on
    // fresh encounters.
    let id             = required_str(&encounter, "id")?;
    let provider_id    = required_str(&encounter, "provider_id")?;
    let encounter_date = required_str(&encounter, "encounter_date")?;
    let created_at     = required_str(&encounter, "created_at")?;
    let status         = encounter["status"].as_str().unwrap_or("draft");
    // Reject unknown states at the boundary. Any provided value must appear
    // on the shared allowlist above; a caller omitting the field entirely
    // still lands on "draft", which is always valid. [audit M4]
    check_status(status)?;

    let mut conn = state.0.get()?;
    let tx = conn.transaction()?;
    enforce_signed_immutability(&tx, &encounter)?;
    upsert_encounter_row(
        &tx,
        id,
        provider_id,
        encounter_date,
        encounter["patient_alias"].as_str(),
        status,
        encounter["audio_path"].as_str(),
        created_at,
        encounter["signed_at"].as_str(),
        encounter["signed_hash"].as_str(),
    )?;
    tx.commit()?;
    Ok(())
}

/// Perform the actual INSERT-or-UPDATE for an encounter row inside an
/// already-open transaction/connection. Factored out of `upsert_encounter` so
/// the race-closing SQL below can be driven directly from unit tests without
/// a Tauri `State` harness.
///
/// Defense in depth: `enforce_signed_immutability`'s SELECT (run by the
/// caller before this function) executes in a DEFERRED transaction, which
/// does not take SQLite's write lock until the first write statement. On the
/// 4-connection pool that means two concurrent upserts for the same id
/// (double-click, or a retried call after a UI timeout) can both pass the
/// immutability SELECT before either commits -- a classic check-then-act
/// TOCTOU race that could silently un-sign an attested note.
///
/// The UPDATE's WHERE clause below closes that window at the SQL level
/// instead of relying solely on the earlier application-level SELECT. It
/// only allows the write through when one of two things is true, mirroring
/// exactly what `enforce_signed_immutability` already validated:
///   (a) the row is not currently 'signed' (the common draft-edit case, and
///       also the legitimate draft-to-signed transition itself), or
///   (b) the row IS 'signed' but the incoming signed_at/signed_hash/status
///       are unchanged (the explicitly-supported patient_alias-only edit
///       of an already-signed row).
/// Any other case -- in particular a concurrent writer trying to write a
/// signed row whose signed_at/signed_hash differ from what's already
/// committed -- makes the UPDATE a no-op (0 rows changed), which the caller
/// detects and surfaces as an explicit, retryable error instead of a silent
/// lost update.
fn upsert_encounter_row(
    conn: &Connection,
    id: &str,
    provider_id: &str,
    encounter_date: &str,
    patient_alias: Option<&str>,
    status: &str,
    audio_path: Option<&str>,
    created_at: &str,
    signed_at: Option<&str>,
    signed_hash: Option<&str>,
) -> Result<(), AppError> {
    let is_new_row = !conn
        .query_row(
            "SELECT 1 FROM encounters WHERE id = ?1",
            params![id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let rows_changed = conn.execute(
        "INSERT INTO encounters (id, provider_id, encounter_date, patient_alias, status, \
         audio_path, created_at, signed_at, signed_hash) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) \
         ON CONFLICT(id) DO UPDATE SET \
         status = excluded.status, \
         patient_alias = excluded.patient_alias, \
         audio_path = excluded.audio_path, \
         signed_at = excluded.signed_at, \
         signed_hash = excluded.signed_hash \
         WHERE encounters.status != 'signed' \
            OR (excluded.status = encounters.status \
                AND excluded.signed_at IS encounters.signed_at \
                AND excluded.signed_hash IS encounters.signed_hash)",
        params![
            id,
            provider_id,
            encounter_date,
            patient_alias,
            status,
            audio_path,
            created_at,
            signed_at,
            signed_hash,
        ],
    )?;
    if rows_changed == 0 && !is_new_row {
        // The row existed and the UPDATE's WHERE guard suppressed the write --
        // it raced a concurrent sign-off that landed between the caller's
        // immutability SELECT and this UPDATE. Report it rather than
        // silently dropping the write so the caller can reload the row and
        // decide how to proceed.
        return Err(AppError::invalid(
            "encounter was signed by a concurrent request; reload and retry",
        ));
    }
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
            );
            CREATE TABLE kv (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at INTEGER NOT NULL
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

    // Read back the sign-off metadata for a row so tests can prove a rejected
    // re-sign left the original attestation untouched (audit N2).
    fn signed_meta(conn: &Connection, id: &str) -> (String, Option<String>, Option<String>) {
        conn.query_row(
            "SELECT status, signed_at, signed_hash FROM encounters WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
    }

    #[test]
    fn mark_signed_signs_an_unsigned_encounter() {
        // Happy path: a draft row flips to signed and records the metadata.
        let mut conn = fresh_db();
        conn.execute(
            "INSERT INTO encounters (id, provider_id, encounter_date, status, created_at) \
             VALUES ('enc-1','prov-1','2026-07-04','draft','2026-07-04T10:00:00Z')",
            [],
        )
        .unwrap();
        mark_signed(&mut conn, "enc-1", "2026-07-04T10:30:00Z", "deadbeef").unwrap();
        assert_eq!(
            signed_meta(&conn, "enc-1"),
            (
                "signed".to_string(),
                Some("2026-07-04T10:30:00Z".to_string()),
                Some("deadbeef".to_string()),
            ),
        );
    }

    #[test]
    fn mark_signed_rejects_resign_and_preserves_original_metadata() {
        // Re-signing an already-signed row must fail AND leave the original
        // signed_at/signed_hash intact — proving the UPDATE never took effect.
        let mut conn = fresh_db();
        insert_signed(&conn); // status=signed, signed_at=...10:30:00Z, hash=deadbeef
        let before = signed_meta(&conn, "enc-1");

        let err = mark_signed(&mut conn, "enc-1", "2099-01-01T00:00:00Z", "cafef00d")
            .unwrap_err();
        // Same variant enforce_signed_immutability uses, so JS handles an
        // "already signed" conflict identically across both sign-off paths.
        assert!(matches!(err, AppError::InvalidInput(_)));

        let after = signed_meta(&conn, "enc-1");
        assert_eq!(before, after, "rejected re-sign must not mutate the row");
        // Belt-and-suspenders: the attacker's values are provably absent.
        assert_eq!(after.1, Some("2026-07-04T10:30:00Z".to_string()));
        assert_eq!(after.2, Some("deadbeef".to_string()));
    }

    #[test]
    fn mark_signed_reports_missing_row() {
        let mut conn = fresh_db();
        let err = mark_signed(&mut conn, "nope", "2026-07-04T10:30:00Z", "deadbeef")
            .unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        let msg = format!("{err}");
        assert!(msg.contains("not found"), "missing row should say so: {msg}");
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

    // --- upsert_encounter_row: SQL-level TOCTOU guard -----------------------
    //
    // These tests drive the actual INSERT/UPDATE statement (not just the
    // application-level `enforce_signed_immutability` SELECT) to pin the
    // race-closing `WHERE` clause added to close the gap where two
    // concurrent upserts on the same id could both pass the immutability
    // SELECT before either commits.

    #[test]
    fn upsert_row_signs_a_fresh_draft() {
        let conn = fresh_db();
        conn.execute(
            "INSERT INTO encounters (id, provider_id, encounter_date, status, created_at) \
             VALUES ('enc-1','prov-1','2026-07-04','draft','2026-07-04T10:00:00Z')",
            [],
        )
        .unwrap();
        // The legitimate draft -> signed transition must still succeed: this
        // is the exact path the race guard must not block.
        let result = upsert_encounter_row(
            &conn,
            "enc-1",
            "prov-1",
            "2026-07-04",
            None,
            "signed",
            Some("/tmp/audio.wav"),
            "2026-07-04T10:00:00Z",
            Some("2026-07-04T10:30:00Z"),
            Some("deadbeef"),
        );
        assert!(result.is_ok(), "sign-off must succeed: {:?}", result.err());
        let status: String = conn
            .query_row("SELECT status FROM encounters WHERE id='enc-1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "signed");
    }

    #[test]
    fn upsert_row_allows_alias_only_edit_on_signed_row() {
        let conn = fresh_db();
        insert_signed(&conn);
        // Same signed_at/signed_hash/status as already stored, only the
        // alias differs -- must be allowed through the WHERE guard.
        let result = upsert_encounter_row(
            &conn,
            "enc-1",
            "prov-1",
            "2026-07-04",
            Some("J.D. (fixed typo)"),
            "signed",
            Some("/tmp/audio.wav"),
            "2026-07-04T10:00:00Z",
            Some("2026-07-04T10:30:00Z"),
            Some("deadbeef"),
        );
        assert!(result.is_ok(), "alias-only edit must succeed: {:?}", result.err());
        let alias: String = conn
            .query_row("SELECT patient_alias FROM encounters WHERE id='enc-1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(alias, "J.D. (fixed typo)");
    }

    #[test]
    fn upsert_row_rejects_conflicting_write_to_already_signed_row() {
        // Simulates the TOCTOU race: the row is already 'signed' (as if a
        // concurrent writer committed first), and this call tries to write
        // different signed_at/signed_hash values -- as two concurrent
        // sign-off attempts racing on the same draft would each try to do.
        // The app-level `enforce_signed_immutability` SELECT is bypassed
        // here on purpose to prove the SQL-level guard alone stops the
        // demotion/overwrite, since that guard is the actual fix for the
        // race window between the SELECT and the write on separate
        // connections.
        let conn = fresh_db();
        insert_signed(&conn);
        let result = upsert_encounter_row(
            &conn,
            "enc-1",
            "prov-1",
            "2026-07-04",
            Some("J.D."),
            "signed",
            Some("/tmp/audio.wav"),
            "2026-07-04T10:00:00Z",
            Some("2026-07-04T99:99:99Z"), // different signed_at than stored
            Some("00000000"),             // different signed_hash than stored
        );
        assert!(result.is_err(), "conflicting write to a signed row must be rejected");
        assert!(matches!(result.unwrap_err(), AppError::InvalidInput(_)));
        // Original sign-off metadata must remain untouched.
        let (signed_at, signed_hash): (String, String) = conn
            .query_row(
                "SELECT signed_at, signed_hash FROM encounters WHERE id='enc-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(signed_at, "2026-07-04T10:30:00Z");
        assert_eq!(signed_hash, "deadbeef");
    }

    #[test]
    fn upsert_row_rejects_demotion_of_signed_row() {
        // A demote-to-draft attempt on an already-signed row must be
        // blocked by the SQL guard even without any race involved.
        let conn = fresh_db();
        insert_signed(&conn);
        let result = upsert_encounter_row(
            &conn,
            "enc-1",
            "prov-1",
            "2026-07-04",
            Some("J.D."),
            "draft", // <-- illegal demotion
            Some("/tmp/audio.wav"),
            "2026-07-04T10:00:00Z",
            None,
            None,
        );
        assert!(result.is_err(), "demotion of a signed row must be rejected");
        let status: String = conn
            .query_row("SELECT status FROM encounters WHERE id='enc-1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "signed", "row must remain signed after a rejected demotion");
    }

    #[test]
    fn clamp_list_limit_defaults_to_50() {
        assert_eq!(clamp_list_limit(None), 50);
    }

    #[test]
    fn clamp_list_limit_enforces_ceiling() {
        assert_eq!(clamp_list_limit(Some(i64::MAX)), 1000);
        assert_eq!(clamp_list_limit(Some(10_000)), 1000);
        assert_eq!(clamp_list_limit(Some(1000)), 1000); // boundary stays
    }

    #[test]
    fn clamp_list_limit_enforces_floor() {
        // 0 and negatives are pathological — bump to 1 so the caller gets
        // *something* back and notices the bug, rather than a silent empty.
        assert_eq!(clamp_list_limit(Some(0)), 1);
        assert_eq!(clamp_list_limit(Some(-5)), 1);
        assert_eq!(clamp_list_limit(Some(i64::MIN)), 1);
    }

    #[test]
    fn clamp_list_limit_passes_through_reasonable_values() {
        assert_eq!(clamp_list_limit(Some(1)), 1);
        assert_eq!(clamp_list_limit(Some(25)), 25);
        assert_eq!(clamp_list_limit(Some(100)), 100);
    }

    #[test]
    fn required_str_accepts_non_empty_string() {
        let payload = json!({"id": "enc-42"});
        assert_eq!(required_str(&payload, "id").unwrap(), "enc-42");
    }

    #[test]
    fn required_str_rejects_missing_field() {
        // Missing key on the JSON object — the old code would have coerced
        // this to "" via unwrap_or and cheerfully persisted an empty PK.
        let payload = json!({"provider_id": "prov-1"});
        let err = required_str(&payload, "id").unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        // Error message must name the offending field so JS gets an
        // actionable toast instead of a generic "invalid input".
        let msg = format!("{err}");
        assert!(msg.contains("id"), "error should name the missing field: {msg}");
    }

    #[test]
    fn required_str_rejects_empty_string() {
        // An explicit "" is just as bad as missing — both violate NOT NULL
        // semantics in a misleading way (INSERT succeeds with a blank PK).
        let payload = json!({"id": ""});
        assert!(matches!(
            required_str(&payload, "id").unwrap_err(),
            AppError::InvalidInput(_)
        ));
    }

    #[test]
    fn required_str_rejects_whitespace_only_string() {
        // A whitespace-only value is an empty value wearing a disguise: it
        // satisfies NOT NULL and `!s.is_empty()` while carrying no
        // information. That matters most for provider_id, which is the audit
        // actor identity on every encounter row — "   " is not a person.
        // patients::required_str already rejected these; this one did not,
        // despite its sibling's comment claiming the two mirror each other.
        for val in ["   ", "\t", "\n", " \t\n "] {
            let payload = json!({ "provider_id": val });
            assert!(
                matches!(
                    required_str(&payload, "provider_id").unwrap_err(),
                    AppError::InvalidInput(_)
                ),
                "whitespace-only value should reject: {val:?}"
            );
        }
    }

    #[test]
    fn required_str_preserves_surrounding_whitespace_on_real_values() {
        // Rejecting whitespace-ONLY must not start trimming real values --
        // the check is a guard, not a normalizer, and callers persist exactly
        // what they passed.
        let payload = json!({ "id": "  enc-42  " });
        assert_eq!(required_str(&payload, "id").unwrap(), "  enc-42  ");
    }

    #[test]
    fn required_str_rejects_wrong_type() {
        // Numeric/bool/null values were previously silently coerced to "";
        // now they surface a typed error at the boundary.
        for val in [json!(42), json!(true), json!(null), json!({"nested": "obj"})] {
            let payload = json!({"id": val});
            assert!(
                matches!(
                    required_str(&payload, "id").unwrap_err(),
                    AppError::InvalidInput(_)
                ),
                "wrong-type value should reject: {payload}"
            );
        }
    }

    // Every allowlisted status must pass check_status. Iterates the exact
    // constant so a merge that drops a state (breaking the desktop↔server
    // contract) fails the build.
    #[test]
    fn check_status_accepts_every_allowlisted_state() {
        for s in ALLOWED_STATUS {
            assert!(
                check_status(s).is_ok(),
                "{s} is allowlisted but check_status rejected it"
            );
        }
    }

    // Off-list values must be rejected as AppError::InvalidInput. Covers the
    // exact attack the audit named: a compromised JS layer writing a garbage
    // status the UI then can't render or exit.
    #[test]
    fn check_status_rejects_off_list_values() {
        for s in [
            "",
            "pending",         // similar to "draft", but wrong
            "signed_at",       // an adjacent field name
            "DRAFT",           // case sensitivity matters
            "draft ",          // trailing whitespace matters
            "'; DROP TABLE",   // pathological
            "\u{202e}gnitroper", // RTL-override + reversed 'reporting'
        ] {
            let err = check_status(s).unwrap_err();
            assert!(
                matches!(err, AppError::InvalidInput(_)),
                "{s:?} should reject as InvalidInput, got {err:?}"
            );
        }
    }

    // Pin the exact allowlist against the server's ALLOWED_STATUS. If either
    // side edits, this test surfaces the desync during review. Also ties the
    // pin to a doc comment reviewer can grep for.
    #[test]
    fn allowed_status_pin_mirrors_server_contract() {
        assert_eq!(
            ALLOWED_STATUS,
            &[
                "recording",
                "recording_done",
                "transcribing",
                "draft",
                "signed",
                "exported",
            ],
            "ALLOWED_STATUS changed — update `server/src/api.rs::ALLOWED_STATUS` \
             in the same commit or sync will break."
        );
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

    // MP1: folded-COUNT stats. Verify the single-query path produces the
    // same tuple the three-query path would have.

    fn insert_row(conn: &Connection, id: &str, status: &str, date: &str) {
        conn.execute(
            "INSERT INTO encounters (id, provider_id, encounter_date, status, created_at) \
             VALUES (?1, 'prov-1', ?2, ?3, '2026-07-04T10:00:00Z')",
            params![id, date, status],
        )
        .unwrap();
    }

    #[test]
    fn stats_empty_db_returns_all_zero() {
        let conn = fresh_db();
        let (total, signed, today) = query_encounter_stats(&conn, "2026-07-04").unwrap();
        assert_eq!((total, signed, today), (0, 0, 0));
    }

    #[test]
    fn stats_counts_total_signed_and_today_independently() {
        // 5 rows total: 2 signed (one today, one earlier), 2 drafts (one today,
        // one earlier), 1 recording (today). Expect total=5, signed=2, today=3.
        let conn = fresh_db();
        insert_row(&conn, "a", "signed", "2026-07-04");
        insert_row(&conn, "b", "signed", "2026-07-01");
        insert_row(&conn, "c", "draft", "2026-07-04");
        insert_row(&conn, "d", "draft", "2026-07-02");
        insert_row(&conn, "e", "recording", "2026-07-04");
        let (total, signed, today) = query_encounter_stats(&conn, "2026-07-04").unwrap();
        assert_eq!(total, 5, "total counts every row");
        assert_eq!(signed, 2, "signed only counts status='signed'");
        assert_eq!(today, 3, "today counts every status on today's date");
    }

    #[test]
    fn stats_today_filter_binds_param_exactly() {
        // Guard against accidental LIKE/prefix behavior — the filter must
        // be exact string equality on the parameterized value.
        let conn = fresh_db();
        insert_row(&conn, "a", "signed", "2026-07-04");
        insert_row(&conn, "b", "signed", "2026-07-042"); // pathological suffix
        let (_, _, today) = query_encounter_stats(&conn, "2026-07-04").unwrap();
        assert_eq!(today, 1, "?1 must be an exact match, not a prefix");
    }

    #[test]
    fn stats_signed_filter_is_case_sensitive() {
        // Existing writes go through validated status enums, but confirm the
        // filter itself doesn't silently upcase 'SIGNED'.
        let conn = fresh_db();
        insert_row(&conn, "a", "signed", "2026-07-04");
        insert_row(&conn, "b", "SIGNED", "2026-07-04"); // wouldn't pass the enum, but proves the filter
        let (_, signed, _) = query_encounter_stats(&conn, "2026-07-04").unwrap();
        assert_eq!(signed, 1, "filter compares exact lowercase 'signed'");
    }

    // --- delete_encounter_row ------------------------------------------------

    fn seed_kv(conn: &Connection, key: &str, value: &str) {
        conn.execute(
            "INSERT INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
            params![key, value],
        )
        .unwrap();
    }

    fn kv_count(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM kv", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn delete_encounter_row_removes_the_row_and_its_content_kv_rows() {
        let mut conn = fresh_db();
        insert_row(&conn, "enc-1", "draft", "2026-07-04");
        seed_kv(&conn, "note_content_v1::enc-1", "\"the note text\"");
        seed_kv(&conn, "note_content_v1::transcript::enc-1", "\"the transcript\"");
        // An unrelated row must survive.
        seed_kv(&conn, "note_settings_v1::onboarded", "true");

        delete_encounter_row(&mut conn, "enc-1").unwrap();

        assert!(get_encounter_conn(&conn, "enc-1").unwrap().is_none());
        assert_eq!(kv_count(&conn), 1, "only the unrelated row should remain");
    }

    // Helper mirroring get_encounter's query, since that command function
    // needs a Tauri State harness this test module doesn't set up.
    fn get_encounter_conn(conn: &Connection, id: &str) -> Result<Option<Value>, AppError> {
        let sql = format!("SELECT {ENCOUNTER_COLS} FROM encounters WHERE id = ?1");
        Ok(conn.query_row(&sql, params![id], encounter_row_to_json).optional()?)
    }

    #[test]
    fn delete_encounter_row_reports_missing_row() {
        let mut conn = fresh_db();
        let err = delete_encounter_row(&mut conn, "ghost").unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        assert!(format!("{err}").contains("not found"));
    }

    #[test]
    fn delete_encounter_row_on_missing_row_does_not_delete_unrelated_kv_content() {
        // A failed delete (row not found) must not have side effects — the
        // KV DELETE runs inside the same transaction, so a rollback on the
        // encounters-row miss must also undo it.
        let mut conn = fresh_db();
        seed_kv(&conn, "note_content_v1::ghost", "\"orphaned content\"");
        assert!(delete_encounter_row(&mut conn, "ghost").is_err());
        assert_eq!(kv_count(&conn), 1, "the transaction must roll back, not partially apply");
    }

    #[test]
    fn delete_encounter_row_deletes_a_signed_encounter_too() {
        // The finding explicitly names "delete a SIGNED note" as the gap —
        // must not be blocked by any signed-row immutability guard (those
        // guard mutation, not deletion).
        let mut conn = fresh_db();
        insert_signed(&conn);
        delete_encounter_row(&mut conn, "enc-1").unwrap();
        assert!(get_encounter_conn(&conn, "enc-1").unwrap().is_none());
    }

    #[test]
    fn delete_encounter_row_only_touches_the_named_encounter() {
        let mut conn = fresh_db();
        insert_row(&conn, "enc-1", "draft", "2026-07-04");
        insert_row(&conn, "enc-2", "draft", "2026-07-04");
        seed_kv(&conn, "note_content_v1::enc-1", "\"a\"");
        seed_kv(&conn, "note_content_v1::enc-2", "\"b\"");

        delete_encounter_row(&mut conn, "enc-1").unwrap();

        assert!(get_encounter_conn(&conn, "enc-1").unwrap().is_none());
        assert!(get_encounter_conn(&conn, "enc-2").unwrap().is_some());
        assert_eq!(kv_count(&conn), 1, "only enc-1's content rows should be gone");
    }
}
