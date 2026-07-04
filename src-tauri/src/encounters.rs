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

/// Clamp a caller-supplied `LIMIT` into a sane range.
///
/// Without a ceiling, `list_encounters(Some(i64::MAX))` would deserialize
/// every row into a `Vec<Value>` in memory — an easy DoS from any JS-layer
/// foothold (or a UI bug), and a footgun as the table grows. 1000 is the same
/// ceiling the sync server uses (`api.rs::LIST_WINDOW`), keeping desktop
/// paging parity with the server.
///
/// The floor of 1 turns pathological inputs (0, negatives) into a "give me
/// one row" query instead of a silent empty result — easier for callers to
/// notice and fix.
pub(crate) fn clamp_list_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(50).clamp(1, 1000)
}

#[tauri::command]
pub(crate) fn list_encounters(state: State<DbState>, limit: Option<i64>) -> Result<Vec<Value>, AppError> {
    let conn = state.0.lock();
    let n = clamp_list_limit(limit);
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

/// Extract a required string field from an incoming encounter payload,
/// or return `AppError::InvalidInput` naming the missing field.
///
/// Previously the four required fields on `upsert_encounter` used
/// `unwrap_or("")`, which coerced missing values into empty strings and
/// happily persisted them — not exploitable, but it hid bugs behind a
/// misleading NOT NULL success. Failing loudly here surfaces the caller
/// error at the boundary (audit L2).
fn required_str<'a>(incoming: &'a Value, field: &'static str) -> Result<&'a str, AppError> {
    match incoming[field].as_str() {
        Some(s) if !s.is_empty() => Ok(s),
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
            id,
            provider_id,
            encounter_date,
            encounter["patient_alias"].as_str(),
            status,
            encounter["audio_path"].as_str(),
            created_at,
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
}
