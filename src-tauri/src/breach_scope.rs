//! Breach-scoping query — "whose PHI was on this device during the incident?"
//!
//! HITECH audit finding H-2. Before this existed, nothing in the app could
//! answer that question. The incident-response runbook described the process,
//! but the actual enumeration was a manual SQLite session against an encrypted
//! database, performed under a 60-day clock by the same person the incident
//! happened to.
//!
//! What the regulation needs, and this supplies:
//!   * §164.404(a) — notice to **each affected individual**, so the set of
//!     patients whose PHI was present has to be enumerable at all.
//!   * §164.404(c)(1)(B) — a description of the **types** of PHI involved
//!     (note text, transcript, audio, date of birth), which is why every
//!     encounter row carries category flags rather than content.
//!   * §164.408 — the HHS log, which needs a defensible count.
//!   * §164.404(b) — all of it inside 60 days of discovery.
//!
//! This is a read-only report. It creates nothing, changes nothing, and
//! deletes nothing.
//!
//! ## Two decisions worth understanding before reading the SQL
//!
//! **1. Encounters have no lower date bound, deliberately.**
//! The window is `[from, to]`, but the encounter query filters only on
//! `created_at <= to`. A record created two years before the incident and
//! still on the device *was on the device during the incident* — its age is
//! irrelevant to whether it was exposed. Adding `created_at >= from` would
//! read naturally and silently under-report every long-lived record, which is
//! the one direction of error that matters here: an omitted patient is an
//! individual who never receives a notice they are owed. The lower bound
//! applies only to the two genuinely time-stamped event streams (exports and
//! destructions), where "during the window" is the actual question.
//!
//! **2. It returns aliases but never dates of birth.**
//! The alias is unavoidable — the whole point is knowing who to notify. The
//! DOB is not: §164.404(c)(1)(B) asks for the *types* of PHI involved, so
//! `dob_present` answers "was a date of birth exposed?" without reproducing
//! it. A breach report is itself a document that gets copied, emailed, and
//! filed, and there is no reason for it to carry more PHI than the decision
//! requires.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use tauri::State;

use crate::errors::AppError;
use crate::DbState;

/// One raw `encounters` row as read for the scope report: id, encounter_date,
/// status, patient_id, patient_alias, audio_path, created_at. Named because
/// the tuple is threaded through a `query_map` and clippy is right that the
/// bare form is unreadable — the same reason `encounters::FrozenFields` exists.
type EncounterRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);

/// Cap on rows returned per section, so a scope over a large database cannot
/// build an unbounded JSON blob in memory and hand it to the WebView.
///
/// Truncation is REPORTED, never silent: each section carries a `truncated`
/// flag and the true total alongside the rows. A breach report that quietly
/// dropped the tail would be worse than no report — it would read as complete
/// while under-counting the individuals owed a notice.
const MAX_ROWS: usize = 5_000;

/// Validate a `YYYY-MM-DD` bound and expand it to an ISO-8601 instant.
///
/// Timestamps in this database (`time::utc_now_iso`) are full ISO-8601 UTC, so
/// a bare date would compare lexicographically as if it were midnight — which
/// silently excludes everything that happened on the `to` date itself. `to` is
/// therefore expanded to the end of its day, `from` to the start of its.
fn day_bound(date: &str, end_of_day: bool) -> Result<String, AppError> {
    let ok = date.len() == 10
        && date.as_bytes()[4] == b'-'
        && date.as_bytes()[7] == b'-'
        && date
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    if !ok {
        return Err(AppError::invalid("date bounds must be YYYY-MM-DD"));
    }
    Ok(if end_of_day {
        format!("{date}T23:59:59.999Z")
    } else {
        format!("{date}T00:00:00.000Z")
    })
}

/// True when a `kv` row exists for `key`. Used to detect which PHI categories
/// an encounter actually holds.
///
/// Fails toward PRESENT: a query error returns `true`, so an unreadable row is
/// reported as PHI that may have been exposed. This mirrors
/// `audio::reconcile_orphaned_audio`'s `.unwrap_or(1)`, and for the same
/// reason — when the consequence of being wrong is asymmetric, the code should
/// be wrong in the recoverable direction. Over-reporting a category costs a
/// broader notice; under-reporting it means an individual is told their
/// transcript was safe when nobody actually checked.
fn kv_key_exists(conn: &Connection, key: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM kv WHERE key = ?1)",
        params![key],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(1)
        != 0
}

/// Encounters present on the device at any point up to `to_iso`, with the PHI
/// categories each one carries.
fn encounters_in_scope(conn: &Connection, to_iso: &str) -> Result<(Vec<Value>, usize), AppError> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM encounters WHERE created_at <= ?1",
        params![to_iso],
        |r| r.get(0),
    )?;

    let mut stmt = conn.prepare(
        "SELECT id, encounter_date, status, patient_id, patient_alias, audio_path, created_at \
         FROM encounters WHERE created_at <= ?1 \
         ORDER BY created_at ASC LIMIT ?2",
    )?;
    let raw: Vec<EncounterRow> =
        stmt.query_map(params![to_iso, MAX_ROWS as i64], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    let rows = raw
        .into_iter()
        .map(|(id, date, status, patient_id, alias, audio_path, created_at)| {
            json!({
                "id":             id,
                "encounter_date": date,
                "status":         status,
                "created_at":     created_at,
                "patient_id":     patient_id,
                "patient_alias":  alias,
                // The PHI categories §164.404(c)(1)(B) asks us to describe.
                "has_note":       kv_key_exists(conn, &format!("note_content_v1::{id}")),
                "has_transcript": kv_key_exists(conn, &format!("note_content_v1::transcript::{id}")),
                "has_audio":      audio_path.is_some(),
            })
        })
        .collect();

    Ok((rows, total as usize))
}

/// Patient roster rows present up to `to_iso`.
///
/// The roster is enumerated independently of encounters, not derived from
/// them: a patient added to the roster who has no encounter yet still has
/// identifying data on the device, and is still an individual whose
/// information was exposed.
fn patients_in_scope(conn: &Connection, to_iso: &str) -> Result<(Vec<Value>, usize), AppError> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM patients WHERE created_at <= ?1",
        params![to_iso],
        |r| r.get(0),
    )?;

    let mut stmt = conn.prepare(
        "SELECT id, alias, dob IS NOT NULL, notes IS NOT NULL, created_at \
         FROM patients WHERE created_at <= ?1 ORDER BY created_at ASC LIMIT ?2",
    )?;
    let rows: Vec<Value> = stmt
        .query_map(params![to_iso, MAX_ROWS as i64], |r| {
            Ok(json!({
                "id":            r.get::<_, String>(0)?,
                "alias":         r.get::<_, String>(1)?,
                // Presence, not content — see the module doc.
                "dob_present":   r.get::<_, i64>(2)? != 0,
                "notes_present": r.get::<_, i64>(3)? != 0,
                "created_at":    r.get::<_, String>(4)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok((rows, total as usize))
}

/// Note exports recorded inside the window — PHI that left the app as a file
/// or via the clipboard, and therefore may exist in copies beyond this device.
///
/// Read out of the hash-chained `note_audit` table rather than telemetry: the
/// diagnostics log is opt-in and can be cleared by the user, so it cannot be
/// relied on for a compliance answer. `entry_json` is parsed in Rust rather
/// than matched with SQL `LIKE`, which would match the substring anywhere in
/// the row — including inside an unrelated field.
fn exports_in_window(
    conn: &Connection,
    from_iso: &str,
    to_iso: &str,
) -> Result<(Vec<Value>, usize), AppError> {
    let mut stmt = conn.prepare("SELECT encounter_id, entry_json FROM note_audit ORDER BY id ASC")?;
    let all: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();

    let mut rows: Vec<Value> = Vec::new();
    for (encounter_id, entry_json) in all {
        let Ok(entry) = serde_json::from_str::<Value>(&entry_json) else {
            continue; // a scrubbed or malformed row carries no export detail
        };
        if entry.get("action").and_then(Value::as_str) != Some("note_exported") {
            continue;
        }
        let Some(ts) = entry.get("timestamp").and_then(Value::as_str) else {
            continue;
        };
        if ts < from_iso || ts > to_iso {
            continue;
        }
        rows.push(json!({
            "encounter_id": encounter_id,
            "timestamp":    ts,
            "format":       entry.get("format").cloned().unwrap_or(Value::Null),
            "method":       entry.get("method").cloned().unwrap_or(Value::Null),
            "actor":        entry.get("actor").cloned().unwrap_or(Value::Null),
        }));
    }

    let total = rows.len();
    rows.truncate(MAX_ROWS);
    Ok((rows, total))
}

/// Destruction-log rows inside the window.
///
/// Relevant in both directions: PHI destroyed mid-incident still existed for
/// part of it, and a destruction recorded during the window may itself be what
/// is under investigation. `patient_alias` is a one-way SHA-256 blind by
/// design (see `destruction_log`), so it is returned as a correlation handle,
/// not a readable name.
fn destructions_in_window(
    conn: &Connection,
    from_iso: &str,
    to_iso: &str,
) -> Result<(Vec<Value>, usize), AppError> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM destruction_log WHERE created_at BETWEEN ?1 AND ?2",
        params![from_iso, to_iso],
        |r| r.get(0),
    )?;

    let mut stmt = conn.prepare(
        "SELECT created_at, provider_id, entity_type, entity_id, patient_alias, \
                legal_basis, records_scrubbed \
         FROM destruction_log WHERE created_at BETWEEN ?1 AND ?2 \
         ORDER BY created_at ASC LIMIT ?3",
    )?;
    let rows: Vec<Value> = stmt
        .query_map(params![from_iso, to_iso, MAX_ROWS as i64], |r| {
            Ok(json!({
                "created_at":       r.get::<_, String>(0)?,
                "provider_id":      r.get::<_, String>(1)?,
                "entity_type":      r.get::<_, String>(2)?,
                "entity_id":        r.get::<_, String>(3)?,
                "patient_alias_blind": r.get::<_, Option<String>>(4)?,
                "legal_basis":      r.get::<_, String>(5)?,
                "records_scrubbed": r.get::<_, i64>(6)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok((rows, total as usize))
}

/// Build the full scope report. Split from the command wrapper so it is
/// testable against a plain `Connection` without a Tauri `State` harness —
/// the same seam `note_audit::records_listed_conn` uses.
pub(crate) fn scope_report(
    conn: &Connection,
    from: &str,
    to: &str,
) -> Result<Value, AppError> {
    let from_iso = day_bound(from, false)?;
    let to_iso = day_bound(to, true)?;
    if from_iso > to_iso {
        return Err(AppError::invalid("the window's start date is after its end date"));
    }

    let (encounters, encounter_total) = encounters_in_scope(conn, &to_iso)?;
    let (patients, patient_total) = patients_in_scope(conn, &to_iso)?;
    let (exports, export_total) = exports_in_window(conn, &from_iso, &to_iso)?;
    let (destructions, destruction_total) = destructions_in_window(conn, &from_iso, &to_iso)?;

    Ok(json!({
        "window": { "from": from, "to": to, "from_iso": from_iso, "to_iso": to_iso },
        "generated_at": crate::time::utc_now_iso(),
        "max_rows_per_section": MAX_ROWS,
        "encounters": {
            "total": encounter_total,
            "truncated": encounter_total > encounters.len(),
            "rows": encounters,
        },
        "patients": {
            "total": patient_total,
            "truncated": patient_total > patients.len(),
            "rows": patients,
        },
        "exports": {
            "total": export_total,
            "truncated": export_total > exports.len(),
            "rows": exports,
        },
        "destructions": {
            "total": destruction_total,
            "truncated": destruction_total > destructions.len(),
            "rows": destructions,
        },
    }))
}

/// Enumerate the PHI in scope for an incident window.
///
/// Requires an unlocked session — it reads through `state.conn()` like every
/// other PHI command, so a locked app returns the standard precondition rather
/// than answering. That is the same bar as viewing the roster, which is the
/// right comparison: this exposes no PHI category the roster does not already
/// show, it only assembles them.
///
/// The call is itself recorded as a records-listed access event. A query that
/// reads every patient alias on the device is exactly the kind of bulk PHI
/// access §164.312(b) audit controls exist to capture, and "it was for
/// compliance" is a claim the trail should carry rather than assume.
#[tauri::command]
pub(crate) fn breach_scope(
    state: State<'_, DbState>,
    from: String,
    to: String,
) -> Result<Value, AppError> {
    let mut conn = state.conn()?;
    let report = scope_report(&conn, &from, &to)?;

    // Count the individuals whose data this surfaced, for the audit entry.
    let listed = report["patients"]["rows"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0) as i64;
    // Best-effort: the report is already built and correct, and failing to
    // record the access must not deny an incident responder the answer they
    // are legally required to produce. A failure is logged, not swallowed.
    if let Err(e) = crate::note_audit::records_listed_conn(&mut conn, "breach_scope", listed) {
        log::error!(
            "breach_scope ran but its access could not be audited: {}",
            crate::log_safety::cap_len(&e.to_string())
        );
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
             CREATE TABLE encounters (
                 id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, encounter_date TEXT NOT NULL,
                 patient_alias TEXT, patient_id TEXT, status TEXT NOT NULL DEFAULT 'draft',
                 audio_path TEXT, created_at TEXT NOT NULL, signed_at TEXT, signed_hash TEXT);
             CREATE TABLE patients (
                 id TEXT PRIMARY KEY, alias TEXT NOT NULL, dob TEXT, notes TEXT,
                 source_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
             CREATE TABLE note_audit (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, encounter_id TEXT NOT NULL, seq INTEGER NOT NULL,
                 archived INTEGER NOT NULL DEFAULT 0, prev_hash TEXT, entry_hash TEXT NOT NULL,
                 entry_json TEXT NOT NULL, UNIQUE (encounter_id, seq));",
        )
        .unwrap();
        crate::destruction_log::init_schema(&conn).unwrap();
        conn
    }

    fn add_encounter(conn: &Connection, id: &str, created_at: &str, audio: Option<&str>) {
        conn.execute(
            "INSERT INTO encounters (id, provider_id, encounter_date, patient_alias, patient_id, status, audio_path, created_at) \
             VALUES (?1, 'p', '2026-01-01', 'A.B.', 'pt-1', 'signed', ?2, ?3)",
            params![id, audio, created_at],
        )
        .unwrap();
    }

    fn add_export(conn: &Connection, encounter_id: &str, seq: i64, timestamp: &str) {
        let entry = json!({
            "action": "note_exported", "actor": "Dr. Chen", "actorId": "solo",
            "format": "pdf", "method": "file", "timestamp": timestamp,
            "prevHash": null, "entryHash": format!("h{seq}"),
        })
        .to_string();
        conn.execute(
            "INSERT INTO note_audit (encounter_id, seq, prev_hash, entry_hash, entry_json) \
             VALUES (?1, ?2, NULL, ?3, ?4)",
            params![encounter_id, seq, format!("h{seq}"), entry],
        )
        .unwrap();
    }

    #[test]
    fn day_bounds_cover_the_whole_end_date() {
        // A bare "to" date would compare as midnight and silently exclude
        // everything that happened on the last day of the window.
        assert_eq!(day_bound("2026-07-01", false).unwrap(), "2026-07-01T00:00:00.000Z");
        assert_eq!(day_bound("2026-07-31", true).unwrap(), "2026-07-31T23:59:59.999Z");
        assert!(day_bound("2026-7-1", false).is_err());
        assert!(day_bound("not-a-date", false).is_err());
        assert!(day_bound("", false).is_err());
    }

    #[test]
    fn an_inverted_window_is_rejected() {
        let conn = fresh();
        let err = scope_report(&conn, "2026-07-31", "2026-07-01").unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    // The finding this whole module exists for: a record older than the
    // incident window is still ON the device during it. Bounding encounters
    // below by `from` would drop it, and the patient would never be notified.
    #[test]
    fn records_predating_the_window_are_still_in_scope() {
        let conn = fresh();
        add_encounter(&conn, "enc-old", "2024-03-01T10:00:00.000Z", None);
        add_encounter(&conn, "enc-recent", "2026-07-15T10:00:00.000Z", None);

        let r = scope_report(&conn, "2026-07-01", "2026-07-31").unwrap();
        let ids: Vec<&str> = r["encounters"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .collect();

        assert!(
            ids.contains(&"enc-old"),
            "a 2024 record still on the device was exposed during a 2026 incident"
        );
        assert!(ids.contains(&"enc-recent"));
        assert_eq!(r["encounters"]["total"], 2);
    }

    #[test]
    fn records_created_after_the_window_are_excluded() {
        let conn = fresh();
        add_encounter(&conn, "enc-later", "2026-09-01T10:00:00.000Z", None);
        let r = scope_report(&conn, "2026-07-01", "2026-07-31").unwrap();
        assert_eq!(r["encounters"]["total"], 0, "PHI that did not exist yet was not exposed");
    }

    #[test]
    fn phi_categories_are_reported_per_encounter() {
        let conn = fresh();
        add_encounter(&conn, "enc-1", "2026-07-10T10:00:00.000Z", Some("/audio/enc-1.wav.enc"));
        add_encounter(&conn, "enc-2", "2026-07-10T10:00:00.000Z", None);
        conn.execute(
            "INSERT INTO kv (key, value, updated_at) VALUES ('note_content_v1::enc-1', '\"x\"', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO kv (key, value, updated_at) VALUES ('note_content_v1::transcript::enc-1', '\"x\"', 0)",
            [],
        )
        .unwrap();

        let r = scope_report(&conn, "2026-07-01", "2026-07-31").unwrap();
        let rows = r["encounters"]["rows"].as_array().unwrap();
        let e1 = rows.iter().find(|e| e["id"] == "enc-1").unwrap();
        let e2 = rows.iter().find(|e| e["id"] == "enc-2").unwrap();

        assert_eq!(e1["has_note"], true);
        assert_eq!(e1["has_transcript"], true);
        assert_eq!(e1["has_audio"], true);
        assert_eq!(e2["has_note"], false);
        assert_eq!(e2["has_transcript"], false);
        assert_eq!(e2["has_audio"], false);
    }

    // §164.404(c)(1)(B) wants the TYPES of PHI, not the PHI itself. The alias
    // is needed to identify who to notify; the date of birth is not, and a
    // breach report gets copied and filed.
    #[test]
    fn a_date_of_birth_is_reported_as_present_but_never_returned() {
        let conn = fresh();
        conn.execute(
            "INSERT INTO patients (id, alias, dob, created_at, updated_at) \
             VALUES ('pt-1', 'A.B.', '1984-02-29', '2026-07-10T00:00:00.000Z', '2026-07-10T00:00:00.000Z')",
            [],
        )
        .unwrap();

        let r = scope_report(&conn, "2026-07-01", "2026-07-31").unwrap();
        let row = &r["patients"]["rows"][0];
        assert_eq!(row["dob_present"], true);
        assert_eq!(row["alias"], "A.B.", "the alias is needed to identify who to notify");

        let serialized = r.to_string();
        assert!(
            !serialized.contains("1984-02-29"),
            "the report must not reproduce the date of birth anywhere"
        );
    }

    #[test]
    fn only_exports_inside_the_window_are_listed() {
        let conn = fresh();
        add_encounter(&conn, "enc-1", "2026-01-01T00:00:00.000Z", None);
        add_export(&conn, "enc-1", 1, "2026-06-30T12:00:00.000Z"); // before
        add_export(&conn, "enc-1", 2, "2026-07-15T12:00:00.000Z"); // inside
        add_export(&conn, "enc-1", 3, "2026-07-31T23:00:00.000Z"); // inside, last day
        add_export(&conn, "enc-1", 4, "2026-08-02T12:00:00.000Z"); // after

        let r = scope_report(&conn, "2026-07-01", "2026-07-31").unwrap();
        assert_eq!(
            r["exports"]["total"], 2,
            "the last-day export must be included — that is what the end-of-day bound is for"
        );
    }

    #[test]
    fn non_export_audit_entries_are_not_counted_as_disclosures() {
        let conn = fresh();
        add_encounter(&conn, "enc-1", "2026-01-01T00:00:00.000Z", None);
        let viewed = json!({
            "action": "record_viewed", "actor": "Dr. Chen", "actorId": "solo",
            "timestamp": "2026-07-15T12:00:00.000Z", "prevHash": null, "entryHash": "hv",
        })
        .to_string();
        conn.execute(
            "INSERT INTO note_audit (encounter_id, seq, prev_hash, entry_hash, entry_json) \
             VALUES ('enc-1', 1, NULL, 'hv', ?1)",
            params![viewed],
        )
        .unwrap();

        let r = scope_report(&conn, "2026-07-01", "2026-07-31").unwrap();
        assert_eq!(r["exports"]["total"], 0, "viewing a record is not exporting it");
    }

    #[test]
    fn destructions_inside_the_window_are_listed_with_a_blinded_alias() {
        let conn = fresh();
        crate::destruction_log::append(&conn, "Dr. Chen", "encounter", "enc-x", "Jane Doe", "patient_request", 3)
            .unwrap();

        // The append stamps "now", so scope a window that certainly contains it.
        let r = scope_report(&conn, "2000-01-01", "2999-12-31").unwrap();
        assert_eq!(r["destructions"]["total"], 1);
        let row = &r["destructions"]["rows"][0];
        assert_eq!(row["legal_basis"], "patient_request");
        assert_ne!(
            row["patient_alias_blind"], "Jane Doe",
            "the disposal record stores a one-way blind, and the report must not undo it"
        );
    }

    #[test]
    fn an_empty_database_produces_a_valid_empty_report() {
        let conn = fresh();
        let r = scope_report(&conn, "2026-07-01", "2026-07-31").unwrap();
        for section in ["encounters", "patients", "exports", "destructions"] {
            assert_eq!(r[section]["total"], 0, "{section} should be empty");
            assert_eq!(r[section]["truncated"], false, "{section} must not claim truncation");
        }
        assert_eq!(r["window"]["from"], "2026-07-01");
    }
}
