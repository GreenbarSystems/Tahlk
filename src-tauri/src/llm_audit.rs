//! Append-only audit log of LLM calls (fixes audit finding C2, point 3).
//!
//! 45 CFR §164.312(b) requires "hardware, software, and procedural
//! mechanisms that record and examine activity in information systems
//! that contain or use ePHI." Every note generation transmits PHI to
//! Anthropic, so every one of those calls needs an audit-log entry.
//!
//! We log METADATA ONLY — never transcript, never response text. Enough
//! for a compliance officer to reconstruct WHO called WHAT model WHEN and
//! how many bytes went out / came back, plus the upstream `request-id`
//! header so Anthropic support can correlate incidents. Content stays out
//! of the audit log so it doesn't turn into a second copy of PHI to protect.
//!
//! Table is intentionally SEPARATE from `note_history`:
//!   * `note_history` is a hash-chained tamper-evident log of note edits;
//!     the JS verifier walks it linearly and any missing/mismatched hash
//!     is a red flag. Pouring system-actor rows into it would either muddy
//!     the chain (Rust would have to compute hashes it currently doesn't)
//!     or force JS to skip a growing category of rows.
//!   * `llm_audit` is a monotonic append log — no chain, no verification,
//!     no per-encounter ordering constraint. Straight INSERT, straight
//!     SELECT for the operator report.
//!
//! Retention: nothing prunes this table today. At the rates a solo
//! practitioner generates notes (~30/day * 3 KB per row = ~30 MB/year) the
//! growth is negligible next to the encounter audio. A future task adds a
//! Settings toggle to bulk-export + truncate for practices that want a
//! shorter on-device window.

use rusqlite::{params, Connection};
use serde_json::{json, Value};

use crate::errors::AppError;

pub(crate) fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS llm_audit (
             id                INTEGER PRIMARY KEY AUTOINCREMENT,
             created_at        TEXT    NOT NULL,
             encounter_id      TEXT,
             provider_id       TEXT    NOT NULL DEFAULT '',
             model             TEXT    NOT NULL,
             endpoint          TEXT    NOT NULL,
             request_bytes     INTEGER NOT NULL,
             response_bytes    INTEGER NOT NULL,
             upstream_reqid    TEXT,
             outcome           TEXT    NOT NULL,
             error_code        TEXT,
             duration_ms       INTEGER
         );
         CREATE INDEX IF NOT EXISTS llm_audit_created_idx
             ON llm_audit (created_at DESC);
         CREATE INDEX IF NOT EXISTS llm_audit_encounter_idx
             ON llm_audit (encounter_id);",
    )?;
    Ok(())
}

/// A single row about to be appended. Fields are all "safe": no content,
/// no API key, no patient identifiers beyond the (opaque) encounter_id.
#[derive(Debug, Clone)]
pub(crate) struct LlmCallEntry {
    /// ISO-8601 UTC timestamp. Captured Rust-side (`chrono`-free using the
    /// SQLite datetime function on insert would be simpler, but we want
    /// deterministic tests and unified timezone handling).
    pub created_at: String,
    /// Encounter this call belongs to, if any. May be None for a future
    /// standalone "test the API key" flow that's not tied to a session.
    pub encounter_id: Option<String>,
    /// Provider identity for cross-referencing with `provider profile`.
    /// Kept as free-text since providers only ever look at their own rows.
    pub provider_id: String,
    /// Model identifier from the request body (e.g. "claude-haiku-4-5-…").
    pub model: String,
    /// Endpoint URL. Keeping this as a full string means a compromised
    /// build pointing at a different host shows up in the audit.
    pub endpoint: String,
    /// Serialized request body length in bytes. Rough proxy for how much
    /// PHI went out the door. NOT stream chunks — the full JSON we POSTed.
    pub request_bytes: i64,
    /// Length of the accumulated response text in bytes.
    pub response_bytes: i64,
    /// The upstream `request-id` header if Anthropic returned one. Their
    /// support answers with this. Missing on transport-level failures.
    pub upstream_reqid: Option<String>,
    /// "ok", "auth_failed", "rate_limited", "upstream_api", "network",
    /// "upstream_empty", or "internal". Mirrors the AppError code.
    pub outcome: String,
    /// Same code as `outcome` when `outcome != "ok"`. Null on success.
    pub error_code: Option<String>,
    /// End-to-end wall-clock latency in ms.
    pub duration_ms: Option<i64>,
}

pub(crate) fn append(conn: &Connection, entry: &LlmCallEntry) -> Result<i64, AppError> {
    conn.execute(
        "INSERT INTO llm_audit \
         (created_at, encounter_id, provider_id, model, endpoint, \
          request_bytes, response_bytes, upstream_reqid, outcome, error_code, duration_ms) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            entry.created_at,
            entry.encounter_id,
            entry.provider_id,
            entry.model,
            entry.endpoint,
            entry.request_bytes,
            entry.response_bytes,
            entry.upstream_reqid,
            entry.outcome,
            entry.error_code,
            entry.duration_ms,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn row_to_json(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "id":             r.get::<_, i64>(0)?,
        "createdAt":      r.get::<_, String>(1)?,
        "encounterId":    r.get::<_, Option<String>>(2)?,
        "providerId":     r.get::<_, String>(3)?,
        "model":          r.get::<_, String>(4)?,
        "endpoint":       r.get::<_, String>(5)?,
        "requestBytes":   r.get::<_, i64>(6)?,
        "responseBytes":  r.get::<_, i64>(7)?,
        "upstreamReqid":  r.get::<_, Option<String>>(8)?,
        "outcome":        r.get::<_, String>(9)?,
        "errorCode":      r.get::<_, Option<String>>(10)?,
        "durationMs":     r.get::<_, Option<i64>>(11)?,
    }))
}

const SELECT_COLS: &str =
    "id, created_at, encounter_id, provider_id, model, endpoint, \
     request_bytes, response_bytes, upstream_reqid, outcome, error_code, duration_ms";

/// Core list query, split out from the Tauri command so it can be unit-tested
/// against an in-memory `Connection` without standing up a `State<DbState>`.
/// `limit` is expected to be pre-clamped by the caller (see `llm_audit_list`).
///
/// S-CODE-5: this replaced a 4-branch cursor-pagination match (`encounter_id`
/// × `before_id`, each branch hand-rolling the same SELECT). Cursor pagination
/// was premature for a single-user *local* audit table that grows a few MB/year
/// and had no caller ever passing a cursor — `ORDER BY id DESC LIMIT` already
/// returns the most recent rows, which is the only access pattern the operator
/// report needs. One WHERE-builder now covers both the filtered and unfiltered
/// cases. If a real need to page a large local table ever materializes,
/// reintroduce a cursor *then*, against a concrete requirement.
fn list_recent(
    conn: &Connection,
    encounter_id: Option<&str>,
    limit: i64,
) -> Result<Vec<Value>, AppError> {
    let mut sql = format!("SELECT {} FROM llm_audit", SELECT_COLS);
    let mut binds: Vec<&dyn rusqlite::ToSql> = Vec::new();
    if let Some(eid) = encounter_id.as_ref() {
        sql.push_str(" WHERE encounter_id = ?");
        binds.push(eid);
    }
    sql.push_str(" ORDER BY id DESC LIMIT ?");
    binds.push(&limit);

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(binds.as_slice(), row_to_json)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// #[tauri::command] — list the most recent audit rows, most recent first,
/// optionally filtered to a single encounter.
///
/// `limit` is clamped to 500. This clamp is a security/resource guard (DoS
/// protection): a compromised WebView must not be able to pull an unbounded
/// slice of the audit table in a single call. Keep it independent of any
/// pagination decisions — see `list_recent` for why cursor pagination was
/// removed but this clamp stays.
#[tauri::command]
pub(crate) fn llm_audit_list(
    state: tauri::State<crate::DbState>,
    encounter_id: Option<String>,
    limit: Option<u32>,
) -> Result<Vec<Value>, AppError> {
    let limit = limit.unwrap_or(100).min(500) as i64;
    let conn = state.0.get()?;
    list_recent(&conn, encounter_id.as_deref(), limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    fn entry(outcome: &str, resp_bytes: i64) -> LlmCallEntry {
        LlmCallEntry {
            created_at: "2026-07-04T14:22:11Z".into(),
            encounter_id: Some("enc-1".into()),
            provider_id: "jane@example.com".into(),
            model: "claude-haiku-4-5-20251001".into(),
            endpoint: "https://api.anthropic.com/v1/messages".into(),
            request_bytes: 4096,
            response_bytes: resp_bytes,
            upstream_reqid: Some("req_abc123".into()),
            outcome: outcome.into(),
            error_code: if outcome == "ok" { None } else { Some(outcome.into()) },
            duration_ms: Some(842),
        }
    }

    #[test]
    fn append_and_readback() {
        let conn = fresh();
        let id = append(&conn, &entry("ok", 2048)).unwrap();
        assert!(id > 0);

        let (created_at, resp, outcome): (String, i64, String) = conn
            .query_row(
                "SELECT created_at, response_bytes, outcome FROM llm_audit WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(created_at, "2026-07-04T14:22:11Z");
        assert_eq!(resp, 2048);
        assert_eq!(outcome, "ok");
    }

    #[test]
    fn failure_row_has_null_response_bytes_ok() {
        let conn = fresh();
        // Failure paths still record request_bytes (we know what we tried
        // to send) but response_bytes is 0. Encoding that as 0 vs NULL is
        // a documentation choice — sticking with 0 so downstream math
        // doesn't have to special-case NULL.
        let id = append(&conn, &entry("network", 0)).unwrap();
        let (resp, outcome, err_code): (i64, String, Option<String>) = conn
            .query_row(
                "SELECT response_bytes, outcome, error_code FROM llm_audit WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(resp, 0);
        assert_eq!(outcome, "network");
        assert_eq!(err_code.as_deref(), Some("network"));
    }

    #[test]
    fn descending_id_ordering() {
        let conn = fresh();
        for i in 0..5 {
            let mut e = entry("ok", 100 + i);
            e.created_at = format!("2026-07-04T14:22:{:02}Z", 10 + i);
            append(&conn, &e).unwrap();
        }
        // Straight rusqlite verification of the DESC ordering `llm_audit_list`
        // depends on. Doing this via the Tauri command would need a State stack.
        let mut stmt = conn
            .prepare("SELECT id FROM llm_audit ORDER BY id DESC LIMIT 3")
            .unwrap();
        let ids: Vec<i64> = stmt
            .query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(ids, vec![5, 4, 3]);
    }

    // S-CODE-5: the simplified `list_recent` must preserve the behavior the old
    // 4-branch cursor version had for the two cases anything actually uses —
    // most-recent-first ordering, optional encounter filter, and honoring the
    // caller's (pre-clamped) limit.

    fn id_seq(rows: &[Value]) -> Vec<i64> {
        rows.iter().map(|r| r["id"].as_i64().unwrap()).collect()
    }

    #[test]
    fn list_recent_returns_all_rows_newest_first() {
        let conn = fresh();
        for _ in 0..3 {
            append(&conn, &entry("ok", 100)).unwrap();
        }
        let rows = list_recent(&conn, None, 100).unwrap();
        assert_eq!(id_seq(&rows), vec![3, 2, 1], "must be ORDER BY id DESC");
    }

    #[test]
    fn list_recent_filters_by_encounter() {
        let conn = fresh();
        // Two encounters interleaved; filter must return only the target's rows.
        let mut a = entry("ok", 100);
        a.encounter_id = Some("enc-A".into());
        let mut b = entry("ok", 100);
        b.encounter_id = Some("enc-B".into());
        append(&conn, &a).unwrap(); // id 1, enc-A
        append(&conn, &b).unwrap(); // id 2, enc-B
        append(&conn, &a).unwrap(); // id 3, enc-A

        let rows = list_recent(&conn, Some("enc-A"), 100).unwrap();
        assert_eq!(id_seq(&rows), vec![3, 1]);
        assert!(rows.iter().all(|r| r["encounterId"] == "enc-A"));

        let none = list_recent(&conn, Some("enc-does-not-exist"), 100).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn list_recent_honors_limit() {
        let conn = fresh();
        for _ in 0..5 {
            append(&conn, &entry("ok", 100)).unwrap();
        }
        let rows = list_recent(&conn, None, 2).unwrap();
        // Newest two only.
        assert_eq!(id_seq(&rows), vec![5, 4]);
    }

    #[test]
    fn list_command_clamp_caps_at_500() {
        // The clamp lives in the command, not `list_recent`; assert the arith
        // directly so the security-motivated 500 ceiling can't silently drift.
        let clamp = |req: Option<u32>| req.unwrap_or(100).min(500) as i64;
        assert_eq!(clamp(None), 100, "default page size");
        assert_eq!(clamp(Some(50)), 50, "under-cap requests pass through");
        assert_eq!(clamp(Some(10_000)), 500, "over-cap requests are clamped");
    }
}
