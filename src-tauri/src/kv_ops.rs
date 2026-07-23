//! Shared helpers for direct writes against the `kv` table.
//!
//! Both the generic `kv_set`/`kv_remove` path (kv.rs) and typed writers that
//! own their own KV key (baa.rs' BAA ack, device.rs' device id + proxy token)
//! issue byte-identical SQL against the `kv` table. Keeping that SQL
//! spelled out in three places let one caller subtly diverge from another —
//! e.g. one writer forgetting to bump `updated_at`, or one caller passing
//! `strftime` in a different format. This module is the single source of
//! truth for that SQL.
//!
//! Contract:
//! - `upsert_json` writes `(key, value)` and stamps `updated_at` to the
//!   current unix second. Callers own JSON serialization so this module
//!   never needs to know the payload type.
//! - `delete_by_key` removes a single row by primary key. Idempotent —
//!   a missing row returns Ok(0), never an error, so callers doing
//!   best-effort cleanup don't need to branch.
//!
//! Neither helper does key-namespace guarding — that lives at the JS-facing
//! boundary in `kv.rs::guard_key` / `secrets::guard_key`. Typed writers in
//! baa.rs and device.rs are trusted callers writing hard-coded keys, so
//! they intentionally bypass the guard.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::errors::AppError;

/// The acting provider's identity, derived server-side from the stored profile.
///
/// This is the actor stamped on every audit and destruction record, so it must
/// never be supplied by the caller — a compromised WebView could otherwise
/// attribute a permanent record destruction to another clinician. Commands
/// take no `provider_id` parameter; they call this.
///
/// Consolidated from six byte-identical hand-rolled copies (note_audit,
/// note_history, patients ×2 under two different names, retention,
/// destruction_log). All six agreed on the `"provider"` fallback, so there was
/// no live drift — but every one hardcoded the key as a string literal while
/// the write guard in `secrets` referenced the constant. Changing the key
/// would have protected one string and read another, silently. This reads
/// through `NOTE_PROVIDER_PROFILE_KEY` so the guard and the reader cannot
/// disagree.
///
/// Falls back to `"provider"` when the profile row is missing or unparseable:
/// an audit entry attributed to a generic actor is worth more than a failed
/// write that loses the entry entirely.
pub(crate) fn provider_id(conn: &Connection) -> String {
    conn.query_row(
        "SELECT value FROM kv WHERE key = ?1",
        params![crate::secrets::NOTE_PROVIDER_PROFILE_KEY],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .ok()
    .flatten()
    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    .and_then(|v| v["name"].as_str().map(String::from))
    .unwrap_or_else(|| "provider".to_string())
}

/// Insert or update a single KV row. `updated_at` is stamped server-side to
/// the current unix second so callers can't accidentally desync their local
/// clock into the row. The SQL is byte-identical to what `kv_set` and
/// `baa_ack_set` used before this helper existed.
pub(crate) fn upsert_json(conn: &Connection, key: &str, json: &str) -> Result<(), AppError> {
    conn.execute(
        "INSERT INTO kv (key, value, updated_at) \
         VALUES (?1, ?2, strftime('%s', 'now')) \
         ON CONFLICT(key) DO UPDATE SET \
             value      = excluded.value, \
             updated_at = excluded.updated_at",
        params![key, json],
    )?;
    Ok(())
}

/// Delete a single KV row by primary key. Returns the number of rows
/// removed (0 or 1). Never errors on "row not present" — that's the
/// idempotent contract every caller (kv_remove, baa_ack_clear) already
/// relied on before this helper existed.
pub(crate) fn delete_by_key(conn: &Connection, key: &str) -> Result<usize, AppError> {
    let n = conn.execute("DELETE FROM kv WHERE key = ?1", params![key])?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    //! `provider_id` is the actor stamped on every audit and destruction
    //! record, and six modules now depend on it, so its edge cases are pinned
    //! here rather than reasoned about at each call site.

    use super::*;

    fn kv_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kv (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at INTEGER NOT NULL
             );",
        )
        .unwrap();
        conn
    }

    fn put_profile(conn: &Connection, json: &str) {
        upsert_json(conn, crate::secrets::NOTE_PROVIDER_PROFILE_KEY, json).unwrap();
    }

    #[test]
    fn reads_the_provider_name_from_the_stored_profile() {
        let conn = kv_db();
        put_profile(&conn, r#"{"name":"Dr. Jane Smith","specialty":"psych"}"#);
        assert_eq!(provider_id(&conn), "Dr. Jane Smith");
    }

    #[test]
    fn falls_back_to_a_generic_actor_rather_than_failing() {
        // An audit entry attributed to "provider" is worth more than a failed
        // write that loses the entry entirely.
        let conn = kv_db();
        assert_eq!(provider_id(&conn), "provider", "missing row");

        put_profile(&conn, "not json at all");
        assert_eq!(provider_id(&conn), "provider", "unparseable profile");

        put_profile(&conn, r#"{"specialty":"psych"}"#);
        assert_eq!(provider_id(&conn), "provider", "profile with no name field");

        put_profile(&conn, r#"{"name":42}"#);
        assert_eq!(provider_id(&conn), "provider", "name of the wrong type");
    }

    #[test]
    fn reads_through_the_same_key_the_write_guard_protects() {
        // The six copies this replaced each hardcoded the key as a literal
        // while `secrets` referenced the constant. Changing the constant would
        // have protected one string and read another, silently. Seeding via
        // the constant and reading it back pins the two together.
        let conn = kv_db();
        conn.execute(
            "INSERT INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
            params![
                crate::secrets::NOTE_PROVIDER_PROFILE_KEY,
                r#"{"name":"Dr. Keyed"}"#
            ],
        )
        .unwrap();
        assert_eq!(provider_id(&conn), "Dr. Keyed");
        assert!(
            crate::secrets::guard_write_key(crate::secrets::NOTE_PROVIDER_PROFILE_KEY).is_err(),
            "the key this reads must be write-protected, or the actor is forgeable"
        );
    }
}
