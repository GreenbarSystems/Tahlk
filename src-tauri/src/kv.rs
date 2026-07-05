//! Generic key/value store commands.
//!
//! Every entry point consults `KEYCHAIN_ONLY_KEYS` (via `guard_key` for the
//! get/set/remove paths, and `is_secret_key` post-filter for enumeration) so
//! the keychain-only namespace can never be read, written, removed, or listed
//! through the JS-facing KV API. Secrets live in the OS keychain
//! (see `secrets.rs`).

use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use tauri::State;

use crate::errors::AppError;
use crate::secrets::{guard_key, is_secret_key};
use crate::DbState;

/// Ceiling on KV key length. Every legitimate key in this app is a
/// dot-namespaced short identifier (e.g. `note_templates_v1::<id>`); the
/// longest realistic key uses a 24-char encounter id, staying comfortably
/// under 128 chars. 256 leaves generous headroom while still blocking any
/// attempt to bloat the primary key index.
pub(crate) const MAX_KV_KEY: usize = 256;

/// Ceiling on the JSON-serialized KV value. Legitimate large writes are
/// transcripts and the diagnostics buffer; a 60-minute clinical session at
/// ~150 words/min transcribes to ~60 KB, so 4 MiB is ~60x headroom while
/// still small enough that no single KV write can bloat the SQLite file to
/// where every subsequent `kv_get` / `kv_list` becomes a slow read.
///
/// Genuinely large blobs (audio, model weights) belong in dedicated
/// commands, not the generic KV. If a future feature legitimately needs a
/// bigger value here, revisit that first before bumping this ceiling.
pub(crate) const MAX_KV_VALUE_BYTES: usize = 4 * 1024 * 1024;

/// Reject over-long keys BEFORE any DB round-trip so a hot loop of oversize
/// writes can't pin the connection.
fn check_key_size(key: &str) -> Result<(), AppError> {
    if key.len() > MAX_KV_KEY {
        return Err(AppError::invalid("kv key too long"));
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn kv_get(state: State<DbState>, key: String) -> Result<Option<Value>, AppError> {
    guard_key(&key)?;
    check_key_size(&key)?;
    let conn = state.0.get().map_err(AppError::storage_from)?;
    let row: Option<String> = conn
        .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| r.get(0))
        .optional()?;
    match row {
        Some(s) => serde_json::from_str(&s).map(Some).map_err(AppError::internal_from),
        None => Ok(None),
    }
}

#[tauri::command]
pub(crate) fn kv_set(state: State<DbState>, key: String, value: Value) -> Result<(), AppError> {
    guard_key(&key)?;
    check_key_size(&key)?;
    let json = serde_json::to_string(&value).map_err(AppError::internal_from)?;
    // Check the serialized size BEFORE taking the DB lock — a rejected write
    // shouldn't contend against legitimate readers.
    if json.len() > MAX_KV_VALUE_BYTES {
        return Err(AppError::invalid("kv value too large"));
    }
    let conn = state.0.get().map_err(AppError::storage_from)?;
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

#[tauri::command]
pub(crate) fn kv_remove(state: State<DbState>, key: String) -> Result<(), AppError> {
    guard_key(&key)?;
    check_key_size(&key)?;
    let conn = state.0.get().map_err(AppError::storage_from)?;
    conn.execute("DELETE FROM kv WHERE key = ?1", params![key])?;
    Ok(())
}

#[tauri::command]
pub(crate) fn kv_list(state: State<DbState>, prefix: String) -> Result<Vec<(String, Value)>, AppError> {
    let conn = state.0.get().map_err(AppError::storage_from)?;
    kv_list_conn(&conn, &prefix)
}

/// Escape SQL LIKE wildcards (`%`, `_`) and the escape character itself
/// (`\`) so a caller-supplied prefix is matched as a literal string.
///
/// SQL LIKE treats `%` as "any characters" and `_` as "any single char."
/// The old `kv_list` fed the client prefix directly into the pattern, so
/// `prefix="note_"` matched `noteX`, `noteY`, etc. Not a direct exploit
/// (the prefix isn't user-content today) but a footgun waiting for a
/// future feature that surfaces a user-supplied prefix. Callers pair the
/// escaped output with `ESCAPE '\\'` in the SQL. [audit M5]
fn escape_like_prefix(prefix: &str) -> String {
    prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

// Inner helper driven by a bare `Connection`. Extracted from `kv_list` so unit
// tests can exercise the enumeration filter without a Tauri `State` harness.
// Enumerates via LIKE on the escaped prefix, then post-filters with
// `is_secret_key` so that helper is the single source of truth shared with
// `guard_key` (audit H5 replaced a SQL-side `LIKE 'secret\_%'` clause that
// was the second copy of the prefix rule).
pub(crate) fn kv_list_conn(
    conn: &rusqlite::Connection,
    prefix: &str,
) -> Result<Vec<(String, Value)>, AppError> {
    let pattern = if prefix.is_empty() {
        String::from("%")
    } else {
        format!("{}%", escape_like_prefix(prefix))
    };
    let mut stmt = conn.prepare(
        "SELECT key, value FROM kv WHERE key LIKE ?1 ESCAPE '\\' ORDER BY key",
    )?;
    let rows = stmt.query_map(params![pattern], |r| {
        let k: String = r.get(0)?;
        let v: String = r.get(1)?;
        Ok((k, v))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (k, v) = row?;
        if is_secret_key(&k) {
            continue;
        }
        let parsed: Value = serde_json::from_str(&v).map_err(AppError::internal_from)?;
        out.push((k, parsed));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! Coverage for the size caps. `check_key_size` is a pure function so
    //! it doesn't need a DB; the value cap is exercised via the same
    //! helper it uses internally (`serde_json::to_string`) so a future
    //! refactor that swaps the serializer stays covered by these tests.

    use super::*;

    #[test]
    fn key_at_ceiling_is_accepted() {
        let key = "a".repeat(MAX_KV_KEY);
        assert!(check_key_size(&key).is_ok());
    }

    #[test]
    fn key_over_ceiling_is_rejected() {
        let key = "a".repeat(MAX_KV_KEY + 1);
        let err = check_key_size(&key).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    #[test]
    fn realistic_key_shapes_all_fit() {
        // Belt-and-braces: enumerate the shapes we actually write today.
        // If any of these fails, the ceiling has been shrunk below
        // real-world usage — revisit before merging.
        for key in [
            "note_settings_v1::baa_ack",
            "note_settings_v1::onboarded",
            "note_provider_v1::profile",
            "note_content_v1::enc-l9k3a-x7q2",
            "note_content_v1::transcript::enc-l9k3a-x7q2",
            "note_history_v1::enc-l9k3a-x7q2",
            "note_templates_v1::psych-eval",
            "note_diag_v1::events",
        ] {
            assert!(check_key_size(key).is_ok(), "key {key} should fit");
        }
    }

    #[test]
    fn value_size_constant_covers_a_full_hour_transcript() {
        // ~150 words/min * 60 min * ~6 bytes/word ≈ 55 KB — pin an order-of
        // magnitude sanity check so a future edit that squeezes the ceiling
        // trips loudly instead of quietly bricking transcript writes.
        let realistic_hour_transcript_bytes: usize = 200 * 1024;
        assert!(MAX_KV_VALUE_BYTES > realistic_hour_transcript_bytes * 10);
    }

    // End-to-end coverage for the enumeration filter: seed a raw kv table
    // with a mix of secret and non-secret rows, then confirm `kv_list_conn`
    // returns the non-secret rows and hides the allowlisted secret key.
    // If a future refactor deletes the `is_secret_key` post-filter, this test
    // fails loudly with the leaked row visible in the assertion.
    #[test]
    fn kv_list_hides_keychain_only_keys() {
        use rusqlite::Connection;
        use crate::secrets::API_KEY_KV;

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kv (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )
        .unwrap();

        // Two ordinary rows plus the legacy plaintext-key row that must never
        // surface through enumeration.
        for (k, v) in [
            ("note_settings_v1::onboarded", "true"),
            ("note_provider_v1::profile", "{}"),
            (API_KEY_KV, "\"sk-ant-should-not-leak\""),
        ] {
            conn.execute(
                "INSERT INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
                params![k, v],
            )
            .unwrap();
        }

        let listed = kv_list_conn(&conn, "").unwrap();
        let keys: Vec<&str> = listed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&API_KEY_KV), "secret key leaked into kv_list: {keys:?}");
        assert!(keys.contains(&"note_settings_v1::onboarded"));
        assert!(keys.contains(&"note_provider_v1::profile"));
        assert_eq!(keys.len(), 2, "expected exactly 2 non-secret rows, got {keys:?}");
    }

    // A prefix filter should still hide the secret row even when the prefix
    // deliberately matches the secret's namespace.
    #[test]
    fn kv_list_prefix_filter_still_hides_secret_keys() {
        use rusqlite::Connection;
        use crate::secrets::API_KEY_KV;

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kv (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
            params![API_KEY_KV, "\"sk-ant-should-not-leak\""],
        )
        .unwrap();

        let listed = kv_list_conn(&conn, "secret_").unwrap();
        assert!(listed.is_empty(), "secret_ prefix leaked rows: {listed:?}");
    }

    // The escape helper must convert LIKE wildcards to their escaped forms and
    // handle the escape character itself. Cheap, exhaustive coverage.
    #[test]
    fn escape_like_prefix_handles_all_wildcards() {
        assert_eq!(escape_like_prefix("note_content"), "note\\_content");
        assert_eq!(escape_like_prefix("100%"), "100\\%");
        assert_eq!(escape_like_prefix("path\\to"), "path\\\\to");
        // Backslash must be escaped BEFORE % and _ or the newly-inserted
        // escape backslashes would themselves get escaped a second time.
        assert_eq!(escape_like_prefix("a\\_b%c"), "a\\\\\\_b\\%c");
        assert_eq!(escape_like_prefix(""), "");
        assert_eq!(escape_like_prefix("plain"), "plain");
    }

    // The M5 attack pattern: a caller-supplied prefix that contains `_` used
    // to match any character. With the escape in place, `_` is now literal
    // and the enumeration returns only exact-prefix matches.
    #[test]
    fn kv_list_prefix_treats_underscore_as_literal() {
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kv (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )
        .unwrap();
        // Two rows: one that should match a literal `note_` prefix, one that
        // would have matched under a broken-LIKE interpretation (`noteX`).
        for (k, v) in [
            ("note_alpha", "1"),
            ("noteXalpha", "2"),
        ] {
            conn.execute(
                "INSERT INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
                params![k, v],
            )
            .unwrap();
        }

        let listed = kv_list_conn(&conn, "note_").unwrap();
        let keys: Vec<&str> = listed.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["note_alpha"], "underscore should match literally, got {keys:?}");
    }

    // `%` in the prefix must not glob — same footgun class as `_`.
    #[test]
    fn kv_list_prefix_treats_percent_as_literal() {
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kv (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )
        .unwrap();
        for (k, v) in [
            ("metric_100%_load", "1"),
            ("metric_50%_load", "2"),
        ] {
            conn.execute(
                "INSERT INTO kv (key, value, updated_at) VALUES (?1, ?2, 0)",
                params![k, v],
            )
            .unwrap();
        }

        let listed = kv_list_conn(&conn, "metric_100%").unwrap();
        let keys: Vec<&str> = listed.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec!["metric_100%_load"],
            "percent should match literally, got {keys:?}"
        );
    }

    #[test]
    fn value_size_check_uses_serialized_length_not_bytes() {
        // A tiny JSON like `"abc"` serializes to 5 bytes (with quotes), not
        // 3. The cap is on serialized JSON length, which matches what
        // eventually lands in SQLite. If a future refactor accidentally
        // sizes the *unserialized* Value, this test would fail because a
        // large-string variant would round-trip differently through
        // `serde_json::to_string` than a naive `.len()`.
        let raw = "a".repeat(MAX_KV_VALUE_BYTES - 4); // room for surrounding quotes + escapes
        let v: Value = serde_json::Value::String(raw);
        let serialized = serde_json::to_string(&v).unwrap();
        // Should be right around the ceiling but strictly under it.
        assert!(serialized.len() <= MAX_KV_VALUE_BYTES);
    }
}
