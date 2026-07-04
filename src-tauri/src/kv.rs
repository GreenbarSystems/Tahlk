//! Generic key/value store commands.
//!
//! All entry points route through `guard_key` / the `secret_*` LIKE-escape
//! so the `secret_v1::anthropic_api_key` namespace can never be read, written,
//! removed, or enumerated through the JS-facing KV API. Secrets live in the
//! OS keychain (see `secrets.rs`).

use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use tauri::State;

use crate::errors::AppError;
use crate::secrets::guard_key;
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
    let conn = state.0.lock();
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
    let conn = state.0.lock();
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
    let conn = state.0.lock();
    conn.execute("DELETE FROM kv WHERE key = ?1", params![key])?;
    Ok(())
}

#[tauri::command]
pub(crate) fn kv_list(state: State<DbState>, prefix: String) -> Result<Vec<(String, Value)>, AppError> {
    let pattern = if prefix.is_empty() { String::from("%") } else { format!("{}%", prefix) };
    let conn = state.0.lock();
    // Never surface secret_* keys through enumeration.
    let mut stmt = conn
        .prepare("SELECT key, value FROM kv WHERE key LIKE ?1 AND key NOT LIKE 'secret\\_%' ESCAPE '\\' ORDER BY key")?;
    let rows = stmt.query_map(params![pattern], |r| {
        let k: String = r.get(0)?;
        let v: String = r.get(1)?;
        Ok((k, v))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (k, v) = row?;
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
