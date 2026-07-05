//! Shared helpers for direct writes against the `kv` table.
//!
//! Both the generic `kv_set`/`kv_remove` path (kv.rs) and typed writers that
//! own their own KV key (baa.rs' BAA ack, secrets.rs' legacy plaintext-key
//! sweep) issue byte-identical SQL against the `kv` table. Keeping that SQL
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
//!   best-effort cleanup (e.g. `clear_api_key`) don't need to branch.
//!
//! Neither helper does key-namespace guarding — that lives at the JS-facing
//! boundary in `kv.rs::guard_key` / `secrets::guard_key`. Typed writers in
//! baa.rs and secrets.rs are trusted callers writing hard-coded keys, so
//! they intentionally bypass the guard.

use rusqlite::{params, Connection};

use crate::errors::AppError;

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
/// idempotent contract every caller (kv_remove, baa_ack_clear, api-key
/// legacy sweep) already relied on before this helper existed.
pub(crate) fn delete_by_key(conn: &Connection, key: &str) -> Result<usize, AppError> {
    let n = conn.execute("DELETE FROM kv WHERE key = ?1", params![key])?;
    Ok(n)
}
