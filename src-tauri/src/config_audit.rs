//! Append-only audit log for provider-configurable settings changes (H3).
//!
//! Covers retention window and litigation-hold changes. Each row records the
//! old value, new value, server-derived actor, and a server-derived timestamp
//! so the trail cannot be forged from JS. Schema mirrors `destruction_log`:
//! one idempotent `init_schema` call during `open_database`, then `append`
//! called at the point of each write.

use rusqlite::{params, Connection};

use crate::errors::AppError;

/// Create the `config_audit` table when it does not exist. Idempotent.
pub(crate) fn init_schema(conn: &Connection) -> Result<(), AppError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS config_audit (
            id          INTEGER PRIMARY KEY,
            action      TEXT NOT NULL,
            old_value   TEXT,
            new_value   TEXT NOT NULL,
            actor       TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS config_audit_action_idx
            ON config_audit (action, recorded_at DESC);",
    )?;
    Ok(())
}

/// Append one config-change row. `action` is a machine-readable code (e.g.
/// `retention_years_changed`), `old_value` is `None` on first-ever write,
/// `actor` is the provider name from KV (derived server-side in the caller).
pub(crate) fn append(
    conn: &Connection,
    action: &str,
    old_value: Option<&str>,
    new_value: &str,
    actor: &str,
) -> Result<(), AppError> {
    let now = crate::time::utc_now_iso();
    conn.execute(
        "INSERT INTO config_audit (action, old_value, new_value, actor, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![action, old_value, new_value, actor, now],
    )?;
    Ok(())
}
