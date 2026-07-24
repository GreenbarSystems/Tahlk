//! Append-only audit log for provider-configurable policy settings.
//!
//! Covers the two settings that gate PHI destruction: the record-retention
//! window and the litigation hold. 45 CFR §164.312(b) requires audit controls
//! over activity affecting ePHI, and changing either of these changes what the
//! app is willing to destroy — so each change records the old value, the new
//! value, a server-derived actor, and a server-derived timestamp.
//!
//! Modelled on `patient_audit.rs`: a flat, metadata-only, append-only table
//! with an AUTOINCREMENT key and a narrow read command. The original version
//! of this module claimed to mirror `destruction_log` but matched none of its
//! four siblings — see `migrate_legacy_schema` for what that cost.
//!
//! [`append`] takes `&Connection` so callers pass a `&Transaction` and the
//! audit row lands in the SAME transaction as the setting it records. A
//! config change that commits without its audit row is worse than a failed
//! change: the provider sees an error, believes nothing happened, and the
//! trail agrees with them while the setting has actually moved.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use tauri::State;

use crate::errors::AppError;
use crate::time::utc_now_iso;
use crate::DbState;

/// Valid `action` values. Same discipline as `patient_audit::VALID_ACTIONS` —
/// a compliance record must not accept an arbitrary string.
pub(crate) const VALID_ACTIONS: &[&str] =
    &["retention_years_changed", "litigation_hold_changed"];

pub(crate) fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    migrate_legacy_schema(conn)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS config_audit (
             id          INTEGER PRIMARY KEY AUTOINCREMENT,
             created_at  TEXT NOT NULL,
             action      TEXT NOT NULL,
             old_value   TEXT,
             new_value   TEXT NOT NULL,
             provider_id TEXT NOT NULL DEFAULT ''
         );
         CREATE INDEX IF NOT EXISTS config_audit_action_idx
             ON config_audit (action, created_at DESC);
         CREATE INDEX IF NOT EXISTS config_audit_created_idx
             ON config_audit (created_at DESC);",
    )
}

/// Rebuild the table shipped in a191edc, which diverged from all four sibling
/// audit logs in ways that mattered:
///
///   * `INTEGER PRIMARY KEY` with no AUTOINCREMENT. SQLite may then REUSE the
///     rowid of a deleted row — an ordering key that can repeat is wrong for
///     an append-only compliance table, and the four siblings all specify
///     AUTOINCREMENT precisely to prevent it.
///   * `recorded_at` / `actor` where every sibling uses `created_at` /
///     `provider_id`, so a reader joining across audit tables had to know
///     which spelling each one used.
///
/// AUTOINCREMENT cannot be added by `ALTER TABLE`, so the table is rebuilt and
/// its rows copied. Runs inside a transaction; a crash part-way leaves the
/// legacy table intact and the next launch retries, because the detection
/// below keys off the legacy column name.
fn migrate_legacy_schema(conn: &Connection) -> rusqlite::Result<()> {
    let is_legacy: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('config_audit') WHERE name = 'recorded_at'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0)
        > 0;
    if !is_legacy {
        return Ok(());
    }

    conn.execute_batch(
        "BEGIN;
         CREATE TABLE config_audit_rebuilt (
             id          INTEGER PRIMARY KEY AUTOINCREMENT,
             created_at  TEXT NOT NULL,
             action      TEXT NOT NULL,
             old_value   TEXT,
             new_value   TEXT NOT NULL,
             provider_id TEXT NOT NULL DEFAULT ''
         );
         INSERT INTO config_audit_rebuilt (created_at, action, old_value, new_value, provider_id)
             SELECT recorded_at, action, old_value, new_value, actor
             FROM config_audit ORDER BY id;
         DROP TABLE config_audit;
         ALTER TABLE config_audit_rebuilt RENAME TO config_audit;
         COMMIT;",
    )
}

/// Append one config-change row.
///
/// Takes `&Connection` so callers can pass a `&Transaction` and make this
/// write atomic with the setting change it records — see the module doc for
/// why that matters here specifically.
pub(crate) fn append(
    conn: &Connection,
    action: &str,
    old_value: Option<&str>,
    new_value: &str,
    provider_id: &str,
) -> Result<(), AppError> {
    // Real guard, not a debug_assert: a release build must not write an
    // unrecognized action to a compliance table (the debug-only assert let one
    // through in production). Fail closed — the caller's transaction rolls back.
    if !VALID_ACTIONS.contains(&action) {
        return Err(AppError::invalid(format!(
            "config_audit::append called with an unvalidated action: {action}"
        )));
    }
    conn.execute(
        "INSERT INTO config_audit (created_at, action, old_value, new_value, provider_id) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![utc_now_iso(), action, old_value, new_value, provider_id],
    )?;
    Ok(())
}

/// Read the config-change trail, newest first.
///
/// Without this the table was write-only: rows accumulated that no code path
/// could read, so the control it was added for provided no evidence to anyone.
/// Read-only — no delete or clear command is registered, matching every other
/// audit table.
#[tauri::command]
pub(crate) fn config_audit_list(
    state: State<DbState>,
    limit: Option<i64>,
) -> Result<Vec<Value>, AppError> {
    let conn = state.conn()?;
    let n = crate::db::clamp_list_limit(limit, 100);
    let mut stmt = conn.prepare(
        "SELECT created_at, action, old_value, new_value, provider_id \
         FROM config_audit ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt
        .query_map(params![n], |r| {
            Ok(json!({
                "createdAt":  r.get::<_, String>(0)?,
                "action":     r.get::<_, String>(1)?,
                "oldValue":   r.get::<_, Option<String>>(2)?,
                "newValue":   r.get::<_, String>(3)?,
                "providerId": r.get::<_, String>(4)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    fn rows(conn: &Connection) -> Vec<(String, Option<String>, String, String)> {
        let mut stmt = conn
            .prepare("SELECT action, old_value, new_value, provider_id FROM config_audit ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    #[test]
    fn append_records_the_transition_and_the_actor() {
        let conn = fresh_db();
        append(&conn, "retention_years_changed", Some("7"), "10", "Dr. Chen").unwrap();
        assert_eq!(
            rows(&conn),
            vec![(
                "retention_years_changed".into(),
                Some("7".into()),
                "10".into(),
                "Dr. Chen".into()
            )]
        );
    }

    #[test]
    fn an_unrecognized_action_is_rejected_in_every_build() {
        // Real guard, not debug_assert: a release build must also refuse to write
        // an unvalidated action to this compliance table, and write nothing.
        let conn = fresh_db();
        let err = append(&conn, "sneaky_untracked_action", None, "x", "Dr. Chen").unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
        assert!(rows(&conn).is_empty(), "a rejected action must leave no row");
    }

    #[test]
    fn a_first_ever_change_has_no_old_value() {
        let conn = fresh_db();
        append(&conn, "litigation_hold_changed", None, "true", "Dr. Chen").unwrap();
        assert_eq!(rows(&conn)[0].1, None);
    }

    #[test]
    fn ids_do_not_repeat_after_a_delete() {
        // The AUTOINCREMENT property. Without it SQLite reuses the rowid of a
        // deleted row, so an ordering key in an append-only compliance table
        // could repeat. No delete command is exposed, but the table's
        // integrity should not rest on that alone.
        let conn = fresh_db();
        append(&conn, "litigation_hold_changed", None, "true", "a").unwrap();
        append(&conn, "litigation_hold_changed", Some("true"), "false", "b").unwrap();
        let max_before: i64 = conn
            .query_row("SELECT MAX(id) FROM config_audit", [], |r| r.get(0))
            .unwrap();

        conn.execute("DELETE FROM config_audit WHERE id = ?1", params![max_before])
            .unwrap();
        append(&conn, "litigation_hold_changed", Some("false"), "true", "c").unwrap();

        let max_after: i64 = conn
            .query_row("SELECT MAX(id) FROM config_audit", [], |r| r.get(0))
            .unwrap();
        assert!(
            max_after > max_before,
            "AUTOINCREMENT must not reissue {max_before}; got {max_after}"
        );
    }

    #[test]
    fn legacy_rows_survive_the_schema_rebuild() {
        // Simulates an install carrying the a191edc table.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE config_audit (
                 id          INTEGER PRIMARY KEY,
                 action      TEXT NOT NULL,
                 old_value   TEXT,
                 new_value   TEXT NOT NULL,
                 actor       TEXT NOT NULL,
                 recorded_at TEXT NOT NULL
             );
             INSERT INTO config_audit (action, old_value, new_value, actor, recorded_at)
             VALUES ('retention_years_changed', '7', '10', 'Dr. Legacy', '2026-07-21T00:00:00Z');",
        )
        .unwrap();

        init_schema(&conn).unwrap();

        assert_eq!(
            rows(&conn),
            vec![(
                "retention_years_changed".into(),
                Some("7".into()),
                "10".into(),
                "Dr. Legacy".into()
            )],
            "an existing compliance record must not be lost to a schema fix"
        );
        let created: String = conn
            .query_row("SELECT created_at FROM config_audit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(created, "2026-07-21T00:00:00Z", "recorded_at maps to created_at");
    }

    #[test]
    fn schema_migration_is_idempotent() {
        let conn = fresh_db();
        append(&conn, "litigation_hold_changed", None, "true", "a").unwrap();
        init_schema(&conn).unwrap();
        init_schema(&conn).unwrap();
        assert_eq!(rows(&conn).len(), 1, "re-running init must not duplicate or drop rows");
    }
}
