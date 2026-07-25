//! Encrypted backup export (open-item OPS-3; §164.308(a)(7) contingency).
//!
//! Tahlk Solo keeps the entire patient record in one SQLCipher database on one
//! device. If the device or the key is lost, there is no in-app recovery — so a
//! provider-maintained backup is the contingency plan, and this module lets the
//! provider produce a portable **encrypted** copy of that database.
//!
//! Design:
//!   - The backup is a **single, self-contained SQLCipher database**, produced
//!     with `sqlcipher_export` into a destination `ATTACH`ed under a **backup
//!     passphrase the provider chooses** (SQLCipher's default PBKDF2 KDF). It is
//!     therefore recoverable with just that passphrase — independent of the
//!     device's DEK, its keychain, or the `auth_dek_wraps` file. This is the
//!     same primitive `db.rs` already uses for its plaintext→encrypted
//!     migration, only keyed by a passphrase instead of the raw DEK.
//!   - The passphrase is **separate from the login password** and never leaves
//!     the device except as the KDF input to the backup file's own encryption.
//!     It is never logged, and errors from the attach/export never echo the SQL
//!     (which would carry it).
//!   - Export only. Restoring a backup into an install is a larger, separate
//!     flow (it must re-wrap the DEK under the new install's password) and is
//!     tracked as a follow-up; the exported file is a standard SQLCipher DB, so
//!     it is recoverable with the passphrase in the meantime.

use std::path::Path;

use rusqlite::Connection;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::errors::AppError;
use crate::DbState;

/// Minimum backup-passphrase length. Matches the master-password floor
/// (`auth.rs`): this passphrase is the *only* thing protecting a full copy of
/// every patient record, so it must not be weaker than the login credential.
const PASSPHRASE_MIN_LEN: usize = 12;
const PASSPHRASE_MAX_LEN: usize = 256;

/// Validate the backup passphrase. Length only — unlike the login password we
/// don't run the common-password list here, but the ≥12 floor is the same, and
/// the UI requires a confirm field so a typo can't silently key an
/// unrecoverable backup.
pub(crate) fn validate_backup_passphrase(passphrase: &str) -> Result<(), AppError> {
    let len = passphrase.chars().count();
    if len < PASSPHRASE_MIN_LEN {
        return Err(AppError::invalid(format!(
            "backup passphrase must be at least {PASSPHRASE_MIN_LEN} characters"
        )));
    }
    if len > PASSPHRASE_MAX_LEN {
        return Err(AppError::invalid(format!(
            "backup passphrase exceeds {PASSPHRASE_MAX_LEN} characters"
        )));
    }
    Ok(())
}

/// SQL-escape a single-quoted string literal by doubling embedded single
/// quotes — the only metacharacter inside a SQLite `'...'` literal. Mirrors the
/// escaping `db.rs::migrate_plaintext_to_encrypted` applies to the ATTACH path.
fn sql_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// Export the `main` database on `conn` into a fresh SQLCipher file at `dest`,
/// keyed under `passphrase`. `conn` is an already-keyed connection to the live
/// DB (from the pool). Non-destructive to the source.
///
/// Errors are deliberately generic — they must never echo the ATTACH/KEY SQL,
/// which carries the passphrase.
pub(crate) fn export_db_to(conn: &Connection, dest: &str, passphrase: &str) -> Result<(), AppError> {
    // Start from a clean destination. The OS Save-As dialog already confirmed
    // any overwrite with the provider; removing a pre-existing file guarantees
    // ATTACH creates a fresh SQLCipher DB rather than trying to open whatever
    // was there under this passphrase.
    if Path::new(dest).exists() {
        std::fs::remove_file(dest).map_err(AppError::storage_from)?;
    }

    let attach = format!(
        "ATTACH DATABASE '{}' AS backup KEY '{}';",
        sql_quote(dest),
        sql_quote(passphrase)
    );
    // Generic error: do NOT surface the rusqlite message here — it can include
    // the offending SQL, which contains the passphrase.
    conn.execute_batch(&attach)
        .map_err(|_| AppError::Storage("could not open the backup destination".into()))?;

    let exported = conn.query_row("SELECT sqlcipher_export('backup')", [], |_| Ok(()));
    // Detach on every path so the connection isn't left with a dangling attach
    // (it is a pooled connection reused for later work).
    let _ = conn.execute_batch("DETACH DATABASE backup;");
    exported.map_err(|_| AppError::Storage("backup export failed".into()))?;
    Ok(())
}

/// #[tauri::command] — export an encrypted backup of the record database.
///
/// Shows the native Save-As dialog, then writes a single passphrase-encrypted
/// SQLCipher file to the chosen location. Returns `true` when a file was
/// written, `false` when the provider dismissed the dialog (a choice, not an
/// error — same contract as `export::export_note_to_file`).
#[tauri::command]
pub(crate) async fn export_encrypted_backup(
    app: AppHandle,
    state: State<'_, DbState>,
    passphrase: String,
    suggested_name: String,
) -> Result<bool, AppError> {
    validate_backup_passphrase(&passphrase)?;

    // The canonical DB paths — refuse to write the backup over the live files.
    let data_dir = app.path().app_data_dir().map_err(AppError::storage_from)?;
    let live_db = data_dir.join("tahlk.db");
    let live_wraps = data_dir.join("tahlk_auth.db");

    // Dialog on the blocking pool (it can park indefinitely waiting for the
    // user) — see export::export_note_to_file for the rationale.
    let app_for_dialog = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app_for_dialog
            .dialog()
            .file()
            .set_file_name(&suggested_name)
            .add_filter("Tahlk encrypted backup", &["tahlkbackup"])
            .blocking_save_file()
    })
    .await
    .map_err(AppError::storage_from)?;

    let Some(dest_path) = picked else {
        return Ok(false); // provider cancelled — nothing written
    };
    let dest = dest_path.to_string();

    let dest_pb = std::path::PathBuf::from(&dest);
    if dest_pb == live_db || dest_pb == live_wraps {
        return Err(AppError::invalid(
            "choose a location outside the app's data folder for the backup",
        ));
    }

    // Check out a pooled connection and run the export synchronously — no
    // `.await` is held across the connection, so the command future stays Send.
    let conn = state.conn()?;
    export_db_to(&conn, &dest, &passphrase)?;

    // Metadata-only log (the file is encrypted; no PHI here). Provides a trace
    // that a full-record backup was produced, for §164.308(a)(7) evidence.
    let bytes = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    log::info!("encrypted backup exported ({bytes} bytes)");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_length_bounds() {
        assert!(validate_backup_passphrase(&"a".repeat(PASSPHRASE_MIN_LEN - 1)).is_err());
        assert!(validate_backup_passphrase(&"a".repeat(PASSPHRASE_MIN_LEN)).is_ok());
        assert!(validate_backup_passphrase(&"a".repeat(PASSPHRASE_MAX_LEN)).is_ok());
        assert!(validate_backup_passphrase(&"a".repeat(PASSPHRASE_MAX_LEN + 1)).is_err());
    }

    #[test]
    fn sql_quote_doubles_single_quotes() {
        assert_eq!(sql_quote("plain"), "plain");
        assert_eq!(sql_quote("O'Brien"), "O''Brien");
        assert_eq!(sql_quote("a'b'c"), "a''b''c");
    }

    // Round-trips a real SQLCipher DB → passphrase-keyed backup → reopen. This
    // exercises the actual SQLCipher primitives (like db.rs's own primitive
    // tests). Compiles under `cargo check`; runs under `cargo test` on a real
    // toolchain. Uses tempfile (a dev-dependency).
    #[test]
    fn export_round_trips_and_backup_needs_the_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let src_path = dir.path().join("src.db");
        let backup_path = dir.path().join("out.tahlkbackup");

        // Build a source DB keyed with a raw hex DEK, exactly like the live DB.
        let dek_hex = crate::hex::to_hex(&[0x11u8; 32]);
        let src = Connection::open(&src_path).unwrap();
        src.execute_batch(&format!("PRAGMA key = \"x'{dek_hex}'\";")).unwrap();
        src.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL);
             INSERT INTO t (v) VALUES ('secret-row');",
        )
        .unwrap();

        // Export it to a passphrase-keyed backup.
        let passphrase = "correct horse battery";
        export_db_to(&src, backup_path.to_str().unwrap(), passphrase).unwrap();
        drop(src);
        assert!(backup_path.exists(), "backup file must be written");

        // Reopen the backup with the passphrase — the row must be present.
        let good = Connection::open(&backup_path).unwrap();
        good.execute_batch(&format!("PRAGMA key = '{passphrase}';")).unwrap();
        let v: String = good
            .query_row("SELECT v FROM t WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, "secret-row");
        drop(good);

        // Reopen with the WRONG passphrase — must NOT read the data.
        let bad = Connection::open(&backup_path).unwrap();
        bad.execute_batch("PRAGMA key = 'the-wrong-passphrase';").unwrap();
        assert!(
            bad.query_row("SELECT v FROM t WHERE id = 1", [], |r| r.get::<_, String>(0)).is_err(),
            "the backup must be unreadable without the correct passphrase"
        );
    }
}
