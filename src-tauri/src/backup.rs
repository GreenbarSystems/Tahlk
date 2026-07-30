//! Encrypted database backup (NIST CSF `RC.RP-1`, `PR.IP-4`; HIPAA
//! §164.308(a)(7)(ii)(A), a *required* implementation specification).
//!
//! Before this, the Recover function was effectively absent. The risk
//! assessment delegated backup to the provider — defensible for a local-first
//! app — but the app gave them no way to actually do it: the only export paths
//! produce unencrypted note files, one encounter at a time, and there was no
//! documented restore procedure. A provider following the documentation
//! correctly still ended up one disk failure away from losing every patient
//! record irrecoverably.
//!
//! ## Why `VACUUM INTO` rather than copying the file
//!
//! Copying `tahlk.db` off disk while the app is running can capture a torn
//! database: SQLite may have pages in the WAL that the main file does not yet
//! reflect, so the copy is a mixture of two states. `VACUUM INTO` asks SQLite
//! itself to write a consistent snapshot, which is the documented way to back
//! up a live database.
//!
//! On SQLCipher the destination inherits the source's cipher settings and key,
//! so **the backup is encrypted with the same DEK as the live database** — no
//! new key material, no new crypto to get wrong, and the backup is exactly as
//! protected at rest as the original. `backup_is_encrypted_and_restorable`
//! pins that rather than trusting the claim: it writes a backup, proves the
//! right key opens it, and proves a wrong key does not.
//!
//! ## The part providers get wrong, so the UI must say it
//!
//! **A backup is worthless without the password.** It is encrypted under the
//! same DEK, which is wrapped by the provider's password and recovery codes.
//! Someone who loses their password AND all three recovery codes cannot
//! restore from this backup either — the file is intact and permanently
//! unreadable. That is counterintuitive (people expect a backup to be an
//! escape hatch from exactly that situation) and it is the failure mode they
//! will actually hit, so it is stated in the disclosure copy, not just here.
//!
//! ## Known limitation: session audio is not included
//!
//! This backs up the database — clinical notes, transcripts, the patient
//! roster, and the full audit and destruction trails. Session audio lives as
//! separate `.wav.enc` files and is NOT included, because bundling them needs
//! either an archive format (no such dependency here) or folder-picking (the
//! app holds `dialog:allow-save` only). The disclosure says so plainly rather
//! than letting a provider infer that "backup" means everything.

use rusqlite::params;
use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;

use crate::errors::AppError;
use crate::DbState;

/// Suggested filename stem. The extension is deliberately not `.db`: a
/// provider double-clicking a `.db` may launch some SQLite browser that fails
/// confusingly against an encrypted file, and the distinct extension makes the
/// artifact identifiable in a backup folder months later.
const BACKUP_EXT: &str = "tahlkbackup";

/// Write a consistent, encrypted snapshot of the database to a
/// provider-chosen path.
///
/// Returns `true` when a file was written and `false` when the Save dialog was
/// dismissed — the same contract as `export::export_note_to_file`, and for the
/// same reason: a cancelled backup must not be reported to the provider as a
/// completed one, or they will believe they have a recovery point they do not
/// have.
#[tauri::command]
pub(crate) async fn export_encrypted_backup(
    app: AppHandle,
    state: tauri::State<'_, DbState>,
    suggested_name: String,
) -> Result<bool, AppError> {
    // Resolve the pool BEFORE the dialog: a locked session must fail fast with
    // the standard precondition rather than after the provider has spent time
    // choosing a location.
    let pool = state.pool()?;

    let name = if suggested_name.trim().is_empty() {
        format!("tahlk-backup.{BACKUP_EXT}")
    } else {
        suggested_name
    };

    let path = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_file_name(&name)
            .add_filter("Tahlk backup", &[BACKUP_EXT])
            .blocking_save_file()
    })
    .await
    .map_err(AppError::storage_from)?;

    let Some(p) = path else {
        return Ok(false); // dismissed — nothing written
    };
    let dest = p.to_string();

    // VACUUM INTO refuses to overwrite. The native Save dialog already
    // collected the user's overwrite confirmation, so honour that decision by
    // clearing the target first. A failure here is reported rather than
    // ignored: silently writing nothing would be the worst outcome for a
    // command whose whole purpose is producing a recovery point.
    if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
        tokio::fs::remove_file(&dest)
            .await
            .map_err(AppError::storage_from)?;
    }

    let dest_for_task = dest.clone();
    let written = tauri::async_runtime::spawn_blocking(move || -> Result<(), AppError> {
        let conn = pool.get()?;
        // Parameterised: the path comes from a dialog, but building SQL by
        // concatenation is never the right habit, and a path containing a
        // quote would otherwise break the statement.
        conn.execute("VACUUM INTO ?1", params![dest_for_task])?;
        Ok(())
    })
    .await
    .map_err(AppError::storage_from)?;
    written?;

    // Owner-only, matching every other PHI artifact this app writes. The file
    // is encrypted, so this is defence in depth rather than the primary
    // control. No-op on Windows (see perms.rs).
    crate::perms::chmod_0600_unix(std::path::Path::new(&dest));

    // A full-database export is the largest single PHI egress the app
    // performs. Record it in the same hash-chained trail as every other bulk
    // access — best-effort, because the backup already exists on disk and
    // failing to log it must not make the provider believe it does not.
    if let Ok(mut conn) = pool_conn(&state) {
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM encounters", [], |r| r.get(0))
            .unwrap_or(0);
        if let Err(e) = crate::note_audit::records_listed_conn(&mut conn, "backup", count) {
            log::error!(
                "encrypted backup written but the export could not be audited: {}",
                crate::log_safety::cap_len(&e.to_string())
            );
        }
    }

    Ok(true)
}

/// Small helper so the audit step above reads cleanly; the pool was already
/// moved into the blocking task, so this checks out a fresh connection.
fn pool_conn(state: &tauri::State<'_, DbState>) -> Result<crate::db::PooledConn, AppError> {
    state.conn()
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    /// Open an encrypted database at `path` with `key` and return whether the
    /// contents are actually readable. SQLCipher only reports a wrong key when
    /// a read is attempted, so this must query, not merely open.
    fn readable_with(path: &str, key: &str) -> bool {
        let Ok(conn) = Connection::open(path) else {
            return false;
        };
        if conn
            .pragma_update(None, "key", format!("x'{key}'"))
            .is_err()
        {
            return false;
        }
        conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get::<_, i64>(0))
            .is_ok()
    }

    /// The claim this whole module rests on: `VACUUM INTO` from a SQLCipher
    /// database produces a copy that is (a) restorable with the same key and
    /// (b) still encrypted, i.e. useless without it.
    ///
    /// Worth pinning rather than trusting, because the failure mode is silent
    /// and catastrophic in both directions — an unencrypted backup would be
    /// plaintext PHI sitting in whatever folder the provider chose, and an
    /// unreadable one would be a recovery point that does not recover.
    #[test]
    fn backup_is_encrypted_and_restorable() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.db");
        let dest = dir.path().join("backup.tahlkbackup");
        let key = "a".repeat(64);
        let wrong = "b".repeat(64);

        {
            let conn = Connection::open(&src).unwrap();
            conn.pragma_update(None, "key", format!("x'{key}'")).unwrap();
            conn.execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('phi');")
                .unwrap();
            conn.execute("VACUUM INTO ?1", rusqlite::params![dest.to_str().unwrap()])
                .unwrap();
        }

        assert!(dest.exists(), "VACUUM INTO must produce the backup file");

        assert!(
            readable_with(dest.to_str().unwrap(), &key),
            "the backup must be restorable with the provider's own key — otherwise it is not a recovery point"
        );
        assert!(
            !readable_with(dest.to_str().unwrap(), &wrong),
            "the backup must stay encrypted — a wrong key must not read it"
        );

        // Belt and braces: the plaintext must not be sitting in the file.
        let raw = std::fs::read(&dest).unwrap();
        assert!(
            !raw.windows(3).any(|w| w == b"phi"),
            "PHI must not appear in the backup as plaintext"
        );
    }
}
