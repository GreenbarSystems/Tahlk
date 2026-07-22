//! Session audio storage.
//!
//! Encounter ids are client-generated (`genId: "enc-<base36>-<rand>"`). Both
//! commands validate the id shape via `safe_id` and derive paths from
//! `app_data_dir()`, so a WebView-supplied id like `"../../evil"` cannot
//! escape the audio directory (path-traversal hardening — the WebView is a
//! privilege boundary even though it's our own frontend).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rusqlite::{params, Connection};
use std::path::Path;
use tauri::{AppHandle, Manager};

use crate::errors::AppError;

/// Hard ceiling on decoded audio bytes accepted by `save_session_audio`.
/// 512 MiB ≈ 6 hours of 16 kHz mono PCM — comfortably above any real clinical
/// session, comfortably below the point where a single write would evict most
/// laptops from their page cache. The base64-encoded string is capped
/// separately (see [`MAX_BASE64_LEN`]) so an attacker can't force the decoder
/// to allocate a giant intermediate buffer before the size check runs.
pub(crate) const MAX_AUDIO_BYTES: usize = 512 * 1024 * 1024;

/// Cap on the base64 STRING length. Base64 expands 3 raw bytes into 4 ASCII
/// bytes plus up to two `=` padding chars, so the encoded form is at most
/// `ceil(MAX_AUDIO_BYTES / 3) * 4`. A small slack of `+ 8` covers padding and
/// avoids off-by-one rejection of borderline-legal inputs.
pub(crate) const MAX_BASE64_LEN: usize = (MAX_AUDIO_BYTES / 3) * 4 + 8;

/// On-disk filename for an encounter's encrypted session audio. Single source
/// of truth so `save_session_audio` and `delete_session_audio` can never drift
/// onto different extensions (a drift would make delete silently no-op and
/// leave PHI ciphertext behind). Audio is stored AES-256-GCM encrypted, hence
/// the `.wav.enc` suffix (see audio_crypto).
pub(crate) fn enc_filename(encounter_id: &str) -> String {
    format!("{}.wav.enc", encounter_id)
}

pub(crate) fn safe_id(id: &str) -> Result<(), AppError> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(AppError::invalid("invalid encounter id"))
    }
}

#[tauri::command]
pub(crate) async fn save_session_audio(app: AppHandle, encounter_id: String, base64_data: String) -> Result<String, AppError> {
    safe_id(&encounter_id)?;
    // H1 defense: reject over-long base64 BEFORE handing it to the decoder.
    // The decoder would otherwise allocate a Vec<u8> proportional to the
    // encoded length — a multi-GB string from a compromised WebView could OOM
    // the app or fill the disk. We check the encoded form first (cheap: string
    // length) and then verify the decoded length as belt-and-braces in case a
    // future base64 config accepts input we didn't anticipate.
    if base64_data.len() > MAX_BASE64_LEN {
        return Err(AppError::invalid("audio payload too large"));
    }
    // Bad base64 from JS is a frontend-invariant violation, so surface it as
    // InvalidInput rather than an opaque internal error.
    let data = BASE64
        .decode(base64_data.as_bytes())
        .map_err(|e| AppError::invalid(format!("base64 decode: {}", e)))?;
    if data.len() > MAX_AUDIO_BYTES {
        return Err(AppError::invalid("audio payload too large"));
    }
    let audio_dir = app
        .path()
        .app_data_dir()
        .map_err(AppError::internal_from)?
        .join("audio");
    tokio::fs::create_dir_all(&audio_dir).await.map_err(AppError::storage_from)?;
    // At-rest encryption (§164.312(a)(2)(iv)): encrypt the raw audio with the
    // HKDF-derived audio key BEFORE it ever hits disk, and store it under a
    // `.wav.enc` name so the extension advertises the on-disk format. The
    // returned path (`.wav.enc`) is what gets persisted as `audio_path` and
    // later handed to `transcribe_audio`, which decrypts to a transient temp
    // file. delete_session_audio derives the same `.wav.enc` name.
    let key = crate::audio_crypto::audio_key()?;
    let ciphertext = crate::audio_crypto::encrypt(&key, &data)?;
    let path = audio_dir.join(enc_filename(&encounter_id));
    tokio::fs::write(&path, &ciphertext).await.map_err(AppError::storage_from)?;
    // M1: `tokio::fs::write` (like `File::create`) leaves the file at the
    // process umask default — typically 0644 on Unix, which lets any other
    // local user read the ciphertext. Clamp to owner-only 0600 (defense in
    // depth on top of the encryption). No-op on Windows (see perms.rs).
    crate::perms::chmod_0600_unix(&path);
    Ok(path.to_string_lossy().into_owned())
}

// Delete an encounter's saved audio file. Idempotent: returns Ok(false) if
// the file was already gone, Ok(true) if a file was removed. safe_id() and
// deriving the path from app_data_dir keeps this scoped to files this app
// created — the WebView cannot pass an arbitrary path.
#[tauri::command]
pub(crate) async fn delete_session_audio(app: AppHandle, encounter_id: String) -> Result<bool, AppError> {
    safe_id(&encounter_id)?;
    let path = app
        .path()
        .app_data_dir()
        .map_err(AppError::internal_from)?
        .join("audio")
        // Audio is stored encrypted as `<id>.wav.enc` (see save_session_audio).
        // Delete MUST target the same extension or it would silently no-op and
        // leave PHI ciphertext on disk after a purge.
        .join(enc_filename(&encounter_id));
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(AppError::Storage(e.to_string())),
    }
}

/// Delete an encounter's audio AFTER its database rows have been destroyed,
/// recording a queryable row if the file survives.
///
/// Every destruction path commits its SQL first and cleans up audio
/// afterwards — correct ordering, since a file-delete failure must not roll
/// back a committed destruction. But the failure was previously recorded ONLY
/// to the application log. The `destruction_log` row written inside the
/// transaction affirmatively states the encounter was destroyed, which is
/// false with respect to the audio, and nothing an auditor could query
/// disagreed with it.
///
/// A `disposal_incomplete` row makes the discrepancy visible in the same table
/// that claims the destruction happened. Never returns an error: the SQL is
/// already committed and there is nothing left to unwind — a failure to record
/// the failure is logged and swallowed.
pub(crate) async fn purge_after_destruction(
    app: &AppHandle,
    pool: &crate::db::SqlitePool,
    encounter_id: &str,
    provider_id: &str,
) {
    // Ok(false) means the file was already gone — a completed disposal, not a
    // failure. Only Err leaves PHI on disk.
    let Err(e) = delete_session_audio(app.clone(), encounter_id.to_string()).await else {
        return;
    };
    log::error!(
        "audio disposal incomplete for {}: {}",
        crate::log_safety::redact_filename(encounter_id),
        crate::log_safety::cap_len(&e.to_string())
    );
    match pool.get() {
        Ok(conn) => {
            if let Err(e2) = crate::destruction_log::append(
                &conn,
                provider_id,
                "audio",
                encounter_id,
                "",
                "disposal_incomplete",
                0,
            ) {
                log::error!(
                    "could not record incomplete audio disposal: {}",
                    crate::log_safety::cap_len(&e2.to_string())
                );
            }
        }
        Err(e2) => log::error!(
            "could not record incomplete audio disposal: {}",
            crate::log_safety::cap_len(&e2.to_string())
        ),
    }
}

/// Startup sweep for encrypted audio whose encounter row no longer exists.
///
/// Closes the failure mode no per-call handler can: if the process dies
/// part-way through a destruction's cleanup loop, the remaining files are
/// never attempted and NOTHING is written anywhere — not even a log line. The
/// only way to notice is to compare the directory against the table.
///
/// Self-healing where possible: an orphan is re-deleted and the late disposal
/// recorded. Where deletion still fails, one `disposal_incomplete` row is
/// written per orphan and not repeated on subsequent launches, so a
/// permanently-locked file cannot flood the log.
///
/// Deliberately fail-safe on uncertainty: if the existence query errors, the
/// file is treated as still-referenced and left alone. This function deletes
/// PHI, so every ambiguous case must resolve toward keeping the file.
pub(crate) fn reconcile_orphaned_audio(
    conn: &Connection,
    audio_dir: &Path,
    provider_id: &str,
) -> Result<usize, AppError> {
    let entries = match std::fs::read_dir(audio_dir) {
        Ok(e) => e,
        // No audio directory yet — nothing to reconcile.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(AppError::Storage(e.to_string())),
    };

    let mut orphans = 0usize;
    for entry in entries.flatten() {
        let raw = entry.file_name();
        let Some(name) = raw.to_str() else { continue };
        // Only the encrypted form. A legacy plaintext `.wav` is the at-rest
        // migration's business and runs before this sweep.
        let Some(id) = name.strip_suffix(".wav.enc") else { continue };
        // Anything not shaped like one of our ids was not written by us.
        if safe_id(id).is_err() {
            continue;
        }

        let still_referenced = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM encounters WHERE id = ?1)",
                params![id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(1) // query failed → assume referenced, never delete on doubt
            != 0;
        if still_referenced {
            continue;
        }

        orphans += 1;
        match std::fs::remove_file(entry.path()) {
            Ok(()) => {
                crate::destruction_log::append(
                    conn,
                    provider_id,
                    "audio",
                    id,
                    "",
                    "disposal_completed_late",
                    0,
                )?;
            }
            Err(e) => {
                log::error!(
                    "orphaned audio could not be removed: {} ({})",
                    crate::log_safety::redact_filename(name),
                    crate::log_safety::cap_len(&e.to_string())
                );
                let already: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM destruction_log \
                         WHERE entity_type = 'audio' AND entity_id = ?1 \
                           AND legal_basis = 'disposal_incomplete'",
                        params![id],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                if already == 0 {
                    crate::destruction_log::append(
                        conn,
                        provider_id,
                        "audio",
                        id,
                        "",
                        "disposal_incomplete",
                        0,
                    )?;
                }
            }
        }
    }
    Ok(orphans)
}

#[cfg(test)]
mod orphan_tests {
    //! Reconciliation of PHI audio left behind by a destruction that did not
    //! finish its cleanup. The case no per-call handler can catch is a crash
    //! part-way through the loop: the remaining files are never attempted and
    //! nothing is written anywhere, so only a directory-vs-table comparison
    //! finds them.

    use super::*;
    use rusqlite::Connection;

    fn db_with(ids: &[&str]) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE encounters (
                 id             TEXT PRIMARY KEY,
                 provider_id    TEXT NOT NULL,
                 encounter_date TEXT NOT NULL,
                 status         TEXT NOT NULL DEFAULT 'draft',
                 created_at     TEXT NOT NULL
             );",
        )
        .unwrap();
        crate::destruction_log::init_schema(&conn).unwrap();
        for id in ids {
            conn.execute(
                "INSERT INTO encounters (id, provider_id, encounter_date, created_at) \
                 VALUES (?1, 'p', '2026-07-04', '2026-07-04T00:00:00Z')",
                params![id],
            )
            .unwrap();
        }
        conn
    }

    fn write_audio(dir: &Path, name: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), b"ciphertext").unwrap();
    }

    fn log_rows(conn: &Connection) -> Vec<(String, String)> {
        let mut stmt = conn
            .prepare("SELECT entity_id, legal_basis FROM destruction_log ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn an_orphan_is_removed_and_the_late_disposal_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audio");
        write_audio(&dir, "enc-orphan.wav.enc");
        let conn = db_with(&[]); // its encounter row is gone

        let n = reconcile_orphaned_audio(&conn, &dir, "Dr. Chen").unwrap();

        assert_eq!(n, 1);
        assert!(
            !dir.join("enc-orphan.wav.enc").exists(),
            "PHI whose record was destroyed must not survive on disk"
        );
        assert_eq!(
            log_rows(&conn),
            vec![("enc-orphan".to_string(), "disposal_completed_late".to_string())],
            "closing the gap must itself be evidenced"
        );
    }

    #[test]
    fn audio_for_a_live_encounter_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audio");
        write_audio(&dir, "enc-live.wav.enc");
        let conn = db_with(&["enc-live"]);

        assert_eq!(reconcile_orphaned_audio(&conn, &dir, "Dr. Chen").unwrap(), 0);
        assert!(dir.join("enc-live.wav.enc").exists(), "must not delete referenced audio");
        assert!(log_rows(&conn).is_empty());
    }

    #[test]
    fn unrecognised_files_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audio");
        write_audio(&dir, "notes.txt");
        write_audio(&dir, "enc-legacy.wav"); // plaintext: the migration's business
        write_audio(&dir, "../evil.wav.enc".replace('/', "_").as_str());
        let conn = db_with(&[]);

        assert_eq!(reconcile_orphaned_audio(&conn, &dir, "Dr. Chen").unwrap(), 0);
        assert!(dir.join("notes.txt").exists());
        assert!(dir.join("enc-legacy.wav").exists());
    }

    #[test]
    fn a_missing_audio_directory_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let conn = db_with(&[]);
        assert_eq!(
            reconcile_orphaned_audio(&conn, &tmp.path().join("nope"), "Dr. Chen").unwrap(),
            0
        );
    }

    #[test]
    fn an_unreadable_encounters_table_leaves_every_file_in_place() {
        // Fail-safe: this function deletes PHI, so uncertainty must resolve
        // toward keeping the file, never toward removing it.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audio");
        write_audio(&dir, "enc-1.wav.enc");
        let conn = db_with(&[]);
        conn.execute_batch("DROP TABLE encounters;").unwrap();

        assert_eq!(reconcile_orphaned_audio(&conn, &dir, "Dr. Chen").unwrap(), 0);
        assert!(
            dir.join("enc-1.wav.enc").exists(),
            "an unanswerable existence query must not authorise deletion"
        );
    }

    #[test]
    fn a_repeatedly_undeletable_orphan_is_recorded_once() {
        // A locked file would otherwise append a row on every launch.
        // Simulated by making the entry a non-empty directory, which
        // remove_file cannot remove on any platform.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("audio");
        std::fs::create_dir_all(dir.join("enc-locked.wav.enc")).unwrap();
        std::fs::write(dir.join("enc-locked.wav.enc").join("inner"), b"x").unwrap();
        let conn = db_with(&[]);

        for _ in 0..3 {
            reconcile_orphaned_audio(&conn, &dir, "Dr. Chen").unwrap();
        }

        assert_eq!(
            log_rows(&conn),
            vec![("enc-locked".to_string(), "disposal_incomplete".to_string())],
            "an unresolvable orphan must be flagged once, not once per launch"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_AUDIO_BYTES, MAX_BASE64_LEN};

    #[test]
    fn safe_id_accepts_real_ids_rejects_traversal() {
        assert!(super::safe_id("enc-l9k3a-x7q2").is_ok());
        assert!(super::safe_id("enc_123").is_ok());
        // path-traversal / separator / drive attempts must be rejected
        assert!(super::safe_id("../../evil").is_err());
        assert!(super::safe_id("a/b").is_err());
        assert!(super::safe_id("a\\b").is_err());
        assert!(super::safe_id("C:evil").is_err());
        assert!(super::safe_id("").is_err());
    }

    // save and delete both derive the on-disk name from enc_filename, so this
    // pins the `.wav.enc` contract they share. If a future edit changed the
    // extension on one path only, delete would silently no-op and leave PHI
    // ciphertext behind — this test fails loudly instead.
    #[test]
    fn enc_filename_uses_wav_enc_suffix() {
        assert_eq!(super::enc_filename("enc-1"), "enc-1.wav.enc");
        assert!(super::enc_filename("enc_abc").ends_with(".wav.enc"));
        // Never the bare .wav that the pre-encryption code used.
        assert!(!super::enc_filename("x").ends_with(".wav"));
    }

    // Both assertions compare two consts, so clippy flags them as having a
    // constant value. That is exactly the intent: this is a compile-time
    // invariant between MAX_AUDIO_BYTES and MAX_BASE64_LEN expressed as a
    // test, so an edit to one without the other fails CI. Silencing the lint
    // rather than the test.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn size_constants_stay_in_sync() {
        // If MAX_AUDIO_BYTES is bumped without bumping MAX_BASE64_LEN, the
        // string-length check would start rejecting payloads that the byte
        // check would happily accept — confusing UX for anyone hitting the
        // ceiling. Pin the relationship in tests so a future edit that
        // touches one but not the other trips CI.
        assert!(MAX_BASE64_LEN >= (MAX_AUDIO_BYTES / 3) * 4);
        // Some slack for padding is fine, but not runaway slack — the whole
        // point is to reject before decode allocates.
        assert!(MAX_BASE64_LEN <= (MAX_AUDIO_BYTES / 3) * 4 + 32);
    }
}
