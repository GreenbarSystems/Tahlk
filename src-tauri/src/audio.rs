//! Session audio storage.
//!
//! Encounter ids are client-generated (`genId: "enc-<base36>-<rand>"`). Both
//! commands validate the id shape via `safe_id` and derive paths from
//! `app_data_dir()`, so a WebView-supplied id like `"../../evil"` cannot
//! escape the audio directory (path-traversal hardening — the WebView is a
//! privilege boundary even though it's our own frontend).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
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
