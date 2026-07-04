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
    let data = BASE64.decode(base64_data.as_bytes()).map_err(AppError::invalid)?;
    let audio_dir = app
        .path()
        .app_data_dir()
        .map_err(AppError::internal_from)?
        .join("audio");
    tokio::fs::create_dir_all(&audio_dir).await.map_err(AppError::storage_from)?;
    let path = audio_dir.join(format!("{}.wav", encounter_id));
    tokio::fs::write(&path, &data).await.map_err(AppError::storage_from)?;
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
        .join(format!("{}.wav", encounter_id));
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(AppError::Storage(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
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
}
