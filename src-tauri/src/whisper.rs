//! Local Whisper.cpp transcription via the bundled sidecar.
//!
//! The .txt output path is derived from the caller-supplied `audio_path`,
//! so `transcribe_audio` canonicalizes both the audio file and the app's
//! audio directory and rejects anything that escapes the directory. Without
//! that check, an arbitrary read/write anywhere on disk would be possible
//! through the WebView.

use std::path::PathBuf;
use tauri::{AppHandle, Manager};
use tauri_plugin_shell::ShellExt;

use crate::errors::AppError;

fn model_path(app: &AppHandle) -> Result<PathBuf, AppError> {
    app.path()
        .resource_dir()
        .map_err(AppError::internal_from)
        .map(|d| d.join("ggml-base.en.bin"))
}

#[tauri::command]
pub(crate) async fn model_downloaded(app: AppHandle) -> Result<bool, AppError> {
    Ok(tokio::fs::try_exists(model_path(&app)?).await.unwrap_or(false))
}

// Retained for API compatibility; model ships with the app so this is a no-op.
#[tauri::command]
pub(crate) async fn download_whisper_model(app: AppHandle) -> Result<(), AppError> {
    let _ = app;
    Ok(())
}

#[tauri::command]
pub(crate) async fn transcribe_audio(app: AppHandle, audio_path: String) -> Result<String, AppError> {
    let model = model_path(&app)?;
    if !tokio::fs::try_exists(&model).await.unwrap_or(false) {
        return Err(AppError::NoModel);
    }

    // Confine transcription to the app's audio directory. The output .txt path is
    // derived from audio_path, so an unconstrained path would let the WebView
    // read an arbitrary file AND write a .txt next to it (arbitrary write).
    let audio_dir = app
        .path()
        .app_data_dir()
        .map_err(AppError::internal_from)?
        .join("audio");
    let canon = std::path::Path::new(&audio_path)
        .canonicalize()
        .map_err(|_| AppError::invalid("audio file not found"))?;
    let dir_canon = audio_dir.canonicalize().map_err(AppError::storage_from)?;
    if !canon.starts_with(&dir_canon) {
        return Err(AppError::invalid(
            "audio path is outside the session audio directory",
        ));
    }

    let output_base = audio_path.trim_end_matches(".wav").to_string();

    let output = app
        .shell()
        .sidecar("whisper-cpp")
        .map_err(AppError::internal_from)?
        .args([
            "-m", &model.to_string_lossy(),
            "-f", &audio_path,
            "--output-txt",
            "--output-file", &output_base,
            "--language", "en",
            "--no-prints",
        ])
        .output()
        .await
        .map_err(AppError::internal_from)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(AppError::Transcription(stderr));
    }

    let txt_path = format!("{}.txt", output_base);
    let transcript = tokio::fs::read_to_string(&txt_path)
        .await
        .map_err(AppError::storage_from)?;
    let _ = tokio::fs::remove_file(&txt_path).await;
    Ok(transcript.trim().to_string())
}
