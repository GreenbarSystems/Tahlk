//! Filesystem-facing helpers: exposing the data location and saving notes
//! through the system Save-As dialog. Both are AppHandle-only (no DbState).
//!
//! Error mapping: dialog/path lookups and file writes are `Storage` failures.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

use crate::errors::AppError;

#[tauri::command]
pub(crate) fn data_location(app: AppHandle) -> Result<String, AppError> {
    app.path()
        .app_data_dir()
        .map(|p| p.join("tahlk.db").to_string_lossy().into_owned())
        .map_err(AppError::storage_from)
}

#[tauri::command]
pub(crate) async fn export_note_to_file(
    app: AppHandle,
    content: String,
    suggested_name: String,
) -> Result<(), AppError> {
    // L8: blocking_save_file() parks the calling thread on a sync_channel
    // recv() until the user closes the native Save dialog — the dialog
    // plugin's own doc comment says this "should NOT be used when running
    // on the main thread." A Tauri async command runs on a Tokio worker
    // thread, not the main thread, but blocking that worker thread for
    // however long the user takes to pick a location still starves the
    // async runtime's thread pool of a worker for the whole dialog lifetime
    // (seconds to indefinitely, if the user walks away). spawn_blocking
    // moves the blocking call onto Tokio's dedicated blocking-thread pool,
    // which exists exactly for this kind of call and doesn't starve the
    // async worker threads.
    let path = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_file_name(&suggested_name)
            .add_filter("Text", &["txt"])
            .blocking_save_file()
    })
    .await
    .map_err(AppError::storage_from)?;

    match path {
        Some(p) => {
            let path_str = p.to_string();
            tokio::fs::write(&path_str, content.as_bytes())
                .await
                .map_err(AppError::storage_from)
        }
        None => Ok(()), // user cancelled
    }
}

// PDF is binary, so unlike export_note_to_file (UTF-8 text) the payload arrives
// base64-encoded from JS (jsPDF's `.output('arraybuffer')` → base64). We decode
// once and write the raw bytes. Same dialog pattern, same Storage error class,
// and the same user-cancel-returns-Ok(()) behavior as the text path.
#[tauri::command]
pub(crate) async fn export_note_pdf_to_file(
    app: AppHandle,
    data_base64: String,
    suggested_name: String,
) -> Result<(), AppError> {
    let bytes = BASE64
        .decode(data_base64.as_bytes())
        .map_err(|e| AppError::invalid(format!("malformed base64 PDF payload: {}", e)))?;

    // L8: see export_note_to_file's comment — same spawn_blocking rationale.
    let path = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_file_name(&suggested_name)
            .add_filter("PDF", &["pdf"])
            .blocking_save_file()
    })
    .await
    .map_err(AppError::storage_from)?;

    match path {
        Some(p) => {
            let path_str = p.to_string();
            tokio::fs::write(&path_str, &bytes)
                .await
                .map_err(AppError::storage_from)
        }
        None => Ok(()), // user cancelled
    }
}
