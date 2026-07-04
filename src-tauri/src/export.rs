//! Filesystem-facing helpers: exposing the data location and saving notes
//! through the system Save-As dialog. Both are AppHandle-only (no DbState).
//!
//! Error mapping: dialog/path lookups and file writes are `Storage` failures.

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
    let path = app
        .dialog()
        .file()
        .set_file_name(&suggested_name)
        .add_filter("Text", &["txt"])
        .blocking_save_file();

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
