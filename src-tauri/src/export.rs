//! Filesystem-facing helpers: exposing the data location and saving notes
//! through the system Save-As dialog. Both are AppHandle-only (no DbState).

use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

#[tauri::command]
pub(crate) fn data_location(app: AppHandle) -> Result<String, String> {
    app.path()
        .app_data_dir()
        .map(|p| p.join("tahlk.db").to_string_lossy().into_owned())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn export_note_to_file(app: AppHandle, content: String, suggested_name: String) -> Result<(), String> {
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
                .map_err(|e| e.to_string())
        }
        None => Ok(()), // user cancelled
    }
}
