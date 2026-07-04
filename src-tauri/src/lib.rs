//! Tahlk desktop crate root.
//!
//! Modules are split by concern:
//!   - `db`            — SQLite bootstrap, encounter row projection.
//!   - `secrets`       — Anthropic API key in the OS keychain + legacy migration.
//!   - `kv`            — generic key/value store commands (secret_* namespace blocked).
//!   - `encounters`    — encounter CRUD, sign-off, stats.
//!   - `note_history`  — relational note-history append-log + KV→table migration.
//!   - `audio`         — session audio save/delete with path-traversal hardening.
//!   - `whisper`       — local whisper.cpp sidecar transcription.
//!   - `notes`         — Anthropic streaming note generation.
//!   - `export`        — data-location lookup + save-as export.
//!
//! `DbState` stays at the crate root so every module can name it via
//! `crate::DbState` without cyclic imports; this file only wires setup and
//! the `generate_handler!` list.

use parking_lot::Mutex;
use rusqlite::Connection;
use tauri::Manager;

mod audio;
mod db;
mod encounters;
mod export;
mod kv;
mod note_history;
mod notes;
mod secrets;
mod whisper;

pub(crate) struct DbState(pub(crate) Mutex<Connection>);

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let conn = db::open_database(&app.handle()).expect("failed to open SQLite database");
            app.manage(db::new_state(conn));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            kv::kv_get,
            kv::kv_set,
            kv::kv_remove,
            kv::kv_list,
            secrets::set_api_key,
            secrets::clear_api_key,
            secrets::has_api_key,
            export::data_location,
            encounters::list_encounters,
            encounters::get_encounter,
            encounters::encounter_stats,
            encounters::mark_encounter_signed,
            encounters::upsert_encounter,
            audio::save_session_audio,
            audio::delete_session_audio,
            encounters::clear_encounter_audio_path,
            note_history::note_history_list,
            note_history::note_history_append,
            whisper::model_downloaded,
            whisper::download_whisper_model,
            whisper::transcribe_audio,
            notes::generate_note,
            export::export_note_to_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
