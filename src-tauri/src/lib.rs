use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use parking_lot::Mutex;
use reqwest::Client;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::path::PathBuf;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_shell::ShellExt;

struct DbState(Mutex<Connection>);

// Storage key for the Anthropic API key. Lives in the `secret_` namespace,
// which the generic kv_* commands refuse to read or write — so the key is
// write-only from JS (set via set_api_key, presence-checked via has_api_key)
// and only ever read inside generate_note on the Rust side.
const API_KEY_KV: &str = "secret_v1::anthropic_api_key";

// Reject any attempt to reach the secret namespace through the generic KV API.
fn guard_key(key: &str) -> Result<(), String> {
    if key.starts_with("secret_") {
        return Err("access denied: secret keys are not accessible via the KV API".into());
    }
    Ok(())
}

// ── KV store ──────────────────────────────────────────────────────────────

#[tauri::command]
fn kv_get(state: State<DbState>, key: String) -> Result<Option<Value>, String> {
    guard_key(&key)?;
    let conn = state.0.lock();
    let row: Option<String> = conn
        .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    match row {
        Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| e.to_string()),
        None => Ok(None),
    }
}

#[tauri::command]
fn kv_set(state: State<DbState>, key: String, value: Value) -> Result<(), String> {
    guard_key(&key)?;
    let conn = state.0.lock();
    let json = serde_json::to_string(&value).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO kv (key, value, updated_at) \
         VALUES (?1, ?2, strftime('%s', 'now')) \
         ON CONFLICT(key) DO UPDATE SET \
             value      = excluded.value, \
             updated_at = excluded.updated_at",
        params![key, json],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn kv_remove(state: State<DbState>, key: String) -> Result<(), String> {
    guard_key(&key)?;
    let conn = state.0.lock();
    conn.execute("DELETE FROM kv WHERE key = ?1", params![key])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn kv_list(state: State<DbState>, prefix: String) -> Result<Vec<(String, Value)>, String> {
    let pattern = if prefix.is_empty() { String::from("%") } else { format!("{}%", prefix) };
    let conn = state.0.lock();
    // Never surface secret_* keys through enumeration.
    let mut stmt = conn
        .prepare("SELECT key, value FROM kv WHERE key LIKE ?1 AND key NOT LIKE 'secret\\_%' ESCAPE '\\' ORDER BY key")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![pattern], |r| {
            let k: String = r.get(0)?;
            let v: String = r.get(1)?;
            Ok((k, v))
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        let (k, v) = row.map_err(|e| e.to_string())?;
        let parsed: Value = serde_json::from_str(&v).map_err(|e| e.to_string())?;
        out.push((k, parsed));
    }
    Ok(out)
}

// ── API key (write-only secret) ────────────────────────────────────────────

#[tauri::command]
fn set_api_key(state: State<DbState>, key: String) -> Result<(), String> {
    let conn = state.0.lock();
    let json = serde_json::to_string(&Value::String(key)).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO kv (key, value, updated_at) \
         VALUES (?1, ?2, strftime('%s', 'now')) \
         ON CONFLICT(key) DO UPDATE SET \
             value      = excluded.value, \
             updated_at = excluded.updated_at",
        params![API_KEY_KV, json],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn clear_api_key(state: State<DbState>) -> Result<(), String> {
    let conn = state.0.lock();
    conn.execute("DELETE FROM kv WHERE key = ?1", params![API_KEY_KV])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn has_api_key(state: State<DbState>) -> Result<bool, String> {
    let conn = state.0.lock();
    let exists: Option<i64> = conn
        .query_row("SELECT 1 FROM kv WHERE key = ?1", params![API_KEY_KV], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(exists.is_some())
}

#[tauri::command]
fn data_location(app: AppHandle) -> Result<String, String> {
    app.path()
        .app_data_dir()
        .map(|p| p.join("tahlk.db").to_string_lossy().into_owned())
        .map_err(|e| e.to_string())
}

// ── Encounter queries ──────────────────────────────────────────────────────

#[tauri::command]
fn list_encounters(state: State<DbState>, limit: Option<i64>) -> Result<Vec<Value>, String> {
    let conn = state.0.lock();
    let n = limit.unwrap_or(50);
    let mut stmt = conn
        .prepare(
            "SELECT id, provider_id, encounter_date, patient_alias, status, \
                    audio_path, created_at, signed_at, signed_hash \
             FROM encounters ORDER BY created_at DESC LIMIT ?1",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![n], |r| {
            Ok(json!({
                "id":             r.get::<_, String>(0)?,
                "provider_id":    r.get::<_, String>(1)?,
                "encounter_date": r.get::<_, String>(2)?,
                "patient_alias":  r.get::<_, Option<String>>(3)?,
                "status":         r.get::<_, String>(4)?,
                "audio_path":     r.get::<_, Option<String>>(5)?,
                "created_at":     r.get::<_, String>(6)?,
                "signed_at":      r.get::<_, Option<String>>(7)?,
                "signed_hash":    r.get::<_, Option<String>>(8)?,
            }))
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

#[tauri::command]
fn upsert_encounter(state: State<DbState>, encounter: Value) -> Result<(), String> {
    let conn = state.0.lock();
    conn.execute(
        "INSERT INTO encounters (id, provider_id, encounter_date, patient_alias, status, \
                                 audio_path, created_at, signed_at, signed_hash) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) \
         ON CONFLICT(id) DO UPDATE SET \
             status       = excluded.status, \
             patient_alias= excluded.patient_alias, \
             audio_path   = excluded.audio_path, \
             signed_at    = excluded.signed_at, \
             signed_hash  = excluded.signed_hash",
        params![
            encounter["id"].as_str().unwrap_or(""),
            encounter["provider_id"].as_str().unwrap_or(""),
            encounter["encounter_date"].as_str().unwrap_or(""),
            encounter["patient_alias"].as_str(),
            encounter["status"].as_str().unwrap_or("draft"),
            encounter["audio_path"].as_str(),
            encounter["created_at"].as_str().unwrap_or(""),
            encounter["signed_at"].as_str(),
            encounter["signed_hash"].as_str(),
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ── Audio ──────────────────────────────────────────────────────────────────

#[tauri::command]
async fn save_session_audio(app: AppHandle, encounter_id: String, base64_data: String) -> Result<String, String> {
    let data = BASE64.decode(base64_data.as_bytes()).map_err(|e| e.to_string())?;
    let audio_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("audio");
    tokio::fs::create_dir_all(&audio_dir).await.map_err(|e| e.to_string())?;
    let path = audio_dir.join(format!("{}.wav", encounter_id));
    tokio::fs::write(&path, &data).await.map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}

// ── Whisper transcription ──────────────────────────────────────────────────

fn model_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?.join("models");
    Ok(dir.join("ggml-base.en.bin"))
}

#[tauri::command]
async fn model_downloaded(app: AppHandle) -> Result<bool, String> {
    Ok(tokio::fs::try_exists(model_path(&app)?).await.unwrap_or(false))
}

#[tauri::command]
async fn download_whisper_model(app: AppHandle) -> Result<(), String> {
    let model_file = model_path(&app)?;
    if tokio::fs::try_exists(&model_file).await.unwrap_or(false) {
        return Ok(());
    }
    tokio::fs::create_dir_all(model_file.parent().unwrap()).await.map_err(|e| e.to_string())?;

    let url = "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.en.bin";
    let client = Client::new();
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Download failed: {}", resp.status()));
    }
    let total = resp.content_length().unwrap_or(0);
    let _ = app.emit("whisper:download_progress", json!({ "downloaded": 0, "total": total }));

    let mut downloaded: u64 = 0;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| e.to_string())?;
        downloaded += bytes.len() as u64;
        buf.extend_from_slice(&bytes);
        let _ = app.emit("whisper:download_progress", json!({ "downloaded": downloaded, "total": total }));
    }
    tokio::fs::write(&model_file, &buf).await.map_err(|e| e.to_string())?;
    let _ = app.emit("whisper:download_complete", json!({}));
    Ok(())
}

#[tauri::command]
async fn transcribe_audio(app: AppHandle, audio_path: String) -> Result<String, String> {
    let model = model_path(&app)?;
    if !tokio::fs::try_exists(&model).await.unwrap_or(false) {
        return Err("Whisper model not downloaded. Open Settings → Download Transcription Model.".into());
    }

    let output_base = audio_path.trim_end_matches(".wav").to_string();

    let output = app
        .shell()
        .sidecar("whisper-cpp")
        .map_err(|e| e.to_string())?
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
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(format!("Transcription failed: {}", stderr));
    }

    let txt_path = format!("{}.txt", output_base);
    let transcript = tokio::fs::read_to_string(&txt_path).await.map_err(|e| e.to_string())?;
    let _ = tokio::fs::remove_file(&txt_path).await;
    Ok(transcript.trim().to_string())
}

// ── Note generation via Anthropic ──────────────────────────────────────────

#[tauri::command]
async fn generate_note(
    state: State<'_, DbState>,
    transcript: String,
    system_prompt: String,
) -> Result<String, String> {
    // Read API key — drop the lock before awaiting.
    let api_key: Option<String> = {
        let conn = state.0.lock();
        conn.query_row(
            "SELECT value FROM kv WHERE key = ?1",
            params![API_KEY_KV],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.as_str().map(str::to_string))
    };

    let key = api_key.ok_or("Anthropic API key not set. Open Settings to add your key.")?;

    let client = Client::new();
    let body = json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 2048,
        "system": system_prompt,
        "messages": [
            {
                "role": "user",
                "content": format!("Generate a clinical note from the following session transcript:\n\n{}", transcript)
            }
        ]
    });

    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Anthropic API error {}: {}", status, text));
    }

    let result: Value = resp.json().await.map_err(|e| e.to_string())?;
    let note = result["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|c| c["text"].as_str())
        .ok_or("Unexpected response format from Anthropic")?
        .to_string();

    Ok(note)
}

// ── Export ─────────────────────────────────────────────────────────────────

#[tauri::command]
async fn export_note_to_file(app: AppHandle, content: String, suggested_name: String) -> Result<(), String> {
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

// ── Database init ──────────────────────────────────────────────────────────

fn open_database(app: &AppHandle) -> rusqlite::Result<Connection> {
    let data_dir = app.path().app_data_dir().expect("could not resolve app_data_dir");
    std::fs::create_dir_all(&data_dir).expect("could not create app data dir");
    let db_path = data_dir.join("tahlk.db");
    let conn = Connection::open(&db_path)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous   = NORMAL;
         PRAGMA foreign_keys  = ON;

         CREATE TABLE IF NOT EXISTS kv (
             key        TEXT PRIMARY KEY,
             value      TEXT NOT NULL,
             updated_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS kv_prefix_idx ON kv (key);

         CREATE TABLE IF NOT EXISTS encounters (
             id             TEXT PRIMARY KEY,
             provider_id    TEXT NOT NULL,
             encounter_date TEXT NOT NULL,
             patient_alias  TEXT,
             status         TEXT NOT NULL DEFAULT 'draft',
             audio_path     TEXT,
             created_at     TEXT NOT NULL,
             signed_at      TEXT,
             signed_hash    TEXT
         );
         CREATE INDEX IF NOT EXISTS enc_date_idx ON encounters (encounter_date DESC);
         CREATE INDEX IF NOT EXISTS enc_status_idx ON encounters (status);",
    )?;
    Ok(conn)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let conn = open_database(&app.handle()).expect("failed to open SQLite database");
            app.manage(DbState(Mutex::new(conn)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            kv_get,
            kv_set,
            kv_remove,
            kv_list,
            set_api_key,
            clear_api_key,
            has_api_key,
            data_location,
            list_encounters,
            upsert_encounter,
            save_session_audio,
            model_downloaded,
            download_whisper_model,
            transcribe_audio,
            generate_note,
            export_note_to_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
