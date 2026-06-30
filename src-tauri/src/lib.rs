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

// The Anthropic API key lives in the OS secure store (Windows Credential
// Manager / macOS Keychain / Linux Secret Service) via the `keyring` crate —
// never in the app database. It is write-only from JS (set via set_api_key,
// presence-checked via has_api_key) and read only inside generate_note.
//
// API_KEY_KV is the LEGACY SQLite location. It is no longer written; it is read
// once and migrated into the keychain (then deleted) so existing installs stop
// keeping the key in plaintext on disk.
const API_KEY_KV: &str = "secret_v1::anthropic_api_key";
const KEYRING_SERVICE: &str = "com.tahlk.app";
const KEYRING_USER: &str = "anthropic_api_key";

fn keyring_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).map_err(|e| e.to_string())
}

// Read the API key, keychain-first. If absent there but present in the legacy
// SQLite location, migrate it into the keychain and delete the plaintext copy.
fn read_api_key(state: &DbState) -> Option<String> {
    if let Ok(entry) = keyring_entry() {
        if let Ok(pw) = entry.get_password() {
            if !pw.is_empty() {
                return Some(pw);
            }
        }
    }

    // Legacy fallback + one-time migration off plaintext disk.
    let legacy: Option<String> = {
        let conn = state.0.lock();
        conn.query_row("SELECT value FROM kv WHERE key = ?1", params![API_KEY_KV], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.as_str().map(str::to_string))
    };
    if let Some(key) = legacy {
        if let Ok(entry) = keyring_entry() {
            let _ = entry.set_password(&key);
        }
        let conn = state.0.lock();
        let _ = conn.execute("DELETE FROM kv WHERE key = ?1", params![API_KEY_KV]);
        return Some(key);
    }
    None
}

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
    keyring_entry()?.set_password(&key).map_err(|e| e.to_string())?;
    // Remove any legacy plaintext copy so the key no longer lives on disk.
    let conn = state.0.lock();
    let _ = conn.execute("DELETE FROM kv WHERE key = ?1", params![API_KEY_KV]);
    Ok(())
}

#[tauri::command]
fn clear_api_key(state: State<DbState>) -> Result<(), String> {
    if let Ok(entry) = keyring_entry() {
        let _ = entry.delete_credential(); // ignore "no entry"
    }
    let conn = state.0.lock();
    let _ = conn.execute("DELETE FROM kv WHERE key = ?1", params![API_KEY_KV]);
    Ok(())
}

#[tauri::command]
fn has_api_key(state: State<DbState>) -> Result<bool, String> {
    Ok(read_api_key(&state).is_some())
}

#[tauri::command]
fn data_location(app: AppHandle) -> Result<String, String> {
    app.path()
        .app_data_dir()
        .map(|p| p.join("tahlk.db").to_string_lossy().into_owned())
        .map_err(|e| e.to_string())
}

// ── Encounter queries ──────────────────────────────────────────────────────

// Column order shared by list_encounters and get_encounter.
const ENCOUNTER_COLS: &str =
    "id, provider_id, encounter_date, patient_alias, status, \
     audio_path, created_at, signed_at, signed_hash";

fn encounter_row_to_json(r: &rusqlite::Row) -> rusqlite::Result<Value> {
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
}

#[tauri::command]
fn list_encounters(state: State<DbState>, limit: Option<i64>) -> Result<Vec<Value>, String> {
    let conn = state.0.lock();
    let n = limit.unwrap_or(50);
    let sql = format!(
        "SELECT {ENCOUNTER_COLS} FROM encounters ORDER BY created_at DESC LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![n], encounter_row_to_json)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

// Flip an encounter to signed, touching ONLY the sign columns. upsert_encounter
// overwrites patient_alias/audio_path from its payload, so using it for sign-off
// (which doesn't resend those) would null them out — corrupting the record at
// the moment of attestation. This targeted update cannot clobber other columns.
#[tauri::command]
fn mark_encounter_signed(
    state: State<DbState>,
    id: String,
    signed_at: String,
    signed_hash: String,
) -> Result<(), String> {
    let conn = state.0.lock();
    let n = conn
        .execute(
            "UPDATE encounters SET status = 'signed', signed_at = ?2, signed_hash = ?3 WHERE id = ?1",
            params![id, signed_at, signed_hash],
        )
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err(format!("encounter {} not found", id));
    }
    Ok(())
}

// Fetch a single encounter by id — avoids pulling the whole list to open one row.
#[tauri::command]
fn get_encounter(state: State<DbState>, id: String) -> Result<Option<Value>, String> {
    let conn = state.0.lock();
    let sql = format!("SELECT {ENCOUNTER_COLS} FROM encounters WHERE id = ?1");
    conn.query_row(&sql, params![id], encounter_row_to_json)
        .optional()
        .map_err(|e| e.to_string())
}

// Home-screen counters via indexed COUNT(*) — O(index) instead of shipping rows
// to JS and filtering. `today` is passed in so the comparison matches how
// encounter_date is stored client-side.
#[tauri::command]
fn encounter_stats(state: State<DbState>, today: String) -> Result<Value, String> {
    let conn = state.0.lock();
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM encounters", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let signed: i64 = conn
        .query_row("SELECT COUNT(*) FROM encounters WHERE status = 'signed'", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let today_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM encounters WHERE encounter_date = ?1", params![today], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    Ok(json!({ "total": total, "signed": signed, "today": today_count }))
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

// Encounter ids are client-generated (genId: "enc-<base36>-<rand>"). Validate
// the shape before using one to build a filesystem path, so a crafted id like
// "../../evil" cannot escape the audio directory (path-traversal hardening —
// the WebView is a privilege boundary, even though it's our own frontend).
fn safe_id(id: &str) -> Result<(), String> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err("invalid encounter id".into())
    }
}

#[tauri::command]
async fn save_session_audio(app: AppHandle, encounter_id: String, base64_data: String) -> Result<String, String> {
    safe_id(&encounter_id)?;
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
    app.path()
        .resource_dir()
        .map_err(|e| e.to_string())
        .map(|d| d.join("ggml-base.en.bin"))
}

#[tauri::command]
async fn model_downloaded(app: AppHandle) -> Result<bool, String> {
    Ok(tokio::fs::try_exists(model_path(&app)?).await.unwrap_or(false))
}

// Retained for API compatibility; model ships with the app so this is a no-op.
#[tauri::command]
async fn download_whisper_model(app: AppHandle) -> Result<(), String> {
    let _ = app;
    Ok(())
}

#[tauri::command]
async fn transcribe_audio(app: AppHandle, audio_path: String) -> Result<String, String> {
    let model = model_path(&app)?;
    if !tokio::fs::try_exists(&model).await.unwrap_or(false) {
        return Err("Whisper model not downloaded. Open Settings → Download Transcription Model.".into());
    }

    // Confine transcription to the app's audio directory. The output .txt path is
    // derived from audio_path, so an unconstrained path would let the WebView
    // read an arbitrary file AND write a .txt next to it (arbitrary write).
    let audio_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("audio");
    let canon = std::path::Path::new(&audio_path)
        .canonicalize()
        .map_err(|_| "audio file not found".to_string())?;
    let dir_canon = audio_dir.canonicalize().map_err(|e| e.to_string())?;
    if !canon.starts_with(&dir_canon) {
        return Err("audio path is outside the session audio directory".into());
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
    app: AppHandle,
    state: State<'_, DbState>,
    transcript: String,
    system_prompt: String,
) -> Result<String, String> {
    // Read the key from the OS keychain (locks drop inside read_api_key — no
    // lock is held across the await below).
    let key = read_api_key(&state)
        .ok_or("Anthropic API key not set. Open Settings to add your key.")?;

    let client = Client::new();
    let body = json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 2048,
        "stream": true,
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

    // Parse the SSE stream: accumulate the full note while emitting each text
    // delta as a `scribe:note_chunk` event for live display. The complete
    // assembled note is returned regardless, so callers don't depend on the
    // events having been observed.
    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut full = String::new();

    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| format!("Stream error: {}", e))?;
        byte_buf.extend_from_slice(&bytes);

        // SSE fields are newline-delimited; process each complete line.
        while let Some(pos) = byte_buf.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = byte_buf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line_bytes);
            let line = line.trim();
            let Some(data) = line.strip_prefix("data:") else { continue };
            let data = data.trim();
            if data.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(data) else { continue };
            match v["type"].as_str() {
                Some("content_block_delta") => {
                    if let Some(t) = v["delta"]["text"].as_str() {
                        full.push_str(t);
                        let _ = app.emit("scribe:note_chunk", t);
                    }
                }
                Some("error") => {
                    let msg = v["error"]["message"].as_str().unwrap_or("unknown stream error");
                    return Err(format!("Anthropic stream error: {}", msg));
                }
                _ => {}
            }
        }
    }

    if full.is_empty() {
        return Err("Anthropic returned an empty response".into());
    }
    Ok(full)
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
         CREATE INDEX IF NOT EXISTS enc_status_idx ON encounters (status);
         CREATE INDEX IF NOT EXISTS enc_created_idx ON encounters (created_at DESC);",
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
            get_encounter,
            encounter_stats,
            mark_encounter_signed,
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

#[cfg(test)]
mod tests {
    // Round-trips a credential through the real OS secure store to confirm the
    // keyring backend works on this platform. Uses a dedicated service name and
    // cleans up after itself, so it never touches a real saved key.
    #[test]
    fn keyring_roundtrip() {
        let entry = keyring::Entry::new("com.tahlk.app.test", "roundtrip").unwrap();
        entry.set_password("sk-ant-test-value").unwrap();
        assert_eq!(entry.get_password().unwrap(), "sk-ant-test-value");
        entry.delete_credential().unwrap();
        assert!(entry.get_password().is_err(), "credential should be gone after delete");
    }

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
