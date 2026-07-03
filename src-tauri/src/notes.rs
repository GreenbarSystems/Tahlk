//! Note generation via Anthropic Messages API (streaming SSE).
//!
//! The DB lock is dropped inside `read_api_key` before the HTTP call, so no
//! lock is held across `.await`. The stream is parsed line-by-line: each
//! `content_block_delta` is emitted as a `scribe:note_chunk` event AND
//! accumulated into the returned full note, so callers don't need to
//! observe events to get the final result.

use reqwest::Client;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, State};

use crate::secrets::read_api_key;
use crate::DbState;

#[tauri::command]
pub(crate) async fn generate_note(
    app: AppHandle,
    state: State<'_, DbState>,
    transcript: String,
    system_prompt: String,
) -> Result<String, String> {
    // Read the key from the OS keychain (locks drop inside read_api_key — no
    // lock is held across the await below).
    let key = read_api_key(&state)
        .ok_or("Anthropic API key not set. Open Settings to add your key.")?;

    // TLS: reqwest validates the server certificate against the system trust
    // store by default; we additionally pin the floor to TLS 1.2. Certificate
    // pinning is intentionally NOT used — Anthropic rotates its certs/CAs, so
    // pinning a third-party API would cause outages on rotation; the residual
    // rogue-CA MITM risk is accepted (low for a desktop client). [audit L4]
    let client = Client::builder()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .map_err(|e| e.to_string())?;
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
