//! Note generation via Anthropic Messages API (streaming SSE).
//!
//! The DB lock is dropped inside `read_api_key` before the HTTP call, so no
//! lock is held across `.await`. The stream is parsed line-by-line: each
//! `content_block_delta` is emitted as a `scribe:note_chunk` event AND
//! accumulated into the returned full note, so callers don't need to
//! observe events to get the final result.
//!
//! Compliance gate (audit finding C2): before ANY network I/O, `baa::require_ack`
//! is called. If the provider has not explicitly acknowledged that the
//! Anthropic account behind this API key is covered by a signed BAA, the
//! call is refused with `AppError::BaaRequired` — no transcript leaves the
//! device. Every completed call (success OR failure) is written to the
//! `llm_audit` table with metadata only (no transcript, no response text)
//! so a compliance officer can trace who sent what model when.
//!
//! Error mapping (see `errors.rs`):
//!   * BAA gate not acknowledged  → `AppError::BaaRequired`
//!   * missing keychain entry     → `AppError::NoApiKey`
//!   * client builder failure     → `AppError::internal_from` (reqwest config bug)
//!   * transport error on send    → `AppError::Network`
//!   * HTTP 401/403               → `AppError::AuthFailed`
//!   * HTTP 429                   → `AppError::RateLimited`
//!   * any other non-2xx          → `AppError::UpstreamApi`
//!   * stream body read error     → `AppError::Network`
//!   * server-emitted stream error→ `AppError::UpstreamApi`
//!   * zero-length accumulation   → `AppError::UpstreamEmpty`

use reqwest::Client;
use serde_json::{json, Value};
use std::time::Instant;
use tauri::{AppHandle, Emitter, State};

use crate::baa;
use crate::errors::AppError;
use crate::llm_audit::{self, LlmCallEntry};
use crate::secrets::read_api_key;
use crate::DbState;

const ANTHROPIC_ENDPOINT: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_MODEL: &str = "claude-haiku-4-5-20251001";

// Rust-side ISO-8601 UTC timestamp for audit rows. Kept local to this
// module because it's the only place we need it; if a second caller
// shows up, promote it to `errors` or a `time` util.
fn utc_now_iso() -> String {
    // std has no ISO-8601 formatter, but we can piece one together from
    // SystemTime. Precision is seconds — audit rows don't need ms.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Days-from-epoch → (y,m,d) via the civil-from-days algorithm; hours,
    // minutes, seconds fall out of the remainder. This is enough for the
    // audit-log timestamp — we're not doing calendar math anywhere else.
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Howard Hinnant "civil_from_days" (public domain).
    let z = days + 719_468;
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, minute, second
    )
}

// Persists an audit row for one Anthropic call. Called on both success and
// failure paths so the log doesn't develop survivor bias. Errors from the
// insert itself are logged to stderr but NOT propagated — a failed audit
// row is worse for compliance than a missing one, but propagating an audit
// failure to the caller would mask the real error they came in with.
fn record_llm_call(state: &State<DbState>, entry: LlmCallEntry) {
    let conn = state.0.lock();
    if let Err(e) = llm_audit::append(&conn, &entry) {
        eprintln!(
            "llm_audit: failed to record {} call ({}): {}",
            entry.outcome, entry.endpoint, e
        );
    }
}

#[tauri::command]
pub(crate) async fn generate_note(
    app: AppHandle,
    state: State<'_, DbState>,
    transcript: String,
    system_prompt: String,
    encounter_id: Option<String>,
) -> Result<String, AppError> {
    // BAA gate FIRST — before we look at the key, before we build a client,
    // before we allocate the request body. The compliance failure is that
    // PHI reaches Anthropic without a BAA, so the check has to sit strictly
    // upstream of any state that could accidentally get flushed to the wire.
    let ack = baa::require_ack(&state)?;

    // Read the key from the OS keychain (locks drop inside read_api_key — no
    // lock is held across the await below).
    let key = read_api_key(&state).ok_or(AppError::NoApiKey)?;

    // TLS: reqwest validates the server certificate against the system trust
    // store by default; we additionally pin the floor to TLS 1.2. Certificate
    // pinning is intentionally NOT used — Anthropic rotates its certs/CAs, so
    // pinning a third-party API would cause outages on rotation; the residual
    // rogue-CA MITM risk is accepted (low for a desktop client). [audit L4]
    let client = Client::builder()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .map_err(AppError::internal_from)?;
    let body = json!({
        "model": ANTHROPIC_MODEL,
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

    // Snapshot fields we'll need for the audit row up front. `body` is
    // serialized twice — once for the wire, once here — rather than trying
    // to peek at reqwest's internal serialization, which would tie us to
    // its version and hide sizing bugs.
    let request_bytes = serde_json::to_vec(&body)
        .map(|v| v.len() as i64)
        .unwrap_or(0);
    let started_at = Instant::now();
    let created_at = utc_now_iso();

    // Small closure so success + all failure paths funnel through the same
    // audit-write shape. `outcome`/`error_code` mirror the AppError code.
    let audit_row = |outcome: &str,
                     error_code: Option<&str>,
                     response_bytes: i64,
                     upstream_reqid: Option<String>| LlmCallEntry {
        created_at: created_at.clone(),
        encounter_id: encounter_id.clone(),
        provider_id: ack.provider_id.clone(),
        model: ANTHROPIC_MODEL.into(),
        endpoint: ANTHROPIC_ENDPOINT.into(),
        request_bytes,
        response_bytes,
        upstream_reqid,
        outcome: outcome.into(),
        error_code: error_code.map(str::to_string),
        duration_ms: Some(started_at.elapsed().as_millis() as i64),
    };

    let resp = match client
        .post(ANTHROPIC_ENDPOINT)
        .header("x-api-key", &key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            record_llm_call(&state, audit_row("network", Some("network"), 0, None));
            return Err(AppError::Network(e.to_string()));
        }
    };

    // Snapshot the upstream request ID before consuming the body — both
    // success and non-2xx paths want it in the audit row.
    let upstream_reqid = resp
        .headers()
        .get("request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let (code, err) = match status.as_u16() {
            401 | 403 => ("auth_failed", AppError::AuthFailed(text)),
            429 => ("rate_limited", AppError::RateLimited),
            _ => (
                "upstream_api",
                AppError::UpstreamApi(format!("HTTP {}: {}", status, text)),
            ),
        };
        record_llm_call(
            &state,
            audit_row(code, Some(code), 0, upstream_reqid.clone()),
        );
        return Err(err);
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
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => {
                record_llm_call(
                    &state,
                    audit_row(
                        "network",
                        Some("network"),
                        full.len() as i64,
                        upstream_reqid.clone(),
                    ),
                );
                return Err(AppError::Network(format!("stream: {}", e)));
            }
        };
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
                    record_llm_call(
                        &state,
                        audit_row(
                            "upstream_api",
                            Some("upstream_api"),
                            full.len() as i64,
                            upstream_reqid.clone(),
                        ),
                    );
                    return Err(AppError::UpstreamApi(format!("stream: {}", msg)));
                }
                _ => {}
            }
        }
    }

    if full.is_empty() {
        record_llm_call(
            &state,
            audit_row("upstream_empty", Some("upstream_empty"), 0, upstream_reqid),
        );
        return Err(AppError::UpstreamEmpty);
    }

    record_llm_call(
        &state,
        audit_row("ok", None, full.len() as i64, upstream_reqid),
    );
    Ok(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_now_iso_shape() {
        let s = utc_now_iso();
        // Format: YYYY-MM-DDTHH:MM:SSZ (20 chars). We can't assert exact
        // values without freezing time — shape + a floor year keeps this
        // meaningful without turning into a change-detector test.
        assert_eq!(s.len(), 20, "unexpected timestamp: {:?}", s);
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[13..14], ":");
        assert_eq!(&s[16..17], ":");
        assert_eq!(&s[19..20], "Z");
        let year: i32 = s[..4].parse().unwrap();
        assert!(year >= 2026, "timestamp year suspiciously old: {}", year);
    }
}
