//! Anthropic Messages API provider (streaming SSE).
//!
//! Implements [`LlmProvider`](super::LlmProvider) for Anthropic's
//! `/v1/messages` endpoint: builds the messages request body, sets the
//! `x-api-key` + `anthropic-version` headers, and decodes Anthropic's SSE
//! event taxonomy (`content_block_delta` → text delta, `error` → error frame,
//! everything else ignored) into the normalized
//! [`StreamEvent`](super::StreamEvent).
//!
//! Endpoint and model are instance fields (constructed from settings) rather
//! than compile-time constants; [`DEFAULT_ENDPOINT`] / [`DEFAULT_MODEL`] keep
//! the previous hardcoded values as defaults so behavior is unchanged out of
//! the box.

use reqwest::RequestBuilder;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{LlmProvider, StreamEvent};

/// Default Anthropic Messages endpoint — the value `notes.rs` hardcoded before
/// the provider refactor. Kept as the fallback so existing installs are
/// unaffected.
pub(crate) const DEFAULT_ENDPOINT: &str = "https://api.anthropic.com/v1/messages";

/// Default model — the value `notes.rs` hardcoded before the refactor.
pub(crate) const DEFAULT_MODEL: &str = "claude-haiku-4-5-20251001";

/// OS-keychain entry name ("username") for the Anthropic API key. Matches the
/// pre-refactor `secrets::KEYRING_USER` so a saved key is found unchanged.
pub(crate) const KEYRING_USER: &str = "anthropic_api_key";

/// Anthropic API version header value. Pinned like the model — a bump is an
/// intentional, reviewable change.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Max tokens requested for a generated note. 2048 is a comfortable ceiling
/// for a clinical note; unchanged from the pre-refactor request body.
const MAX_TOKENS: u32 = 2048;

/// Anthropic note-generation provider. Endpoint + model are configurable so a
/// future BAA-covered gateway or a different model needs no code change.
pub(crate) struct AnthropicProvider {
    endpoint: String,
    model: String,
}

impl AnthropicProvider {
    /// Construct with the given model and the default Anthropic endpoint.
    pub(crate) fn new(model: String) -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            model,
        }
    }

    /// Construct with an explicit endpoint (e.g. a BAA-covered gateway) and
    /// model. Currently used only in tests; kept `pub(crate)` so a future
    /// settings-driven endpoint override is a one-line factory change.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn with_endpoint(endpoint: String, model: String) -> Self {
        Self { endpoint, model }
    }
}

/// View of the Anthropic SSE frames we consume. Only the fields we act on are
/// declared; unknown fields are ignored.
///
/// Each string field is an owned `String` (not a borrowed `&str`) — this is
/// the crux of HIPAA integrity finding N1: a borrowed `&str` cannot represent
/// a JSON string that needs unescaping (`\n`, `\"`, `\\`, `\uXXXX`, …), so any
/// note delta containing an escape used to fail to deserialize and be silently
/// dropped mid-stream. Owning the strings lets serde allocate-and-unescape so
/// every delta is preserved character-for-character.
#[derive(Deserialize)]
struct SseEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    delta: Option<SseDelta>,
    #[serde(default)]
    error: Option<SseErrorBody>,
}

#[derive(Deserialize)]
struct SseDelta {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct SseErrorBody {
    #[serde(default)]
    message: Option<String>,
}

impl LlmProvider for AnthropicProvider {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn keyring_user(&self) -> &str {
        KEYRING_USER
    }

    fn build_body(&self, system_prompt: &str, user_content: &str) -> Value {
        json!({
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "stream": true,
            "system": system_prompt,
            "messages": [
                {
                    "role": "user",
                    "content": user_content
                }
            ]
        })
    }

    fn apply_headers(&self, req: RequestBuilder, api_key: &str) -> RequestBuilder {
        req.header("x-api-key", api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
    }

    fn parse_frame(&self, data: &str) -> Result<StreamEvent, serde_json::Error> {
        let evt: SseEvent = serde_json::from_str(data)?;
        Ok(match evt.event_type.as_str() {
            "content_block_delta" => match evt.delta.and_then(|d| d.text) {
                Some(t) => StreamEvent::Delta(t),
                // Non-text delta (e.g. tool_use) — recognized, nothing to emit.
                None => StreamEvent::Ignore,
            },
            "error" => StreamEvent::Error(evt.error.and_then(|e| e.message)),
            // message_start, content_block_start, ping, content_block_stop,
            // message_delta, message_stop — none carry note text.
            _ => StreamEvent::Ignore,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> AnthropicProvider {
        AnthropicProvider::new(DEFAULT_MODEL.to_string())
    }

    // Convenience: run a frame through parse_frame and pull out the delta text
    // (the stream loop's `StreamEvent::Delta` arm), mirroring how generate_note
    // consumes frames.
    fn parse_delta_text(frame: &str) -> Option<String> {
        match provider().parse_frame(frame).unwrap() {
            StreamEvent::Delta(t) => Some(t),
            _ => None,
        }
    }

    #[test]
    fn build_body_has_expected_shape_and_model() {
        let p = AnthropicProvider::new("claude-test".into());
        let body = p.build_body("SYSTEM", "USER");
        assert_eq!(body["model"], "claude-test");
        assert_eq!(body["max_tokens"], MAX_TOKENS);
        assert_eq!(body["stream"], true);
        assert_eq!(body["system"], "SYSTEM");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "USER");
    }

    #[test]
    fn default_endpoint_and_model_are_the_legacy_values() {
        // Behavior-unchanged guard: a silent change to either default would
        // repoint every existing install. Force it through review.
        let p = provider();
        assert_eq!(p.endpoint(), "https://api.anthropic.com/v1/messages");
        assert_eq!(p.model(), "claude-haiku-4-5-20251001");
        assert_eq!(p.keyring_user(), "anthropic_api_key");
    }

    #[test]
    fn with_endpoint_overrides_the_default() {
        let p = AnthropicProvider::with_endpoint(
            "https://gateway.example/v1/messages".into(),
            "m".into(),
        );
        assert_eq!(p.endpoint(), "https://gateway.example/v1/messages");
    }

    // ── SSE parsing (moved from notes.rs; behavior must be identical) ────────

    #[test]
    fn sse_content_block_delta_yields_text() {
        let frame = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#;
        assert_eq!(parse_delta_text(frame).as_deref(), Some("Hello"));
    }

    #[test]
    fn sse_content_block_delta_without_text_is_ignored() {
        // Some upstream frames carry a non-text delta (e.g. tool_use). The
        // parser recognizes them and yields Ignore — no text emitted.
        let frame = r#"{"type":"content_block_delta","delta":{"type":"tool_use_delta"}}"#;
        assert!(matches!(
            provider().parse_frame(frame).unwrap(),
            StreamEvent::Ignore
        ));
    }

    #[test]
    fn sse_error_frame_yields_message() {
        let frame = r#"{"type":"error","error":{"type":"overloaded","message":"upstream busy"}}"#;
        match provider().parse_frame(frame).unwrap() {
            StreamEvent::Error(msg) => assert_eq!(msg.as_deref(), Some("upstream busy")),
            other => panic!("expected Error, got {}", event_name(&other)),
        }
    }

    #[test]
    fn sse_error_frame_without_message_is_none() {
        // Consumer maps None → "unknown" for local logging; the parser just
        // reports the absence.
        let frame = r#"{"type":"error","error":{"type":"overloaded"}}"#;
        match provider().parse_frame(frame).unwrap() {
            StreamEvent::Error(msg) => assert!(msg.is_none()),
            other => panic!("expected Error, got {}", event_name(&other)),
        }
    }

    #[test]
    fn sse_ping_and_other_events_are_ignored() {
        // Anthropic emits: message_start, content_block_start, ping,
        // content_block_stop, message_delta, message_stop. None carry note
        // text — all must parse to Ignore.
        for frame in [
            r#"{"type":"message_start","message":{"id":"msg_1","model":"claude-haiku-4-5"}}"#,
            r#"{"type":"content_block_start","index":0}"#,
            r#"{"type":"ping"}"#,
            r#"{"type":"content_block_stop","index":0}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#,
            r#"{"type":"message_stop"}"#,
        ] {
            assert!(
                matches!(provider().parse_frame(frame).unwrap(), StreamEvent::Ignore),
                "frame should be ignored: {frame}"
            );
        }
    }

    #[test]
    fn sse_delta_text_plain_ascii_round_trips() {
        let frame = r#"{"type":"content_block_delta","delta":{"text":"plain text"}}"#;
        assert_eq!(parse_delta_text(frame).as_deref(), Some("plain text"));
    }

    #[test]
    fn sse_malformed_json_is_a_parse_error() {
        // The consumer logs-and-skips parse errors (N1). We only need to know
        // that malformed input produces Err, not Ok(garbage).
        let frame = r#"{"type":"content_block_delta","delta":{"text":"missing_close""#;
        assert!(provider().parse_frame(frame).is_err());
    }

    // N1 (HIPAA §164.312(c)(1) Integrity) — regression tests. Escaped content
    // must deserialize into an owned String and survive character-for-character
    // rather than failing to parse and being silently dropped mid-stream.

    #[test]
    fn sse_delta_text_with_newline_survives_round_trip() {
        let frame =
            r#"{"type":"content_block_delta","delta":{"text":"Line one\nLine two"}}"#;
        assert_eq!(parse_delta_text(frame).as_deref(), Some("Line one\nLine two"));
    }

    #[test]
    fn sse_delta_text_with_embedded_quotes_survives_round_trip() {
        let frame =
            r#"{"type":"content_block_delta","delta":{"text":"Patient said \"I feel better\" today"}}"#;
        assert_eq!(
            parse_delta_text(frame).as_deref(),
            Some(r#"Patient said "I feel better" today"#)
        );
    }

    #[test]
    fn sse_delta_text_with_backslash_survives_round_trip() {
        let frame = r#"{"type":"content_block_delta","delta":{"text":"dosage 5\\10mg"}}"#;
        assert_eq!(parse_delta_text(frame).as_deref(), Some(r"dosage 5\10mg"));
    }

    #[test]
    fn sse_delta_text_with_tab_and_unicode_escape_survives_round_trip() {
        // \t and a \uXXXX escape both require unescaping. The escape decodes to
        // 'A' (U+0041).
        let frame =
            "{\"type\":\"content_block_delta\",\"delta\":{\"text\":\"col1\\tcol2 \\u0041\"}}";
        assert_eq!(parse_delta_text(frame).as_deref(), Some("col1\tcol2 A"));
    }

    #[test]
    fn sse_delta_text_with_multibyte_utf8_survives_round_trip() {
        let frame =
            "{\"type\":\"content_block_delta\",\"delta\":{\"text\":\"café ☕\\nnext\"}}";
        assert_eq!(parse_delta_text(frame).as_deref(), Some("café ☕\nnext"));
    }

    #[test]
    fn sse_full_escaped_note_reconstructs_across_deltas() {
        // End-to-end reconstruction across several deltas, some escaped,
        // concatenated exactly as the stream loop does into `full`.
        let frames = [
            r#"{"type":"content_block_delta","delta":{"text":"S: Patient reports \"feeling low\".\n"}}"#,
            r#"{"type":"content_block_delta","delta":{"text":"O: Affect flat.\tMood 3/10.\n"}}"#,
            r#"{"type":"content_block_delta","delta":{"text":"A/P: Continue plan; path C:\\notes."}}"#,
        ];
        let mut full = String::new();
        for frame in frames {
            let t = parse_delta_text(frame).expect("every delta must parse and carry text");
            full.push_str(&t);
        }
        let expected = "S: Patient reports \"feeling low\".\n\
                        O: Affect flat.\tMood 3/10.\n\
                        A/P: Continue plan; path C:\\notes.";
        assert_eq!(full, expected);
    }

    #[test]
    fn sse_malformed_frame_does_not_prevent_other_valid_frames() {
        // Mirror the loop's behavior: a bad frame is skipped while subsequent
        // valid frames are still consumed.
        let frames = [
            r#"{"type":"content_block_delta","delta":{"text":"good one\n"}}"#,
            r#"{"type":"content_block_delta","delta":{"text":"broken"#, // truncated
            r#"{"type":"content_block_delta","delta":{"text":"good two"}}"#,
        ];
        let p = provider();
        let mut full = String::new();
        let mut dropped = 0u64;
        for frame in frames {
            match p.parse_frame(frame) {
                Ok(StreamEvent::Delta(t)) => full.push_str(&t),
                Ok(_) => {}
                Err(_) => dropped += 1,
            }
        }
        assert_eq!(dropped, 1, "exactly one frame should be dropped");
        assert_eq!(full, "good one\ngood two");
    }

    // Small helper so the panic messages above name the unexpected variant
    // without requiring StreamEvent: Debug.
    fn event_name(e: &StreamEvent) -> &'static str {
        match e {
            StreamEvent::Delta(_) => "Delta",
            StreamEvent::Error(_) => "Error",
            StreamEvent::Ignore => "Ignore",
        }
    }
}
