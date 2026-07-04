//! Typed error at the IPC boundary.
//!
//! Every #[tauri::command] returns Result<T, AppError> so the JS side can
//! branch on a stable machine-readable `code` (open Settings on `no_api_key`,
//! prompt reconnect on `auth_failed`, offer retry on `network`) instead of
//! substring-matching the human message. The `message` field is still filled
//! in with the underlying diagnostic so logs remain useful.
//!
//! Serialization: serde emits `{ "code": "...", "message": "..." }` for every
//! variant (variants without their own message reuse a canonical default).
//! `Display` produces the same human line for Rust-side logging.
//!
//! Adding a new variant is a JS-side breaking change only if JS branches on
//! its code; new codes gracefully fall back to `userMessage`'s default.

use std::fmt;

#[derive(Debug)]
pub enum AppError {
    /// The Anthropic API key is not set in the OS keychain.
    NoApiKey,
    /// The Whisper model file is missing from resources.
    NoModel,
    /// Underlying HTTP transport error (DNS, TLS, timeout, connection reset).
    Network(String),
    /// Anthropic returned 401/403 — key is invalid or revoked.
    AuthFailed(String),
    /// Anthropic returned 429 — user should wait and retry.
    RateLimited,
    /// Anthropic returned a non-2xx that isn't 401/403/429.
    UpstreamApi(String),
    /// Empty or malformed streamed response from Anthropic.
    UpstreamEmpty,
    /// Whisper.cpp sidecar failed.
    Transcription(String),
    /// JS-supplied argument rejected by validation (path traversal, length cap,
    /// KV secret namespace, missing field). Never surfaced verbatim to end
    /// users — it means the frontend violated an invariant and is a bug.
    InvalidInput(String),
    /// SQLite or filesystem I/O failure.
    Storage(String),
    /// Anything else — includes serde failures, bugs, and unknown OS errors.
    Internal(String),
}

impl AppError {
    fn code(&self) -> &'static str {
        match self {
            AppError::NoApiKey        => "no_api_key",
            AppError::NoModel         => "no_model",
            AppError::Network(_)      => "network",
            AppError::AuthFailed(_)   => "auth_failed",
            AppError::RateLimited     => "rate_limited",
            AppError::UpstreamApi(_)  => "upstream_api",
            AppError::UpstreamEmpty   => "upstream_empty",
            AppError::Transcription(_)=> "transcription",
            AppError::InvalidInput(_) => "invalid_input",
            AppError::Storage(_)      => "storage",
            AppError::Internal(_)     => "internal",
        }
    }
    fn message(&self) -> String {
        match self {
            AppError::NoApiKey        => "Anthropic API key not set.".into(),
            AppError::NoModel         => "Whisper model not downloaded.".into(),
            AppError::Network(m)      => format!("Network error: {}", m),
            AppError::AuthFailed(m)   => format!("Anthropic auth failed: {}", m),
            AppError::RateLimited     => "Anthropic rate limit hit.".into(),
            AppError::UpstreamApi(m)  => format!("Anthropic API error: {}", m),
            AppError::UpstreamEmpty   => "Anthropic returned an empty response.".into(),
            AppError::Transcription(m)=> format!("Transcription failed: {}", m),
            AppError::InvalidInput(m) => format!("Invalid input: {}", m),
            AppError::Storage(m)      => format!("Storage error: {}", m),
            AppError::Internal(m)     => format!("Internal error: {}", m),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

// Manual Serialize impl instead of derive so we can control the wire shape and
// keep the enum variants free of #[serde] plumbing (they carry heterogeneous
// payloads, which #[serde(tag=...)] would require becoming struct-variants
// for). The Tauri JS side receives `{ code, message }` for every error.
impl serde::Serialize for AppError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("AppError", 2)?;
        st.serialize_field("code", self.code())?;
        st.serialize_field("message", &self.message())?;
        st.end()
    }
}

// Sugar so `foo().map_err(AppError::storage_from)?` reads clearly at call sites.
impl AppError {
    pub(crate) fn storage_from<E: fmt::Display>(e: E)  -> Self { AppError::Storage(e.to_string()) }
    pub(crate) fn internal_from<E: fmt::Display>(e: E) -> Self { AppError::Internal(e.to_string()) }
    pub(crate) fn invalid<S: Into<String>>(m: S)       -> Self { AppError::InvalidInput(m.into()) }
}

// Convenience: rusqlite errors always map to Storage (they're all disk/DB).
impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self { AppError::Storage(e.to_string()) }
}
