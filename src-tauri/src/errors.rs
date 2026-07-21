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
    /// The Anthropic BAA acknowledgment gate has not been satisfied —
    /// note generation is refused because sending PHI to a non-BAA
    /// endpoint would be a §164.502 impermissible disclosure.
    BaaRequired,
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
    /// A rule the PROVIDER needs to know about refused the operation: a
    /// litigation hold blocking a deletion, an already-signed encounter
    /// refusing a re-sign, a signed note refusing a content overwrite.
    ///
    /// Distinct from `InvalidInput` because the JS side must treat the two
    /// oppositely. `InvalidInput` means the frontend has a bug and its text is
    /// meaningless to a clinician, so `userMessage` deliberately swallows it.
    /// That swallowing was applied to these messages too, so a provider blocked
    /// by a legal hold saw "Delete failed: unknown error" — the app knew
    /// exactly why and declined to say. This variant's message IS the
    /// explanation and is safe to show verbatim.
    PreconditionFailed(String),
    /// SQLite or filesystem I/O failure.
    Storage(String),
    /// Anything else — includes serde failures, bugs, and unknown OS errors.
    Internal(String),
}

impl AppError {
    fn code(&self) -> &'static str {
        match self {
            AppError::NoApiKey        => "no_api_key",
            AppError::BaaRequired     => "baa_required",
            AppError::NoModel         => "no_model",
            AppError::Network(_)      => "network",
            AppError::AuthFailed(_)   => "auth_failed",
            AppError::RateLimited     => "rate_limited",
            AppError::UpstreamApi(_)  => "upstream_api",
            AppError::UpstreamEmpty   => "upstream_empty",
            AppError::Transcription(_)=> "transcription",
            AppError::InvalidInput(_) => "invalid_input",
            AppError::PreconditionFailed(_) => "precondition_failed",
            AppError::Storage(_)      => "storage",
            AppError::Internal(_)     => "internal",
        }
    }
    fn message(&self) -> String {
        match self {
            AppError::NoApiKey        => "Anthropic API key not set.".into(),
            AppError::BaaRequired     => "Anthropic BAA acknowledgment required before note generation.".into(),
            AppError::NoModel         => "Whisper model not downloaded.".into(),
            AppError::Network(m)      => format!("Network error: {}", m),
            AppError::AuthFailed(m)   => format!("Anthropic auth failed: {}", m),
            AppError::RateLimited     => "Anthropic rate limit hit.".into(),
            AppError::UpstreamApi(m)  => format!("Anthropic API error: {}", m),
            AppError::UpstreamEmpty   => "Anthropic returned an empty response.".into(),
            AppError::Transcription(m)=> format!("Transcription failed: {}", m),
            AppError::InvalidInput(m) => format!("Invalid input: {}", m),
            // No prefix: this string is shown to the provider as-is.
            AppError::PreconditionFailed(m) => m.clone(),
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
    /// For rules the provider needs explained. The message is shown verbatim,
    /// so write it for a clinician, not for a log.
    pub(crate) fn precondition<S: Into<String>>(m: S)  -> Self { AppError::PreconditionFailed(m.into()) }
}

// Convenience: rusqlite errors always map to Storage (they're all disk/DB).
impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self { AppError::Storage(e.to_string()) }
}

// r2d2 pool checkout failures are also storage — same class as a rusqlite
// error. Having this impl means every `state.0.get().map_err(AppError::
// storage_from)?` site collapses to `state.0.get()?`, folding 21 identical
// lines across the KV/encounters/notes/audit surface into the pool call
// itself. Introduced during the ADR 0001 modularity pass.
impl From<r2d2::Error> for AppError {
    fn from(e: r2d2::Error) -> Self { AppError::Storage(e.to_string()) }
}
