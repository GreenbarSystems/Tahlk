//! LLM provider abstraction for note generation.
//!
//! `notes::generate_note` owns everything provider-INDEPENDENT: the BAA gate,
//! the LLM audit log, bounded HTTP timeouts, the 1 MiB accumulator cap, the
//! prompt-injection guardrails, and the SSE streaming loop that emits
//! `scribe:note_chunk` events. This module owns everything provider-SPECIFIC:
//! the request body shape, the auth headers, the model/endpoint, and how one
//! `data:` SSE frame decodes into a normalized [`StreamEvent`].
//!
//! Today the only vendor is Anthropic (see [`anthropic`]). Adding another
//! (OpenAI, etc.) is a small, mechanical change:
//!   1. add a module `providers/<vendor>.rs` implementing [`LlmProvider`];
//!   2. add a variant to [`Provider`] and wire its `id`/`default_model`/
//!      `keyring_user`/factory arms;
//!   3. add the option to the Settings dropdown on the JS side.
//! No change to `generate_note` or the audit/BAA/timeout machinery is needed.
//!
//! NOTE: this `Provider` (the LLM vendor) is unrelated to the `provider_id` /
//! `note_provider_v1` concept elsewhere, which identifies the *clinician*.

pub(crate) mod anthropic;

use reqwest::RequestBuilder;
use rusqlite::{params, OptionalExtension};
use tauri::State;

use crate::DbState;

/// KV keys for the selected provider + model. Live under the same
/// `note_settings_v1::` prefix as the other app-wide settings (BAA ack,
/// onboarded, audio retention) so they load with the eager settings warmup
/// and are hidden from no keychain guard (they hold no secrets — only the
/// vendor id and model name; the API key stays in the OS keychain).
pub(crate) const LLM_PROVIDER_KEY: &str = "note_settings_v1::llm_provider";
pub(crate) const LLM_MODEL_KEY: &str = "note_settings_v1::llm_model";

/// One decoded SSE frame, normalized across vendors so the streaming loop in
/// `generate_note` never has to know a vendor's event taxonomy.
pub(crate) enum StreamEvent {
    /// A text delta to append to the note and emit as a `scribe:note_chunk`.
    Delta(String),
    /// An upstream-signalled error frame. The optional message is for LOCAL
    /// debug logging only (audit M10) — it must never reach the AppError.
    Error(Option<String>),
    /// A recognized frame we deliberately don't act on (ping, message_start,
    /// a non-text delta, …). The loop skips it.
    Ignore,
}

/// A note-generation LLM backend. Object-safe (used as `Box<dyn LlmProvider>`)
/// so the factory can return a single concrete type per selection without the
/// call site branching on the vendor.
///
/// Implementors are pure request-shape + response-parse adapters: they do NOT
/// perform I/O, own the HTTP client, touch the DB, or know about the BAA gate,
/// the audit log, or the streaming buffer. That keeps the compliance-critical
/// machinery in exactly one place regardless of how many vendors exist.
pub(crate) trait LlmProvider: Send + Sync {
    /// Full endpoint URL. Recorded verbatim in the audit log so a build
    /// pointed at a different host is visible after the fact.
    fn endpoint(&self) -> &str;

    /// Model identifier sent in the request body and recorded in the audit log.
    fn model(&self) -> &str;

    /// OS-keychain entry name (`keyring` "username") under which this
    /// provider's API key is stored, so switching providers reads a different
    /// saved key instead of forcing re-entry.
    fn keyring_user(&self) -> &str;

    /// Build the JSON request body. Returned as a `serde_json::Value` (rather
    /// than applied straight to a `RequestBuilder`) so `generate_note` can
    /// measure the serialized byte length for the audit row exactly once,
    /// using the same bytes that go on the wire.
    fn build_body(&self, system_prompt: &str, user_content: &str) -> serde_json::Value;

    /// Apply provider-specific auth/version headers to a request. Content-type
    /// is set by the caller's `.json(&body)`, so implementors only add what's
    /// unique to the vendor (e.g. `x-api-key` + `anthropic-version`).
    fn apply_headers(&self, req: RequestBuilder, api_key: &str) -> RequestBuilder;

    /// Decode one SSE `data:` payload into a normalized [`StreamEvent`].
    ///
    /// A returned `Err` means a genuinely malformed frame (truncated/corrupt
    /// JSON). `generate_note` logs it (metadata only — no PHI) and skips it,
    /// matching HIPAA integrity finding N1: the loss is observable, one bad
    /// frame can't kill the stream.
    fn parse_frame(&self, data: &str) -> Result<StreamEvent, serde_json::Error>;
}

/// The selectable LLM vendor. Distinct from the runtime `Box<dyn LlmProvider>`
/// implementation: this enum is the small, serializable identity parsed from
/// settings, and it owns the per-vendor constant lookups (id, default model,
/// keychain entry) plus the [`build`] factory arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Provider {
    Anthropic,
}

impl Provider {
    /// Parse the settings string id. Unknown ids return `None` so the caller
    /// falls back to the default rather than failing note generation.
    pub(crate) fn from_id(id: &str) -> Option<Self> {
        match id {
            "anthropic" => Some(Provider::Anthropic),
            _ => None,
        }
    }

    /// Stable string id persisted in settings and shown to the JS layer.
    pub(crate) fn id(&self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
        }
    }

    /// Default model when settings has none — preserves the previous
    /// hardcoded model so existing installs are unaffected.
    pub(crate) fn default_model(&self) -> &'static str {
        match self {
            Provider::Anthropic => anthropic::DEFAULT_MODEL,
        }
    }

    /// OS-keychain entry name for this provider's API key.
    pub(crate) fn keyring_user(&self) -> &'static str {
        match self {
            Provider::Anthropic => anthropic::KEYRING_USER,
        }
    }
}

/// Factory: map a selected [`Provider`] + model to a boxed [`LlmProvider`].
/// This one arm-per-vendor match is the single registration point — adding a
/// vendor is a new arm here plus its module.
pub(crate) fn build(provider: Provider, model: String) -> Box<dyn LlmProvider> {
    match provider {
        Provider::Anthropic => Box::new(anthropic::AnthropicProvider::new(model)),
    }
}

/// Read a JSON-encoded string setting from the `kv` table. Returns `None` for
/// a missing row, a non-string value, a checkout failure, or a blank string
/// (treated as unset so a stray empty write falls back to the default).
fn read_string_setting(state: &State<DbState>, key: &str) -> Option<String> {
    let conn = state.0.get().ok()?;
    let row: Option<String> = conn
        .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .optional()
        .ok()
        .flatten();
    row.and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|s| !s.trim().is_empty())
}

/// Resolve the selected provider from settings, defaulting to Anthropic so
/// an unset (or unrecognized) value leaves behavior unchanged.
pub(crate) fn selected_provider(state: &State<DbState>) -> Provider {
    read_string_setting(state, LLM_PROVIDER_KEY)
        .and_then(|id| Provider::from_id(&id))
        .unwrap_or(Provider::Anthropic)
}

/// Resolve provider + model from settings into a ready-to-use boxed
/// implementation. Falls back to the provider's default model when unset.
pub(crate) fn resolve(state: &State<DbState>) -> Box<dyn LlmProvider> {
    let provider = selected_provider(state);
    let model = read_string_setting(state, LLM_MODEL_KEY)
        .unwrap_or_else(|| provider.default_model().to_string());
    build(provider, model)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_id_round_trips() {
        for p in [Provider::Anthropic] {
            assert_eq!(Provider::from_id(p.id()), Some(p), "id round-trip for {p:?}");
        }
    }

    #[test]
    fn unknown_provider_id_is_none() {
        assert_eq!(Provider::from_id("openai"), None);
        assert_eq!(Provider::from_id(""), None);
        assert_eq!(Provider::from_id("Anthropic"), None, "id match is case-sensitive");
    }

    #[test]
    fn anthropic_defaults_match_legacy_constants() {
        // Behavior-unchanged guard: the default model + keychain entry must
        // equal what notes.rs/secrets.rs hardcoded before this refactor. A
        // silent drift here would repoint existing installs at a new model or
        // orphan their saved key.
        let a = Provider::Anthropic;
        assert_eq!(a.default_model(), "claude-haiku-4-5-20251001");
        assert_eq!(a.keyring_user(), "anthropic_api_key");
    }

    #[test]
    fn factory_builds_anthropic_with_requested_model() {
        let p = build(Provider::Anthropic, "claude-test-model".into());
        assert_eq!(p.model(), "claude-test-model");
        assert_eq!(p.endpoint(), anthropic::DEFAULT_ENDPOINT);
        assert_eq!(p.keyring_user(), "anthropic_api_key");
    }

    // The kv-backed resolvers (`selected_provider`, `resolve`) need a
    // `State<DbState>` harness we can't build in a unit test, so their happy
    // path is exercised at the integration level; the parsing/default logic
    // they depend on is covered by `from_id` + `default_model` above.
}
