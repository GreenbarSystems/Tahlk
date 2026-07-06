// Single source of truth for SQLite KV key formats.
//
// Every note_* aggregate lives under its own versioned prefix. Centralizing the
// formats here means a storage-layout change happens in one file instead of
// being grepped across the editor, panel, and audit modules.

export const keys = {
  provider:       () => 'note_provider_v1::profile',
  onboarded:      () => 'note_settings_v1::onboarded',
  noteContent:    id => `note_content_v1::${id}`,
  noteTranscript: id => `note_content_v1::transcript::${id}`,
  // note_history is stored in a proper SQLite table now (see src-tauri/src/
  // note_history.rs). The legacy KV key format is retained ONLY for the
  // non-Tauri fallback in domain/historyChain.js and for tests that mock KV.
  noteHistory:    id => `note_history_v1::${id}`,
  noteAudit:      id => `note_audit_v1::${id}`,
  customTemplate: id => `note_templates_v1::${id}`,
  telemetryEnabled: () => 'note_settings_v1::telemetry_enabled',
  audioRetention:   () => 'note_settings_v1::audio_retention',
  // Selected LLM vendor + model for note generation. The Rust side
  // (providers/mod.rs) owns the canonical read/resolve path; these keys live
  // under note_settings_v1 so they load with the eager settings warmup. They
  // hold no secrets — only a vendor id and model name; the API key stays in the
  // OS keychain. Unrelated to `provider` above, which identifies the clinician.
  llmProvider:      () => 'note_settings_v1::llm_provider',
  llmModel:         () => 'note_settings_v1::llm_model',
  // BAA acknowledgment for the Anthropic upstream. The Rust side (baa.rs)
  // owns the canonical read/write path via invoke('baa_ack_*'); this key is
  // named here purely for observability — nothing in JS should read the row
  // directly since the gate lives in Rust before any network I/O.
  baaAck:           () => 'note_settings_v1::baa_ack',
  diagEvents:       () => 'note_diag_v1::events', // not in EAGER_PREFIXES — loaded on demand
};

// Per-encounter keys pulled into cache lazily when an encounter is opened.
// noteHistory is intentionally excluded — history now lives in its own
// SQLite table, loaded via note_history_list, not the KV cache.
export const encounterCacheKeys = id => [
  keys.noteContent(id),
  keys.noteTranscript(id),
  keys.noteAudit(id),
];
