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
  // note_audit is stored in a proper SQLite table now (see src-tauri/src/
  // note_audit.rs), with an `archived` column replacing the separate
  // archive key below. The legacy KV key formats are retained ONLY for the
  // non-Tauri fallback in core/auditLog.js and for tests that mock KV.
  noteAudit:      id => `note_audit_v1::${id}`,
  noteAuditArchive: id => `note_audit_archive_v1::${id}`,
  customTemplate: id => `note_templates_v1::${id}`,
  telemetryEnabled: () => 'note_settings_v1::telemetry_enabled',
  audioRetention:   () => 'note_settings_v1::audio_retention',
  // BAA acknowledgment for the Anthropic upstream. The Rust side (baa.rs)
  // owns the canonical read/write path via invoke('baa_ack_*'); this key is
  // named here purely for observability — nothing in JS should read the row
  // directly since the gate lives in Rust before any network I/O.
  baaAck:           () => 'note_settings_v1::baa_ack',
  diagEvents:       () => 'note_diag_v1::events', // not in EAGER_PREFIXES — loaded on demand
  // Idle-lock settings (enabled flag + timeout). The PIN itself is never
  // stored here — it lives only in the OS keychain via src-tauri/src/lock.rs,
  // same "never the kv table" discipline as the API key and the DEK.
  lockEnabled:        () => 'note_settings_v1::lock_enabled',
  lockTimeoutMinutes: () => 'note_settings_v1::lock_timeout_minutes',
};

// Per-encounter keys pulled into cache lazily when an encounter is opened.
// noteHistory and noteAudit are intentionally excluded — both now live in
// their own SQLite tables, loaded via note_history_list / audit_list, not
// the KV cache.
export const encounterCacheKeys = id => [
  keys.noteContent(id),
  keys.noteTranscript(id),
];
