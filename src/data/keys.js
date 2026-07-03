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
  noteHistory:    id => `note_history_v1::${id}`,
  noteAudit:      id => `note_audit_v1::${id}`,
  customTemplate: id => `note_templates_v1::${id}`,
  telemetryEnabled: () => 'note_settings_v1::telemetry_enabled',
  audioRetention:   () => 'note_settings_v1::audio_retention',
  diagEvents:       () => 'note_diag_v1::events', // not in EAGER_PREFIXES — loaded on demand
};

// Per-encounter keys pulled into cache lazily when an encounter is opened.
export const encounterCacheKeys = id => [
  keys.noteContent(id),
  keys.noteTranscript(id),
  keys.noteHistory(id),
  keys.noteAudit(id),
];
