// Encounters repository — the one place that knows the encounter command names
// and argument shapes. Presentation and domain code call these methods; they
// never see `invoke` or a command string. Swapping the backend (e.g. an HTTP
// API for the Group tier) means reimplementing this module only.
//
// delete() resolves the acting provider's identity here (same source as
// patientsRepo) so the destruction_log row records who performed the act.

import { invoke } from '../platform/tauri.js';
import { kvGet } from '../core/storageBackend.js';
import { keys } from './keys.js';

function currentProviderId() {
  return (kvGet(keys.provider()) || {}).name || 'provider';
}

export const encountersRepo = {
  list:  (limit = 50) => invoke('list_encounters', { limit }),
  get:   id           => invoke('get_encounter', { id }),
  stats: today        => invoke('encounter_stats', { today }),
  save:  encounter    => invoke('upsert_encounter', { encounter }),
  markSigned: (id, signedAt, signedHash) =>
    invoke('mark_encounter_signed', { id, signedAt, signedHash }),
  // Permanently destroys the encounter: removes the encounters row, note/
  // transcript KV content, and audio. Scrubs PHI from note_audit (tombstone
  // + encounter_id blinding), hard-deletes note_history, and appends to the
  // append-only destruction_log. llm_audit rows (metadata only, no PHI) are
  // retained. All SQL writes are atomic in one transaction.
  delete: id => invoke('delete_encounter', { id, providerId: currentProviderId() }),
  // Delete the .wav file on disk. Idempotent: resolves to `true` if a file
  // was removed, `false` if nothing was there. Does NOT touch the DB row —
  // callers pair this with clearAudioPath so the row and disk stay in sync.
  deleteAudio:     encounterId => invoke('delete_session_audio', { encounterId }),
  clearAudioPath:  id          => invoke('clear_encounter_audio_path', { id }),
};
