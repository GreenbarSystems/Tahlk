// Encounters repository — the one place that knows the encounter command names
// and argument shapes. Presentation and domain code call these methods; they
// never see `invoke` or a command string. Swapping the backend (e.g. an HTTP
// API for the Group tier) means reimplementing this module only.

import { invoke } from '../platform/tauri.js';

export const encountersRepo = {
  list:  (limit = 50) => invoke('list_encounters', { limit }),
  get:   id           => invoke('get_encounter', { id }),
  stats: today        => invoke('encounter_stats', { today }),
  save:  encounter    => invoke('upsert_encounter', { encounter }),
  markSigned: (id, signedAt, signedHash) =>
    invoke('mark_encounter_signed', { id, signedAt, signedHash }),
  // Permanently deletes the encounter row plus its note/transcript content
  // (the note_content_v1/note_content_v1::transcript KV rows) and any
  // residual on-disk audio. Deliberately does NOT delete note_history/
  // note_audit/llm_audit rows for this id — none of those store PHI
  // content (metadata + hashes only), and retaining them preserves the
  // compliance value of "this record existed and was deleted on this
  // date" even after the clinical content itself is gone.
  delete: id => invoke('delete_encounter', { id }),
  // Delete the .wav file on disk. Idempotent: resolves to `true` if a file
  // was removed, `false` if nothing was there. Does NOT touch the DB row —
  // callers pair this with clearAudioPath so the row and disk stay in sync.
  deleteAudio:     encounterId => invoke('delete_session_audio', { encounterId }),
  clearAudioPath:  id          => invoke('clear_encounter_audio_path', { id }),
};
