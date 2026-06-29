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
};
