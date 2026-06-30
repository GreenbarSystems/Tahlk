// Patient records — explicit, locally-stored patient entities (note_patients_v1::).
// Sessions link to a patient by setting the encounter's patient_alias to the
// patient's name. Stored in the KV store, so it works in Tauri and in the browser
// preview alike.

import { kvGet, kvSet, kvRemove, kvList } from '../core/storageBackend.js';
import { genId } from '../utils/format.js';

const KEY = id => `note_patients_v1::${id}`;

export function listPatients() {
  return kvList('note_patients_v1::')
    .map(k => kvGet(k))
    .filter(Boolean)
    .sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
}

export function getPatient(id) {
  return kvGet(KEY(id));
}

export function savePatient(p) {
  const id       = p.id || genId('pt');
  const existing = p.id ? kvGet(KEY(id)) : null;
  const now      = new Date().toISOString();
  const rec = {
    mrn: '', dob: '', notes: '',
    ...p,
    id,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  kvSet(KEY(id), rec);
  return rec;
}

export function deletePatient(id) {
  kvRemove(KEY(id));
}
