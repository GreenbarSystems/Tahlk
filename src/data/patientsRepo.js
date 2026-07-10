// Patients repository — the one place that knows the patient command names and
// argument shapes. Presentation and domain code call these methods; they never
// see `invoke` or a command string. Mirrors encountersRepo.js.

import { invoke } from '../platform/tauri.js';

export const patientsRepo = {
  list:   (limit = 200) => invoke('list_patients', { limit }),
  get:    id            => invoke('get_patient', { id }),
  save:   patient       => invoke('upsert_patient', { patient }),
  delete: id            => invoke('delete_patient', { id }),
};
