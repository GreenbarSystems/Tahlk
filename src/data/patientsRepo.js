// Patients repository — the one place that knows the patient command names and
// argument shapes. Mirrors encountersRepo.js.
//
// provider_id is now derived server-side from the stored provider profile (audit
// finding C2). Previously this module read the profile from the KV cache and
// passed it as a parameter, which a compromised WebView could replace with any
// arbitrary string. The Rust commands now read note_provider_v1::profile directly
// from the DB so the audit trail actor identity cannot be forged from JS.

import { invoke } from '../platform/tauri.js';

export const patientsRepo = {
  list:   (limit = 200) => invoke('list_patients', { limit }),
  get:    id            => invoke('get_patient', { id }),
  save:   patient       => invoke('upsert_patient', { patient }),
  // Roster-only delete — removes the patients row and audit trail entry.
  // Does NOT cascade to linked encounters; use destroyRecords for that.
  delete: id            => invoke('delete_patient', { id }),
  // Permanently destroys all PHI for a patient: cascade-deletes every linked
  // encounter (note_audit scrubbed, note_history hard-deleted, each logged to
  // destruction_log), removes the patient roster row, and cleans up audio
  // files. Returns { encounters_destroyed: number }. Actor identity and audio
  // cleanup are handled server-side.
  destroyRecords:    id => invoke('destroy_patient_records', { patientId: id }),
  // Returns the number of encounters that WOULD be destroyed by destroyRecords.
  // Call this to show the provider a count before they confirm the irreversible action.
  countEncounters:   id => invoke('count_patient_encounters', { patientId: id }),
};
