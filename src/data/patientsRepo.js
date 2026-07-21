// Patients repository — the one place that knows the patient command names and
// argument shapes. Presentation and domain code call these methods; they never
// see `invoke` or a command string. Mirrors encountersRepo.js.
//
// save()/delete() resolve the acting provider's identity here and pass it as
// providerId — the Rust side writes it into a patient_audit row in the same
// transaction as the mutation (audit finding H2: patient CRUD previously had
// no audit trail at all).
//
// Read straight from the provider profile set at onboarding, which is the same
// source settingsModal.js uses for the BAA ack's provider_id — so both audit
// trails name the actor identically rather than by two different rules.
// capabilities.currentUser() ultimately derives from that same profile (Solo's
// impl is installed in entry-solo.js), so this is not a divergence from it; it
// just takes the one field this repo needs, with a 'provider' fallback instead
// of currentUser()'s null-when-unset.

import { invoke } from '../platform/tauri.js';
import { kvGet } from '../core/storageBackend.js';
import { keys } from './keys.js';

function currentProviderId() {
  return (kvGet(keys.provider()) || {}).name || 'provider';
}

export const patientsRepo = {
  list:   (limit = 200) => invoke('list_patients', { limit }),
  get:    id            => invoke('get_patient', { id }),
  save:   patient       => invoke('upsert_patient', { patient, providerId: currentProviderId() }),
  // Roster-only delete — removes the patients row and audit trail entry.
  // Does NOT cascade to linked encounters; use destroyRecords for that.
  delete: id            => invoke('delete_patient', { id, providerId: currentProviderId() }),
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
