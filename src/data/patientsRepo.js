// Patients repository — the one place that knows the patient command names and
// argument shapes. Presentation and domain code call these methods; they never
// see `invoke` or a command string. Mirrors encountersRepo.js.
//
// save()/delete() resolve the acting provider's identity here and pass it as
// providerId — the Rust side writes it into a patient_audit row in the same
// transaction as the mutation (audit finding H2: patient CRUD previously had
// no audit trail at all). Sourced from the provider profile set at onboarding
// (matches baa.rs's provider_id sourcing in settingsModal.js), not
// capabilities.currentUser() — that hook is a Group-tier stub returning null
// in Solo, which would collapse every entry to the same generic fallback.

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
  delete: id            => invoke('delete_patient', { id, providerId: currentProviderId() }),
};
