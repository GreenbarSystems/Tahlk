// Record retention repository — HIPAA data-lifecycle management.
//
// Wraps the Rust retention commands (src-tauri/src/retention.rs).
//
// retention_years: how long encounter records are kept before they become
//   eligible for destruction (HIPAA minimum is 6 years; default is 7).
// litigation_hold: when active, no records are eligible for automated
//   destruction regardless of age.
// listCandidates(today): list encounters past the retention cutoff.
// destroyEligible(today): permanently destroy all expired encounters.
//
// today must be "YYYY-MM-DD" — callers pass new Date().toISOString().slice(0,10).

import { invoke } from '../platform/tauri.js';
import { kvGet } from '../core/storageBackend.js';
import { keys } from './keys.js';

function currentProviderId() {
  return (kvGet(keys.provider()) || {}).name || 'provider';
}

export const retentionRepo = {
  getYears:        ()      => invoke('retention_get_years'),
  setYears:        years   => invoke('retention_set_years', { years }),
  getHold:         ()      => invoke('retention_hold_get'),
  setHold:         active  => invoke('retention_hold_set', { active }),
  listCandidates:  today   => invoke('retention_list_candidates', { today }),
  destroyEligible: today   => invoke('retention_destroy_eligible', {
    today,
    providerId: currentProviderId(),
  }),
};
