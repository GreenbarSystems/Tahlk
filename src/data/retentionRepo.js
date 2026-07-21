// Record retention repository — HIPAA data-lifecycle management.
//
// Wraps the Rust retention commands (src-tauri/src/retention.rs).
//
// retention_years: how long encounter records are kept before they become
//   eligible for destruction (HIPAA minimum is 6 years; default is 7).
// litigation_hold: when active, no records are eligible for automated
//   destruction regardless of age.
// listCandidates(): list signed encounters past the retention cutoff.
// destroyEligible(): permanently destroy all expired signed encounters.
//
// The cutoff date and actor identity are derived server-side; callers no
// longer pass today or providerId (High findings H1/H2, Medium finding M1).

import { invoke } from '../platform/tauri.js';

export const retentionRepo = {
  getYears:        ()     => invoke('retention_get_years'),
  setYears:        years  => invoke('retention_set_years', { years }),
  getHold:         ()     => invoke('retention_hold_get'),
  setHold:         active => invoke('retention_hold_set', { active }),
  listCandidates:  ()     => invoke('retention_list_candidates'),
  destroyEligible: ()     => invoke('retention_destroy_eligible'),
};
