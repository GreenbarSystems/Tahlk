// BAA acknowledgment repository — thin JS wrapper over the Rust `baa_ack_*`
// commands. The gate itself is enforced in Rust (see src-tauri/src/baa.rs)
// before any Anthropic network I/O; this file exists so the onboarding
// modal and Settings pane can *reflect* and *update* that state without
// touching the KV table directly.
//
// The write-only contract lives in Rust: JS supplies `acknowledged`,
// `acknowledged_at` (ISO-8601 string), and `provider_id`. Rust stamps
// `attestation_version` on the row itself so a compromised WebView can't
// forge a satisfied ack under an outdated attestation.
//
// `BAA_ATTESTATION_VERSION` MUST stay in lockstep with the same-named
// constant in `src-tauri/src/baa.rs`. Bumping this is the mechanism by
// which we invalidate all outstanding acks (e.g. after material BAA
// terms change) and force every provider through the modal again.

import { invoke } from '../platform/tauri.js';

/**
 * Version stamp for the current BAA text. Bumping this on either side
 * (Rust or JS) will cause `getStatus()` to return `{ acknowledged: false }`
 * for every existing ack row on the next launch, forcing re-attestation.
 *
 * Keep in sync with `ATTESTATION_VERSION` in `src-tauri/src/baa.rs`.
 */
export const BAA_ATTESTATION_VERSION = 1;

export const baaRepo = {
  /**
   * Fetch the current ack (null if the user has never attested, or if
   * the row is stale relative to the current attestation version).
   *
   * @returns {Promise<null | {
   *   acknowledged: boolean,
   *   acknowledged_at: string,
   *   provider_id: string,
   *   attestation_version: number,
   * }>}
   */
  getStatus: () => invoke('baa_ack_status'),

  /**
   * Record an ack. `providerId` is free-form (name/email — whatever the
   * provider considers the signing identity for this device). It is
   * length-clamped in Rust to 256 bytes and appears in the local audit
   * trail so the sign-off is traceable to a human.
   *
   * @param {{acknowledgedAt: string, providerId: string}} args
   */
  setAck: ({ acknowledgedAt, providerId }) => invoke('baa_ack_set', {
    acknowledged: true,
    acknowledgedAt,
    providerId: providerId ?? '',
  }),

  /**
   * Clear the ack. Used when a provider needs to re-attest (renegotiated
   * BAA, device transfer, or manual revocation from Settings). Idempotent.
   */
  clear: () => invoke('baa_ack_clear'),
};
