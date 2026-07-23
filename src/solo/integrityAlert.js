// User-facing alert for a failed tamper-evident integrity check on a signed note.
//
// The clinician sees plain, actionable language (S-UX-4): "audit chain" and other
// developer terminology mean nothing at a support-critical moment. The technical
// mismatch detail (which entry itself failed, and why) is preserved in the opt-in
// diagnostics log for support/debugging — it just no longer surfaces in the toast.
//
// No decorative glyph on this message by design: toast() renders via
// textContent (safe, but plain-text only), and an emoji-style ⚠ on a serious
// compliance alert reads as informal rather than urgent — the wording alone
// carries the severity.

import { toast } from '../utils/format.js';
import * as telemetry from '../core/telemetry.js';

export const INTEGRITY_FAILURE_MESSAGE =
  'This signed note may have been changed on disk. Contact support before relying on it.';

// Record the technical detail (opt-in, PHI-scrubbed) and show the plain-language toast.
export function reportIntegrityFailure(integrity) {
  const reason = integrity && integrity.reason ? integrity.reason : 'integrity check failed';
  const brokenAt = integrity && Number.isFinite(integrity.brokenAt) ? integrity.brokenAt : undefined;
  // Carry the detail in recordError's safe fields — `name` is the verifier's
  // static reason category (chain math, never patient data) and `code` is the
  // failing entry index — rather than a free-text message. recordError no
  // longer stores raw messages, so a hand-built string would just be dropped.
  telemetry.recordError('integrity', { name: reason, code: brokenAt });
  toast(INTEGRITY_FAILURE_MESSAGE, 6000);
}
