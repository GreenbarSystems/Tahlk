// User-facing alert for a failed tamper-evident integrity check on a signed note.
//
// The clinician sees plain, actionable language (S-UX-4): "audit chain" and other
// developer terminology mean nothing at a support-critical moment. The technical
// mismatch detail (which entry itself failed, and why) is preserved in the opt-in
// diagnostics log for support/debugging — it just no longer surfaces in the toast.

import { toast } from '../utils/format.js';
import * as telemetry from '../core/telemetry.js';

export const INTEGRITY_FAILURE_MESSAGE =
  '⚠ This signed note may have been changed on disk. Contact support before relying on it.';

// Record the technical detail (opt-in, PHI-scrubbed) and show the plain-language toast.
export function reportIntegrityFailure(integrity) {
  const reason = integrity && integrity.reason ? integrity.reason : 'integrity check failed';
  const at = integrity && Number.isFinite(integrity.brokenAt) ? ` (entry ${integrity.brokenAt})` : '';
  telemetry.recordError('integrity', `${reason}${at}`);
  toast(INTEGRITY_FAILURE_MESSAGE, 6000);
}
