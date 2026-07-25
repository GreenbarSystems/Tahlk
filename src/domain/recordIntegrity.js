// Whole-database record-integrity sweeps (audit finding #3).
//
// Two classes of check exist, and BOTH are needed (see audit_mac.rs):
//   - Hash-chain sweeps (verifyAllChains / verifyAllAuditChains) recompute each
//     stored entry's hash from its content and check the self-referential links.
//     They prove a chain is internally self-consistent.
//   - Keyed-MAC sweeps (verifyAllHistoryMacs / verifyAllAuditMacs) recompute
//     each row's chain_mac with the keychain-derived MAC key. They prove the
//     chain was not wholesale-substituted or forged by a party WITHOUT that key
//     — the exact attack a self-referential hash chain cannot detect.
//
// Before this module, the keyed-MAC sweeps had NO call site at all (note_audit)
// or ran only on a single panel open (note_history), so the substitution-
// detecting check effectively never ran in the shipped app. This wires them.

import { verifyAllChains, verifyAllHistoryMacs } from './historyChain.js';
import { verifyAllAuditChains, verifyAllAuditMacs } from '../core/auditLog.js';

function tag(list, kind) {
  return (list || []).map(b => ({ ...b, kind }));
}

// Thorough check for the user-initiated Settings "Check note records" action:
// all four sweeps. Runs them concurrently and merges the broken lists, tagging
// each with which trail/check flagged it. Returns { ok, checked, broken }.
export async function verifyAllRecordIntegrity() {
  const [histChain, auditChain, histMac, auditMac] = await Promise.all([
    verifyAllChains(),
    verifyAllAuditChains(),
    verifyAllHistoryMacs(),
    verifyAllAuditMacs(),
  ]);

  const broken = [
    ...tag(histChain.broken, 'note history'),
    ...tag(auditChain.broken, 'access log'),
    ...tag(histMac.broken, 'note history (substitution)'),
    ...tag(auditMac.broken, 'access log (substitution)'),
  ];

  // "checked" is the provider-facing count of note records examined; the access
  // and MAC sweeps cover the same encounters' trails, so the max is the honest
  // "records looked at" figure.
  const checked = Math.max(
    histChain.checked || 0,
    auditChain.checked || 0,
    histMac.checked || 0,
    auditMac.checked || 0,
  );

  return { ok: broken.length === 0, checked, broken };
}

// Lighter launch-time sweep: ONLY the two authoritative keyed-MAC sweeps (two
// IPC calls total), not the per-encounter hash-chain walks (which are 2N IPC
// calls and belong to the explicit Settings action). The keyed-MAC sweeps are
// the substitution-detecting checks the app previously never ran on launch.
export async function verifyRecordMacsOnLaunch() {
  const [histMac, auditMac] = await Promise.all([
    verifyAllHistoryMacs(),
    verifyAllAuditMacs(),
  ]);
  const broken = [
    ...tag(histMac.broken, 'note history (substitution)'),
    ...tag(auditMac.broken, 'access log (substitution)'),
  ];
  return { ok: broken.length === 0, broken };
}
