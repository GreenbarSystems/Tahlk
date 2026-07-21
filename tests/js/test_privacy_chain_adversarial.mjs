// Adversarial tests for the tamper-evident note-history and audit chains.
//
// These go BEYOND tests/js/test_contentHash.mjs and test_verifyAllChains.mjs
// (which cover single-entry tampering and prevHash breaks). Here we model a
// motivated local attacker who has gained WRITE access to the SQLite DB (a
// realistic threat for a local-first desktop app: a compromised WebView, a
// second process running as the same user, or malware) and ask: which
// tamperings does chain verification actually catch, and which slip through?
//
// The goal is twofold:
//   1. Prove the protections that MUST hold do hold (content edit, reorder,
//      splice) — regression guards.
//   2. Pin the KNOWN LIMITS of a self-anchored hash chain so they are explicit,
//      documented, and can't silently widen: trailing truncation and wholesale
//      substitution are NOT detectable by internal verification alone. These
//      assertions encode the current behavior and point at the remediation
//      (anchor the tail to a signed/keychained root — see remediation plan).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  hashHistoryEntry,
  verifyHistoryChain,
  hashAuditEntry,
  verifyAuditChain,
  computeNoteHash,
} from '../../src/utils/contentHash.js';

// Build a well-formed note-history chain of the given actions, each hashed and
// linked exactly the way the non-Tauri append path (and the Rust server path)
// produce it. Returns a fresh array the caller can then tamper with.
async function buildChain(actions) {
  const chain = [];
  let prevHash = null;
  for (let i = 0; i < actions.length; i++) {
    const entry = {
      action: actions[i],
      actor: 'Dr. Smith',
      timestamp: `2026-01-0${i + 1}T10:00:00.000Z`,
      contentHash: `contenthash-${i}`,
      notes: '',
      prevHash,
    };
    entry.entryHash = await hashHistoryEntry(entry, prevHash);
    chain.push(entry);
    prevHash = entry.entryHash;
  }
  return chain;
}

// ── Protections that MUST hold ────────────────────────────────────────────

test('ATTACK content-edit: mutating a signed entry field is caught', async () => {
  const chain = await buildChain(['generated', 'edited', 'signed']);
  // Attacker rewrites the attested contentHash on the signed entry but leaves
  // the stored entryHash in place, hoping verification only checks linkage.
  chain[2].contentHash = 'forged-content-after-signing';
  const v = await verifyHistoryChain(chain);
  assert.equal(v.ok, false, 'a mutated attested field must break verification');
  assert.equal(v.brokenAt, 2);
  assert.equal(v.reason, 'entryHash mismatch');
});

test('ATTACK recompute-single: recomputing one entryHash desyncs the next link', async () => {
  const chain = await buildChain(['generated', 'edited', 'signed']);
  // Smarter attacker: edits entry 1 AND recomputes its entryHash so the entry
  // is internally consistent — but does not (cannot cheaply) fix entry 2's
  // prevHash, which still points at the original hash.
  chain[1].contentHash = 'forged';
  chain[1].entryHash = await hashHistoryEntry(chain[1], chain[1].prevHash);
  const v = await verifyHistoryChain(chain);
  assert.equal(v.ok, false, 'a locally-consistent edit must still break the forward link');
  assert.equal(v.reason, 'prevHash does not chain to prior entry');
  assert.equal(v.brokenAt, 2);
});

test('ATTACK reorder: swapping two entries breaks the chain', async () => {
  const chain = await buildChain(['generated', 'edited', 'signed']);
  const [a, b] = [chain[0], chain[1]];
  chain[0] = b;
  chain[1] = a;
  const v = await verifyHistoryChain(chain);
  assert.equal(v.ok, false, 'reordering must be detected');
});

test('ATTACK splice-middle: removing an interior entry breaks linkage', async () => {
  const chain = await buildChain(['generated', 'edited', 'edited', 'signed']);
  chain.splice(1, 1); // drop one interior 'edited'
  const v = await verifyHistoryChain(chain);
  assert.equal(v.ok, false, 'removing an interior entry must break the chain');
  assert.equal(v.reason, 'prevHash does not chain to prior entry');
});

// ── KNOWN LIMITS of a self-anchored chain (documented, not yet remediated) ──

test('LIMIT trailing-truncation: dropping the LAST entry still verifies ok', async () => {
  // The signed attestation is the final entry. An attacker who deletes it (to
  // make a signed note look like an unsigned draft, or to remove evidence of a
  // later edit) leaves a shorter but still internally-consistent chain.
  const full = await buildChain(['generated', 'edited', 'signed']);
  const truncated = full.slice(0, 2); // remove the 'signed' entry
  const v = await verifyHistoryChain(truncated);
  // This documents the gap: internal verification CANNOT see a missing tail,
  // because a prefix of a valid chain is itself a valid chain.
  assert.equal(v.ok, true,
    'FYI/known-limit: trailing truncation is invisible to internal chain verification');
  // Remediation lever: the count is the only signal. A verifier that also knew
  // the expected tail length (anchored elsewhere) would catch this.
  assert.equal(truncated.length, 2);
});

test('LIMIT wholesale-substitution: a freshly forged self-consistent chain verifies ok', async () => {
  // The deepest limitation: the chain proves INTERNAL CONSISTENCY, not
  // AUTHENTICITY. An attacker with DB write access can discard the real chain
  // and author a brand-new one over fabricated content — every hash and link
  // is valid because the attacker computed them the same way the app does.
  const forged = await buildChain(['generated', 'signed']);
  forged[0].contentHash = 'entirely-fabricated-note';
  forged[0].entryHash = await hashHistoryEntry(forged[0], null);
  forged[1].prevHash = forged[0].entryHash;
  forged[1].contentHash = 'fabricated-attestation';
  forged[1].entryHash = await hashHistoryEntry(forged[1], forged[0].entryHash);
  const v = await verifyHistoryChain(forged);
  assert.equal(v.ok, true,
    'FYI/known-limit: a self-anchored chain has no external root, so a forged replacement passes');
  // Remediation lever: bind the genesis prevHash (or the signed entryHash) to a
  // value the attacker cannot recompute — an HMAC keyed by the keychain DEK, or
  // a per-encounter signature — so a fabricated chain fails to reproduce it.
});

// ── Audit chain (generic details-carrying entries) ─────────────────────────

test('ATTACK audit-detail-tamper: mutating a details field is caught', async () => {
  // hashAuditEntry hashes the entry's OWN keys, so a variable detail field
  // (reason, removed, format...) can't be edited invisibly. Prove it.
  const e0 = { action: 'note_signed', actor: 'Dr. Smith', ts: '2026-01-01', prevHash: null };
  e0.entryHash = await hashAuditEntry(e0, null);
  const e1 = { action: 'audio_deleted', actor: 'Dr. Smith', ts: '2026-01-02', reason: 'retention_expired', prevHash: e0.entryHash };
  e1.entryHash = await hashAuditEntry(e1, e0.entryHash);
  const log = [e0, e1];

  // sanity: intact log verifies
  assert.equal((await verifyAuditChain(log)).ok, true);

  // Attacker rewrites the reason on the disposal record to hide why PHI was
  // destroyed, leaving entryHash in place.
  log[1].reason = 'patient_request';
  const v = await verifyAuditChain(log);
  assert.equal(v.ok, false, 'a mutated details field must break the audit chain');
  assert.equal(v.reason, 'entryHash mismatch');
});

test('LIMIT audit allowPartial can be abused to accept a forged first entry', async () => {
  // allowPartial exists for legitimately-truncated live logs (oldest entries
  // archived). But it trusts the first entry's stated prevHash as an external
  // anchor without verifying it — so a forged tail with a made-up prevHash is
  // accepted under allowPartial. Full verification requires walking
  // archive+live together (verifyAuditChain([...archive, ...live])).
  const forged = { action: 'note_signed', actor: 'X', ts: '2026-01-01', prevHash: 'anchor-that-was-never-verified' };
  forged.entryHash = await hashAuditEntry(forged, 'anchor-that-was-never-verified');
  const vStrict = await verifyAuditChain([forged]); // default: strict
  assert.equal(vStrict.ok, false, 'strict mode rejects a non-null first prevHash');
  const vPartial = await verifyAuditChain([forged], { allowPartial: true });
  assert.equal(vPartial.ok, true,
    'FYI/known-limit: allowPartial trusts the first prevHash; only archive+live verification is complete');
});

// ── Sign-off attestation (computeNoteHash) ─────────────────────────────────

test('ATTACK post-sign-edit: any change to note or transcript changes the attestation', async () => {
  const base = { transcript: 'pt reports SI resolved', noteContent: 'Risk: low', signedBy: 'Dr. Smith', encounterId: 'enc-1' };
  const signed = await computeNoteHash(base);
  // Every field an attacker might alter after signing must move the hash.
  assert.notEqual(await computeNoteHash({ ...base, noteContent: 'Risk: high' }), signed, 'note edit undetected');
  assert.notEqual(await computeNoteHash({ ...base, transcript: 'pt reports SI active' }), signed, 'transcript edit undetected');
  assert.notEqual(await computeNoteHash({ ...base, signedBy: 'Dr. Jones' }), signed, 'signer swap undetected');
  assert.notEqual(await computeNoteHash({ ...base, encounterId: 'enc-2' }), signed, 'encounter reassignment undetected');
});
