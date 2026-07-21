// H-8 regression: a lawfully scrubbed audit row must not read as tampering.
//
// delete_encounter_in_tx replaces note_audit.entry_json with a destruction
// tombstone while deliberately preserving the chain columns, and the code
// comment claimed the trail "stays tamper-evident even after the PHI content
// is wiped". It did not. entryHash is a hash OVER the content, so once the
// content is gone the verifier recomputes a different value and reports
// "entryHash mismatch" — the identical verdict a malicious rewrite produces.
// A check that cannot tell a lawful scrub from a forgery is not tamper
// evidence.
//
// Rust now flags the row and re-attaches its chain fields from the columns.
// The verifier skips the unreproducible CONTENT hash for those rows while
// still enforcing LINKAGE, so the chain is walkable across a destruction and
// the discontinuity is explicit.

import { test } from 'node:test';
import assert from 'node:assert/strict';

const { hashAuditEntry, verifyAuditChain } = await import('../../src/utils/contentHash.js');

// Build a genuine 3-entry chain the way the Rust appender does.
async function buildChain() {
  const out = [];
  let prev = null;
  for (const action of ['record_viewed', 'note_edited', 'note_signed']) {
    const entry = { action, actor: 'Dr. Chen', actorId: 'solo', timestamp: `2026-07-2${out.length}T00:00:00Z` };
    const entryHash = await hashAuditEntry(entry, prev);
    out.push({ ...entry, prevHash: prev, entryHash });
    prev = entryHash;
  }
  return out;
}

// What entries_from returns for a scrubbed row: tombstone content, chain
// fields re-attached from the columns, scrubbed flag set.
function scrubInPlace(chain, i) {
  chain[i] = {
    destroyed: true,
    destroyed_at: '2026-07-21T00:00:00Z',
    legal_basis: 'provider_request',
    prevHash: chain[i].prevHash,
    entryHash: chain[i].entryHash,
    scrubbed: true,
  };
}

test('an intact chain verifies', async () => {
  const chain = await buildChain();
  const v = await verifyAuditChain(chain);
  assert.equal(v.ok, true);
  assert.equal(v.scrubbedSkipped, 0);
});

test('a scrubbed middle entry does not break the chain', async () => {
  const chain = await buildChain();
  scrubInPlace(chain, 1);

  const v = await verifyAuditChain(chain);
  assert.equal(v.ok, true, 'a lawful destruction must not read as tampering');
  assert.equal(v.scrubbedSkipped, 1, 'and must be reported as unverifiable content, not hidden');
});

test('every entry scrubbed still verifies as linked', async () => {
  // The state after an encounter is fully destroyed.
  const chain = await buildChain();
  chain.forEach((_, i) => scrubInPlace(chain, i));

  const v = await verifyAuditChain(chain);
  assert.equal(v.ok, true);
  assert.equal(v.scrubbedSkipped, 3);
});

test('tampering with an UNSCRUBBED entry is still caught', async () => {
  const chain = await buildChain();
  chain[1] = { ...chain[1], actor: 'Someone Else' };

  const v = await verifyAuditChain(chain);
  assert.equal(v.ok, false);
  assert.equal(v.reason, 'entryHash mismatch');
  assert.equal(v.brokenAt, 1);
});

test('breaking LINKAGE is caught even when the row is scrubbed', async () => {
  // The exemption covers content only. If it covered linkage too, a scrubbed
  // row would become a hole an attacker could splice a forged chain through.
  const chain = await buildChain();
  scrubInPlace(chain, 1);
  chain[1].prevHash = 'not-the-previous-hash';

  const v = await verifyAuditChain(chain);
  assert.equal(v.ok, false, 'a scrubbed row must still have to chain correctly');
  assert.equal(v.reason, 'prevHash does not chain to prior entry');
  assert.equal(v.brokenAt, 1);
});

test('a scrubbed row cannot be used to hide a successor break', async () => {
  const chain = await buildChain();
  scrubInPlace(chain, 1);
  chain[2] = { ...chain[2], prevHash: 'wrong' };

  const v = await verifyAuditChain(chain);
  assert.equal(v.ok, false);
  assert.equal(v.brokenAt, 2);
});
