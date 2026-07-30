// Adversarial tests for the audit hash chain.
//
// THESE TESTS FAIL ON PURPOSE as of the commit that introduces them. Each one
// pins a tampering scenario that the shipped verifier currently accepts as
// valid. They were written before the fixes, so the fixes are proven rather
// than asserted — the same discipline used for every other integrity control
// in this repo, applied in the order that actually demonstrates the property.
//
// Provenance: an external architecture audit executed six bypasses against an
// earlier build. Four still reproduce against current `main`, which was
// confirmed by executing them rather than by reading the code. A fifth is new
// and was introduced by the scrubbed-row handling added for lawful destruction.
//
// What is NOT covered here: forgery by an actor holding the SQLCipher DEK.
// `entryHash` is an unkeyed SHA-256 over public fields, so anyone who can read
// the key can recompute the whole chain. That is mitigated separately by the
// keyed MACs in `audit_mac.rs` and is formally accepted in AUDIT-RESIDUAL-RISK
// Item 3. This file covers the attacks that need NO key at all.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { verifyAuditChain, hashAuditEntry } from '../../src/utils/contentHash.js';

async function buildChain(n, encounterId = 'enc-1') {
  const out = [];
  let prev = null;
  for (let i = 0; i < n; i++) {
    const e = {
      action: 'note_edited',
      actor: 'Dr. Chen',
      actorId: 'solo',
      timestamp: `2026-07-30T0${i}:00:00.000Z`,
      encounterId,
      prevHash: prev,
    };
    e.entryHash = await hashAuditEntry(e, prev);
    out.push(e);
    prev = e.entryHash;
  }
  return out;
}

// ── Case 2: the downgrade bypass ───────────────────────────────────────────
//
// The cheapest attack on the chain, and the only one needing neither the key
// nor any cryptography. The verifier skips an entry that has no `entryHash`
// when the chain has not yet started; strip the field from EVERY entry and the
// loop never starts, so every row is skipped and the result is `ok: true`.
//
// An attacker does not forge the chain — they delete it and let the legacy
// escape hatch wave the remains through. Unlike truncation, this is not
// recorded anywhere as an accepted risk.

test('a chain with every entryHash stripped must NOT verify', async () => {
  const stripped = (await buildChain(3)).map(e => {
    const copy = { ...e };
    delete copy.entryHash;
    return copy;
  });

  const v = await verifyAuditChain(stripped);
  assert.equal(
    v.ok, false,
    'stripping entryHash from every entry currently downgrades the whole chain to "legacy" and passes — ' +
    'removing integrity metadata must never be a way to satisfy an integrity check',
  );
});

test('a chain that starts unhashed and later becomes hashed must NOT verify', async () => {
  // Prefix injection: prepend unhashed rows to a genuine chain. The prefix is
  // skipped as legacy, so fabricated history rides in front of real history.
  const genuine = await buildChain(2);
  const injected = [
    { action: 'note_signed', actor: 'Someone Else', actorId: 'solo',
      timestamp: '2026-07-29T00:00:00.000Z', encounterId: 'enc-1', prevHash: null },
    ...genuine,
  ];

  const v = await verifyAuditChain(injected);
  assert.equal(
    v.ok, false,
    'unhashed rows before the first hashed row are accepted, letting fabricated history be prepended',
  );
});

// ── Cases 3, 4, 6: deletion and truncation ─────────────────────────────────
//
// A MAC-valid prefix of a chain is still MAC-valid, so per-row hashing cannot
// detect that rows were removed from the end. Detecting it needs an anchor the
// chain is checked against — the expected entry count and head hash, persisted
// on the encounter row.
//
// This is partly accepted in AUDIT-RESIDUAL-RISK Item 3 on the grounds that the
// tamperer and the key-holder are the same party. That argument covers
// deliberate tampering. It does NOT cover accidental loss — a partial write, a
// failed restore, a truncated backup — where an empty or short history reads as
// a clean pass and nothing surfaces the discrepancy.

test('an empty history must NOT verify when the encounter claims entries', async () => {
  const v = await verifyAuditChain([], { expectedCount: 3 });
  assert.equal(
    v.ok, false,
    'a wiped history is currently indistinguishable from a clean one — verifyAuditChain([]) returns ok:true',
  );
});

test('a truncated chain must NOT verify against the expected head', async () => {
  const genuine = await buildChain(3);
  const truncated = genuine.slice(0, 2); // drop the newest entry

  const v = await verifyAuditChain(truncated, {
    expectedCount: genuine.length,
    expectedHead: genuine[genuine.length - 1].entryHash,
  });
  assert.equal(
    v.ok, false,
    'dropping the newest entries leaves a chain that verifies clean — truncation must be detectable',
  );
});

test('a genuine chain still verifies when checked against its own anchor', async () => {
  // Guards against over-correction: the anchor must not make valid chains fail.
  const genuine = await buildChain(3);
  const v = await verifyAuditChain(genuine, {
    expectedCount: 3,
    expectedHead: genuine[2].entryHash,
  });
  assert.equal(v.ok, true, 'a correct chain must pass when its anchor matches');
});

// ── Case 7: the scrubbed-row exemption ─────────────────────────────────────
//
// Introduced by this codebase, not by the original audit. A row marked
// `scrubbed` is exempt from content verification, because its content was
// lawfully destroyed and cannot be recomputed. The flag is a plain boolean on
// the row, so setting it on a REWRITTEN row exempts that rewrite from checking
// while leaving the linkage intact — the result reads as a clean pass.
//
// The exemption itself is legitimate and must stay. What is missing is any
// constraint on what a scrubbed row may contain: a genuine tombstone has a
// known shape, and anything else wearing the flag should be rejected.

test('a scrubbed row carrying rewritten content must NOT verify', async () => {
  const chain = (await buildChain(3)).map(e => ({ ...e }));
  chain[1].action = 'note_signed';      // rewrite the row's meaning
  chain[1].actor = 'Someone Else';
  chain[1].scrubbed = true;             // and exempt it from the content check

  const v = await verifyAuditChain(chain);
  assert.equal(
    v.ok, false,
    'the scrubbed flag currently exempts any row from content verification, including one that was rewritten — ' +
    'the exemption must be limited to rows that actually look like destruction tombstones',
  );
});

test('a genuine destruction tombstone still verifies', async () => {
  // The exemption exists for a real reason and must keep working: lawfully
  // destroyed content cannot be recomputed, and that is not a failure.
  const chain = (await buildChain(3)).map(e => ({ ...e }));
  chain[1] = { ...chain[1], destroyed: true, scrubbed: true };

  const v = await verifyAuditChain(chain);
  assert.equal(v.ok, true, 'a real tombstone must not be reported as tampering');
  assert.equal(v.scrubbedSkipped, 1, 'and must be reported as content-unverifiable, not silently passed');
});
