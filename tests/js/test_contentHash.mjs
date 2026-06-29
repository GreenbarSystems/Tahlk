// Unit tests for the SHA-256 note attestation + tamper-evident history chain.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeNoteHash,
  hashHistoryEntry,
  verifyHistoryChain,
} from '../../src/utils/contentHash.js';

test('computeNoteHash is a 64-char hex digest', async () => {
  const h = await computeNoteHash({
    transcript: 'patient reports improved sleep',
    noteContent: 'SOAP note body',
    signedBy: 'Dr. Smith',
    encounterId: 'enc-1',
  });
  assert.match(h, /^[0-9a-f]{64}$/);
});

test('computeNoteHash is deterministic for identical input', async () => {
  const input = { transcript: 't', noteContent: 'n', signedBy: 's', encounterId: 'e' };
  assert.equal(await computeNoteHash(input), await computeNoteHash(input));
});

test('computeNoteHash changes when any field changes', async () => {
  const base = { transcript: 't', noteContent: 'n', signedBy: 's', encounterId: 'e' };
  const a = await computeNoteHash(base);
  const b = await computeNoteHash({ ...base, noteContent: 'n2' });
  assert.notEqual(a, b);
});

async function buildChain() {
  const e1 = { action: 'generated', actor: 'AI', timestamp: '2026-01-01T00:00:00Z', contentHash: 'c1', notes: '' };
  e1.prevHash = null;
  e1.entryHash = await hashHistoryEntry(e1, null);

  const e2 = { action: 'signed', actor: 'Dr. Smith', timestamp: '2026-01-01T00:01:00Z', contentHash: 'c2', notes: 'attested' };
  e2.prevHash = e1.entryHash;
  e2.entryHash = await hashHistoryEntry(e2, e2.prevHash);

  return [e1, e2];
}

test('verifyHistoryChain accepts a well-formed chain', async () => {
  const res = await verifyHistoryChain(await buildChain());
  assert.equal(res.ok, true);
});

test('verifyHistoryChain detects a tampered entry', async () => {
  const chain = await buildChain();
  chain[1].contentHash = 'tampered'; // entryHash no longer matches recomputed hash
  const res = await verifyHistoryChain(chain);
  assert.equal(res.ok, false);
  assert.equal(res.brokenAt, 1);
});

test('verifyHistoryChain detects a broken prevHash link', async () => {
  const chain = await buildChain();
  chain[1].prevHash = 'not-the-previous-hash';
  chain[1].entryHash = await hashHistoryEntry(chain[1], chain[1].prevHash);
  const res = await verifyHistoryChain(chain);
  assert.equal(res.ok, false);
});

test('verifyHistoryChain treats an empty history as valid', async () => {
  assert.equal((await verifyHistoryChain([])).ok, true);
});
