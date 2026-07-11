// Unit tests for the read-only cross-encounter chain-integrity sweep
// (domain/historyChain.js::verifyAllChains). Mocks the Tauri `invoke` bridge
// so this exercises the real orchestration logic — discovering encounter
// ids, fetching each chain, aggregating verdicts — against fake but
// realistic note_history rows, without needing a live SQLite/Tauri runtime.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { hashHistoryEntry } from '../../src/utils/contentHash.js';

// In-memory fake of the note_history table, keyed by encounter_id. Tests
// populate this directly instead of going through appendHistoryEntry, since
// the point is to test verifyAllChains' own discovery + aggregation, not
// the write path (which already has its own coverage in test_contentHash.mjs
// and the Rust append_history_row tests).
let fakeTable = new Map();

globalThis.__TAHLK_TEST_TAURI__ = {
  core: {
    invoke: (command, args) => {
      if (command === 'note_history_list_encounter_ids') {
        return Promise.resolve([...fakeTable.keys()].sort());
      }
      if (command === 'note_history_list') {
        return Promise.resolve(fakeTable.get(args.encounterId) ?? []);
      }
      return Promise.reject(new Error(`unexpected invoke: ${command}`));
    },
  },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

const { verifyAllChains } = await import('../../src/domain/historyChain.js');

// Build a valid two-entry chain the same way appendHistoryEntry would.
async function buildValidChain() {
  const e1 = { action: 'generated', actor: 'AI', timestamp: '2026-01-01T00:00:00Z', contentHash: 'c1', notes: '' };
  e1.prevHash = null;
  e1.entryHash = await hashHistoryEntry(e1, null);

  const e2 = { action: 'signed', actor: 'Dr. Smith', timestamp: '2026-01-01T00:01:00Z', contentHash: 'c2', notes: 'attested' };
  e2.prevHash = e1.entryHash;
  e2.entryHash = await hashHistoryEntry(e2, e2.prevHash);

  return [e1, e2];
}

beforeEach(() => {
  fakeTable = new Map();
});

test('an empty table reports zero checked and ok:true', async () => {
  const result = await verifyAllChains();
  assert.equal(result.ok, true);
  assert.equal(result.checked, 0);
  assert.deepEqual(result.broken, []);
  assert.deepEqual(result.results, []);
});

test('a single intact chain verifies clean', async () => {
  fakeTable.set('enc-1', await buildValidChain());
  const result = await verifyAllChains();
  assert.equal(result.ok, true);
  assert.equal(result.checked, 1);
  assert.deepEqual(result.broken, []);
  assert.equal(result.results[0].encounterId, 'enc-1');
  assert.equal(result.results[0].ok, true);
});

test('multiple intact chains across different encounters all verify clean', async () => {
  fakeTable.set('enc-1', await buildValidChain());
  fakeTable.set('enc-2', await buildValidChain());
  fakeTable.set('enc-3', await buildValidChain());
  const result = await verifyAllChains();
  assert.equal(result.ok, true);
  assert.equal(result.checked, 3);
  assert.deepEqual(result.broken, []);
});

// The core regression this feature exists to catch: an encounter whose
// stored chain was corrupted out-of-band (simulating a migration bug or a
// manual DB edit) with NO new write ever happening afterward — the scenario
// the write-time-only checks in appendHistoryEntry/note_history_append
// cannot see.
test('detects a tampered entry in one encounter while others stay clean', async () => {
  const good = await buildValidChain();
  const tampered = await buildValidChain();
  tampered[1].contentHash = 'tampered-out-of-band'; // entryHash no longer matches

  fakeTable.set('enc-good', good);
  fakeTable.set('enc-bad', tampered);

  const result = await verifyAllChains();
  assert.equal(result.ok, false);
  assert.equal(result.checked, 2);
  assert.equal(result.broken.length, 1);
  assert.equal(result.broken[0].encounterId, 'enc-bad');
  assert.equal(result.broken[0].brokenAt, 1);
  assert.match(result.broken[0].reason, /mismatch/);

  // The good encounter's own verdict must still report ok — one broken
  // chain must not poison the aggregate per-encounter results.
  const goodResult = result.results.find(r => r.encounterId === 'enc-good');
  assert.equal(goodResult.ok, true);
});

test('detects a broken prevHash link (a chain that was spliced/reordered)', async () => {
  const chain = await buildValidChain();
  chain[1].prevHash = 'not-the-real-previous-hash';
  chain[1].entryHash = await hashHistoryEntry(chain[1], chain[1].prevHash);
  fakeTable.set('enc-spliced', chain);

  const result = await verifyAllChains();
  assert.equal(result.ok, false);
  assert.equal(result.broken[0].encounterId, 'enc-spliced');
});

test('an encounter with only legacy (pre-hash-chain) entries is not flagged broken', async () => {
  // Legacy rows migrated from the old KV blob may have empty entry_hash;
  // verifyHistoryChain treats these as "legacySkipped", not a failure.
  fakeTable.set('enc-legacy', [
    { action: 'generated', actor: 'AI', timestamp: '2025-01-01T00:00:00Z', contentHash: 'c0', notes: '', entryHash: '' },
  ]);
  const result = await verifyAllChains();
  assert.equal(result.ok, true);
  assert.equal(result.results[0].legacySkipped, 1);
});

// Bug-inject-and-revert: prove this test suite would actually fail if
// verifyAllChains regressed to only checking the first encounter (e.g. an
// accidental `return` inside the loop instead of pushing to results and
// continuing). This is a meta-test asserting the fixture itself is capable
// of catching that class of regression, not a test of production code.
test('fixture sanity: three distinct encounters really do reach the verifier independently', async () => {
  fakeTable.set('enc-a', await buildValidChain());
  fakeTable.set('enc-b', await buildValidChain());
  fakeTable.set('enc-c', await buildValidChain());
  const result = await verifyAllChains();
  const ids = result.results.map(r => r.encounterId).sort();
  assert.deepEqual(ids, ['enc-a', 'enc-b', 'enc-c']);
});
