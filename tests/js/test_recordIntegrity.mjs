// Unit tests for the whole-database record-integrity orchestrator
// (domain/recordIntegrity.js). This exercises the NEW logic that audit finding
// #3 added: running the four sweeps, merging their broken lists, tagging each
// with which trail/check flagged it, and the lighter launch-time subset that
// runs only the two authoritative keyed-MAC sweeps.
//
// The four underlying sweeps are covered elsewhere (test_verifyAllChains.mjs,
// the Rust audit_mac tests). Here we mock the `invoke` bridge so the note-history
// and note-audit tables are empty (their hash sweeps report clean/checked:0) and
// we drive the keyed-MAC sweep commands directly, so the assertions are about
// the orchestrator's own merge/tag/aggregate behaviour.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// Controllable return values for the two keyed-MAC sweep commands.
let historyMac = { ok: true, checked: 0, broken: [] };
let auditMac = { ok: true, checked: 0, broken: [] };

globalThis.__TAHLK_TEST_TAURI__ = {
  core: {
    invoke: (command) => {
      switch (command) {
        // Empty tables => the JS hash-chain sweeps report clean, checked:0.
        case 'note_history_list_encounter_ids':
        case 'note_audit_list_encounter_ids':
          return Promise.resolve([]);
        case 'verify_all_history_macs':
          return Promise.resolve(historyMac);
        case 'verify_all_audit_macs':
          return Promise.resolve(auditMac);
        default:
          return Promise.reject(new Error(`unexpected invoke: ${command}`));
      }
    },
  },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

const { verifyAllRecordIntegrity, verifyRecordMacsOnLaunch } = await import(
  '../../src/domain/recordIntegrity.js'
);

beforeEach(() => {
  historyMac = { ok: true, checked: 0, broken: [] };
  auditMac = { ok: true, checked: 0, broken: [] };
});

test('all four sweeps clean => ok:true, no broken', async () => {
  const r = await verifyAllRecordIntegrity();
  assert.equal(r.ok, true);
  assert.deepEqual(r.broken, []);
});

test('a broken keyed-MAC chain surfaces in the merged result, tagged by trail', async () => {
  historyMac = {
    ok: false,
    checked: 5,
    broken: [{ encounterId: 'enc-1', brokenAt: 2, reason: 'chain_mac mismatch' }],
  };
  const r = await verifyAllRecordIntegrity();
  assert.equal(r.ok, false);
  assert.equal(r.broken.length, 1);
  assert.equal(r.broken[0].encounterId, 'enc-1');
  assert.equal(r.broken[0].kind, 'note history (substitution)');
  // "checked" reflects the largest sweep's count (records examined).
  assert.equal(r.checked, 5);
});

test('broken chains from different sweeps are all merged with distinct kinds', async () => {
  historyMac = { ok: false, checked: 3, broken: [{ encounterId: 'h', reason: 'chain_mac mismatch' }] };
  auditMac = { ok: false, checked: 4, broken: [{ encounterId: 'a', reason: 'null chain_mac after anchoring' }] };
  const r = await verifyAllRecordIntegrity();
  assert.equal(r.ok, false);
  const byId = Object.fromEntries(r.broken.map(b => [b.encounterId, b.kind]));
  assert.equal(byId['h'], 'note history (substitution)');
  assert.equal(byId['a'], 'access log (substitution)');
  assert.equal(r.checked, 4);
});

test('launch sweep runs ONLY the keyed-MAC checks and tags them', async () => {
  auditMac = { ok: false, checked: 2, broken: [{ encounterId: 'x', reason: 'chain_mac mismatch' }] };
  const r = await verifyRecordMacsOnLaunch();
  assert.equal(r.ok, false);
  assert.equal(r.broken.length, 1);
  assert.equal(r.broken[0].encounterId, 'x');
  assert.equal(r.broken[0].kind, 'access log (substitution)');
});

test('launch sweep is clean when both MAC sweeps pass', async () => {
  const r = await verifyRecordMacsOnLaunch();
  assert.equal(r.ok, true);
  assert.deepEqual(r.broken, []);
});
