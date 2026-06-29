// Integration tests for the sign-off / hash-chain money path.
//
// These exercise the REAL production path: noteEditor -> domain/historyChain ->
// storageBackend (TauriBackend) -> platform/tauri invoke -> encountersRepo.
// A mock Tauri runtime is installed BEFORE the app modules load, so `isTauri`
// resolves true and KV + commands flow through a recording `invoke` we control.
//
// Guards, in order of how much they'd hurt in production:
//   - the chain built by generate->edit->sign verifies and links correctly
//   - signing flips status via mark_encounter_signed, NEVER a full upsert
//     (regression test for the alias/audio-nulling data-loss bug)
//   - post-sign tampering is detectable
//   - the signed hash binds to exact note + transcript + signer
//   - sign-off fails closed: if the durable history write fails, the encounter
//     is never marked signed

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// ── Mock Tauri runtime (installed before app modules import) ────────────────
const calls = [];
let responders = {};

function invokeMock(cmd, args) {
  calls.push({ cmd, args });
  const r = responders[cmd];
  if (r instanceof Error) return Promise.reject(r);
  if (typeof r === 'function') return Promise.resolve(r(args));
  return Promise.resolve(r === undefined ? null : r);
}

globalThis.document = { getElementById: () => null }; // toast() no-ops in tests
globalThis.window = {
  __TAURI__: {
    core: { invoke: invokeMock },
    event: { listen: () => () => {} },
  },
};

// Dynamic import so the globals above exist when the module graph evaluates.
const { saveDraftGenerated, saveDraftEdited, signNote, loadHistory } =
  await import('../../src/editor/noteEditor.js');
const { verifyHistoryChain, computeNoteHash } =
  await import('../../src/utils/contentHash.js');

let _n = 0;
const uid = () => `enc-test-${++_n}`;

beforeEach(() => {
  calls.length = 0;
  responders = {};
});

test('generate -> edit -> sign builds a valid, linked hash chain', async () => {
  const id = uid();
  await saveDraftGenerated(id, 'NOTE v1', 'TRANSCRIPT');
  await saveDraftEdited(id, 'NOTE v2', 'TRANSCRIPT');
  await signNote(id, 'NOTE v2', 'TRANSCRIPT', 'Dr. Smith');

  const history = loadHistory(id);
  assert.equal(history.length, 3);
  assert.deepEqual(history.map(e => e.action), ['generated', 'edited', 'signed']);

  // every entry links to the prior one's hash
  for (let i = 1; i < history.length; i++) {
    assert.equal(history[i].prevHash, history[i - 1].entryHash);
  }
  const result = await verifyHistoryChain(history);
  assert.equal(result.ok, true);
});

test('signNote flips status via mark_encounter_signed, never upsert_encounter', async () => {
  const id = uid();
  await signNote(id, 'NOTE', 'T', 'Dr. Smith');

  const cmds = calls.map(c => c.cmd);
  assert.ok(cmds.includes('mark_encounter_signed'), 'should call the targeted update');
  assert.ok(!cmds.includes('upsert_encounter'), 'a full upsert would null alias/audio_path');

  const mark = calls.find(c => c.cmd === 'mark_encounter_signed');
  assert.equal(mark.args.id, id);
  assert.match(mark.args.signedHash, /^[0-9a-f]{64}$/);
  assert.equal(typeof mark.args.signedAt, 'string');
});

test('post-sign tampering is detectable', async () => {
  const id = uid();
  await signNote(id, 'SIGNED NOTE', 'TRANSCRIPT', 'Dr. Smith');

  const history = loadHistory(id);
  assert.equal((await verifyHistoryChain(history)).ok, true);

  // mutate the signed entry's content hash without re-deriving entryHash
  history[history.length - 1].contentHash = 'tampered';
  const result = await verifyHistoryChain(history);
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, history.length - 1);
});

test('signed hash binds note + transcript + signer', async () => {
  const id = uid();
  const hash = await signNote(id, 'NOTE', 'TRANSCRIPT', 'Dr. Smith');

  const expected = await computeNoteHash({
    transcript: 'TRANSCRIPT', noteContent: 'NOTE', signedBy: 'Dr. Smith', encounterId: id,
  });
  assert.equal(hash, expected);

  const differentSigner = await computeNoteHash({
    transcript: 'TRANSCRIPT', noteContent: 'NOTE', signedBy: 'Dr. Other', encounterId: id,
  });
  assert.notEqual(hash, differentSigner);
});

test('sign-off fails closed: a failed history write never marks the encounter signed', async () => {
  const id = uid();
  responders['kv_set'] = new Error('disk full'); // durable chain write fails

  await assert.rejects(() => signNote(id, 'NOTE', 'TRANSCRIPT', 'Dr. Smith'));

  const cmds = calls.map(c => c.cmd);
  assert.ok(!cmds.includes('mark_encounter_signed'),
    'status must not flip to signed when the chain did not persist');
});
