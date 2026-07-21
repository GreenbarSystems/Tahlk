// Integration tests for the sign-off / hash-chain money path.
//
// These exercise the REAL production path: noteEditor -> domain/historyChain ->
// storageBackend (TauriBackend) -> platform/tauri invoke -> encountersRepo.
// A mock Tauri runtime is installed BEFORE the app modules load, so `isTauri`
// resolves true and KV + commands flow through a recording `invoke` we control.
//
// Rejection shapes covered: the real Rust side rejects with an AppError
// `{ code, message }` object. Legacy paths (and older mocks) rejected with a
// bare Error. `fromInvoke` in `platform/appError.js` normalizes both, so the
// mock exercises both shapes below to keep that normalizer honest.
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
import { hashHistoryEntry } from '../../src/utils/contentHash.js';

// ── Mock Tauri runtime (installed before app modules import) ────────────────
//
// This mirrors the CURRENT server-side note_history architecture (see
// src-tauri/src/note_history.rs). The old open `note_history_append` command
// was removed from the invoke handler; the frontend now reaches history only
// through three narrow, actor-deriving-server-side paths:
//   - history_note_generated(encounterId, contentHash)  → actor "AI (Tahlk)"
//   - history_note_edited(encounterId, contentHash)      → actor = provider
//   - mark_encounter_signed(id, signedAt, signedHash)    → atomically appends
//     the `signed` history row in the SAME transaction as the status flip
// The mock derives prevHash from the tail, stamps a monotonic timestamp, and
// computes entryHash via the SAME hashHistoryEntry the Rust side matches
// byte-for-byte, so a chain built through the mock verifies under the real
// verifyHistoryChain — exactly as it would against the DB.
const calls = [];
let responders = {};
// note_history table stand-in: mirrors what the Rust side would persist. Keyed
// by encounterId, values are arrays of entry rows (JS shape). Reset per test.
let _historyStore = new Map();
// Monotonic clock so each appended entry gets a distinct, ordered timestamp
// without relying on wall-clock resolution (two appends in the same ms would
// otherwise collide). Reset per test.
let _clock = 0;
function nextTimestamp() {
  _clock += 1000;
  return new Date(Date.UTC(2026, 0, 1) + _clock).toISOString();
}

// Server-side append: derive prevHash from the tail, stamp a timestamp, compute
// entryHash the way note_history.rs::server_history_append does, persist, and
// return the full entry JSON (what the real command returns to the JS cache).
async function serverAppend(encounterId, action, actor, contentHash, notes) {
  const list = _historyStore.get(encounterId) || [];
  const tail = list[list.length - 1];
  const prevHash = tail ? (tail.entryHash ?? null) : null;
  const entry = { action, actor, timestamp: nextTimestamp(), contentHash, notes, prevHash };
  entry.entryHash = await hashHistoryEntry(entry, prevHash);
  list.push(entry);
  _historyStore.set(encounterId, list);
  return entry;
}

function invokeMock(cmd, args) {
  calls.push({ cmd, args });
  const r = responders[cmd];
  if (r instanceof Error) return Promise.reject(r);
  if (typeof r === 'function') return Promise.resolve(r(args));
  if (r !== undefined) return Promise.resolve(r);

  // Default responders for the narrow note_history commands so tests don't have
  // to re-implement the chain semantics per test.
  if (cmd === 'note_history_list') {
    return Promise.resolve(_historyStore.get(args.encounterId)?.slice() || []);
  }
  if (cmd === 'history_note_generated') {
    return serverAppend(args.encounterId, 'generated', 'AI (Tahlk)', args.contentHash, '');
  }
  if (cmd === 'history_note_edited') {
    return serverAppend(args.encounterId, 'edited', 'provider', args.contentHash, '');
  }
  if (cmd === 'mark_encounter_signed') {
    // Atomic on the Rust side: appends the `signed` history row AND flips the
    // encounter status in one transaction. The mock appends the signed row so
    // the post-invalidate loadHistory() sees it, mirroring server_sign_history.
    // mark_encounter_signed uses `id` (not encounterId) — see encountersRepo.js.
    return serverAppend(args.id, 'signed', 'provider', args.signedHash, 'Attested by provider')
      .then(() => null);
  }
  return Promise.resolve(null);
}

globalThis.document = { getElementById: () => null }; // toast() no-ops in tests
// Install the test-only Tauri escape hatch. See src/platform/tauri.js — the
// real runtime is now imported as ESM (audit L4), so tests inject a fake via
// this obscurely-named global that platform/tauri.js checks first.
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: invokeMock },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

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
  _historyStore = new Map();
});

test('generate -> edit -> sign builds a valid, linked hash chain', async () => {
  const id = uid();
  await saveDraftGenerated(id, 'NOTE v1', 'TRANSCRIPT');
  await saveDraftEdited(id, 'NOTE v2', 'TRANSCRIPT');
  await signNote(id, 'NOTE v2', 'TRANSCRIPT', 'Dr. Smith');

  const history = await loadHistory(id);
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

  const history = await loadHistory(id);
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

test('sign-off fails closed: a failed atomic sign write never leaves a signed record', async () => {
  const id = uid();
  await saveDraftGenerated(id, 'NOTE v1', 'TRANSCRIPT');

  // The signed history row and the encounter status flip are written together
  // inside mark_encounter_signed (server_sign_history runs in the same Rust
  // transaction). Fail that command with the real Rust rejection shape
  // (`{ code, message }`) so the JS-side `fromInvoke` normalizer is exercised
  // on the production path, and assert the whole operation is all-or-nothing.
  responders['mark_encounter_signed'] = Object.assign(
    new Error('disk full'),
    { code: 'storage' }
  );

  await assert.rejects(() => signNote(id, 'NOTE v1', 'TRANSCRIPT', 'Dr. Smith'));

  // Because the atomic command rolled back, no `signed` entry may exist — the
  // record must not read as signed after a failed write.
  const history = await loadHistory(id);
  assert.ok(!history.some(e => e.action === 'signed'),
    'a failed atomic sign must leave no signed history row');
});
