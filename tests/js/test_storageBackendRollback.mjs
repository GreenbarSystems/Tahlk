// Cache-poisoning regression (audit C-5).
//
// Every kv write updates the in-memory cache BEFORE the backend confirms, so
// synchronous kvGet() stays fast. Without a rollback that optimism is a
// security hole: Rust REJECTS generic writes to the guarded keys — provider
// profile, BAA ack, retention window, litigation hold — which are exactly the
// values whose integrity matters most. The rejected value used to stay in the
// cache for the rest of the session, and every later kvGet() returned it.
//
// Concretely that defeated the C3 provider-profile guard: the forged name
// flows into computeNoteHash({ signedBy }) — which Rust stores verbatim and
// never recomputes — and into the destruction_log actor. And since the
// retention window and litigation hold became write-protected, a rejected
// write there would leave the UI believing a legal hold was lifted when Rust
// had refused to lift it.
//
// Drives the REAL TauriBackend via the __TAHLK_TEST_TAURI__ escape hatch.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// storageBackend pulls in toast(), which touches the DOM at call time.
globalThis.document = { getElementById: () => null };
globalThis.window = globalThis.window || {};

// Each invoke returns a promise this harness settles by hand, so a test can
// interleave a second write with an in-flight failure.
let pending = [];
const calls = [];
globalThis.__TAHLK_TEST_TAURI__ = {
  core: {
    invoke: (command, args) => {
      calls.push({ command, args });
      return new Promise((resolve, reject) => pending.push({ resolve, reject }));
    },
  },
  event: { listen: () => () => {} },
};

const { kvGet, kvSet, kvSetAwait, kvRemove, kvSetCacheOnly } =
  await import('../../src/core/storageBackend.js');

// Let queued .then/.catch handlers run.
const flush = () => new Promise(r => setTimeout(r, 0));

const GUARDED = 'note_provider_v1::profile';

beforeEach(() => {
  pending = [];
  calls.length = 0;
});

test('a rejected write reverts the cache to the previous value', async () => {
  // Seed the legitimate profile the way a warmup/dedicated-command write would.
  kvSetCacheOnly(GUARDED, { name: 'Dr. Real' });

  kvSet(GUARDED, { name: 'Dr. Forged' });
  assert.equal(kvGet(GUARDED).name, 'Dr. Forged', 'optimistic write is visible immediately');

  // Rust refuses: guard_write_key rejects the provider profile key.
  pending[0].reject({ code: 'invalid_input', message: 'this key cannot be written via the generic KV API' });
  await flush();

  assert.equal(
    kvGet(GUARDED).name,
    'Dr. Real',
    'a rejected write must not leave the forged identity readable',
  );
});

test('a rejected write to a previously-absent key clears it entirely', async () => {
  const key = 'note_settings_v1::litigation_hold';
  assert.equal(kvGet(key), null, 'precondition: not cached');

  kvSet(key, 'false');
  assert.equal(kvGet(key), 'false');

  pending[0].reject({ code: 'invalid_input', message: 'blocked' });
  await flush();

  assert.equal(
    kvGet(key),
    null,
    'the UI must not believe a legal hold was lifted when Rust refused',
  );
});

test('kvSetAwait reverts and still throws', async () => {
  const key = 'note_content_v1::enc-signed';
  kvSetCacheOnly(key, 'the signed note');

  const p = kvSetAwait(key, 'tampered text');
  assert.equal(kvGet(key), 'tampered text', 'optimistic');

  pending[0].reject({ code: 'invalid_input', message: 'cannot overwrite note content of a signed encounter' });

  await assert.rejects(p, 'callers depending on persistence must still fail closed');
  assert.equal(
    kvGet(key),
    'the signed note',
    'rejected content must not be readable as if it had been saved',
  );
});

test('a rejected remove restores the value', async () => {
  const key = 'note_settings_v1::retention_years';
  kvSetCacheOnly(key, '7');

  kvRemove(key);
  assert.equal(kvGet(key), null, 'optimistic removal is visible');

  pending[0].reject({ code: 'invalid_input', message: 'blocked' });
  await flush();

  assert.equal(kvGet(key), '7', 'a refused delete must not appear to have succeeded');
});

test('a successful write keeps the new value', async () => {
  const key = 'note_settings_v1::onboarded';
  kvSet(key, true);
  pending[0].resolve(null);
  await flush();
  assert.equal(kvGet(key), true, 'rollback must not fire on success');
});

test('rollback does not clobber a newer write that landed meanwhile', async () => {
  // The subtle case: two writes in flight, the FIRST fails. Blindly restoring
  // its snapshot would discard the second, legitimate value.
  const key = 'note_settings_v1::audio_retention';
  kvSetCacheOnly(key, 'keep');

  kvSet(key, 'first');   // pending[0]
  kvSet(key, 'second');  // pending[1]
  assert.equal(kvGet(key), 'second');

  pending[1].resolve(null);   // the newer write succeeds
  await flush();
  pending[0].reject({ code: 'storage', message: 'disk full' }); // the older one fails
  await flush();

  assert.equal(
    kvGet(key),
    'second',
    'a stale snapshot must not overwrite a newer value that did persist',
  );
});
