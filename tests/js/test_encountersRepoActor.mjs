// H-3 regression: delete_encounter must not carry a client-supplied actor.
//
// C2 removed the forgeable `provider_id` parameter from upsert_patient and
// delete_patient but missed delete_encounter, whose value flows straight into
// the append-only destruction_log — the record HIPAA §164.310(d)(2)(i) most
// relies on. A compromised WebView could attribute a permanent PHI destruction
// to any clinician it named.
//
// Rust now derives the actor from the stored provider profile. This pins the
// JS side so the argument cannot creep back in: a payload carrying providerId
// would be silently ignored by Rust today, but reintroducing it here is the
// first half of reintroducing the vulnerability.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

globalThis.document = { getElementById: () => null };
globalThis.window = globalThis.window || {};

const calls = [];
globalThis.__TAHLK_TEST_TAURI__ = {
  core: {
    invoke: (command, args) => {
      calls.push({ command, args });
      return Promise.resolve(null);
    },
  },
  event: { listen: () => () => {} },
};

const { encountersRepo } = await import('../../src/data/encountersRepo.js');

beforeEach(() => { calls.length = 0; });

test('delete sends only the encounter id — no actor identity', async () => {
  await encountersRepo.delete('enc-1');

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, 'delete_encounter');
  assert.deepEqual(
    Object.keys(calls[0].args).sort(),
    ['id'],
    'the payload must carry nothing but the id — the actor is server-derived',
  );
  assert.equal(calls[0].args.id, 'enc-1');
  assert.equal(
    calls[0].args.providerId,
    undefined,
    'a client-supplied actor would be forgeable in the destruction log',
  );
});

test('markSigned still carries no client timestamp either', async () => {
  // Same class of finding (H2), pinned alongside so the two server-derived
  // fields on the encounter commands are covered in one place.
  await encountersRepo.markSigned('enc-1', 'a'.repeat(64));

  assert.equal(calls[0].command, 'mark_encounter_signed');
  assert.deepEqual(Object.keys(calls[0].args).sort(), ['id', 'signedHash']);
  assert.equal(calls[0].args.signedAt, undefined);
});
