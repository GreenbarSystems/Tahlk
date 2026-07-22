// Unit tests for the BAA acknowledgment JS layer.
//
// The Rust side (baa.rs / notes.rs) owns the actual gate — a compromised
// WebView cannot bypass it. These tests therefore focus on the JS surface:
//
//   1. baaRepo.getStatus / setAck / clear map to the right Tauri commands
//      with the right payload shapes (arg names and types must match the
//      Rust #[tauri::command] signatures verbatim).
//   2. When Rust rejects with `{ code: 'baa_required' }`, `noteGenerator`
//      surfaces it as an AppError whose code the UI can branch on.
//   3. `userMessage` returns the CTA line for `baa_required` (this is the
//      copy the encounter panel toast falls back to).
//
// We stub the injected Tauri runtime with a recording invoke() rather than
// hitting real IPC — the tests must run under `node --test`.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// Some modules read `document`/`window` at import time (storageBackend
// touches DOM inside its class body). Provide the shims BEFORE any dynamic
// import so the module graph resolves cleanly.
globalThis.document = { getElementById: () => null };

// Recording Tauri runtime. Each test resets `calls` and `nextResult` so
// invocations from prior tests can't leak into later assertions.
// See src/platform/tauri.js — L4 migrated the wrapper from the __TAURI__
// global to ESM imports; tests use the __TAHLK_TEST_TAURI__ escape hatch.
const calls = [];
let nextResult = { ok: null };
globalThis.__TAHLK_TEST_TAURI__ = {
  core: {
    invoke: (command, args) => {
      calls.push({ command, args });
      if (nextResult.reject !== undefined) {
        return Promise.reject(nextResult.reject);
      }
      return Promise.resolve(nextResult.ok);
    },
  },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

const { baaRepo, BAA_ATTESTATION_VERSION } = await import('../../src/data/baa.js');
const { AppError, fromInvoke, userMessage } = await import('../../src/platform/appError.js');
const { generateNote } = await import('../../src/scribe/noteGenerator.js');

beforeEach(() => {
  calls.length = 0;
  nextResult = { ok: null };
});

test('BAA_ATTESTATION_VERSION matches the Rust constant', async () => {
  // Reads baa.rs and compares. The previous version only asserted
  // `typeof === 'number' && >= 1`, which is true of ANY plausible value — so
  // if Rust bumped ATTESTATION_VERSION to 2 and JS stayed at 1 it passed,
  // while every provider silently skipped re-attestation. Its comment claimed
  // to catch exactly that drift, which made it worse than no test: a reader
  // would believe the two were pinned together.
  //
  // The two MUST bump together. Rust treats a stored ack with a LOWER version
  // than its own as un-acknowledged (baa.rs read_ack), so a JS value behind
  // Rust's re-prompts everyone, and a JS value ahead writes acks Rust will
  // reject on the next launch.
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const { dirname, resolve } = await import('node:path');

  const here = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(resolve(here, '../../src-tauri/src/baa.rs'), 'utf8');
  const m = src.match(/ATTESTATION_VERSION:\s*u32\s*=\s*(\d+)\s*;/);
  assert.ok(m, 'could not find ATTESTATION_VERSION in baa.rs — did it move or change shape?');

  assert.equal(
    BAA_ATTESTATION_VERSION,
    Number(m[1]),
    'src/data/baa.js and src-tauri/src/baa.rs disagree on the attestation version',
  );
  assert.ok(Number.isInteger(BAA_ATTESTATION_VERSION) && BAA_ATTESTATION_VERSION >= 1);
});

test('baaRepo.getStatus invokes baa_ack_status with no args', async () => {
  nextResult = { ok: null };
  const out = await baaRepo.getStatus();
  assert.equal(out, null);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, 'baa_ack_status');
});

test('baaRepo.getStatus returns the Rust row when acknowledged', async () => {
  const row = {
    acknowledged: true,
    acknowledged_at: '2026-07-04T14:22:11Z',
    provider_id: 'Dr. Jane Smith',
    attestation_version: BAA_ATTESTATION_VERSION,
  };
  nextResult = { ok: row };
  const out = await baaRepo.getStatus();
  assert.deepEqual(out, row);
});

test('baaRepo.setAck sends the required Rust payload (camelCase keys)', async () => {
  nextResult = { ok: null };
  await baaRepo.setAck({
    acknowledgedAt: '2026-07-04T14:22:11Z',
    providerId: 'Dr. Jane Smith',
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, 'baa_ack_set');
  // Tauri converts JS camelCase into Rust snake_case for command params, so
  // the JS side must supply camelCase keys. The Rust signature is
  // (acknowledged: bool, acknowledged_at: String, provider_id: String).
  assert.deepEqual(calls[0].args, {
    acknowledged: true,
    acknowledgedAt: '2026-07-04T14:22:11Z',
    providerId: 'Dr. Jane Smith',
  });
});

test('baaRepo.setAck coerces missing providerId to empty string', async () => {
  nextResult = { ok: null };
  await baaRepo.setAck({ acknowledgedAt: 'x', providerId: undefined });
  assert.equal(calls[0].args.providerId, '');
});

test('baaRepo.clear invokes baa_ack_clear with no args', async () => {
  nextResult = { ok: null };
  await baaRepo.clear();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, 'baa_ack_clear');
});

test('fromInvoke preserves baa_required code from Rust rejection', () => {
  const rustErr = { code: 'baa_required', message: 'Anthropic BAA acknowledgment required before note generation.' };
  const err = fromInvoke(rustErr);
  assert.ok(err instanceof AppError);
  assert.equal(err.code, 'baa_required');
  assert.match(err.message, /BAA/);
});

test('userMessage returns the Settings CTA for baa_required', () => {
  const err = new AppError('baa_required', 'blah');
  const msg = userMessage(err);
  // We assert on the *shape* of the message (points at the agreements +
  // Settings) rather than the exact string so copy tweaks don't break this
  // test unnecessarily. Copy moved from "BAA" to "agreements" when the model
  // became a BAA + EULA with Greenbar rather than a BAA with Anthropic.
  assert.match(msg, /agreement/i);
  assert.match(msg, /Settings/);
});

test('generateNote rejects with baa_required AppError when Rust gate refuses', async () => {
  nextResult = { reject: { code: 'baa_required', message: 'Anthropic BAA acknowledgment required before note generation.' } };
  let caught;
  try {
    await generateNote('some transcript text', 'soap-generic', 'enc-123');
  } catch (e) {
    caught = e;
  }
  assert.ok(caught, 'generateNote should have rejected');
  assert.equal(caught.code, 'baa_required');
});

test('generateNote passes encounterId through to Rust invoke', async () => {
  nextResult = { ok: 'generated note text' };
  const note = await generateNote('t', 'soap-generic', 'enc-abc');
  assert.equal(note, 'generated note text');
  // Find the generate_note call (there may be no other invokes in this path
  // but assert defensively so a future refactor doesn't silently drop the id).
  const gen = calls.find(c => c.command === 'generate_note');
  assert.ok(gen, 'generate_note must be invoked');
  assert.equal(gen.args.encounterId, 'enc-abc');
  assert.equal(gen.args.transcript, 't');
  assert.equal(typeof gen.args.systemPrompt, 'string');
});

test('generateNote passes null encounterId when caller omits it', async () => {
  nextResult = { ok: 'x' };
  await generateNote('t', 'soap-generic', undefined);
  const gen = calls.find(c => c.command === 'generate_note');
  assert.equal(gen.args.encounterId, null);
});
