// Unit tests for opt-in, PHI-scrubbed diagnostics.
// The critical guard is scrubbing: free-form strings (where PHI would hide) must
// never make it into the log, even when a developer passes them.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// Mock Tauri runtime so storageBackend uses the real TauriBackend path.
// See src/platform/tauri.js — L4 migrated the wrapper from the __TAURI__
// global to ESM imports; tests use the __TAHLK_TEST_TAURI__ escape hatch.
globalThis.document = { getElementById: () => null };
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: () => Promise.resolve(null) },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

const telemetry = await import('../../src/core/telemetry.js');

beforeEach(() => {
  telemetry.setEnabled(false);
  telemetry.clear();
});

test('disabled by default: track records nothing', () => {
  telemetry.track('app_started', { a: 1 });
  telemetry.recordError('x', new Error('y'));
  assert.equal(telemetry.getEvents().length, 0);
});

test('enabled: track records the event', () => {
  telemetry.setEnabled(true);
  telemetry.track('note_signed');
  const events = telemetry.getEvents();
  assert.equal(events.length, 1);
  assert.equal(events[0].event, 'note_signed');
  assert.equal(typeof events[0].t, 'string');
});

test('scrub: numbers/booleans/allowlisted strings pass; free-form strings dropped', () => {
  telemetry.setEnabled(true);
  telemetry.track('evt', {
    chars: 1200,            // number -> kept
    ok: true,              // boolean -> kept
    code: 'E401',          // allowlisted key -> kept
    template: 'psych-eval', // allowlisted key -> kept
    alias: 'JOHN DOE',     // PHI in a non-allowlisted string -> DROPPED
    note: 'patient reports…', // PHI -> DROPPED
  });
  const ev = telemetry.getEvents().at(-1);
  assert.equal(ev.chars, 1200);
  assert.equal(ev.ok, true);
  assert.equal(ev.code, 'E401');
  assert.equal(ev.template, 'psych-eval');
  assert.ok(!('alias' in ev), 'free-form alias must be scrubbed');
  assert.ok(!('note' in ev), 'free-form note must be scrubbed');
});

test('allowlisted strings are length-capped', () => {
  telemetry.setEnabled(true);
  telemetry.track('evt', { code: 'x'.repeat(200) });
  assert.equal(telemetry.getEvents().at(-1).code.length, 64);
});

test('log is capped at 500 events (oldest dropped)', () => {
  telemetry.setEnabled(true);
  for (let i = 0; i < 510; i++) telemetry.track('evt', { i });
  const events = telemetry.getEvents();
  assert.equal(events.length, 500);
  assert.equal(events[0].i, 10); // first 10 dropped
});

test('recordError stores kind + name but NEVER the raw message', () => {
  telemetry.setEnabled(true);
  telemetry.recordError('generation', new Error('boom'));
  let ev = telemetry.getEvents().at(-1);
  assert.equal(ev.event, 'error');
  assert.equal(ev.kind, 'generation');
  assert.equal(ev.name, 'Error');
  assert.ok(!('message' in ev), 'raw error message must not be persisted');

  // A bare string error carries no name/code — nothing free-text is kept.
  telemetry.recordError('audio', 'm'.repeat(300));
  ev = telemetry.getEvents().at(-1);
  assert.equal(ev.name, 'Error');
  assert.ok(!('message' in ev), 'string error must not be stored as a message');
  assert.ok(!('code' in ev), 'a bare string has no code');
});

test('recordError keeps the stable AppError code but not its message', () => {
  telemetry.setEnabled(true);
  // Shape of a rejected Rust invoke(): { code, message }.
  telemetry.recordError('transcription', {
    name: 'AppError',
    code: 'secure_service_unreachable',
    message: 'failed for patient Jane Q. Public',
  });
  const ev = telemetry.getEvents().at(-1);
  assert.equal(ev.name, 'AppError');
  assert.equal(ev.code, 'secure_service_unreachable');
  assert.ok(!('message' in ev), 'the free-text message is dropped even when a code is present');
});

test('recordError does NOT persist PHI hidden in an error message', () => {
  telemetry.setEnabled(true);
  // A synthetic exception whose message embeds PHI-shaped fragments: a patient
  // name and an SSN-like string. None of this may reach the persisted log.
  const phi = 'Failed to save note for John Doe, SSN 123-45-6789, DOB 1994-02-14';
  telemetry.recordError('generation', new Error(phi));

  const ev = telemetry.getEvents().at(-1);
  const serialized = JSON.stringify(ev);
  assert.ok(!serialized.includes('John Doe'), 'patient name must not appear in the log');
  assert.ok(!serialized.includes('123-45-6789'), 'SSN-like string must not appear in the log');
  assert.ok(!serialized.includes('1994-02-14'), 'DOB must not appear in the log');
  assert.ok(!('message' in ev), 'message field must be absent entirely');
});

test('clear empties the log', () => {
  telemetry.setEnabled(true);
  telemetry.track('a');
  telemetry.clear();
  assert.equal(telemetry.getEvents().length, 0);
});
