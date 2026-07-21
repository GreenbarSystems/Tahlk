// Adversarial tests for PHI egress via the on-device diagnostics log.
//
// telemetry.js is the one place in the app that deliberately writes a
// developer-supplied string to a KV row that a provider can later EXPORT to a
// file and email to support (telemetry.exportLog()). That export is the egress
// boundary: anything that reaches the diag log can leave the device by an
// explicit-but-easy user action. So the scrubbing here is a real PHI control,
// not just hygiene.
//
// test_telemetry.mjs proves the happy path of scrubProps. These tests attack
// it: they try to smuggle PHI in through every shape a careless (or malicious)
// call site might use, and they pin the one path that BYPASSES scrubProps
// entirely — recordError's `message` — as a documented gap with a fix lever.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

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
  telemetry.setEnabled(true);
});

const PHI = 'John Q. Patient, DOB 1980-02-14, reports suicidal ideation';

function lastEvent() {
  const e = telemetry.getEvents();
  return e[e.length - 1];
}

// Serialize the whole stored event and assert the PHI string appears nowhere
// in it — the strongest possible "did it leak" check, agnostic to key name.
function assertNoPhi(record, needle = 'Patient') {
  assert.ok(!JSON.stringify(record).includes(needle),
    `PHI leaked into telemetry record: ${JSON.stringify(record)}`);
}

// ── Protections that MUST hold: track() scrubbing ─────────────────────────

test('ATTACK free-form-string: a non-allowlisted string prop is dropped', () => {
  telemetry.track('note_generated', { patientName: PHI });
  assertNoPhi(lastEvent());
  assert.equal(lastEvent().patientName, undefined);
});

test('ATTACK allowlist-key-smuggle: PHI under an allowlisted key is length-capped, not free', () => {
  // 'status' is allowlisted. Even a legitimately-keyed string is capped to 64
  // chars so it can't carry a full note. (Defense-in-depth: the allowlist keys
  // are structural enums; this proves the cap still bounds the blast radius.)
  telemetry.track('note_generated', { status: PHI + ' '.repeat(200) + 'trailing' });
  assert.ok(lastEvent().status.length <= 64, 'allowlisted string not capped to 64');
  assert.ok(!lastEvent().status.includes('trailing'), 'cap did not actually truncate');
});

test('ATTACK nested-object: PHI hidden in a nested object is dropped', () => {
  telemetry.track('note_generated', { meta: { patientName: PHI } });
  assertNoPhi(lastEvent());
  assert.equal(lastEvent().meta, undefined);
});

test('ATTACK array-payload: PHI hidden in an array is dropped', () => {
  telemetry.track('note_generated', { transcriptLines: [PHI, 'more phi'] });
  assertNoPhi(lastEvent());
  assert.equal(lastEvent().transcriptLines, undefined);
});

test('ATTACK number-coercion: a String-object (typeof object) is dropped, not coerced', () => {
  // new String(x) is typeof 'object', so it fails both the number and string
  // branches and is dropped — good. Pin it so a future "stringify everything"
  // refactor can't quietly start coercing PHI-bearing objects to strings.
  // eslint-disable-next-line no-new-wrappers
  telemetry.track('note_generated', { status: new String(PHI) });
  assertNoPhi(lastEvent());
});

test('disabled telemetry writes nothing even under attack (opt-in gate holds)', () => {
  telemetry.setEnabled(false);
  telemetry.track('note_generated', { status: 'draft', patientName: PHI });
  telemetry.recordError('audio', new Error(PHI));
  assert.equal(telemetry.getEvents().length, 0, 'opt-in gate must suppress all writes');
});

// ── KNOWN GAP: recordError bypasses scrubProps ────────────────────────────

test('GAP recordError-message: an error message is stored verbatim (capped), NOT allowlist-scrubbed', () => {
  // recordError() calls append() directly with { message }, bypassing
  // scrubProps entirely. Its `message` is only slice(0,200)'d, not
  // key-allowlisted. So if any upstream ever throws an Error whose message
  // embeds PHI — e.g. an API/DB error that echoes note text, a validation
  // error that quotes a patient field — that PHI lands in the exportable diag
  // log. This test DEMONSTRATES the gap (it asserts the PHI is present) so the
  // behavior is explicit and the fix can be verified against it later.
  telemetry.recordError('note_generation', new Error(PHI));
  const rec = lastEvent();
  assert.equal(rec.event, 'error');
  assert.ok(rec.message.includes('Patient'),
    'documents current behavior: recordError stores the raw message, PHI included');
  // Fix lever: recordError should treat `message` as untrusted and either drop
  // it, hash it, or route it through the same redaction policy as the Rust
  // log_safety layer (path-strip + a PHI-token denylist), rather than storing
  // an arbitrary upstream string. The 200-char cap bounds size, not content.
});

test('GAP boundary: a 300-char PHI error message is truncated but the leading PHI survives', () => {
  const long = PHI + ' ' + 'x'.repeat(400);
  telemetry.recordError('audio', new Error(long));
  const rec = lastEvent();
  assert.ok(rec.message.length <= 200, 'message must be size-capped');
  assert.ok(rec.message.includes('John Q. Patient'),
    'the cap is on length only — leading PHI is retained within the first 200 chars');
});
