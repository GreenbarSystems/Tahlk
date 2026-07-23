// S-UX-4: the integrity-failure alert shown to a clinician must use plain,
// actionable language — never developer jargon like "audit chain". The technical
// mismatch detail is preserved in the opt-in diagnostics log for support, not the toast.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// Mock Tauri runtime so storageBackend (pulled in by telemetry) uses the real
// TauriBackend path with an empty cache. See src/platform/tauri.js.
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: () => Promise.resolve(null) },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

// Capture whatever the toast writes to the DOM.
let shownToast = '';
const msgEl = { set textContent(v) { shownToast = v; }, get textContent() { return shownToast; } };
const toastEl = { classList: { add() {}, remove() {} }, setAttribute() {}, onmouseenter: null, onmouseleave: null };
globalThis.document = {
  getElementById: id => (id === 'toast' ? toastEl : id === 'toast-msg' ? msgEl : null),
};

const { INTEGRITY_FAILURE_MESSAGE, reportIntegrityFailure } =
  await import('../../src/solo/integrityAlert.js');
const telemetry = await import('../../src/core/telemetry.js');

beforeEach(() => {
  shownToast = '';
  telemetry.setEnabled(false);
  telemetry.clear();
});

test('the toast copy is plain language, not developer jargon', () => {
  const lower = INTEGRITY_FAILURE_MESSAGE.toLowerCase();
  assert.ok(!lower.includes('audit chain'), 'must not mention "audit chain"');
  assert.ok(!lower.includes('hash'), 'must not mention "hash"');
  assert.ok(!lower.includes('chain'), 'must not mention "chain"');
  assert.match(INTEGRITY_FAILURE_MESSAGE, /changed on disk/);
  assert.match(INTEGRITY_FAILURE_MESSAGE, /Contact support/);
});

test('reportIntegrityFailure shows the plain-language toast to the user', () => {
  reportIntegrityFailure({ ok: false, reason: 'entryHash mismatch', brokenAt: 2 });
  assert.equal(shownToast, INTEGRITY_FAILURE_MESSAGE);
  assert.ok(!shownToast.toLowerCase().includes('audit chain'));
});

test('the technical detail is preserved in the diagnostics log, not the toast', () => {
  telemetry.setEnabled(true);
  reportIntegrityFailure({ ok: false, reason: 'entryHash mismatch', brokenAt: 2 });

  // Toast stays plain; the jargon/technical detail is NOT surfaced to the user.
  assert.ok(!shownToast.toLowerCase().includes('mismatch'));

  // ...but support can still see exactly what failed in the opt-in log. The
  // technical detail rides recordError's allowlisted `code` channel now, not a
  // free-text `message` (which recordError drops to keep PHI out of the log).
  const ev = telemetry.getEvents().at(-1);
  assert.equal(ev.event, 'error');
  assert.equal(ev.kind, 'integrity');
  assert.ok(!('message' in ev), 'no free-text message is persisted');
  assert.match(ev.code, /entryHash mismatch/);
  assert.match(ev.code, /entry 2/);
});

test('a missing reason still records a sensible diagnostic and shows the toast', () => {
  telemetry.setEnabled(true);
  reportIntegrityFailure({ ok: false });
  assert.equal(shownToast, INTEGRITY_FAILURE_MESSAGE);
  const ev = telemetry.getEvents().at(-1);
  assert.equal(ev.kind, 'integrity');
  assert.match(ev.code, /integrity check failed/);
});
