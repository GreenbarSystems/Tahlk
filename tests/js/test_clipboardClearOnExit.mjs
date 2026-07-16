// Regression tests for clearClipboardOnExit (exportFormatter.js).
//
// Before this fix, PHI copied to the clipboard only cleared via a
// setTimeout scheduled CLIPBOARD_CLEAR_MS (90s) in the future — a plain JS
// timer that never fires once the process exits. Quitting the app shortly
// after copying a note left PHI sitting on the OS clipboard indefinitely.
// clearClipboardOnExit is wired to the window close-requested event
// (entry-solo.js) so the same check-then-clear runs immediately at exit
// time instead of waiting on the timer.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

let clipboardText = null; // simulated OS clipboard contents

globalThis.document = { getElementById: () => null };
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: () => Promise.resolve(null) },
  event: { listen: () => () => {} },
  ['clipboard-manager']: {
    writeText: async text => { clipboardText = text; },
    readText: async () => clipboardText,
  },
};
globalThis.window = globalThis.window || {};

const { copyToClipboard, clearClipboardOnExit } = await import('../../src/export/exportFormatter.js');

const encounterId = 'enc-clip-1';

beforeEach(() => {
  clipboardText = null;
});

test('clearClipboardOnExit is a no-op when nothing was ever copied', async () => {
  await clearClipboardOnExit();
  assert.equal(clipboardText, null);
});

test('clearClipboardOnExit clears the clipboard immediately if it still holds what copyToClipboard wrote', async () => {
  await copyToClipboard('PHI note body', encounterId, 'plain');
  assert.equal(clipboardText, 'PHI note body');

  await clearClipboardOnExit();
  assert.equal(clipboardText, '', 'clipboard must be wiped, not left holding PHI');
});

test('clearClipboardOnExit does not clobber clipboard content the user copied afterward', async () => {
  await copyToClipboard('PHI note body', encounterId, 'plain');
  clipboardText = 'something the user copied from elsewhere';

  await clearClipboardOnExit();
  assert.equal(
    clipboardText,
    'something the user copied from elsewhere',
    'must never wipe clipboard content that no longer matches what we wrote'
  );
});

test('clearClipboardOnExit is a no-op after the timed auto-clear already ran', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  await copyToClipboard('PHI note body', encounterId, 'plain');

  // Fast-forward past CLIPBOARD_CLEAR_MS so the scheduled auto-clear fires
  // and marks nothing as pending any more.
  t.mock.timers.tick(90_001);
  // Let the timer callback's own microtasks (clipboardReadText/WriteText
  // awaits) settle before asserting.
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(clipboardText, '', 'the timed auto-clear should have already fired');

  clipboardText = 'unrelated content typed after the auto-clear';
  await clearClipboardOnExit();
  assert.equal(
    clipboardText,
    'unrelated content typed after the auto-clear',
    'nothing should be pending any more, so this must not touch the clipboard'
  );
});

test('calling clearClipboardOnExit twice in a row is safe (second call is a no-op)', async () => {
  await copyToClipboard('PHI note body', encounterId, 'plain');
  await clearClipboardOnExit();
  assert.equal(clipboardText, '');

  clipboardText = 'something new';
  await clearClipboardOnExit();
  assert.equal(clipboardText, 'something new', 'second call must be a no-op, nothing left pending');
});
