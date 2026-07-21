// Regression tests for exportSection.js's error handling.
//
// Previously the three export handlers (copy / save-file / save-pdf) had
// zero try/catch — a rejected export (clipboard permission denied, disk
// full, an invalid save path from the native dialog) surfaced as a silent
// unhandled promise rejection with no toast and no feedback to the
// provider. These tests drive the real wireExportSection handlers against a
// fake DOM + mocked Tauri invoke/clipboard layer and assert that a failure
// always produces a user-visible failure toast instead of vanishing.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// ── Fake DOM (same minimal shape used by the other UI-wiring tests) ────────
let els;

class FakeEl {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.id = '';
    this.value = '';
    this.textContent = '';
    this._on = {};
    this.classList = { add() {}, remove() {}, contains() { return false; } };
  }
  addEventListener(type, fn) { this._on[type] = fn; }
  removeEventListener() {}
  click() { return this._on.click && this._on.click(); }
  setAttribute() {}
  getAttribute() {}
}

function resetDom() {
  els = new Map();
  for (const id of ['note-area', 'export-format', 'btn-copy', 'btn-save-file', 'btn-save-pdf', 'toast', 'toast-msg']) {
    const e = new FakeEl();
    e.id = id;
    els.set(id, e);
  }
  els.get('note-area').value = 'NOTE BODY';
  els.get('export-format').value = 'plain';
}

globalThis.document = {
  getElementById: id => els?.get(id) || null,
  querySelector: () => null,
};
// jsPDF's node build treats `window` as its global scope if present, so the
// mock must expose the primitives it reaches for (atob/btoa/console). An
// empty object here makes jsPDF throw on load (see test_pdfExport.mjs).
globalThis.window = globalThis.window || {};
globalThis.window.atob = globalThis.window.atob || globalThis.atob;
globalThis.window.btoa = globalThis.window.btoa || globalThis.btoa;
globalThis.window.console = globalThis.window.console || globalThis.console;

// pdfExport's toBase64 encodes via FileReader.readAsDataURL rather than a
// synchronous btoa loop (which froze the UI on long notes). Node has no DOM
// File API — supply the two primitives it needs. Same fakes as
// test_pdfExport.mjs.
globalThis.Blob = globalThis.Blob || class {
  constructor(parts) { this.parts = parts; }
};
globalThis.FileReader = globalThis.FileReader || class {
  readAsDataURL() { queueMicrotask(() => this.onload?.()); }
  get result() { return 'data:application/pdf;base64,JVBERi0x'; }
};

// ── Mock Tauri runtime ───────────────────────────────────────────────────
let invokeResponders = {};
let clipboardWriteImpl = null; // null => falls through to "Clipboard unavailable" throw

function invokeMock(cmd, args) {
  const r = invokeResponders[cmd];
  if (r instanceof Error || (r && typeof r === 'object' && typeof r.code === 'string')) {
    return Promise.reject(r);
  }
  if (typeof r === 'function') return Promise.resolve(r(args));
  if (r !== undefined) return Promise.resolve(r);
  return Promise.resolve(null);
}

globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: invokeMock },
  event: { listen: () => () => {} },
  get ['clipboard-manager']() {
    return clipboardWriteImpl ? { writeText: clipboardWriteImpl, readText: async () => null } : undefined;
  },
};

const { wireExportSection } = await import('../../src/solo/encounter/exportSection.js');

function makeCtx() {
  return { currentEncounter: { id: 'enc-1', encounter_date: '2026-07-04', patient_alias: 'P-1' } };
}

beforeEach(() => {
  resetDom();
  invokeResponders = {};
  clipboardWriteImpl = null;
});

test('copy failure shows a failure toast instead of throwing silently', async () => {
  // No clipboard mock installed -> clipboardWriteText's test-mode fallback
  // throws 'Clipboard unavailable', simulating a real clipboard permission
  // failure.
  wireExportSection(makeCtx());
  await els.get('btn-copy')._on.click();

  const msg = els.get('toast-msg').textContent;
  assert.ok(msg, 'a toast must be shown on failure');
  assert.doesNotMatch(msg, /copied to clipboard/i, 'must not show the success message on failure');
});

test('copy success still shows the success toast', async () => {
  clipboardWriteImpl = async () => {};
  wireExportSection(makeCtx());
  await els.get('btn-copy')._on.click();

  assert.match(els.get('toast-msg').textContent, /copied to clipboard/i);
});

test('save-to-file failure shows a failure toast instead of throwing silently', async () => {
  invokeResponders['export_note_to_file'] = Object.assign(new Error('disk full'), { code: 'storage' });
  wireExportSection(makeCtx());
  await els.get('btn-save-file')._on.click();

  const msg = els.get('toast-msg').textContent;
  assert.ok(msg, 'a toast must be shown on failure');
  assert.doesNotMatch(msg, /saved to file/i, 'must not show the success message on failure');
});

test('save-to-file success still shows the success toast', async () => {
  invokeResponders['export_note_to_file'] = null;
  wireExportSection(makeCtx());
  await els.get('btn-save-file')._on.click();

  assert.match(els.get('toast-msg').textContent, /saved to file/i);
});

test('save-to-pdf failure shows a failure toast instead of throwing silently', async () => {
  invokeResponders['export_note_pdf_to_file'] = Object.assign(new Error('permission denied'), { code: 'storage' });
  wireExportSection(makeCtx());
  await els.get('btn-save-pdf')._on.click();

  const msg = els.get('toast-msg').textContent;
  assert.ok(msg, 'a toast must be shown on failure');
  assert.doesNotMatch(msg, /saved as pdf/i, 'must not show the success message on failure');
});

test('save-to-pdf success still shows the success toast', async () => {
  invokeResponders['export_note_pdf_to_file'] = null;
  wireExportSection(makeCtx());
  await els.get('btn-save-pdf')._on.click();

  assert.match(els.get('toast-msg').textContent, /saved as pdf/i);
});
