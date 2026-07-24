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

// ── Fake DOM with createElement / appendChild ──────────────────────────────
// Richer than a flat id→node map because the H4 export warning mounts a real
// confirmModal (createModal → document.createElement + body.appendChild + a
// document-level keydown listener). Mirrors the pattern in test_lockScreen.mjs
// so the modal is actually driven, not stubbed.
let els;           // id -> element lookup (mirrors document.getElementById)
let docListeners;  // document-level listeners (keydown)

class FakeEl {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.id = '';
    this.value = '';
    this.textContent = '';
    this.hidden = false;
    this.disabled = false;
    this.className = '';
    this.style = {};
    this.children = [];
    this._on = {};
    this._attrs = {};
    this.classList = { add() {}, remove() {}, contains() { return false; } };
  }
  addEventListener(type, fn) { this._on[type] = fn; }
  removeEventListener(type) { delete this._on[type]; }
  setAttribute(a, v) { this._attrs[a] = v; }
  getAttribute(a) { return this._attrs[a]; }
  appendChild(child) { this.children.push(child); registerTree(child); return child; }
  remove() { removeFromRegistry(this); }
  focus() { globalThis.document.activeElement = this; }
  querySelector() { return null; }
  querySelectorAll() {
    const focusableTags = new Set(['button', 'input', 'select', 'textarea']);
    const out = [];
    const walk = node => {
      for (const c of node.children) {
        const tag = (c.tagName || '').toLowerCase();
        if (focusableTags.has(tag) || c._attrs.href != null || c._attrs.tabindex != null) {
          out.push(c);
        }
        walk(c);
      }
    };
    walk(this);
    return out;
  }
  click() { return this._on.click && this._on.click({ target: this }); }
}

function registerTree(el) {
  if (el && el.id) els.set(el.id, el);
  el?.children?.forEach(registerTree);
}
function removeFromRegistry(el) {
  if (el?.id) els.delete(el.id);
  el?.children?.forEach(removeFromRegistry);
}

function resetDom() {
  els = new Map();
  docListeners = {};
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
  createElement: tag => new FakeEl(tag),
  querySelector: () => null,
  addEventListener: (type, fn) => { docListeners[type] = fn; },
  removeEventListener: type => { delete docListeners[type]; },
  get body() { return { appendChild: child => registerTree(child) }; },
  activeElement: null,
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

// Every invoke, in order — lets a test assert that a command was NOT issued
// (e.g. no audit row for a cancelled export), which a responder map alone
// cannot express.
const calls = [];

function invokeMock(cmd, args) {
  calls.push({ cmd, args });
  const r = invokeResponders[cmd];
  if (r instanceof Error || (r && typeof r === 'object' && typeof r.code === 'string')) {
    return Promise.reject(r);
  }
  if (typeof r === 'function') return Promise.resolve(r(args));
  if (r !== undefined) return Promise.resolve(r);
  // The two Save-As commands resolve `true` when a file was actually written
  // and `false` when the provider dismissed the dialog (see export.rs — both
  // are successful outcomes, neither is an error). Default the fake to `true`
  // so an unconfigured test exercises the real save path; a cancel test opts
  // in explicitly with `invokeResponders[cmd] = false`.
  if (cmd === 'export_note_to_file' || cmd === 'export_note_pdf_to_file') {
    return Promise.resolve(true);
  }
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

// File exports (save-file / save-pdf) are gated behind the H4 unencrypted-PHI
// confirmModal. Clicking the button synchronously mounts that modal; the
// handler then awaits it. Answer it by clicking #modal-confirm / #modal-cancel,
// then await the handler's promise. `answer: null` leaves the modal up (used to
// assert nothing was written while the provider is still deciding).
async function clickFileExport(btnId, answer = 'confirm') {
  const handlerDone = els.get(btnId)._on.click();
  const modalBtn = els.get(answer === 'confirm' ? 'modal-confirm' : 'modal-cancel');
  assert.ok(els.get('modal-message'), 'the unencrypted-export warning must be shown before export');
  if (answer === null) return handlerDone; // caller resolves later
  modalBtn.click();
  await handlerDone;
}

beforeEach(() => {
  resetDom();
  invokeResponders = {};
  clipboardWriteImpl = null;
  calls.length = 0;
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
  await clickFileExport('btn-save-file', 'confirm');

  const msg = els.get('toast-msg').textContent;
  assert.ok(msg, 'a toast must be shown on failure');
  assert.doesNotMatch(msg, /saved to file/i, 'must not show the success message on failure');
});

test('save-to-file success still shows the success toast', async () => {
  invokeResponders['export_note_to_file'] = true; // a file was written
  wireExportSection(makeCtx());
  await clickFileExport('btn-save-file', 'confirm');

  assert.match(els.get('toast-msg').textContent, /saved to file/i);
});

test('save-to-pdf failure shows a failure toast instead of throwing silently', async () => {
  invokeResponders['export_note_pdf_to_file'] = Object.assign(new Error('permission denied'), { code: 'storage' });
  wireExportSection(makeCtx());
  await clickFileExport('btn-save-pdf', 'confirm');

  const msg = els.get('toast-msg').textContent;
  assert.ok(msg, 'a toast must be shown on failure');
  assert.doesNotMatch(msg, /saved as pdf/i, 'must not show the success message on failure');
});

test('save-to-pdf success still shows the success toast', async () => {
  invokeResponders['export_note_pdf_to_file'] = true; // a file was written
  wireExportSection(makeCtx());
  await clickFileExport('btn-save-pdf', 'confirm');

  assert.match(els.get('toast-msg').textContent, /saved as pdf/i);
});

// ── M-1: dismissing the Save dialog is not a disclosure ────────────────────
//
// export_note_to_file / export_note_pdf_to_file resolve `false` when the
// provider dismissed the native Save dialog. Nothing was written, so nothing
// downstream may act as though it was: no success toast claiming the note is
// on disk, and — the reason this is a compliance issue rather than a polish
// one — no `note_exported` audit row. That log is what a breach assessment
// reads to decide who to notify under §164.404, so a phantom row means
// notifying an individual about a disclosure that never happened.

test('a dismissed Save dialog shows no success toast and records no export', async () => {
  invokeResponders['export_note_to_file'] = false; // user cancelled
  wireExportSection(makeCtx());
  await clickFileExport('btn-save-file', 'confirm');

  assert.doesNotMatch(
    els.get('toast-msg').textContent || '',
    /saved to file/i,
    'the app must not claim a file was saved when the dialog was dismissed',
  );
  assert.ok(
    !calls.some(c => c.cmd === 'audit_log_note_exported'),
    'a cancelled export is not a disclosure and must not reach the audit trail',
  );
});

test('a dismissed PDF Save dialog shows no success toast and records no export', async () => {
  invokeResponders['export_note_pdf_to_file'] = false; // user cancelled
  wireExportSection(makeCtx());
  await clickFileExport('btn-save-pdf', 'confirm');

  assert.doesNotMatch(
    els.get('toast-msg').textContent || '',
    /saved as pdf/i,
    'the app must not claim a PDF was saved when the dialog was dismissed',
  );
  assert.ok(
    !calls.some(c => c.cmd === 'audit_log_note_exported'),
    'a cancelled export is not a disclosure and must not reach the audit trail',
  );
});

// ── H4: the unencrypted-PHI warning must gate every file export ────────────

test('save-to-file shows the unencrypted-PHI warning and does not write until confirmed', async () => {
  let wrote = false;
  invokeResponders['export_note_to_file'] = () => { wrote = true; return true; };
  wireExportSection(makeCtx());

  // Open the export; the warning must be up and nothing written yet.
  const done = clickFileExport('btn-save-file', null);
  assert.match(els.get('modal-message').textContent, /not\b.*encrypt|without encryption|encrypted/i);
  assert.equal(wrote, false, 'must not write the file before the provider acknowledges');

  // Acknowledge → the write proceeds.
  els.get('modal-confirm').click();
  await done;
  assert.equal(wrote, true, 'confirming the warning must let the export proceed');
  assert.match(els.get('toast-msg').textContent, /saved to file/i);
});

test('cancelling the warning blocks the file export entirely', async () => {
  let wrote = false;
  invokeResponders['export_note_to_file'] = () => { wrote = true; return true; };
  wireExportSection(makeCtx());

  await clickFileExport('btn-save-file', 'cancel');
  assert.equal(wrote, false, 'cancelling must prevent any file from being written');
  assert.doesNotMatch(els.get('toast-msg').textContent || '', /saved to file/i);
});

test('cancelling the warning blocks the PDF export entirely', async () => {
  let wrote = false;
  invokeResponders['export_note_pdf_to_file'] = () => { wrote = true; return true; };
  wireExportSection(makeCtx());

  await clickFileExport('btn-save-pdf', 'cancel');
  assert.equal(wrote, false, 'cancelling must prevent any PDF from being written');
  assert.doesNotMatch(els.get('toast-msg').textContent || '', /saved as pdf/i);
});

test('copy to clipboard is NOT gated by the file-export warning', async () => {
  // The warning is specifically about a plaintext file persisted to disk; the
  // clipboard path is transient and auto-clears, so it stays unmodalled.
  clipboardWriteImpl = async () => {};
  wireExportSection(makeCtx());
  await els.get('btn-copy')._on.click();

  assert.equal(els.get('modal-message'), undefined, 'copy must not raise the file-export warning');
  assert.match(els.get('toast-msg').textContent, /copied to clipboard/i);
});
