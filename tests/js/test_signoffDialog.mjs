// S-UX-5: sign-off uses a styled in-app confirmation dialog instead of the
// browser-native confirm(). Wires the REAL noteSection against a fake DOM that
// supports createElement/appendChild (so the dialog actually mounts), then
// drives the dialog's buttons. Verifies:
//   - the dialog copy carries the "will be locked" warning
//   - confirming ("Sign & Lock") runs the real sign-off (mark_encounter_signed)
//   - cancelling does NOT sign and leaves the encounter unsigned
//   - Escape cancels (no sign-off)

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// ── Fake DOM with createElement / appendChild so the modal can mount ────────
let els;          // id -> element lookup (mirrors document.getElementById)
let docListeners; // document-level listeners (keydown for Escape/Enter)

class FakeEl {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.id = '';
    this.value = '';
    this.textContent = '';
    this.placeholder = '';
    this.disabled = false;
    this.readOnly = false;
    this.className = '';
    this.style = {};
    this.children = [];
    this._on = {};
    this._attrs = {};
    this.classList = {
      _s: new Set(),
      add: c => this.classList._s.add(c),
      remove: c => this.classList._s.delete(c),
      contains: c => this.classList._s.has(c),
    };
  }
  addEventListener(type, fn) { this._on[type] = fn; }
  removeEventListener() {}
  removeAttribute(a) { if (a === 'disabled') this.disabled = false; delete this._attrs[a]; }
  setAttribute(a, v) { this._attrs[a] = v; }
  getAttribute(a) { return this._attrs[a]; }
  appendChild(child) { this.children.push(child); registerTree(child); return child; }
  remove() {}
  focus() {}
  click() { return this._on.click && this._on.click(); }
}

// Register any element in a freshly-appended subtree that carries an id, so
// document.getElementById can find the dialog's buttons after it mounts.
function registerTree(el) {
  if (el && el.id) els.set(el.id, el);
  el?.children?.forEach(registerTree);
}

function resetDom() {
  els = new Map();
  docListeners = {};
  for (const id of [
    'note-area', 'transcript-area', 'btn-sign', 'btn-copy', 'btn-save-file',
    'note-save-indicator', 'toast', 'toast-msg',
  ]) {
    const e = new FakeEl();
    e.id = id;
    els.set(id, e);
  }
}

globalThis.document = {
  getElementById: id => els?.get(id) || null,
  querySelector: () => null,
  createElement: tag => new FakeEl(tag),
  addEventListener: (type, fn) => { docListeners[type] = fn; },
  removeEventListener: type => { delete docListeners[type]; },
  get body() { return { appendChild: child => registerTree(child) }; },
};
function pressKey(key) {
  docListeners.keydown?.({ key, preventDefault() {} });
}
globalThis.window = globalThis.window || {};
globalThis.requestAnimationFrame = cb => { cb(); return 0; };
globalThis.cancelAnimationFrame = () => {};

// ── Mock Tauri runtime (same shape as the other integration tests) ──────────
let responders = {};
let _history = new Map();
let _calls = [];
function invokeMock(cmd, args) {
  _calls.push({ cmd, args });
  const r = responders[cmd];
  if (r instanceof Error || (r && typeof r === 'object' && typeof r.code === 'string')) {
    return Promise.reject(r);
  }
  if (typeof r === 'function') return Promise.resolve(r(args));
  if (r !== undefined) return Promise.resolve(r);
  if (cmd === 'note_history_list') return Promise.resolve(_history.get(args.encounterId)?.slice() || []);
  if (cmd === 'note_history_append') {
    const list = _history.get(args.encounterId) || [];
    list.push(args.entry);
    _history.set(args.encounterId, list);
    return Promise.resolve(list.length);
  }
  return Promise.resolve(null);
}
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: invokeMock },
  event: { listen: () => () => {} },
};

const { wireNoteSection } = await import('../../src/solo/encounter/noteSection.js');

function makeCtx() {
  const enc = { id: 'enc-1', status: 'draft', audio_path: null };
  return {
    currentEncounter: enc,
    providerProfile: { name: 'Dr. Smith' },
    sub: () => {},
    onEncounterUpdated: () => {},
    currentTranscript: () => 'TRANSCRIPT',
  };
}

// Click Sign, then return the mounted dialog's message + a resolver for either
// button. The sign handler awaits confirmModal, which mounts synchronously, so
// the dialog elements exist as soon as click() returns its pending promise.
function openSignDialog(ctx) {
  wireNoteSection(ctx);
  els.get('note-area').value = 'SIGNED NOTE BODY';
  const signHandlerPromise = els.get('btn-sign')._on.click();
  return { signHandlerPromise, message: els.get('modal-message')?.textContent || '' };
}

function _historyCommands() { return _calls.map(c => c.cmd); }

beforeEach(() => {
  resetDom();
  responders = {};
  _history = new Map();
  _calls = [];
});

test('sign dialog warns that the note will be locked', async () => {
  const ctx = makeCtx();
  const { signHandlerPromise, message } = openSignDialog(ctx);

  assert.match(message, /will be locked/i);
  assert.ok(els.get('modal-confirm'), 'a distinct confirm button is rendered');
  assert.ok(els.get('modal-cancel'), 'a distinct cancel button is rendered');
  assert.match(els.get('modal-confirm').textContent, /sign/i);

  // Dismiss so the awaited handler settles.
  els.get('modal-cancel').click();
  await signHandlerPromise;
});

test('confirming the dialog runs the real sign-off', async () => {
  const ctx = makeCtx();
  const { signHandlerPromise } = openSignDialog(ctx);

  els.get('modal-confirm').click();
  await signHandlerPromise;

  const cmds = _historyCommands();
  assert.ok(cmds.includes('mark_encounter_signed'), 'confirm triggers sign-off');
  assert.equal(ctx.currentEncounter.status, 'signed');
});

test('cancelling the dialog does NOT sign and leaves the encounter unsigned', async () => {
  const ctx = makeCtx();
  const { signHandlerPromise } = openSignDialog(ctx);

  els.get('modal-cancel').click();
  await signHandlerPromise;

  const cmds = _historyCommands();
  assert.ok(!cmds.includes('mark_encounter_signed'), 'cancel must not sign');
  assert.equal(ctx.currentEncounter.status, 'draft', 'encounter stays unsigned');
});

test('Escape cancels the dialog without signing', async () => {
  const ctx = makeCtx();
  const { signHandlerPromise } = openSignDialog(ctx);

  pressKey('Escape');
  await signHandlerPromise;

  assert.ok(!_historyCommands().includes('mark_encounter_signed'));
  assert.equal(ctx.currentEncounter.status, 'draft');
});
