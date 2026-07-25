// Unit tests for the patient consent-to-record modal (solo/consentModal.js,
// finding S1): the confirm button is gated on the attestation checkbox, the
// promise resolves true only on a checked+confirm, false on cancel, and the
// copy is state-aware (all-party vs one-party).
//
// Fake-DOM harness mirrors test_lockScreen.mjs (consentModal is built on the
// same platform/modal.js shell).

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

let els;
let docListeners;

class FakeEl {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.id = '';
    this.value = '';
    this.textContent = '';
    this.hidden = false;
    this.disabled = false;
    this.checked = false;
    this.className = '';
    this.type = '';
    this.style = {};
    this.children = [];
    this._on = {};
    this._attrs = {};
  }
  addEventListener(type, fn) { this._on[type] = fn; }
  removeEventListener(type) { delete this._on[type]; }
  setAttribute(a, v) { this._attrs[a] = v; }
  getAttribute(a) { return this._attrs[a]; }
  appendChild(child) { this.children.push(child); registerTree(child); return child; }
  remove() { removeFromRegistry(this); }
  focus() { globalThis.document.activeElement = this; }
  querySelectorAll() {
    const focusableTags = new Set(['button', 'input', 'select', 'textarea']);
    const out = [];
    const walk = node => {
      for (const c of node.children) {
        const tag = (c.tagName || '').toLowerCase();
        if (focusableTags.has(tag) || c._attrs.href != null || c._attrs.tabindex != null) out.push(c);
        walk(c);
      }
    };
    walk(this);
    return out;
  }
  click() { return this._on.click && this._on.click({ target: this }); }
  change() { return this._on.change && this._on.change({ target: this }); }
}

function registerTree(el) {
  if (el && el.id) els.set(el.id, el);
  el?.children?.forEach(registerTree);
}
function removeFromRegistry(el) {
  if (el?.id) els.delete(el.id);
  el?.children?.forEach(removeFromRegistry);
}

globalThis.document = {
  getElementById: id => els?.get(id) || null,
  createElement: tag => new FakeEl(tag),
  addEventListener: (type, fn) => { docListeners[type] = fn; },
  removeEventListener: type => { delete docListeners[type]; },
  get body() { return { appendChild: child => registerTree(child) }; },
  activeElement: null,
};
globalThis.window = globalThis.window || {};

const { consentToRecordModal } = await import('../../src/solo/consentModal.js');

beforeEach(() => {
  els = new Map();
  docListeners = {};
});

test('confirm is disabled until the attestation box is checked', () => {
  consentToRecordModal({ allParty: true, stateLabel: 'California' });
  const confirm = els.get('consent-confirm');
  const box = els.get('consent-attest-box');
  assert.equal(confirm.disabled, true, 'confirm must start disabled');
  box.checked = true;
  box.change();
  assert.equal(confirm.disabled, false, 'checking the box enables confirm');
});

test('checked + confirm resolves true', async () => {
  const p = consentToRecordModal({ allParty: true, stateLabel: 'Washington' });
  const box = els.get('consent-attest-box');
  box.checked = true;
  box.change();
  els.get('consent-confirm').click();
  assert.equal(await p, true);
});

test('confirm click without checking does nothing (stays open, unresolved)', async () => {
  let resolved = false;
  const p = consentToRecordModal({ allParty: true, stateLabel: 'Illinois' }).then(v => { resolved = true; return v; });
  els.get('consent-confirm').click(); // box unchecked
  await new Promise(r => setImmediate(r));
  assert.equal(resolved, false, 'an unchecked confirm must not resolve the promise');
  // now do it properly so the test doesn't leak a pending promise
  const box = els.get('consent-attest-box');
  box.checked = true; box.change();
  els.get('consent-confirm').click();
  assert.equal(await p, true);
});

test('cancel resolves false (fail safe: no attestation, no recording)', async () => {
  const p = consentToRecordModal({ allParty: true, stateLabel: 'Florida' });
  els.get('consent-cancel').click();
  assert.equal(await p, false);
});

test('copy is state-aware: all-party names the ALL-parties requirement', () => {
  consentToRecordModal({ allParty: true, stateLabel: 'Pennsylvania' });
  const msg = els.get('modal-message').textContent;
  assert.match(msg, /Pennsylvania/);
  assert.match(msg, /ALL parties/);
  assert.match(msg, /unlawful/);
});

test('copy is state-aware: one-party omits the ALL-parties / unlawful language', () => {
  consentToRecordModal({ allParty: false, stateLabel: 'New York' });
  const msg = els.get('modal-message').textContent;
  assert.doesNotMatch(msg, /ALL parties/);
  assert.doesNotMatch(msg, /unlawful/);
  assert.match(msg, /consents to this session being recorded/);
});
