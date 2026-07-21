// Unit tests for the shared modal scaffolding (src/platform/modal.js):
//   - open() mounts the backdrop+card shell into document.body
//   - the shell carries the expected classes / dialog ARIA
//   - Escape requests close (and close() unmounts + detaches the listener)
//   - a click on the backdrop (but not the card) requests close
//   - close() is idempotent
//
// Uses a tiny fake DOM (createElement / appendChild / a single document-level
// keydown listener) so the module runs under `node --test` without a browser.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

let docListeners; // document-level listeners keyed by type (keydown)
let bodyChildren; // top-level nodes mounted on document.body

class FakeEl {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.id = '';
    this.className = '';
    this.children = [];
    this.parent = null;
    this._on = {};
    this._attrs = {};
  }
  setAttribute(a, v) { this._attrs[a] = v; }
  getAttribute(a) { return this._attrs[a]; }
  addEventListener(type, fn) { this._on[type] = fn; }
  removeEventListener(type) { delete this._on[type]; }
  focus() { globalThis.document.activeElement = this; }
  // Minimal querySelectorAll covering the focusable selector modal.js's focus
  // trap uses (tag names plus [href]/[tabindex]). Implemented as a real subtree
  // walk rather than a `() => []` stub so the trap stays exercisable from tests
  // instead of being permanently invisible to them.
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
  appendChild(child) { child.parent = this; this.children.push(child); return child; }
  remove() {
    if (!this.parent) return;
    const i = this.parent.children.indexOf(this);
    if (i >= 0) this.parent.children.splice(i, 1);
    this.parent = null;
  }
  // Simulate a real click dispatch: the handler is registered on the node the
  // listener was attached to, and receives an event whose `target` is the node
  // that was actually clicked.
  dispatchClick(target) { return this._on.click && this._on.click({ target }); }
}

const body = {
  children: [],
  appendChild(child) { child.parent = body; body.children.push(child); return child; },
};

globalThis.document = {
  createElement: tag => new FakeEl(tag),
  addEventListener: (type, fn) => { docListeners[type] = fn; },
  removeEventListener: type => { delete docListeners[type]; },
  get body() { return body; },
  // modal.js captures this on open() and restores focus to it on close().
  activeElement: null,
};

function pressKey(key) {
  docListeners.keydown?.({ key, preventDefault() {} });
}

const { createModal } = await import('../../src/platform/modal.js');

beforeEach(() => {
  docListeners = {};
  body.children = [];
  bodyChildren = body.children;
});

test('open() mounts the backdrop+card shell with dialog semantics', () => {
  const modal = createModal({ backdropId: 'modal-backdrop' });
  modal.open();

  assert.equal(bodyChildren.length, 1, 'backdrop is mounted on body');
  const backdrop = bodyChildren[0];
  assert.equal(backdrop, modal.backdrop);
  assert.equal(backdrop.className, 'modal-backdrop');
  assert.equal(backdrop.id, 'modal-backdrop');

  assert.equal(backdrop.children.length, 1, 'card is inside the backdrop');
  const card = backdrop.children[0];
  assert.equal(card, modal.card);
  assert.equal(card.className, 'modal-card');
  assert.equal(card.getAttribute('role'), 'dialog');
  assert.equal(card.getAttribute('aria-modal'), 'true');
});

test('Escape requests close', () => {
  let reason = null;
  const modal = createModal({ onRequestClose: r => { reason = r; } });
  modal.open();

  pressKey('Escape');
  assert.equal(reason, 'escape', 'Escape triggers onRequestClose');
});

test('backdrop click requests close, card click does not', () => {
  let count = 0;
  const modal = createModal({ onRequestClose: () => { count++; } });
  modal.open();

  modal.backdrop.dispatchClick(modal.card);   // click landed on the card
  assert.equal(count, 0, 'click inside the card must not close');

  modal.backdrop.dispatchClick(modal.backdrop); // click landed on the dim area
  assert.equal(count, 1, 'click on the backdrop closes');
});

test('close() unmounts the shell and detaches the keydown listener', () => {
  const modal = createModal();
  modal.open();
  assert.equal(bodyChildren.length, 1);
  assert.ok(docListeners.keydown, 'listens for keydown while open');

  modal.close();
  assert.equal(bodyChildren.length, 0, 'backdrop removed from body');
  assert.equal(docListeners.keydown, undefined, 'keydown listener detached');
});

test('close() is idempotent', () => {
  let count = 0;
  const modal = createModal({ onRequestClose: () => { count++; } });
  modal.open();
  modal.close();
  modal.close();

  // A late Escape after close must not reach the handler.
  pressKey('Escape');
  assert.equal(count, 0);
  assert.equal(bodyChildren.length, 0);
});

test('onKeyDown receives non-Escape keys (e.g. Enter)', () => {
  const seen = [];
  const modal = createModal({ onKeyDown: e => seen.push(e.key) });
  modal.open();

  pressKey('Enter');
  pressKey('a');
  assert.deepEqual(seen, ['Enter', 'a']);
});

test('closeOnEscape:false leaves Escape to onKeyDown', () => {
  let closes = 0;
  const seen = [];
  const modal = createModal({
    closeOnEscape: false,
    onRequestClose: () => { closes++; },
    onKeyDown: e => seen.push(e.key),
  });
  modal.open();

  pressKey('Escape');
  assert.equal(closes, 0, 'Escape does not close when disabled');
  assert.deepEqual(seen, ['Escape'], 'Escape is forwarded to onKeyDown instead');
});
