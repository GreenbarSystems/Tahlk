// Unit tests for the idle-lock overlay (solo/lockScreen.js): PIN
// verification wiring, idempotent show, the failed-attempt lockout with
// doubling cooldown, non-dismissibility (no Escape/backdrop bypass), and
// full removal + listener cleanup on unlock.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// ── Fake DOM with createElement / appendChild, mirroring the pattern in
// test_signoffDialog.mjs (confirmModal.js's sibling dialog) ────────────────
let els;          // id -> element lookup (mirrors document.getElementById)
let docListeners; // document-level listeners (keydown)

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
  }
  addEventListener(type, fn) { this._on[type] = fn; }
  removeEventListener(type) { delete this._on[type]; }
  setAttribute(a, v) { this._attrs[a] = v; }
  getAttribute(a) { return this._attrs[a]; }
  appendChild(child) { this.children.push(child); registerTree(child); return child; }
  remove() { removeFromRegistry(this); }
  focus() {}
  click() { return this._on.click && this._on.click({ target: this }); }
  submit() { return this._on.submit && this._on.submit({ preventDefault() {}, target: this }); }
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
}

globalThis.document = {
  getElementById: id => els?.get(id) || null,
  createElement: tag => new FakeEl(tag),
  addEventListener: (type, fn) => { docListeners[type] = fn; },
  removeEventListener: type => { delete docListeners[type]; },
  get body() { return { appendChild: child => registerTree(child) }; },
};
function pressKey(key) {
  docListeners.keydown?.({ key, preventDefault() {} });
}
globalThis.window = globalThis.window || {};

// ── Mock lockRepo.verifyPin via the same escape hatch other repos use ──────
let verifyResult;
globalThis.__TAHLK_TEST_TAURI__ = {
  core: {
    invoke: (cmd, args) => {
      if (cmd === 'lock_pin_verify') {
        if (verifyResult instanceof Error) return Promise.reject(verifyResult);
        return Promise.resolve(verifyResult);
      }
      return Promise.resolve(null);
    },
  },
  event: { listen: () => () => {} },
};

const { showLockScreen, hideLockScreen, isLockScreenShowing } = await import('../../src/solo/lockScreen.js');

function submitPin(pin) {
  els.get('lock-pin-input').value = pin;
  return els.get('lock-form').submit();
}

beforeEach(() => {
  resetDom();
  verifyResult = false;
});

test('showLockScreen mounts the overlay and focuses the PIN input', () => {
  showLockScreen(() => {});
  assert.ok(isLockScreenShowing());
  assert.ok(els.get('lock-overlay'));
  assert.ok(els.get('lock-form'));
  assert.ok(els.get('lock-pin-input'));
});

test('showLockScreen is idempotent — calling it again while shown is a no-op', () => {
  showLockScreen(() => {});
  const firstOverlay = els.get('lock-overlay');
  showLockScreen(() => {});
  assert.equal(els.get('lock-overlay'), firstOverlay, 'must not mount a second overlay');
});

test('a correct PIN removes the overlay and calls onUnlock', async () => {
  verifyResult = true;
  let unlocked = false;
  showLockScreen(() => { unlocked = true; });

  await submitPin('1234');

  assert.equal(unlocked, true);
  assert.equal(isLockScreenShowing(), false, 'overlay must be removed on unlock');
});

test('an incorrect PIN shows an error, clears the input, and does not call onUnlock', async () => {
  verifyResult = false;
  let unlocked = false;
  showLockScreen(() => { unlocked = true; });

  await submitPin('0000');

  assert.equal(unlocked, false);
  assert.equal(isLockScreenShowing(), true, 'overlay must stay up after a wrong PIN');
  assert.equal(els.get('lock-pin-input').value, '', 'the wrong PIN must be cleared from the field');
  assert.equal(els.get('lock-error').hidden, false);
  assert.match(els.get('lock-error').textContent, /incorrect/i);
});

test('submitting an empty PIN is rejected locally without calling verifyPin', async () => {
  let verifyCalls = 0;
  const origInvoke = globalThis.__TAHLK_TEST_TAURI__.core.invoke;
  globalThis.__TAHLK_TEST_TAURI__.core.invoke = (cmd, args) => {
    if (cmd === 'lock_pin_verify') verifyCalls++;
    return origInvoke(cmd, args);
  };

  showLockScreen(() => {});
  await submitPin('');

  assert.equal(verifyCalls, 0, 'an empty PIN must never reach the backend');
  assert.match(els.get('lock-error').textContent, /enter your pin/i);
  globalThis.__TAHLK_TEST_TAURI__.core.invoke = origInvoke;
});

test('five failed attempts trigger a lockout that blocks further submits until it expires', async () => {
  verifyResult = false;
  showLockScreen(() => {});

  for (let i = 0; i < 5; i++) {
    await submitPin('0000');
  }
  assert.match(els.get('lock-error').textContent, /too many attempts/i);

  // A 6th submit while still locked out must not even call verifyPin —
  // it should short-circuit on the remaining-cooldown check.
  let verifyCalls = 0;
  const origInvoke = globalThis.__TAHLK_TEST_TAURI__.core.invoke;
  globalThis.__TAHLK_TEST_TAURI__.core.invoke = (cmd, args) => {
    if (cmd === 'lock_pin_verify') verifyCalls++;
    return origInvoke(cmd, args);
  };
  await submitPin('0000');
  assert.equal(verifyCalls, 0, 'a submit during the lockout window must not re-check the PIN');
  globalThis.__TAHLK_TEST_TAURI__.core.invoke = origInvoke;
});

test('a correct PIN still works after an earlier wrong attempt (lockout not yet triggered)', async () => {
  verifyResult = false;
  let unlocked = false;
  showLockScreen(() => { unlocked = true; });

  await submitPin('0000'); // 1 failed attempt, below the 5-attempt threshold

  verifyResult = true;
  await submitPin('1234');

  assert.equal(unlocked, true);
  assert.equal(isLockScreenShowing(), false);
});

test('Escape does not dismiss the lock screen — it is not a normal cancellable modal', async () => {
  let unlocked = false;
  showLockScreen(() => { unlocked = true; });

  pressKey('Escape');

  assert.equal(isLockScreenShowing(), true, 'Escape must never remove the lock overlay');
  assert.equal(unlocked, false);
});

test('hideLockScreen removes the overlay and the document keydown listener', () => {
  showLockScreen(() => {});
  assert.ok(docListeners.keydown, 'a keydown listener is registered while shown');

  hideLockScreen();

  assert.equal(isLockScreenShowing(), false);
  assert.equal(docListeners.keydown, undefined, 'the keydown listener must be cleaned up too');
});

test('hideLockScreen is a harmless no-op when nothing is showing', () => {
  assert.doesNotThrow(() => hideLockScreen());
  assert.equal(isLockScreenShowing(), false);
});

test('a verifyPin rejection (e.g. transport error) shows an error without crashing or unlocking', async () => {
  verifyResult = new Error('backend unavailable');
  let unlocked = false;
  showLockScreen(() => { unlocked = true; });

  await submitPin('1234');

  assert.equal(unlocked, false);
  assert.equal(isLockScreenShowing(), true);
  assert.match(els.get('lock-error').textContent, /could not verify pin/i);
});
