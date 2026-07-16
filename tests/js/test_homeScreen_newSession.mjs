// Regression tests for the New Session button (homeScreen.js).
//
// The click handler previously did a bare `await encountersRepo.save(...)`
// with no catch, then opened the encounter panel. A save failure (disk full,
// DB locked, pool exhausted) rejected into nothing — no toast, no log, just a
// button that appeared dead, with the rejection escaping as an unhandled
// promise. That silence is the bug these pin.
//
// Note on what was NOT broken: the panel already didn't open on failure, since
// the throw skipped past onOpenEncounter. The "does NOT open" test below is
// still worth keeping — it pins that ordering guarantee explicitly so a future
// refactor can't quietly invert it — but it is a characterization test, not a
// regression test for a bug that shipped.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// ── Minimal fake DOM: enough for renderHomeScreen's output to be wired and
// for toast() to find its host (utils/format.js writes into #toast-msg).
let els;

class FakeEl {
  constructor(tag = 'div') {
    this.tagName = tag;
    this.id = '';
    this.textContent = '';
    this.className = '';
    this.dataset = {};
    this.style = {};
    this.hidden = false;
    this._on = {};
    this._attrs = {};
    this.classList = { add() {}, remove() {}, toggle() {}, contains: () => false };
  }
  addEventListener(type, fn) { this._on[type] = fn; }
  removeEventListener(type) { delete this._on[type]; }
  // toast() sets role="status" and swaps a .show class on the toast host.
  setAttribute(a, v) { this._attrs[a] = v; }
  getAttribute(a) { return this._attrs[a]; }
  removeAttribute(a) { delete this._attrs[a]; }
  click() { return this._on.click && this._on.click(); }
  querySelectorAll() { return []; }
}

function resetDom() {
  els = new Map();
  for (const id of ['btn-new-session', 'toast', 'toast-msg']) {
    const e = new FakeEl();
    e.id = id;
    els.set(id, e);
  }
}

globalThis.document = {
  getElementById: id => els?.get(id) || null,
  querySelectorAll: () => [],
  createElement: tag => new FakeEl(tag),
  addEventListener() {},
  removeEventListener() {},
  get body() { return { appendChild() {} }; },
};
globalThis.window = globalThis.window || {};

// ── Mock Tauri runtime. `saveOutcome` decides what upsert_encounter does.
let saveOutcome; // 'ok' | Error
let invokedCommands;

globalThis.__TAHLK_TEST_TAURI__ = {
  core: {
    invoke: (cmd, args) => {
      invokedCommands.push(cmd);
      if (cmd === 'upsert_encounter') {
        if (saveOutcome instanceof Error) return Promise.reject(saveOutcome);
        return Promise.resolve(null);
      }
      // Stats/list feed the initial render; keep them boring.
      if (cmd === 'encounter_stats') return Promise.resolve({ total: 0, signed: 0, today: 0 });
      if (cmd === 'list_encounters') return Promise.resolve([]);
      return Promise.resolve(null);
    },
  },
  event: { listen: () => () => {} },
};

const { wireHomeScreen } = await import('../../src/solo/homeScreen.js');

function toastText() {
  return els.get('toast-msg')?.textContent || '';
}

beforeEach(() => {
  resetDom();
  saveOutcome = 'ok';
  invokedCommands = [];
});

test('a successful save opens the encounter panel exactly once', async () => {
  const opened = [];
  await wireHomeScreen(enc => opened.push(enc));

  await els.get('btn-new-session').click();

  assert.equal(opened.length, 1, 'panel should open once on success');
  assert.ok(invokedCommands.includes('upsert_encounter'), 'the row should be saved');
  assert.match(opened[0].id, /^enc-/, 'a fresh encounter id should be generated');
  assert.equal(opened[0].status, 'recording');
});

test('a failed save does NOT open the encounter panel', async () => {
  saveOutcome = new Error('database is locked');
  const opened = [];
  await wireHomeScreen(enc => opened.push(enc));

  await els.get('btn-new-session').click();

  assert.equal(
    opened.length,
    0,
    'must not hand the provider an encounter the DB never stored'
  );
});

test('a failed save surfaces a toast instead of failing silently', async () => {
  saveOutcome = new Error('database is locked');
  await wireHomeScreen(() => {});

  await els.get('btn-new-session').click();

  const msg = toastText();
  assert.notEqual(msg, '', 'a save failure must not be silent — this is the whole bug');
  assert.match(msg, /could not start a new session/i);
});

test('the click handler never rejects, even when the save throws', async () => {
  // The original bug surfaced as an unhandled rejection. The handler must
  // absorb the failure itself rather than leaking it to the event loop.
  saveOutcome = new Error('disk full');
  await wireHomeScreen(() => {});

  await assert.doesNotReject(async () => {
    await els.get('btn-new-session').click();
  });
});
