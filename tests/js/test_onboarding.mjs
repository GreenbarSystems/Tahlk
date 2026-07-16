// S-UX-7 (plain-language inline help) + ADR 0003 (BAA step removed from
// onboarding for the test-data-only beta — see
// docs/adr/0003-disable-baa-gate-for-beta.md). Onboarding is now 2 steps:
// provider profile, then Anthropic API key. There is no BAA checkbox or
// step-baa block here anymore; the Rust-side gate is soft-disabled
// (baa::GATE_ENABLED = false) and Settings still offers a voluntary,
// non-blocking BAA acknowledgment for testers who already have one.
//
// The disclosures use the same native <details>/<summary> pattern introduced
// for "View integrity details" in S-UX-3 (see template.js / test_integrityDisplay).

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// storageBackend / secretsRepo touch the injected Tauri runtime and DOM at
// import time, so shim both BEFORE the dynamic import (same approach as
// test_baa.mjs and test_integrityDisplay.mjs).
const calls = [];
let nextResult = { ok: null };
globalThis.__TAHLK_TEST_TAURI__ = {
  core: {
    invoke: (command, args) => {
      calls.push({ command, args });
      if (nextResult.reject !== undefined) return Promise.reject(nextResult.reject);
      return Promise.resolve(nextResult.ok);
    },
  },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};
globalThis.document = { getElementById: () => null, querySelector: () => null };

const { renderOnboarding, wireOnboarding } = await import('../../src/solo/onboarding.js');

beforeEach(() => {
  calls.length = 0;
  nextResult = { ok: null };
});

// ── API-key step: explanation + "How do I get one?" disclosure ───────────────

test('API-key step explains what the key is and that Tahlk never stores it', () => {
  const html = renderOnboarding();
  const step = html.slice(html.indexOf('id="step-apikey"'), html.indexOf('onboarding-footer'));
  assert.match(step, /Anthropic/);
  assert.match(step, /API key/i);
  // Plain-language reassurance that the key stays local / Tahlk never sees it.
  assert.match(step, /never sees or stores your key|secure credential store/i);
});

test('API-key step has a collapsed "How do I get one?" disclosure with steps', () => {
  const html = renderOnboarding();
  const step = html.slice(html.indexOf('id="step-apikey"'), html.indexOf('onboarding-footer'));
  // Native <details> disclosure (collapsed by default — no `open` attribute).
  assert.match(step, /<details[^>]*class="onboarding-help"[^>]*>[\s\S]*How do I get one\?/);
  const details = step.slice(step.indexOf('<details'));
  assert.ok(!/<details[^>]*\bopen\b/.test(details), 'API-key disclosure must be collapsed by default');
  // Actionable steps to obtain a key, consistent with SETUP.md.
  assert.match(details, /console\.anthropic\.com/);
  assert.match(details, /<ol>[\s\S]*<\/ol>/);
});

// ── BAA step is gone from onboarding (ADR 0003) ───────────────────────────────

test('onboarding no longer renders a BAA step or checkbox', () => {
  const html = renderOnboarding();
  assert.ok(!html.includes('id="step-baa"'), 'step-baa block must be removed');
  assert.ok(!html.includes('id="ob-baa"'), 'BAA checkbox must be removed');
  assert.ok(!/Anthropic BAA acknowledgment/.test(html), 'BAA step heading must be removed');
});

test('onboarding only has two numbered steps', () => {
  const html = renderOnboarding();
  const stepCount = (html.match(/class="onboarding-step"/g) || []).length;
  assert.equal(stepCount, 2);
});

// Drive the real wireOnboarding click handler with a minimal DOM to prove the
// gate now only requires (a) a name and (b) an API key — no BAA checkbox.
function mountDom({ name = 'Dr. Jane Smith', apikey = 'sk-ant-test' } = {}) {
  const handlers = {};
  const els = {
    'ob-finish': { addEventListener: (ev, fn) => { handlers[ev] = fn; } },
    'ob-name': { value: name },
    'ob-creds': { value: '' },
    'ob-specialty': { value: 'podiatry' },
    'ob-apikey': { value: apikey },
  };
  globalThis.document = {
    getElementById: id => (id in els ? els[id] : null),
    querySelector: () => null,
  };
  return { fire: () => handlers.click?.() };
}

test('gate: name + API key alone completes onboarding — no BAA ack written', async () => {
  let completed = false;
  const dom = mountDom();
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  await new Promise(r => setImmediate(r));
  assert.equal(completed, true, 'onComplete must run once name + key are satisfied');
  assert.ok(!calls.some(c => c.command === 'baa_ack_set'), 'onboarding must never write a BAA ack');
  const setKey = calls.find(c => c.command === 'set_api_key');
  assert.ok(setKey, 'set_api_key must be invoked');
  assert.equal(setKey.args.key, 'sk-ant-test');
});

test('gate: missing name blocks completion', async () => {
  let completed = false;
  const dom = mountDom({ name: '' });
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  assert.equal(completed, false, 'onComplete must not run without a name');
  assert.equal(calls.length, 0, 'nothing should be written without a name');
});

test('gate: missing API key blocks completion', async () => {
  let completed = false;
  const dom = mountDom({ apikey: '' });
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  assert.equal(completed, false, 'onComplete must not run without an API key');
  assert.ok(!calls.some(c => c.command === 'set_api_key'), 'no key should be written without a value');
});
