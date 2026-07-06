// S-UX-7: first-run onboarding must explain, in plain clinician language, what
// an Anthropic API key and a HIPAA BAA are and how to get them — via collapsed
// "How do I get one?" / "What is this?" disclosures, not permanent walls of
// text. This is inline-help only: the underlying BAA self-attestation gate
// (checkbox `ob-baa`, what it writes, the Rust baa.rs gate) is unchanged.
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
  const step = html.slice(html.indexOf('id="step-apikey"'), html.indexOf('id="step-baa"'));
  assert.match(step, /Anthropic/);
  assert.match(step, /API key/i);
  // Plain-language reassurance that the key stays local / Tahlk never sees it.
  assert.match(step, /never sees or stores your key|stored only|local/i);
});

test('API-key step has a collapsed "How do I get one?" disclosure with steps', () => {
  const html = renderOnboarding();
  const step = html.slice(html.indexOf('id="step-apikey"'), html.indexOf('id="step-baa"'));
  // Native <details> disclosure (collapsed by default — no `open` attribute).
  assert.match(step, /<details[^>]*class="onboarding-help"[^>]*>[\s\S]*How do I get one\?/);
  const details = step.slice(step.indexOf('<details'));
  assert.ok(!/<details[^>]*\bopen\b/.test(details), 'API-key disclosure must be collapsed by default');
  // Actionable steps to obtain a key, consistent with SETUP.md.
  assert.match(details, /console\.anthropic\.com/);
  assert.match(details, /<ol>[\s\S]*<\/ol>/);
});

// ── BAA step: explanation + "What is this?" disclosure ───────────────────────

test('BAA step explains what a BAA is and why HIPAA requires it', () => {
  const html = renderOnboarding();
  const step = html.slice(html.indexOf('id="step-baa"'));
  assert.match(step, /Business Associate Agreement/);
  assert.match(step, /HIPAA/);
  assert.match(step, /PHI|health information/i);
});

test('BAA step has a collapsed "What is this?" disclosure explaining how to get one', () => {
  const html = renderOnboarding();
  const step = html.slice(html.indexOf('id="step-baa"'));
  assert.match(step, /<details[^>]*class="onboarding-help"[^>]*>[\s\S]*What is this\?/);
  const details = step.slice(step.indexOf('<details'));
  assert.ok(!/<details[^>]*\bopen\b/.test(details), 'BAA disclosure must be collapsed by default');
  // Consistent with SETUP.md's BAA request guidance.
  assert.match(details, /console\.anthropic\.com/);
});

// ── The underlying self-attestation gate is UNCHANGED (additive help only) ───

test('BAA checkbox #ob-baa and its consent attestation copy are unchanged', () => {
  const html = renderOnboarding();
  assert.match(html, /<input id="ob-baa" type="checkbox"/);
  assert.match(html, /I confirm my organization has an executed BAA with Anthropic/);
});

// Drive the real wireOnboarding click handler with a minimal DOM to prove the
// gate still (a) requires a name, (b) requires an API key, and (c) requires the
// BAA checkbox before it writes anything or completes.
function mountDom({ name = 'Dr. Jane Smith', apikey = 'sk-ant-test', baaChecked = false } = {}) {
  const handlers = {};
  const els = {
    'ob-finish': { addEventListener: (ev, fn) => { handlers[ev] = fn; } },
    'ob-name': { value: name },
    'ob-creds': { value: '' },
    'ob-specialty': { value: 'podiatry' },
    'ob-apikey': { value: apikey },
    'ob-baa': { checked: baaChecked },
  };
  globalThis.document = {
    getElementById: id => (id in els ? els[id] : null),
    querySelector: () => null,
  };
  return { fire: () => handlers.click?.() };
}

test('gate: unchecked BAA blocks completion — no ack written, onComplete not called', async () => {
  let completed = false;
  const dom = mountDom({ baaChecked: false });
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  assert.equal(completed, false, 'onComplete must not run when BAA is unchecked');
  assert.ok(!calls.some(c => c.command === 'baa_ack_set'), 'no BAA ack should be written');
});

test('gate: checked BAA (with name + key) writes the same ack payload and completes', async () => {
  let completed = false;
  const dom = mountDom({ baaChecked: true });
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  // wait a microtask beyond the awaited invokes inside the handler
  await new Promise(r => setImmediate(r));
  assert.equal(completed, true, 'onComplete must run once name + key + BAA are all satisfied');
  const ack = calls.find(c => c.command === 'baa_ack_set');
  assert.ok(ack, 'baa_ack_set must be invoked');
  // Payload shape is unchanged (camelCase keys, acknowledged:true, providerId = name).
  assert.equal(ack.args.acknowledged, true);
  assert.equal(ack.args.providerId, 'Dr. Jane Smith');
  assert.equal(typeof ack.args.acknowledgedAt, 'string');
});

test('gate: missing API key blocks completion even if BAA is checked', async () => {
  let completed = false;
  const dom = mountDom({ apikey: '', baaChecked: true });
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  assert.equal(completed, false, 'onComplete must not run without an API key');
  assert.ok(!calls.some(c => c.command === 'baa_ack_set'), 'no ack should be written without a key');
});
