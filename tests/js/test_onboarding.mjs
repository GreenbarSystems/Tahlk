// S-UX-7 (plain-language inline help) + C-6. Onboarding is 3 steps: provider
// profile, Anthropic API key, then the BAA/EULA confirmation.
//
// ADR 0003 removed that third step for the test-data-only beta while
// baa::GATE_ENABLED was false. The gate is true again, and ADR 0003 said the
// step had to come back with it — it did not, so every new install finished
// onboarding into an app that refused to generate notes. These tests now pin
// the restored step; the previous "onboarding must never write a BAA ack"
// assertion was correct for the old regime and is inverted below.
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

test('onboarding renders the agreements step and its checkbox', () => {
  const html = renderOnboarding();
  assert.ok(html.includes('id="step-agreements"'), 'the agreements step must be present');
  assert.ok(html.includes('id="ob-baa"'), 'the confirmation checkbox must be present');
  assert.match(html, /Business Associate Agreement/, 'names the BAA in full at least once');
  assert.match(html, /End User License Agreement/, 'names the EULA in full at least once');
});

test('the agreements step states that note generation is blocked without it', () => {
  // The Settings pane previously called this confirmation "optional" while
  // the Rust gate treated it as mandatory. Whatever the copy says here and
  // there, it must not tell the provider the opposite of what the app does.
  const html = renderOnboarding();
  assert.match(
    html,
    /will not generate notes/i,
    'onboarding must say the gate blocks note generation, not that this is optional',
  );
  assert.ok(!/optional/i.test(html), 'nothing in onboarding may describe the confirmation as optional');
});

test('onboarding has three numbered steps', () => {
  const html = renderOnboarding();
  const stepCount = (html.match(/class="onboarding-step"/g) || []).length;
  assert.equal(stepCount, 3);
});

// Drive the real wireOnboarding click handler with a minimal DOM to prove the
// gate requires (a) a name, (b) an API key, and (c) the agreements checkbox.
function mountDom({ name = 'Dr. Jane Smith', apikey = 'sk-ant-test', baa = true } = {}) {
  const handlers = {};
  const els = {
    'ob-finish': { addEventListener: (ev, fn) => { handlers[ev] = fn; } },
    'ob-name': { value: name },
    'ob-creds': { value: '' },
    'ob-specialty': { value: 'podiatry' },
    'ob-apikey': { value: apikey },
    'ob-baa': { checked: baa },
  };
  globalThis.document = {
    getElementById: id => (id in els ? els[id] : null),
    querySelector: () => null,
  };
  return { fire: () => handlers.click?.() };
}

test('completing onboarding records the BAA acknowledgment', async () => {
  // Inverted from "onboarding must never write a BAA ack". That held while
  // baa::GATE_ENABLED was false; with the gate on, an install that finishes
  // onboarding without an ack cannot generate a single note — it hits
  // `baa_required` on first Generate with no path forward but a checkbox
  // buried in Settings.
  let completed = false;
  const dom = mountDom();
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  await new Promise(r => setImmediate(r));

  assert.equal(completed, true, 'onComplete must run once all three are satisfied');
  const ack = calls.find(c => c.command === 'baa_ack_set');
  assert.ok(ack, 'onboarding must record the acknowledgment the Rust gate requires');
  assert.equal(ack.args.acknowledged, true);
  assert.equal(ack.args.providerId, 'Dr. Jane Smith', 'the ack names who confirmed');
  assert.match(ack.args.acknowledgedAt, /^\d{4}-\d{2}-\d{2}T/, 'and when');

  const setKey = calls.find(c => c.command === 'set_api_key');
  assert.ok(setKey, 'set_api_key must be invoked');
  assert.equal(setKey.args.key, 'sk-ant-test');
});

test('gate: an unconfirmed BAA blocks completion and writes nothing', async () => {
  // Checked before any write, so a provider who declines is not left
  // half-onboarded with a profile and API key stored and no way to work.
  let completed = false;
  const dom = mountDom({ baa: false });
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  await new Promise(r => setImmediate(r));

  assert.equal(completed, false, 'onComplete must not run without the confirmation');
  assert.equal(calls.length, 0, 'nothing should be written without the confirmation');
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
