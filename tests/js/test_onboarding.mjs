// Onboarding flow tests.
//
// Managed-proxy cutover (Phase 2b): onboarding no longer collects an Anthropic
// API key. Note generation runs through Greenbar's managed proxy on a
// per-device token minted transparently on first use (see
// src-tauri/src/device.rs), so there is no key step.
//
// BAA/EULA gate re-enabled (ADR 0006, supersedes ADR 0003): the Rust gate is
// enabled and blocking (baa::GATE_ENABLED = true), so onboarding now collects
// the BAA/EULA acknowledgment as a BLOCKING second step. It records the ack via
// the same baa_ack_set command Settings uses, so a fresh install that finishes
// onboarding can generate a note immediately without hitting BaaRequired.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// storageBackend touches the injected Tauri runtime and DOM at import time, so
// shim both BEFORE the dynamic import (same approach as test_baa.mjs and
// test_integrityDisplay.mjs).
const calls = [];
let nextResult = { ok: null };
// Optional per-command failure: { command, error }. Lets a test fail exactly
// one IPC command (e.g. baa_ack_set) while others still resolve.
let failCommand = null;
globalThis.__TAHLK_TEST_TAURI__ = {
  core: {
    invoke: (command, args) => {
      calls.push({ command, args });
      if (failCommand && failCommand.command === command) {
        return Promise.reject(failCommand.error);
      }
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
  failCommand = null;
});

// ── No API-key surface anywhere in onboarding (BYOK retired) ──────────────────

test('onboarding never mentions an Anthropic API key', () => {
  const html = renderOnboarding();
  assert.ok(!html.includes('id="step-apikey"'), 'API-key step must be removed');
  assert.ok(!html.includes('id="ob-apikey"'), 'API-key input must be removed');
  assert.ok(!/API key/i.test(html), 'no API-key copy may remain');
  assert.ok(!/console\.anthropic\.com/.test(html), 'no console.anthropic.com link may remain');
});

// ── Onboarding now renders a blocking BAA/EULA step (ADR 0006) ────────────────

test('onboarding renders a BAA/EULA acknowledgment step and checkbox', () => {
  const html = renderOnboarding();
  assert.ok(html.includes('id="step-baa"'), 'step-baa block must be present');
  assert.ok(html.includes('id="ob-baa"'), 'BAA checkbox must be present');
  assert.match(html, /BAA/, 'BAA must be described');
  assert.match(html, /EULA/, 'EULA must be described');
});

test('BAA checkbox is not pre-checked (no default-checked skip path)', () => {
  const html = renderOnboarding();
  // Grab the ob-baa input element markup and assert it carries no `checked`.
  const m = html.match(/<input[^>]*id="ob-baa"[^>]*>/);
  assert.ok(m, 'ob-baa input must exist');
  assert.ok(!/\bchecked\b/.test(m[0]), 'BAA checkbox must start unchecked');
});

test('the Beta product-stage badge is kept', () => {
  const html = renderOnboarding();
  assert.match(html, /onboarding-badge">Beta</, 'Beta badge must remain');
});

test('onboarding has two numbered steps (provider profile + BAA/EULA)', () => {
  const html = renderOnboarding();
  const stepCount = (html.match(/class="onboarding-step"/g) || []).length;
  assert.equal(stepCount, 2);
  assert.match(html, /id="step-provider"/);
  assert.match(html, /id="step-baa"/);
});

// Drive the real wireOnboarding click handler with a minimal DOM.
function mountDom({ name = 'Dr. Jane Smith', baaChecked = true } = {}) {
  const handlers = {};
  const els = {
    'ob-finish': { addEventListener: (ev, fn) => { handlers[ev] = fn; } },
    'ob-name': { value: name },
    'ob-creds': { value: '' },
    'ob-specialty': { value: 'podiatry' },
    'ob-baa': { checked: baaChecked },
  };
  globalThis.document = {
    getElementById: id => (id in els ? els[id] : null),
    querySelector: () => null,
  };
  return { fire: () => handlers.click?.() };
}

// Core bug fix: a fresh install that completes onboarding must have recorded the
// BAA ack (so the Rust gate is satisfied and the first note generation does not
// hit BaaRequired), and must NOT invoke any API-key command.
test('completing onboarding records a BAA ack so first note generation is unblocked', async () => {
  let completed = false;
  const dom = mountDom();
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  await new Promise(r => setImmediate(r));

  assert.equal(completed, true, 'onComplete must run once name + BAA ack are provided');

  const setProfile = calls.find(c => c.command === 'set_provider_profile');
  assert.ok(setProfile, 'set_provider_profile must be invoked');
  assert.equal(setProfile.args.profile.name, 'Dr. Jane Smith');

  const ack = calls.find(c => c.command === 'baa_ack_set');
  assert.ok(ack, 'onboarding must record a BAA ack via baa_ack_set');
  assert.equal(ack.args.acknowledged, true, 'the recorded ack must be affirmative');
  assert.equal(ack.args.providerId, 'Dr. Jane Smith', 'provider identity must be attributed');
  assert.equal(typeof ack.args.acknowledgedAt, 'string');
  assert.ok(ack.args.acknowledgedAt.length > 0, 'a timestamp must be captured');

  assert.ok(
    !calls.some(c => c.command === 'set_api_key' || c.command === 'has_api_key'),
    'no API-key command may be invoked — BYOK is retired',
  );
});

test('gate: missing name blocks completion (and writes nothing)', async () => {
  let completed = false;
  const dom = mountDom({ name: '' });
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  assert.equal(completed, false, 'onComplete must not run without a name');
  assert.equal(calls.length, 0, 'nothing should be written without a name');
});

test('gate: unchecked BAA blocks completion and records no ack', async () => {
  let completed = false;
  const dom = mountDom({ baaChecked: false });
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  await new Promise(r => setImmediate(r));
  assert.equal(completed, false, 'onComplete must not run without the BAA acknowledgment');
  assert.ok(!calls.some(c => c.command === 'baa_ack_set'), 'no ack may be written when the box is unchecked');
});

test('gate: onboarding does not complete if the ack write fails', async () => {
  let completed = false;
  const dom = mountDom();
  await wireOnboarding(() => { completed = true; });
  // set_provider_profile succeeds, then baa_ack_set rejects.
  failCommand = { command: 'baa_ack_set', error: { code: 'internal', message: 'kv write failed' } };
  await dom.fire();
  await new Promise(r => setImmediate(r));
  assert.equal(completed, false, 'onboarding must not complete if the ack cannot be recorded');
});
