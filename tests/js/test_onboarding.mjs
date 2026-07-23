// Phase 2b (managed-proxy cutover): onboarding no longer collects an Anthropic
// API key. Note generation runs through Greenbar's managed proxy on a
// per-device token minted transparently on first use (see
// src-tauri/src/device.rs), so there is no key step and no user-visible sign of
// device registration. Onboarding is now a SINGLE step: the provider profile.
//
// ADR 0003 (BAA step removed from onboarding for the test-data-only beta — see
// docs/adr/0003-disable-baa-gate-for-beta.md) still applies: there is no BAA
// checkbox or step-baa block here; the Rust-side gate is soft-disabled
// (baa::GATE_ENABLED = false) and Settings still offers a voluntary,
// non-blocking BAA acknowledgment for testers who already have one.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// storageBackend touches the injected Tauri runtime and DOM at import time, so
// shim both BEFORE the dynamic import (same approach as test_baa.mjs and
// test_integrityDisplay.mjs).
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

// ── No API-key surface anywhere in onboarding (BYOK retired) ──────────────────

test('onboarding never mentions an Anthropic API key', () => {
  const html = renderOnboarding();
  assert.ok(!html.includes('id="step-apikey"'), 'API-key step must be removed');
  assert.ok(!html.includes('id="ob-apikey"'), 'API-key input must be removed');
  assert.ok(!/API key/i.test(html), 'no API-key copy may remain');
  assert.ok(!/console\.anthropic\.com/.test(html), 'no console.anthropic.com link may remain');
});

// ── BAA step is gone from onboarding (ADR 0003) ───────────────────────────────

test('onboarding no longer renders a BAA step or checkbox', () => {
  const html = renderOnboarding();
  assert.ok(!html.includes('id="step-baa"'), 'step-baa block must be removed');
  assert.ok(!html.includes('id="ob-baa"'), 'BAA checkbox must be removed');
  assert.ok(!/Anthropic BAA acknowledgment/.test(html), 'BAA step heading must be removed');
});

test('onboarding has a single numbered step (provider profile)', () => {
  const html = renderOnboarding();
  const stepCount = (html.match(/class="onboarding-step"/g) || []).length;
  assert.equal(stepCount, 1);
  assert.match(html, /id="step-provider"/);
});

// Drive the real wireOnboarding click handler with a minimal DOM to prove the
// gate now requires only a name — no API key, no BAA checkbox — and that no
// key-related command is ever invoked.
function mountDom({ name = 'Dr. Jane Smith' } = {}) {
  const handlers = {};
  const els = {
    'ob-finish': { addEventListener: (ev, fn) => { handlers[ev] = fn; } },
    'ob-name': { value: name },
    'ob-creds': { value: '' },
    'ob-specialty': { value: 'podiatry' },
  };
  globalThis.document = {
    getElementById: id => (id in els ? els[id] : null),
    querySelector: () => null,
  };
  return { fire: () => handlers.click?.() };
}

test('gate: name alone completes onboarding — no key, no BAA ack written', async () => {
  let completed = false;
  const dom = mountDom();
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  await new Promise(r => setImmediate(r));
  assert.equal(completed, true, 'onComplete must run once a name is provided');
  assert.ok(!calls.some(c => c.command === 'baa_ack_set'), 'onboarding must never write a BAA ack');
  assert.ok(
    !calls.some(c => c.command === 'set_api_key' || c.command === 'has_api_key'),
    'no API-key command may be invoked — BYOK is retired',
  );
  const setProfile = calls.find(c => c.command === 'set_provider_profile');
  assert.ok(setProfile, 'set_provider_profile must be invoked');
  assert.equal(setProfile.args.profile.name, 'Dr. Jane Smith');
});

test('gate: missing name blocks completion', async () => {
  let completed = false;
  const dom = mountDom({ name: '' });
  await wireOnboarding(() => { completed = true; });
  await dom.fire();
  assert.equal(completed, false, 'onComplete must not run without a name');
  assert.equal(calls.length, 0, 'nothing should be written without a name');
});
