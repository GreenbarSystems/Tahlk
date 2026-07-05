// S-UX-2: specialty-aware template ordering + default.
//
// The picker must not default a podiatrist to "Psychiatric Evaluation". These
// tests exercise the real listTemplates()/defaultTemplateId() against the
// bundled built-in templates, driving off the provider's specialty. A mock
// Tauri runtime is installed before the module graph loads so the KV backend
// (which listTemplates uses to fold in custom templates) resolves through an
// in-memory cache instead of localStorage.
//
// Guards:
//   - podiatry provider defaults to a podiatry template, podiatry templates
//     sort first, and NO behavioral-health template is the default
//   - psychiatry + behavioral-health providers each get their own family first
//     (the behavior generalizes by specialty — podiatry doesn't always win)
//   - unset / 'other' specialty falls back to the generic SOAP template, never
//     to any single specialty's template
//   - off-specialty templates remain reachable (sorted to the bottom, not
//     deleted)

import { test } from 'node:test';
import assert from 'node:assert/strict';

// Mock Tauri so storageBackend picks TauriBackend (in-memory _cache) and
// kv_list returns no custom templates.
globalThis.document = { getElementById: () => null };
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: (cmd) => (cmd === 'kv_list' ? Promise.resolve([]) : Promise.resolve(null)) },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

const { listTemplates, defaultTemplateId } =
  await import('../../src/templates/templateLibrary.js');

const ids = (specialty) => listTemplates(specialty).map(t => t.id);

test('podiatry provider defaults to a podiatry template and sorts podiatry first', () => {
  assert.equal(defaultTemplateId('podiatry'), 'podiatry-eval');
  const list = listTemplates('podiatry');
  assert.equal(list[0].specialty, 'podiatry');
  // The default is a podiatry template, not the psychiatric eval.
  assert.notEqual(defaultTemplateId('podiatry'), 'psych-eval');
});

test('podiatry provider still reaches off-specialty templates (not deleted)', () => {
  const list = ids('podiatry');
  assert.ok(list.includes('psych-eval'), 'psych templates stay reachable');
  assert.ok(list.includes('soap-generic'), 'generic SOAP stays reachable');
  // Behavioral-health templates sort AFTER podiatry ones.
  assert.ok(list.indexOf('podiatry-eval') < list.indexOf('psych-eval'));
});

test('psychiatry provider defaults to and sorts psychiatry first', () => {
  assert.equal(defaultTemplateId('psychiatry'), 'psych-eval');
  const list = ids('psychiatry');
  assert.ok(list.indexOf('psych-eval') < list.indexOf('podiatry-eval'));
});

test('behavioral-health provider defaults to the therapy note (generalizes by specialty)', () => {
  // Exact-specialty match wins over the psychiatry family — proves the logic
  // keys off the provider's specialty rather than hardcoding podiatry/psych.
  assert.equal(defaultTemplateId('behavioral-health'), 'therapy-progress');
  const list = ids('behavioral-health');
  assert.ok(list.indexOf('therapy-progress') < list.indexOf('podiatry-eval'));
});

test('psychology provider sees the behavioral-health family first, not podiatry', () => {
  const list = listTemplates('psychology');
  // No psychology-specific template exists, so a family template leads — and
  // it is not a podiatry template.
  assert.notEqual(list[0].specialty, 'podiatry');
  assert.equal(specialtyOf(list[0]), 'behavioral-health-family');
});

function specialtyOf(t) {
  return ['psychiatry', 'behavioral-health', 'psychology'].includes(t.specialty)
    ? 'behavioral-health-family'
    : t.specialty;
}

test('unset specialty falls back to the generic SOAP template', () => {
  assert.equal(defaultTemplateId(undefined), 'soap-generic');
  assert.equal(defaultTemplateId(''), 'soap-generic');
});

test("'other' specialty falls back to the generic SOAP template, not psychiatry", () => {
  assert.equal(defaultTemplateId('other'), 'soap-generic');
  assert.notEqual(defaultTemplateId('other'), 'psych-eval');
});

test('listTemplates() with no specialty preserves the legacy built-in order', () => {
  const list = listTemplates();
  assert.equal(list[0].id, 'psych-eval'); // unchanged legacy ordering
});
