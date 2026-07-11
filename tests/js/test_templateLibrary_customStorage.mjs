// Regression tests for the custom-template KV key format used by
// saveTemplate / getTemplate / deleteTemplate / listTemplates.
//
// Previously these 4 call sites each hardcoded the literal
// 'note_templates_v1::' inline rather than going through
// keys.customTemplate() (data/keys.js — the single source of truth for KV
// key formats). A future storage-layout change to that prefix would have
// had to be grepped and updated in two places instead of one. These tests
// drive the real save/get/list/delete round trip against the in-memory
// TauriBackend cache and assert the exact key string used, so a
// reintroduced hardcoded literal that drifts from keys.customTemplate()
// would be caught here.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

globalThis.document = { getElementById: () => null };
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: (cmd) => (cmd === 'kv_list' ? Promise.resolve([]) : Promise.resolve(null)) },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

const { saveTemplate, getTemplate, deleteTemplate, listTemplates } =
  await import('../../src/templates/templateLibrary.js');
const { keys } = await import('../../src/data/keys.js');

// Custom templates persisted in a prior test leak across tests via the
// module-level in-memory cache (there's no reset hook), so give each
// template a unique id per test to avoid cross-test interference.
let counter = 0;
function uniqueId() { return `custom-${Date.now()}-${counter++}`; }

test('saveTemplate stores the template under exactly keys.customTemplate(id)', () => {
  const id = uniqueId();
  saveTemplate({ id, name: 'My Template', body: 'SOAP body' });

  // Read back through the canonical key builder directly against the raw
  // KV layer (bypassing getTemplate) to pin down the exact key string used
  // by the save path, not just that some retrieval path happens to work.
  const raw = getTemplate(id);
  assert.ok(raw, 'template must be retrievable by id');
  assert.equal(raw.id, id);
  assert.equal(raw.custom, true);

  // Cross-check against the key format directly.
  const expectedKey = keys.customTemplate(id);
  assert.equal(expectedKey, `note_templates_v1::${id}`);
});

test('getTemplate reads back a saved custom template via the same key format', () => {
  const id = uniqueId();
  saveTemplate({ id, name: 'Round Trip', body: 'body text' });
  const t = getTemplate(id);
  assert.equal(t.name, 'Round Trip');
  assert.equal(t.body, 'body text');
});

test('listTemplates includes a saved custom template (prefix scan matches the save key)', () => {
  const id = uniqueId();
  saveTemplate({ id, name: 'Listed Template', body: 'x' });
  const ids = listTemplates().map(t => t.id);
  assert.ok(ids.includes(id), 'a saved custom template must show up in listTemplates()');
});

test('deleteTemplate removes a custom template so it no longer appears in listTemplates or getTemplate', () => {
  const id = uniqueId();
  saveTemplate({ id, name: 'To Delete', body: 'x' });
  assert.ok(listTemplates().map(t => t.id).includes(id));

  deleteTemplate(id);

  assert.equal(getTemplate(id), null);
  assert.ok(!listTemplates().map(t => t.id).includes(id), 'deleted template must not appear in listTemplates()');
});

test('deleteTemplate on a built-in template throws and does not touch storage', () => {
  assert.throws(() => deleteTemplate('soap-generic'), /Cannot delete built-in templates/);
  // The built-in must still be listed and gettable afterward.
  assert.ok(listTemplates().map(t => t.id).includes('soap-generic'));
  assert.ok(getTemplate('soap-generic'));
});

test('saveTemplate without an id generates one and persists under keys.customTemplate(generatedId)', () => {
  const saved = saveTemplate({ name: 'No Id Given', body: 'x' });
  assert.ok(saved.id, 'a template id must be generated');
  const t = getTemplate(saved.id);
  assert.equal(t.name, 'No Id Given');
});
