// Audit finding #15: the non-Tauri fallback must refuse to write PHI-bearing
// keys to cleartext browser localStorage. This file deliberately does NOT set
// __TAHLK_TEST_TAURI__, so isTauri is false and storageBackend selects
// LocalStorageBackend — the path that would otherwise persist patient data
// unencrypted if a web build were opened outside the Tauri shell.

import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.document = { getElementById: () => null };
globalThis.window = globalThis.window || {};

// Minimal localStorage so the allowed (non-PHI) path can actually persist.
const _store = new Map();
globalThis.localStorage = {
  getItem: k => (_store.has(k) ? _store.get(k) : null),
  setItem: (k, v) => { _store.set(k, String(v)); },
  removeItem: k => { _store.delete(k); },
  key: i => [..._store.keys()][i] ?? null,
  get length() { return _store.size; },
};

const { kvGet, kvSet, kvSetAwait } = await import('../../src/core/storageBackend.js');

test('refuses to write note content / transcript to browser storage', () => {
  assert.throws(() => kvSet('note_content_v1::enc-1', 'SOAP note body'), /unencrypted browser/i);
  assert.throws(() => kvSet('note_content_v1::transcript::enc-1', 'raw transcript'), /unencrypted browser/i);
});

test('refuses the note-audit / note-history trails too', () => {
  assert.throws(() => kvSet('note_audit_v1::enc-1', []), /unencrypted browser/i);
  assert.throws(() => kvSet('note_audit_archive_v1::enc-1', []), /unencrypted browser/i);
  assert.throws(() => kvSet('note_history_v1::enc-1', []), /unencrypted browser/i);
});

test('a refused write leaves nothing in storage or cache', () => {
  try { kvSet('note_content_v1::enc-2', 'leak me'); } catch { /* expected */ }
  assert.equal(localStorage.getItem('note_content_v1::enc-2'), null, 'nothing persisted');
  assert.equal(kvGet('note_content_v1::enc-2'), null, 'nothing cached');
});

test('kvSetAwait rejects (fails closed) for PHI keys', async () => {
  await assert.rejects(kvSetAwait('note_content_v1::enc-3', 'x'), /unencrypted browser/i);
});

test('non-PHI settings keys still work in browser mode', () => {
  kvSet('note_settings_v1::onboarded', true);
  assert.equal(kvGet('note_settings_v1::onboarded'), true);
  kvSet('note_provider_v1::profile', { name: 'Dr. Dev' });
  assert.equal(kvGet('note_provider_v1::profile').name, 'Dr. Dev');
});
