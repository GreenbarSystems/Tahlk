// hashAuditEntry must cover nested detail fields, and statusLabel must
// actually be the sanitizer the build guard allowlists it as.
//
// hashAuditEntry used JSON.stringify(payload, Object.keys(payload).sort()).
// That array-replacer form applies its key list RECURSIVELY to every nested
// object, so any `details` value that was itself an object had its own keys
// stripped from the hashed payload — two entries differing only in a nested
// field hashed identically, and the difference was invisible to the chain.
//
// Latent rather than live: every current call site passes scalars. But Rust's
// extra_fields is Vec<(String, Value)> and accepts Value::Object, so the first
// structured detail field would have opened the hole on both sides at once.

import { test } from 'node:test';
import assert from 'node:assert/strict';

const { hashAuditEntry } = await import('../../src/utils/contentHash.js');
const { statusLabel } = await import('../../src/utils/format.js');

test('nested detail fields change the hash', async () => {
  const a = await hashAuditEntry({ action: 'note_exported', details: { format: 'pdf' } }, null);
  const b = await hashAuditEntry({ action: 'note_exported', details: { format: 'txt' } }, null);
  assert.notEqual(a, b, 'a nested field must be covered by the entry hash');
});

test('a nested field being removed changes the hash', async () => {
  const withField = await hashAuditEntry({ action: 'x', details: { a: 1, b: 2 } }, null);
  const without = await hashAuditEntry({ action: 'x', details: { a: 1 } }, null);
  assert.notEqual(withField, without);
});

test('key order does not change the hash', async () => {
  // Canonicalisation is the whole point: the same logical entry must hash the
  // same regardless of construction order, on both sides of the FFI boundary.
  const a = await hashAuditEntry({ action: 'x', actor: 'Dr. Chen', details: { p: 1, q: 2 } }, null);
  const b = await hashAuditEntry({ details: { q: 2, p: 1 }, actor: 'Dr. Chen', action: 'x' }, null);
  assert.equal(a, b);
});

test('arrays are covered element-wise and order-sensitively', async () => {
  const a = await hashAuditEntry({ action: 'x', tags: ['a', 'b'] }, null);
  const b = await hashAuditEntry({ action: 'x', tags: ['b', 'a'] }, null);
  assert.notEqual(a, b, 'array order is meaningful and must not be canonicalised away');
});

test('prevHash is covered and entryHash is excluded', async () => {
  const base = { action: 'x', actor: 'Dr. Chen' };
  const p1 = await hashAuditEntry(base, 'prev-1');
  const p2 = await hashAuditEntry(base, 'prev-2');
  assert.notEqual(p1, p2, 'prevHash must be part of the hashed payload');

  // An entry cannot hash over its own output field.
  const withOwn = await hashAuditEntry({ ...base, entryHash: 'anything' }, 'prev-1');
  assert.equal(withOwn, p1);
});

test('statusLabel returns a fixed literal for unknown input', () => {
  // The interpolation build guard allowlists statusLabel as a sanitizer
  // because it "returns a fixed literal per known status", and three sinks
  // render its result unescaped on that basis. The old `|| status`
  // fall-through echoed unrecognised input straight back.
  assert.equal(statusLabel('signed'), 'Signed');
  assert.equal(statusLabel('draft'), 'Draft');
  assert.equal(statusLabel('<img src=x onerror=alert(1)>'), 'Unknown');
  assert.equal(statusLabel(undefined), 'Unknown');
  assert.equal(statusLabel(''), 'Unknown');
});
