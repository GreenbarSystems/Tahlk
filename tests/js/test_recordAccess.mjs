// Unit tests for domain/recordAccess.js::shouldLogRecordView — the predicate
// deciding whether opening an encounter panel should emit a record_viewed
// audit event (HIPAA risk assessment §4, remediation item 1).
//
// Kept dependency-free deliberately (see the module's own header comment) so
// this can be tested without pulling in entry-solo.js's full import graph,
// which transitively reaches jspdf/pdfExport.js and cannot load outside a
// browser-like environment.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shouldLogRecordView } from '../../src/domain/recordAccess.js';

test('a fresh "recording" encounter is NOT logged — the open IS the creation', () => {
  assert.equal(shouldLogRecordView({ id: 'e1', status: 'recording' }), false);
});

// Every other status in the Rust ALLOWED_STATUS allowlist (encounters.rs)
// represents an encounter with existing content — pinned individually so a
// future status addition that's silently excluded here fails this test
// rather than shipping unnoticed.
for (const status of ['recording_done', 'transcribing', 'draft', 'signed', 'exported']) {
  test(`an encounter with status "${status}" IS logged as a view`, () => {
    assert.equal(shouldLogRecordView({ id: 'e1', status }), true);
  });
}

test('a null/undefined encounter is not logged (nothing was actually opened)', () => {
  assert.equal(shouldLogRecordView(null), false);
  assert.equal(shouldLogRecordView(undefined), false);
});

test('an encounter object missing a status field entirely is still logged (fail open toward more logging, not less)', () => {
  // Defensive: if some future code path ever constructs an encounter object
  // without a status, under-logging access is the worse compliance failure
  // (silently missing an access event) vs. an extra harmless log line, so
  // the predicate must only special-case the literal 'recording' value, not
  // treat "no status" as equivalent to it.
  assert.equal(shouldLogRecordView({ id: 'e1' }), true);
});
