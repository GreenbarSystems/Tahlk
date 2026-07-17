// Unit tests for parseCsv() and suggestMappings() from patientsImport.js.
// Both are pure functions (no DOM, no Tauri) so they can be imported directly.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// Minimal stubs so the module graph resolves without a browser or Tauri runtime.
globalThis.document = { createElement: () => ({}), body: {} };
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: () => Promise.resolve(null) },
  event: { listen: () => Promise.resolve(() => {}) },
};

const { parseCsv, suggestMappings } = await import('../../src/solo/patientsImport.js');

// ── parseCsv ─────────────────────────────────────────────────────────────────

test('parseCsv: basic two-column CSV', () => {
  const { headers, rows } = parseCsv('Name,DOB\nAlice,1990-01-01\nBob,1985-06-15\n');
  assert.deepEqual(headers, ['Name', 'DOB']);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0], ['Alice', '1990-01-01']);
  assert.deepEqual(rows[1], ['Bob', '1985-06-15']);
});

test('parseCsv: CRLF line endings', () => {
  const { headers, rows } = parseCsv('A,B\r\n1,2\r\n3,4\r\n');
  assert.deepEqual(headers, ['A', 'B']);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0], ['1', '2']);
});

test('parseCsv: quoted field containing a comma', () => {
  const { headers, rows } = parseCsv('Name,Notes\n"Smith, John",regular\n');
  assert.equal(rows[0][0], 'Smith, John');
  assert.equal(rows[0][1], 'regular');
});

test('parseCsv: escaped double-quote inside a quoted field', () => {
  const { headers, rows } = parseCsv('Name,Notes\n"O""Brien",test\n');
  assert.equal(rows[0][0], 'O"Brien');
});

test('parseCsv: strips UTF-8 BOM from first field', () => {
  const bom = '﻿';
  const { headers } = parseCsv(`${bom}ClientID,Name\n1,Alice\n`);
  assert.equal(headers[0], 'ClientID');
});

test('parseCsv: empty file returns empty headers and rows', () => {
  const { headers, rows } = parseCsv('');
  assert.deepEqual(headers, []);
  assert.deepEqual(rows, []);
});

test('parseCsv: header-only file returns empty rows', () => {
  const { headers, rows } = parseCsv('ID,Name,DOB\n');
  assert.deepEqual(headers, ['ID', 'Name', 'DOB']);
  assert.deepEqual(rows, []);
});

test('parseCsv: trailing blank lines are excluded from rows', () => {
  const { rows } = parseCsv('A,B\n1,2\n\n\n');
  assert.equal(rows.length, 1);
});

// ── suggestMappings ──────────────────────────────────────────────��────────────

test('suggestMappings: SimplePractice-style headers', () => {
  const hdrs = ['Client ID', 'First Name', 'Last Name', 'Date of Birth', 'Notes'];
  const m = suggestMappings(hdrs);
  // "First Name" matches alias (first in the alias term list that matches)
  assert.ok(m.aliasCol !== null, 'aliasCol should be suggested');
  assert.equal(m.dobCol, 'Date of Birth');
  assert.equal(m.notesCol, 'Notes');
  assert.equal(m.sourceIdCol, 'Client ID');
});

test('suggestMappings: TherapyNotes-style headers', () => {
  const hdrs = ['Client Number', 'First Name', 'Last Name', 'Birth Date'];
  const m = suggestMappings(hdrs);
  assert.equal(m.dobCol, 'Birth Date');
  assert.equal(m.sourceIdCol, 'Client Number');
});

test('suggestMappings: generic Alias/DOB headers', () => {
  const hdrs = ['Alias', 'DOB'];
  const m = suggestMappings(hdrs);
  assert.equal(m.aliasCol, 'Alias');
  assert.equal(m.dobCol, 'DOB');
  assert.equal(m.notesCol, null);
  assert.equal(m.sourceIdCol, null);
});

test('suggestMappings: unrecognised headers return null for all', () => {
  const hdrs = ['Col1', 'Col2', 'Col3'];
  const m = suggestMappings(hdrs);
  assert.equal(m.aliasCol,    null);
  assert.equal(m.dobCol,      null);
  assert.equal(m.notesCol,    null);
  assert.equal(m.sourceIdCol, null);
});

test('suggestMappings: matching is case-insensitive', () => {
  const hdrs = ['CLIENT NAME', 'DATE OF BIRTH', 'COMMENTS', 'MRN'];
  const m = suggestMappings(hdrs);
  assert.equal(m.aliasCol,    'CLIENT NAME');
  assert.equal(m.dobCol,      'DATE OF BIRTH');
  assert.equal(m.notesCol,    'COMMENTS');
  assert.equal(m.sourceIdCol, 'MRN');
});

test('suggestMappings: empty header list returns all null', () => {
  const m = suggestMappings([]);
  assert.equal(m.aliasCol,    null);
  assert.equal(m.dobCol,      null);
  assert.equal(m.notesCol,    null);
  assert.equal(m.sourceIdCol, null);
});
