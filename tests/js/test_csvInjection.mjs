// CSV formula injection in the destruction-log export.
//
// The export quoted cells and doubled embedded quotes, which makes the file
// PARSE correctly but does nothing about Excel, LibreOffice and Sheets
// treating a leading =, +, - or @ as the start of a formula. provider_id and
// patient_alias are provider-entered free text, so a value like
// =HYPERLINK("http://evil","Click") executes on open — and this is the
// destruction log, the file an auditor is most likely to open.
//
// destructionLogToCsv is module-private, so this tests csvCell's contract
// through a local reimplementation of the same regex. Kept deliberately in
// lockstep with settingsModal.js; if that guard changes, this must too.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// Mirror of csvCell in src/solo/settingsModal.js.
function csvCell(v) {
  const s = String(v ?? '');
  const needsGuard = /^[=+\-@\t\r]/.test(s);
  const guarded = needsGuard ? `'${s}` : s;
  return `"${guarded.replace(/"/g, '""')}"`;
}

test('formula-leading cells are neutralised', () => {
  for (const payload of [
    '=HYPERLINK("http://evil","Click")',
    '+1+1',
    '-2+3',
    '@SUM(A1:A9)',
    '\t=cmd|calc',
    '\r=1+1',
  ]) {
    const out = csvCell(payload);
    assert.ok(
      out.startsWith(`"'`),
      `${JSON.stringify(payload)} must be forced to text, got ${out}`,
    );
  }
});

test('ordinary values are not altered', () => {
  // An apostrophe on every cell would corrupt the data for anyone parsing it
  // programmatically, so the guard must be narrow.
  assert.equal(csvCell('Dr. Chen'), '"Dr. Chen"');
  assert.equal(csvCell('2026-07-21'), '"2026-07-21"');
  assert.equal(csvCell('encounter'), '"encounter"');
  assert.equal(csvCell(3), '"3"');
  assert.equal(csvCell(''), '""');
  assert.equal(csvCell(null), '""');
});

test('quotes are still escaped, and escaping composes with the guard', () => {
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell('="a"'), `"'=""a"""`);
});

test('a negative number in a data column is still guarded', () => {
  // records_scrubbed is numeric, but a leading '-' is indistinguishable from
  // a formula to a spreadsheet, so it is guarded too. Correctness of the
  // export beats prettiness of the cell.
  assert.equal(csvCell(-1), `"'-1"`);
});
