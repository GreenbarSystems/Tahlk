// S-UX-3: a signed note shows a plain-language trust indicator by default; the
// raw SHA-256 is tucked behind a "View integrity details" disclosure (present
// in the DOM but not the prominent default display). Renders the REAL
// renderEncounterPanel and asserts the structure. The hash shown when expanded
// must be the actual computed hash, not a placeholder.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// Minimal Tauri stub so storageBackend resolves as Tauri with an empty cache
// (kvGet returns null → draft/transcript render empty, which is fine here).
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: () => Promise.resolve(null) },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};
globalThis.document = { getElementById: () => null, querySelector: () => null };

const { renderEncounterPanel } = await import('../../src/solo/encounter/template.js');
const { computeNoteHash } = await import('../../src/utils/contentHash.js');

// A real, deterministic signed hash so the test proves the disclosure shows the
// actual stored value (not a hardcoded placeholder).
const signedHash = await computeNoteHash({
  transcript: 'TRANSCRIPT', noteContent: 'NOTE', signedBy: 'Dr. Smith', encounterId: 'enc-1',
});

function signedPanel() {
  return renderEncounterPanel({
    id: 'enc-1',
    status: 'signed',
    encounter_date: '2026-07-06',
    signed_at: '2026-07-06T12:00:00Z',
    signed_hash: signedHash,
    audio_path: null,
  });
}

test('signed hash is a real 64-char hex (guards the fixture)', () => {
  assert.match(signedHash, /^[0-9a-f]{64}$/);
});

test('trust indicator is shown by default on a signed note', () => {
  const html = signedPanel();
  // The checkmark is a small inline SVG (src/solo/icons.js), not a text glyph
  // — assert on the element and its label text, not literal markup shape.
  assert.match(html, /<span class="trust-indicator">[\s\S]*?Tamper-evident record<\/span>/);
});

test('raw SHA-256 is NOT part of the default (pre-disclosure) display', () => {
  const html = signedPanel();
  const before = html.slice(0, html.indexOf('<details'));
  assert.ok(!before.includes(signedHash), 'hash must not appear before the disclosure');
  assert.ok(!before.includes('SHA-256:'), 'raw hash label must not appear by default');
});

test('"View integrity details" disclosure reveals the real matching hash', () => {
  const html = signedPanel();
  assert.match(html, /<details[^>]*>[\s\S]*View integrity details/);
  const details = html.slice(html.indexOf('<details'));
  assert.ok(details.includes('SHA-256:'), 'the raw hash label lives inside the disclosure');
  assert.ok(details.includes(signedHash), 'the disclosure shows the actual computed hash');
});

test('a draft (unsigned) note shows neither the indicator nor the hash', () => {
  const html = renderEncounterPanel({
    id: 'enc-2', status: 'draft', encounter_date: '2026-07-06', audio_path: null,
  });
  assert.ok(!html.includes('Tamper-evident record'));
  assert.ok(!html.includes('View integrity details'));
});
