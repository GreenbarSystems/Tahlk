// S-UX-6: specialty-aware export-format options.
//
// The export dropdown must not offer behavioral-health EHR brand names
// ("SimplePractice"/"TherapyNotes") to providers outside the behavioral-health
// family — a podiatrist has no use for them. Plain text stays available to
// everyone, and behavioral-health providers keep their brand-specific presets.
//
// Two layers are exercised:
//   - exportFormatOptions() directly, keyed off the provider's specialty family
//     (proves the logic generalizes by specialty, not a podiatry special-case)
//   - renderEncounterPanel() HTML, proving the filtered options are actually
//     wired into both the unsigned and signed export controls.
//
// A mock Tauri runtime is installed before the module graph loads so the KV
// backend resolves through its in-memory cache (same pattern as the S-UX-2
// templateLibrary test).

import { test } from 'node:test';
import assert from 'node:assert/strict';

globalThis.document = { getElementById: () => null };
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: (cmd) => (cmd === 'kv_list' ? Promise.resolve([]) : Promise.resolve(null)) },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};

const { exportFormatOptions, renderEncounterPanel } =
  await import('../../src/solo/encounter/template.js');
const { kvSet } = await import('../../src/core/storageBackend.js');
const { keys } = await import('../../src/data/keys.js');

const BRANDS = ['SimplePractice', 'TherapyNotes'];

function setSpecialty(specialty) {
  kvSet(keys.provider(), specialty === undefined ? {} : { specialty });
}

// ── exportFormatOptions(): the specialty-family filter ──────────────────────

test('non-behavioral-health specialty (podiatry) gets no EHR brand presets', () => {
  const html = exportFormatOptions('podiatry');
  for (const brand of BRANDS) assert.ok(!html.includes(brand), `must not offer ${brand}`);
  assert.ok(html.includes('Plain text'), 'plain text stays available');
});

test("'other' and unset specialties get plain text only, no brand presets", () => {
  for (const s of ['other', undefined, '']) {
    const html = exportFormatOptions(s);
    for (const brand of BRANDS) assert.ok(!html.includes(brand), `${s}: must not offer ${brand}`);
    assert.ok(html.includes('Plain text'), `${s}: plain text stays available`);
  }
});

test('behavioral-health-family specialties keep the brand presets', () => {
  // Covers the whole family, not just one specialty — psychology has no
  // psychology-specific preset but still belongs to behavioral health.
  for (const s of ['psychiatry', 'behavioral-health', 'psychology']) {
    const html = exportFormatOptions(s);
    for (const brand of BRANDS) assert.ok(html.includes(brand), `${s}: must offer ${brand}`);
    assert.ok(html.includes('Plain text'), `${s}: plain text still available`);
  }
});

test('plain text is always the first (default) option', () => {
  for (const s of ['podiatry', 'psychiatry', undefined]) {
    assert.match(exportFormatOptions(s), /^<option value="plain"/);
  }
});

// ── renderEncounterPanel(): the options are wired into both export controls ──

test('podiatry panel shows no brand names in the export dropdown (draft + signed)', () => {
  setSpecialty('podiatry');
  for (const status of ['draft', 'signed']) {
    const html = renderEncounterPanel({
      id: 'enc-1', status, patient_alias: '', encounter_date: '2026-07-06',
      signed_at: '2026-07-06T00:00:00Z', signed_hash: 'abc',
    });
    for (const brand of BRANDS) assert.ok(!html.includes(brand), `${status}: no ${brand}`);
    assert.ok(html.includes('Plain text'), `${status}: plain text present`);
  }
});

test('psychiatry panel keeps brand names in the export dropdown', () => {
  setSpecialty('psychiatry');
  const html = renderEncounterPanel({
    id: 'enc-2', status: 'draft', patient_alias: '', encounter_date: '2026-07-06',
  });
  for (const brand of BRANDS) assert.ok(html.includes(brand), `must keep ${brand}`);
  assert.ok(html.includes('Plain text'));
});
