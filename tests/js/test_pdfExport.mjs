// Unit tests for the client-side PDF export wrapper.
//
// We test OUR contract only — filename hygiene, that buildPdf returns non-empty
// bytes, and the cloud-archive hook seam (defaults null, honored when set). We
// do NOT assert PDF binary structure; jsPDF's own tests cover rendering.
//
// A mock Tauri runtime is installed BEFORE the app modules load (same pattern
// as test_signoff.mjs) so `isTauri` resolves true, the audit KV writes flow
// through a recording `invoke`, and saveToPdf's export_note_pdf_to_file call is
// captured instead of hitting a real dialog.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

const calls = [];
function invokeMock(cmd, args) {
  calls.push({ cmd, args });
  return Promise.resolve(null);
}

globalThis.document = { getElementById: () => null }; // toast() no-ops in tests
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: invokeMock },
  event: { listen: () => () => {} },
};
// jsPDF's node build treats `window` as its global scope if present, so the
// mock must expose the primitives it reaches for (atob/btoa/console). An empty
// object here makes jsPDF throw on load.
globalThis.window = globalThis.window || {};
globalThis.window.atob = globalThis.window.atob || globalThis.atob;
globalThis.window.btoa = globalThis.window.btoa || globalThis.btoa;
globalThis.window.console = globalThis.window.console || globalThis.console;

const { buildPdf, saveToPdf, exportFilenamePdf, archivePdfHook, setArchivePdfHook } =
  await import('../../src/export/pdfExport.js');

const encounter = {
  id: 'enc-1',
  encounter_date: '2026-06-29',
  patient_alias: 'John Doe',
  status: 'signed',
};

beforeEach(() => {
  calls.length = 0;
  setArchivePdfHook(null);
});

test('exportFilenamePdf uses .pdf and never leaks the patient alias', () => {
  const name = exportFilenamePdf(encounter);
  assert.equal(name, 'note_20260629_enc-1.pdf');
  assert.doesNotMatch(name, /John|Doe/);
});

test('buildPdf returns a non-empty ArrayBuffer of PDF bytes', () => {
  const buf = buildPdf('A clinical note body.', encounter);
  assert.ok(buf instanceof ArrayBuffer, 'buildPdf should return an ArrayBuffer');
  const bytes = new Uint8Array(buf);
  assert.ok(bytes.length > 0, 'PDF bytes must be non-empty');
  // A real PDF starts with "%PDF" — a cheap sanity check on our wrapper output
  // without asserting internal structure.
  assert.deepEqual([...bytes.slice(0, 4)], [...Buffer.from('%PDF')]);
});

test('buildPdf handles a missing note body without throwing', () => {
  const buf = buildPdf('', { id: 'e2', encounter_date: '2026-01-01', status: 'draft' });
  assert.ok(new Uint8Array(buf).length > 0);
});

test('archivePdfHook defaults to null', () => {
  assert.equal(archivePdfHook, null);
});

test('saveToPdf invokes the PDF command and does NOT call a null hook', async () => {
  await saveToPdf('Body', encounter);
  const pdfCall = calls.find(c => c.cmd === 'export_note_pdf_to_file');
  assert.ok(pdfCall, 'export_note_pdf_to_file must be invoked');
  assert.equal(pdfCall.args.suggestedName, 'note_20260629_enc-1.pdf');
  assert.equal(typeof pdfCall.args.dataBase64, 'string');
  assert.ok(pdfCall.args.dataBase64.length > 0, 'base64 payload must be non-empty');
});

test('saveToPdf calls the archive hook after a successful save when one is set', async () => {
  let hookArgs = null;
  setArchivePdfHook(async (bytes, enc) => { hookArgs = { bytes, enc }; });
  await saveToPdf('Body', encounter);
  assert.ok(hookArgs, 'hook should be invoked when non-null');
  assert.equal(hookArgs.enc.id, 'enc-1');
});

test('a throwing archive hook never fails the local save', async () => {
  setArchivePdfHook(async () => { throw new Error('archive backend down'); });
  await assert.doesNotReject(saveToPdf('Body', encounter));
});
