// S-UX-1 (integration): stop-recording → transcript → note, no manual clicks.
//
// Wires the REAL transcriptSection + noteSection against a minimal fake DOM and
// a mock Tauri runtime, then drives runScribeChain the same way panel.js does
// on scribe:audio_saved. Verifies:
//   - happy path: transcript textarea and note textarea both populate with no
//     button clicks, and the sign/copy/export buttons enable
//   - transcription failure stops the chain (no note generated) and surfaces
//     the mapped plain-language error via the toast
//   - the manual "Transcribe" / "Generate Note" buttons still work afterward
//     (re-transcribe / re-generate for edits or template switches)

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// ── Minimal fake DOM ────────────────────────────────────────────────────────
class FakeEl {
  constructor(id) {
    this.id = id;
    this.value = '';
    this.textContent = '';
    this.placeholder = '';
    this.disabled = false;
    this.readOnly = false;
    this.className = '';
    this.style = {};
    this._on = {};
    this.classList = {
      _s: new Set(),
      add: (c) => this.classList._s.add(c),
      remove: (c) => this.classList._s.delete(c),
      contains: (c) => this.classList._s.has(c),
    };
  }
  addEventListener(type, fn) { this._on[type] = fn; }
  removeAttribute(attr) { if (attr === 'disabled') this.disabled = false; }
  setAttribute() {}
  remove() {}
  click() { return this._on.click && this._on.click(); }
}

let els;
function resetDom() {
  els = new Map();
  for (const id of [
    'btn-transcribe', 'transcript-area', 'btn-generate', 'status-banner',
    'note-area', 'note-save-indicator', 'btn-sign', 'btn-copy', 'btn-save-file',
    'template-select', 'toast', 'toast-msg',
  ]) {
    els.set(id, new FakeEl(id));
  }
  els.get('template-select').value = 'soap-generic';
}

globalThis.document = { getElementById: (id) => els?.get(id) || null, querySelector: () => null };
globalThis.window = globalThis.window || {};
globalThis.requestAnimationFrame = (cb) => { cb(); return 0; };
globalThis.cancelAnimationFrame = () => {};

// ── Mock Tauri runtime ──────────────────────────────────────────────────────
let responders = {};
let _history = new Map();
function invokeMock(cmd, args) {
  const r = responders[cmd];
  if (r instanceof Error || (r && typeof r === 'object' && typeof r.code === 'string')) {
    return Promise.reject(r);
  }
  if (typeof r === 'function') return Promise.resolve(r(args));
  if (r !== undefined) return Promise.resolve(r);
  if (cmd === 'note_history_list') return Promise.resolve(_history.get(args.encounterId)?.slice() || []);
  if (cmd === 'note_history_append') {
    const list = _history.get(args.encounterId) || [];
    list.push(args.entry);
    _history.set(args.encounterId, list);
    return Promise.resolve(list.length);
  }
  return Promise.resolve(null);
}
globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: invokeMock },
  event: { listen: () => () => {} },
};

const { wireTranscriptSection } = await import('../../src/solo/encounter/transcriptSection.js');
const { wireNoteSection } = await import('../../src/solo/encounter/noteSection.js');
const { runScribeChain } = await import('../../src/solo/encounter/autoChain.js');

function makeCtx() {
  let transcript = '';
  return {
    currentEncounter: { id: 'enc-1', audio_path: '/tmp/enc-1.wav', status: 'recording_done' },
    providerProfile: {},
    sub: () => {},
    onEncounterUpdated: () => {},
    currentTranscript: () => transcript,
    setTranscript: (v) => { transcript = v; },
  };
}

beforeEach(() => {
  resetDom();
  responders = {};
  _history = new Map();
});

test('happy path: audio_saved auto-chains transcript then note with no clicks', async () => {
  responders['transcribe_audio'] = 'PATIENT REPORTS HEEL PAIN';
  responders['generate_note'] = 'Chief Complaint: heel pain.';

  const ctx = makeCtx();
  const t = wireTranscriptSection(ctx);
  const n = wireNoteSection(ctx);

  const ok = await runScribeChain({ transcribeNow: t.transcribeNow, generateNow: n.generateNow });

  assert.equal(ok, true);
  assert.equal(els.get('transcript-area').value, 'PATIENT REPORTS HEEL PAIN');
  assert.equal(els.get('note-area').value, 'Chief Complaint: heel pain.');
  assert.equal(els.get('btn-sign').disabled, false, 'sign enables after generation');
  assert.equal(els.get('status-banner').style.display, 'none', 'banner clears when done');
});

test('transcription failure stops the chain and surfaces a plain-language error', async () => {
  responders['transcribe_audio'] = { code: 'transcription', message: 'whisper failed' };
  responders['generate_note'] = 'SHOULD NOT BE PRODUCED';

  const ctx = makeCtx();
  const t = wireTranscriptSection(ctx);
  const n = wireNoteSection(ctx);

  const ok = await runScribeChain({ transcribeNow: t.transcribeNow, generateNow: n.generateNow });

  assert.equal(ok, false);
  assert.equal(els.get('note-area').value, '', 'no note generated when transcription failed');
  assert.equal(els.get('toast-msg').textContent, 'Transcription failed on this device.');
  assert.equal(els.get('status-banner').style.display, 'none', 'banner cleared on failure');
});

test('manual re-transcribe and re-generate still work after the auto-chain', async () => {
  responders['transcribe_audio'] = 'FIRST PASS';
  responders['generate_note'] = 'FIRST NOTE';

  const ctx = makeCtx();
  const t = wireTranscriptSection(ctx);
  const n = wireNoteSection(ctx);
  await runScribeChain({ transcribeNow: t.transcribeNow, generateNow: n.generateNow });
  assert.equal(els.get('note-area').value, 'FIRST NOTE');

  // Provider edits/switches template, then clicks the manual buttons.
  responders['transcribe_audio'] = 'SECOND PASS';
  await els.get('btn-transcribe').click();
  assert.equal(els.get('transcript-area').value, 'SECOND PASS');

  responders['generate_note'] = 'SECOND NOTE';
  await els.get('btn-generate').click();
  assert.equal(els.get('note-area').value, 'SECOND NOTE');
});
